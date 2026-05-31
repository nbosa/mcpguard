package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"mcpguard/internal/dynamic/client"
	"mcpguard/internal/dynamic/prober"
	"mcpguard/internal/dynamic/rugpull"
	proxydetector "mcpguard/internal/proxy/detector"
	proxystdio "mcpguard/internal/proxy/stdio"
	"mcpguard/internal/report"
	"mcpguard/internal/rules/engine"
	"mcpguard/internal/rules/model"
)

var (
	rulesDir      string
	format        string
	outputPath    string
	failSeverity  string
	configPath    string
	serverName    string
	probeDuration int

	upstreamCommand          string
	upstreamArgs             []string
	upstreamEnv              []string
	proxyReportPath          string
	proxyUseFoundationModels bool
)

var (
	// Version is set by release builds using -ldflags.
	Version = "dev"
	// Commit is set by release builds using -ldflags.
	Commit = "unknown"
	// BuildDate is set by release builds using -ldflags.
	BuildDate = "unknown"
)

func buildInfoString() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}

// ExitError carries the process exit code for handled CLI failures.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// RootCmd is the primary CLI command.
var RootCmd = &cobra.Command{
	Use:           "mcpguard",
	Short:         "mcpguard is a security scanner and watchdog for Model Context Protocol (MCP) servers.",
	Long:          `A dedicated security scanner and watchdog designed to discover excessive capabilities, supply chain vulnerabilities, Unicode obfuscation, and runtime schema drift in MCP servers.`,
	Version:       buildInfoString(),
	SilenceUsage:  true,
	SilenceErrors: true,
}

// scanCmd defines the scan subcommand parameters.
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Audit configuration and codebase for MCP security vulnerabilities",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}
		if _, ok := parseSeverity(failSeverity); !ok {
			return scanError("invalid fail severity %q", failSeverity)
		}

		scannerEngine := engine.NewEngine()
		scannerEngine.LoadBuiltinRules()

		if rulesDir != "" {
			if err := scannerEngine.LoadRulesFromDirectory(rulesDir); err != nil {
				return scanError("load rules from %s: %w", rulesDir, err)
			}
		}

		scanReport, err := scannerEngine.ScanPath(path)
		if err != nil {
			return scanError("scan target %s: %w", path, err)
		}

		var out io.Writer = os.Stdout
		if outputPath != "" {
			f, err := os.Create(outputPath)
			if err != nil {
				return scanError("create output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		if err := report.GenerateReport(out, scanReport, format); err != nil {
			return scanError("generate report: %w", err)
		}

		if hasFailingFindings(scanReport.Findings, failSeverity) {
			return &ExitError{Code: 1}
		}

		return nil
	},
}

// probeCmd defines the dynamic prober subcommand.
var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Connect to a live MCP server and probe its dynamic behaviors",
	RunE: func(cmd *cobra.Command, args []string) error {
		startTime := time.Now()
		if _, ok := parseSeverity(failSeverity); !ok {
			return scanError("invalid fail severity %q", failSeverity)
		}

		// Parse the config file to locate the server command
		file, err := os.Open(configPath)
		if err != nil {
			return scanError("open config file: %w", err)
		}
		defer file.Close()

		var parsed map[string]interface{}
		if err := json.NewDecoder(file).Decode(&parsed); err != nil {
			return scanError("parse config JSON: %w", err)
		}

		mcpServers, exists := parsed["mcpServers"].(map[string]interface{})
		if !exists {
			return scanError("no mcpServers defined in config")
		}

		serverVal, exists := mcpServers[serverName]
		if !exists {
			return scanError("server %q not found in config", serverName)
		}

		serverConfig, ok := serverVal.(map[string]interface{})
		if !ok {
			return scanError("invalid configuration for server %q", serverName)
		}

		command, _ := serverConfig["command"].(string)
		if command == "" {
			return scanError("no command defined for server %q", serverName)
		}

		var serverArgs []string
		if rawArgs, ok := serverConfig["args"].([]interface{}); ok {
			for _, arg := range rawArgs {
				if str, ok := arg.(string); ok {
					serverArgs = append(serverArgs, str)
				}
			}
		}

		var env []string
		if rawEnv, ok := serverConfig["env"].(map[string]interface{}); ok {
			for k, v := range rawEnv {
				if str, ok := v.(string); ok {
					env = append(env, fmt.Sprintf("%s=%s", k, str))
				}
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(probeDuration)*time.Second)
		defer cancel()

		fmt.Fprintf(cmd.ErrOrStderr(), "Connecting to live MCP server %q via command %q...\n", serverName, command)
		session, err := client.ConnectToStdioServer(ctx, command, serverArgs, env)
		if err != nil {
			return scanError("connect to server: %w", err)
		}
		defer session.Close()

		// 1. Take baseline schema snapshot
		beforeSnapshot, err := rugpull.TakeSchemaSnapshot(ctx, session)
		if err != nil {
			return scanError("take baseline schema snapshot: %w", err)
		}

		// 2. Run initial prober checks
		findings, err := prober.RunProbes(ctx, session, configPath)
		if err != nil {
			return scanError("run probes: %w", err)
		}

		// 3. Simulate client interaction / trigger rugpull if tool exists
		hasTrigger := false
		for name := range beforeSnapshot {
			if name == "trigger_rugpull" {
				hasTrigger = true
				break
			}
		}

		if hasTrigger {
			fmt.Fprintln(cmd.ErrOrStderr(), "Triggering simulated rugpull on server...")
			_, err = session.CallTool(ctx, "trigger_rugpull", map[string]interface{}{})
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Failed to execute rugpull trigger: %v\n", err)
			}
		}

		// Let the server execute / process
		time.Sleep(1 * time.Second)

		// 4. Take post-execution snapshot
		afterSnapshot, err := rugpull.TakeSchemaSnapshot(ctx, session)
		if err == nil {
			// Diff schemas
			rugpullFindings := rugpull.DiffSchemas(beforeSnapshot, afterSnapshot, configPath)
			findings = append(findings, rugpullFindings...)
		}

		// Prepare report
		scanReport := &model.ScanReport{
			Path:         configPath,
			StartTime:    startTime,
			DurationMs:   time.Since(startTime).Milliseconds(),
			Findings:     findings,
			TotalScanned: 1,
		}

		// Format output
		var out io.Writer = os.Stdout
		if outputPath != "" {
			f, err := os.Create(outputPath)
			if err != nil {
				return scanError("create output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		if err := report.GenerateReport(out, scanReport, format); err != nil {
			return scanError("generate report: %w", err)
		}

		if hasFailingFindings(scanReport.Findings, failSeverity) {
			return &ExitError{Code: 1}
		}

		return nil
	},
}

// proxyCmd exposes a local stdio MCP server that guards an upstream stdio MCP server.
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run a local stdio MCP guard proxy for an upstream MCP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		command := upstreamCommand
		serverArgs := append([]string(nil), upstreamArgs...)
		env := append([]string(nil), upstreamEnv...)

		if configPath != "" {
			loadedCommand, loadedArgs, loadedEnv, err := loadServerFromConfig(configPath, serverName)
			if err != nil {
				return scanError("load upstream server from config: %w", err)
			}
			command = loadedCommand
			serverArgs = loadedArgs
			env = loadedEnv
		}
		if command == "" {
			return scanError("proxy requires --upstream-command or --config with --server")
		}

		var classifier proxydetector.ModelClassifier
		if proxyUseFoundationModels {
			modelClassifier, err := proxydetector.NewFoundationModelsClassifier()
			if err != nil {
				return scanError("initialize foundation models detector: %w", err)
			}
			classifier = modelClassifier
		}

		guardProxy, err := proxystdio.New(proxystdio.Config{
			UpstreamCommand: command,
			UpstreamArgs:    serverArgs,
			UpstreamEnv:     env,
			ReportPath:      proxyReportPath,
			Guard:           proxydetector.NewGuard(classifier),
		})
		if err != nil {
			return scanError("create proxy: %w", err)
		}
		defer guardProxy.Close()

		fmt.Fprintf(cmd.ErrOrStderr(), "mcpguard proxy forwarding to %q\n", command)
		if err := guardProxy.Run(context.Background(), os.Stdin, os.Stdout); err != nil {
			return scanError("run proxy: %w", err)
		}
		return nil
	},
}

// versionCmd prints build metadata in a script-friendly format.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print mcpguard version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "mcpguard %s\ncommit: %s\nbuilt: %s\n", Version, Commit, BuildDate)
	},
}

func scanError(format string, args ...interface{}) error {
	return &ExitError{Code: 2, Err: fmt.Errorf(format, args...)}
}

func parseSeverity(sev string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 5, true
	case "HIGH":
		return 4, true
	case "MEDIUM":
		return 3, true
	case "LOW":
		return 2, true
	case "INFO":
		return 1, true
	default:
		return 0, false
	}
}

func hasFailingFindings(findings []model.Finding, failSeverity string) bool {
	threshold, ok := parseSeverity(failSeverity)
	if !ok {
		return true
	}
	for _, finding := range findings {
		severity, ok := parseSeverity(string(finding.Severity))
		if ok && severity >= threshold {
			return true
		}
	}
	return false
}

func loadServerFromConfig(path, name string) (string, []string, []string, error) {
	if name == "" {
		return "", nil, nil, fmt.Errorf("server name is required when using config")
	}

	file, err := os.Open(path)
	if err != nil {
		return "", nil, nil, err
	}
	defer file.Close()

	var parsed map[string]interface{}
	if err := json.NewDecoder(file).Decode(&parsed); err != nil {
		return "", nil, nil, err
	}

	mcpServers, exists := parsed["mcpServers"].(map[string]interface{})
	if !exists {
		return "", nil, nil, fmt.Errorf("no mcpServers defined in config")
	}

	serverVal, exists := mcpServers[name]
	if !exists {
		return "", nil, nil, fmt.Errorf("server %q not found in config", name)
	}

	serverConfig, ok := serverVal.(map[string]interface{})
	if !ok {
		return "", nil, nil, fmt.Errorf("invalid configuration for server %q", name)
	}

	command, _ := serverConfig["command"].(string)
	if command == "" {
		return "", nil, nil, fmt.Errorf("no command defined for server %q", name)
	}

	var serverArgs []string
	if rawArgs, ok := serverConfig["args"].([]interface{}); ok {
		for _, arg := range rawArgs {
			if str, ok := arg.(string); ok {
				serverArgs = append(serverArgs, str)
			}
		}
	}

	var env []string
	if rawEnv, ok := serverConfig["env"].(map[string]interface{}); ok {
		for k, v := range rawEnv {
			if str, ok := v.(string); ok {
				env = append(env, fmt.Sprintf("%s=%s", k, str))
			}
		}
	}

	return command, serverArgs, env, nil
}

func init() {
	RootCmd.PersistentFlags().StringVar(&format, "format", "markdown", "Output format (json, markdown, html, sarif)")
	RootCmd.PersistentFlags().StringVar(&outputPath, "output", "", "Output file path (default stdout)")
	RootCmd.PersistentFlags().StringVar(&failSeverity, "fail-severity", "HIGH", "Minimum severity to trigger non-zero exit code (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	RootCmd.SetVersionTemplate("mcpguard {{.Version}}\n")

	scanCmd.Flags().StringVar(&rulesDir, "rules-dir", "", "Directory containing custom YAML rules")

	probeCmd.Flags().StringVar(&configPath, "config", "", "Path to Claude Desktop config JSON file")
	_ = probeCmd.MarkFlagRequired("config")
	probeCmd.Flags().StringVar(&serverName, "server", "", "Name of the MCP server to probe")
	_ = probeCmd.MarkFlagRequired("server")
	probeCmd.Flags().IntVar(&probeDuration, "duration", 3, "Duration in seconds to monitor the server")

	proxyCmd.Flags().StringVar(&upstreamCommand, "upstream-command", "", "Upstream stdio MCP server command")
	proxyCmd.Flags().StringArrayVar(&upstreamArgs, "upstream-arg", nil, "Upstream command argument (repeatable)")
	proxyCmd.Flags().StringArrayVar(&upstreamEnv, "upstream-env", nil, "Upstream environment variable in KEY=VALUE form (repeatable)")
	proxyCmd.Flags().StringVar(&proxyReportPath, "proxy-report", "", "Optional JSONL file for blocked proxy events")
	proxyCmd.Flags().BoolVar(&proxyUseFoundationModels, "foundation-models", false, "Enable optional go-foundationmodels classifier in addition to regex")
	proxyCmd.Flags().StringVar(&configPath, "config", "", "Path to Claude Desktop config JSON file")
	proxyCmd.Flags().StringVar(&serverName, "server", "", "Name of the MCP server to proxy from config")

	RootCmd.AddCommand(scanCmd)
	RootCmd.AddCommand(probeCmd)
	RootCmd.AddCommand(proxyCmd)
	RootCmd.AddCommand(versionCmd)
}

// Execute CLI entrypoint.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Err != nil {
				fmt.Fprintln(os.Stderr, exitErr.Err)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
