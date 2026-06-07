// Package cli implements the mcpguard command-line interface.
//
// After the v0.2 focus refactor, mcpguard ships a single proxy subcommand
// (plus version and list-classifiers). The static scanner and dynamic
// prober were removed; the only MCP-facing feature is the stdio guard proxy.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"mcpguard/internal/proxy/classifier"
	proxystdio "mcpguard/internal/proxy/stdio"
	"mcpguard/internal/view"
)

var (
	upstreamCommand string
	upstreamArgs    []string
	upstreamEnv     []string
	upstreamCwd     string
	proxyReportPath string
	classifierNames []string
	timeoutMS       int
	maxParseErrors  int

	viewReportPath string
	viewPort       int
	viewNoBrowser  bool
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

func (e *ExitError) Unwrap() error { return e.Err }

// RootCmd is the primary CLI command.
var RootCmd = &cobra.Command{
	Use:           "mcpguard",
	Short:         "mcpguard is a stdio MCP guard proxy.",
	Long:          `mcpguard is a local stdio MCP guard proxy that blocks prompt injection, tool poisoning, and rug-pull schema drift between a local MCP client and an upstream stdio MCP server.`,
	Version:       buildInfoString(),
	SilenceUsage:  true,
	SilenceErrors: true,
}

// proxyCmd is the only MCP-facing subcommand. It runs a stdio guard proxy
// in front of an upstream stdio MCP server.
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run a stdio MCP guard proxy in front of an upstream MCP server",
	Long: `Run a stdio MCP guard proxy. The proxy reads JSON-RPC requests from
stdin, inspects them, forwards to the upstream server, inspects responses,
and writes the filtered stream to stdout. Blocked requests and responses
return JSON-RPC error code -32090.

The proxy is configured via flags. Either point at an upstream command
explicitly, or load one from a Claude Desktop / mcp.json style config file.`,
	RunE: runProxy,
}

// listClassifiersCmd enumerates the registered classifiers and their
// availability. Useful for users building the proxy on a new machine.
var listClassifiersCmd = &cobra.Command{
	Use:   "list-classifiers",
	Short: "List registered threat classifiers and their availability",
	RunE:  runListClassifiers,
}

// viewCmd tails a proxy JSONL report file and serves a live HTML viewer.
var viewCmd = &cobra.Command{
	Use:   "view",
	Short: "Live HTML viewer for a proxy JSONL report",
	Long: `Tails a JSONL report file (the one written by 'mcpguard proxy
--proxy-report PATH') and serves a real-time HTML view at
http://localhost:PORT. New findings appear in the browser as the proxy
writes them.

Open the printed URL in any modern browser. The page works in dark mode by
default and does not require a build step or external resources.`,
	RunE: runView,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print mcpguard version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "mcpguard %s\ncommit: %s\nbuilt: %s\n", Version, Commit, BuildDate)
	},
}

func runProxy(cmd *cobra.Command, args []string) error {
	command := upstreamCommand
	serverArgs := append([]string(nil), upstreamArgs...)
	env := append([]string(nil), upstreamEnv...)

	if configPath != "" {
		loadedCommand, loadedArgs, loadedEnv, err := loadServerFromConfig(configPath, serverName)
		if err != nil {
			return &ExitError{Code: 2, Err: fmt.Errorf("load upstream server from config: %w", err)}
		}
		command = loadedCommand
		serverArgs = loadedArgs
		env = loadedEnv
	}
	if command == "" {
		return &ExitError{Code: 2, Err: fmt.Errorf("proxy requires --upstream-command or --config with --server")}
	}

	cfg := proxystdio.Config{
		UpstreamCommand: command,
		UpstreamArgs:    serverArgs,
		UpstreamEnv:     env,
		UpstreamCwd:     upstreamCwd,
		ReportPath:      proxyReportPath,
		ClassifierNames: classifierNames,
		Timeout:         time.Duration(timeoutMS) * time.Millisecond,
		MaxParseErrors:  maxParseErrors,
	}
	guardProxy, err := proxystdio.New(cfg)
	if err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("create proxy: %w", err)}
	}
	defer guardProxy.Close()

	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(cmd.ErrOrStderr(), "mcpguard proxy forwarding to %q (classifiers: %s)\n", command, strings.Join(cfg.ClassifierNames, ", "))
	if err := guardProxy.Run(ctx, os.Stdin, os.Stdout); err != nil {
		if errors.Is(err, context.Canceled) || isGracefulClose(err) {
			return nil
		}
		return &ExitError{Code: 2, Err: fmt.Errorf("run proxy: %w", err)}
	}
	return nil
}

// isGracefulClose returns true for the "client closed stdin" / "upstream
// closed stdout" sentinel errors that the proxy returns when one side of
// the conversation disconnects cleanly. These are not failures.
func isGracefulClose(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "client closed stdin") ||
		strings.Contains(msg, "upstream closed stdout")
}

func runListClassifiers(cmd *cobra.Command, args []string) error {
	reg := classifier.Default()
	names := reg.Names()
	sort.Strings(names)

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Registered classifiers:")
	if len(names) == 0 {
		fmt.Fprintln(out, "  (none)")
		return nil
	}
	for _, n := range names {
		c, err := reg.Get(n)
		if err != nil {
			continue
		}
		status := "available"
		if err := c.Available(); err != nil {
			status = "unavailable: " + err.Error()
		}
		fmt.Fprintf(out, "  %s — %s\n    %s\n", c.Name(), status, c.Description())
	}
	return nil
}

func runView(cmd *cobra.Command, args []string) error {
	if viewReportPath == "" {
		return &ExitError{Code: 2, Err: fmt.Errorf("--report is required (point at the file written by 'mcpguard proxy --proxy-report')")}
	}
	if _, err := os.Stat(viewReportPath); err != nil && !os.IsNotExist(err) {
		return &ExitError{Code: 2, Err: fmt.Errorf("stat report: %w", err)}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", viewPort)
	s := view.New(viewReportPath, addr)
	s.Logger = cmd.ErrOrStderr()

	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		return &ExitError{Code: 2, Err: fmt.Errorf("start view server: %w", err)}
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = s.Shutdown(shutdownCtx)
	}()

	url := s.URL()
	fmt.Fprintf(cmd.ErrOrStderr(), "mcpguard view serving %s\nOpen %s in a browser.\nPress Ctrl-C to stop.\n", viewReportPath, url)
	if !viewNoBrowser {
		fmt.Fprintf(cmd.ErrOrStderr(), "(tip: pass --no-browser to suppress this hint; the URL is always printed above)\n")
	}

	<-ctx.Done()
	fmt.Fprintln(cmd.ErrOrStderr(), "mcpguard view: shutting down")
	return nil
}

func cliError(code int, format string, args ...interface{}) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// configPath and serverName are shared between proxy and loadServerFromConfig.
var (
	configPath string
	serverName string
)

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
	RootCmd.SetVersionTemplate("mcpguard {{.Version}}\n")

	proxyCmd.Flags().StringVar(&upstreamCommand, "upstream-command", "", "Upstream stdio MCP server command (e.g. node, python3)")
	proxyCmd.Flags().StringArrayVar(&upstreamArgs, "upstream-arg", nil, "Argument to pass to --upstream-command (repeatable)")
	proxyCmd.Flags().StringArrayVar(&upstreamEnv, "upstream-env", nil, "Environment variable in KEY=VALUE form (repeatable)")
	proxyCmd.Flags().StringVar(&upstreamCwd, "upstream-cwd", "", "Working directory for the upstream process")
	proxyCmd.Flags().StringVar(&proxyReportPath, "proxy-report", "", "Optional JSONL file for blocked/observed proxy events")
	proxyCmd.Flags().StringArrayVar(&classifierNames, "classifier", nil, "Classifier to apply (repeatable, default: regex). Run `mcpguard list-classifiers` to see available names.")
	proxyCmd.Flags().IntVar(&timeoutMS, "timeout", 30000, "Per-request upstream timeout in milliseconds")
	proxyCmd.Flags().IntVar(&maxParseErrors, "max-parse-errors", 10, "Abort proxy after this many consecutive JSON parse failures from either side")
	proxyCmd.Flags().StringVar(&configPath, "config", "", "Path to a Claude Desktop / mcp.json style config file")
	proxyCmd.Flags().StringVar(&serverName, "server", "", "Name of the MCP server entry to proxy from --config")

	viewCmd.Flags().StringVar(&viewReportPath, "report", "", "Path to the proxy JSONL report file (the same path given to 'mcpguard proxy --proxy-report')")
	viewCmd.Flags().IntVar(&viewPort, "port", view.DefaultPort, "HTTP listen port")
	viewCmd.Flags().BoolVar(&viewNoBrowser, "no-browser", false, "Suppress the open-browser hint (the URL is always printed)")

	RootCmd.AddCommand(proxyCmd)
	RootCmd.AddCommand(listClassifiersCmd)
	RootCmd.AddCommand(viewCmd)
	RootCmd.AddCommand(versionCmd)
}

// Execute is the CLI entrypoint.
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
