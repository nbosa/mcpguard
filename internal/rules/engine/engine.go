package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"mcpguard/internal/rules/model"
)

// Engine orchestrates loading rules, traversing directories, scanning target codebases, and consolidating findings.
type Engine struct {
	Rules      []model.Rule
	IgnoreList *model.IgnoreList
}

// NewEngine creates an empty Rules Engine.
func NewEngine() *Engine {
	return &Engine{
		Rules:      []model.Rule{},
		IgnoreList: &model.IgnoreList{},
	}
}

// LoadBuiltinRules initializes the engine with default MCPLIB/OWASP-aligned rules.
func (e *Engine) LoadBuiltinRules() {
	for _, rule := range GetDefaultRules() {
		e.addRule(rule)
	}
}

// LoadRulesFromDirectory loads all YAML rules from a directory.
func (e *Engine) LoadRulesFromDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			path := filepath.Join(dir, name)
			if err := e.LoadRuleFromFile(path); err != nil {
				return fmt.Errorf("failed to load rule %q: %w", path, err)
			}
		}
	}
	return nil
}

// LoadRuleFromFile parses and validates a single YAML rule.
func (e *Engine) LoadRuleFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var r model.Rule
	dec := yaml.NewDecoder(file)
	if err := dec.Decode(&r); err != nil {
		return err
	}

	if err := r.Validate(); err != nil {
		return err
	}

	e.addRule(r)
	return nil
}

func (e *Engine) addRule(rule model.Rule) {
	for i, existing := range e.Rules {
		if existing.ID == rule.ID {
			e.Rules[i] = rule
			return
		}
	}
	e.Rules = append(e.Rules, rule)
}

// LoadIgnoreList loads ignore rules from .mcpguard-ignore if it exists.
func (e *Engine) LoadIgnoreList(path string) error {
	list, err := model.LoadIgnoreList(path)
	if err != nil {
		return err
	}
	e.IgnoreList = list
	return nil
}

// CalculateEntropy calculates the Shannon entropy of a string.
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// HasUnicodeObfuscation flags potential homoglyph attacks or hidden control characters.
func HasUnicodeObfuscation(s string) bool {
	// Look for invisible control characters (zero-width spaces, RTL/LTR overrides, etc.)
	// \u200b (Zero-width space), \u200c (Zero-width non-joiner), \u200d (Zero-width joiner), \u202a-\u202e (directional overrides)
	controlRegex := regexp.MustCompile(`[\x{200B}-\x{200D}\x{FEFF}\x{202A}-\x{202E}]`)
	if controlRegex.MatchString(s) {
		return true
	}
	return false
}

// ScanPath walks a target path recursively and scans relevant files.
func (e *Engine) ScanPath(rootPath string) (*model.ScanReport, error) {
	report := &model.ScanReport{
		Path:      rootPath,
		StartTime: time.Now(),
		Findings:  []model.Finding{},
	}

	// Try loading the ignore list in the target root path if none has been loaded yet
	if e.IgnoreList == nil || len(e.IgnoreList.Rules) == 0 {
		ignorePath := filepath.Join(rootPath, ".mcpguard-ignore")
		_ = e.LoadIgnoreList(ignorePath)
	}

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden folders (like .git, .antigravitycli, etc.)
		if info.IsDir() {
			name := info.Name()
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipFile(path, info) {
			return nil
		}

		// Scan files depending on extension
		relPath, relErr := filepath.Rel(rootPath, path)
		if relErr != nil {
			relPath = path
		}

		report.TotalScanned++
		findings, err := e.ScanFile(path, relPath)
		if err == nil {
			for _, f := range findings {
				if !e.IgnoreList.IsIgnored(f) {
					report.Findings = append(report.Findings, f)
				}
			}
		}

		return nil
	})

	report.DurationMs = time.Since(report.StartTime).Milliseconds()

	// Resolve conflicts and deduplicate findings
	report.Findings = e.deduplicateFindings(report.Findings)

	return report, err
}

func shouldSkipDir(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "node_modules", "vendor", "dist", "build", "coverage", "__pycache__":
		return true
	default:
		return false
	}
}

func shouldSkipFile(path string, info os.FileInfo) bool {
	if info.Size() > 5*1024*1024 {
		return true
	}
	name := filepath.Base(path)
	if strings.HasPrefix(name, ".") && name != ".env" && name != ".mcpguard-ignore" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" && info.Mode()&0o111 != 0 {
		return true
	}
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".exe", ".dll", ".dylib", ".so":
		return true
	default:
		return false
	}
}

// ScanFile inspects a single file using configured rules and generic parsers.
func (e *Engine) ScanFile(absPath, relPath string) ([]model.Finding, error) {
	var findings []model.Finding

	file, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(absPath))
	base := filepath.Base(absPath)

	// Read content
	contentBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if isBinaryContent(contentBytes) {
		return nil, nil
	}
	content := string(contentBytes)

	for _, finding := range e.scanFilePathRules(relPath) {
		findings = append(findings, finding)
	}

	// Check if this is a configuration file
	if base == "claude_desktop_config.json" || base == "mcp.json" || ext == ".json" {
		configFindings := e.scanConfigJson(content, relPath)
		findings = append(findings, configFindings...)
		findings = append(findings, e.scanStructuredMatchers(contentBytes, relPath, "json")...)
	} else if ext == ".yaml" || ext == ".yml" {
		findings = append(findings, e.scanStructuredMatchers(contentBytes, relPath, "yaml")...)
	}

	// Line-by-line scanning for regex rules and secret detection
	lines := strings.Split(content, "\n")
	for lineNum, lineContent := range lines {
		// Run matchers
		for _, rule := range e.Rules {
			for _, m := range rule.Matchers {
				if !matcherAppliesToFile(m, ext) {
					continue
				}
				if m.Type == model.MatcherRegex {
					re, err := regexp.Compile(m.Pattern)
					if err == nil && regexMatcherMatches(re, m, lineContent) {
						findings = append(findings, model.Finding{
							RuleID:      rule.ID,
							Title:       rule.Title,
							Severity:    rule.Severity,
							Description: rule.Description,
							Remediation: rule.Remediation,
							FilePath:    relPath,
							LineNumber:  lineNum + 1,
							MatchString: strings.TrimSpace(lineContent),
							Timestamp:   time.Now(),
						})
					}
				}
			}
		}

		// Generic entropy scanner for credentials (secrets) on configuration-like or code files
		if ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".env" || ext == ".py" || ext == ".js" || ext == ".ts" || ext == ".go" {
			// Find string literals or variables that might be secrets
			// We look for assignments like API_KEY = "..." or "api_key": "..."
			secretRegex := regexp.MustCompile(`(?i)(api_key|token|jwt|password|secret|private_key|credential|passwd|auth)\s*[:=]\s*["']([^"']+)["']`)
			matches := secretRegex.FindStringSubmatch(lineContent)
			if len(matches) > 2 {
				potentialSecret := matches[2]
				// Calculate shannon entropy
				entropy := CalculateEntropy(potentialSecret)
				// High entropy strings (usually length > 12 and entropy >= 4.0 or 4.5)
				if len(potentialSecret) > 12 && entropy >= 4.0 {
					// We find the secret rule or report generic secret finding
					findings = append(findings, model.Finding{
						RuleID:      "MCP-SEC-008", // Secret Leakage Rule
						Title:       "Potential Secret Leakage Detected",
						Severity:    model.SeverityHigh,
						Description: fmt.Sprintf("High-entropy key/credential detected in line: %s (entropy: %.2f)", matches[1], entropy),
						Remediation: "Remove plain-text secrets and load them using secure environment variables or a secrets manager.",
						FilePath:    relPath,
						LineNumber:  lineNum + 1,
						MatchString: fmt.Sprintf("%s = *****", matches[1]),
						Timestamp:   time.Now(),
					})
				}
			}
		}

		// Unicode obfuscation detector in codebase comments/strings/JSON values
		if HasUnicodeObfuscation(lineContent) {
			findings = append(findings, model.Finding{
				RuleID:      "MCP-SEC-002",
				Title:       "Unicode Homoglyph / Obfuscation Detected",
				Severity:    model.SeverityHigh,
				Description: "Hidden unicode characters or directional overrides were discovered inside the source content.",
				Remediation: "Remove directional override markings, zero-width characters, or homoglyphs.",
				FilePath:    relPath,
				LineNumber:  lineNum + 1,
				MatchString: strings.TrimSpace(lineContent),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func isBinaryContent(content []byte) bool {
	limit := len(content)
	if limit > 8192 {
		limit = 8192
	}
	for i := 0; i < limit; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

func matcherAppliesToFile(m model.Matcher, ext string) bool {
	if len(m.FileTypes) == 0 {
		return true
	}
	normalizedExt := strings.TrimPrefix(strings.ToLower(ext), ".")
	for _, fileType := range m.FileTypes {
		if normalizedExt == strings.TrimPrefix(strings.ToLower(strings.TrimSpace(fileType)), ".") {
			return true
		}
	}
	return false
}

func regexMatcherMatches(re *regexp.Regexp, matcher model.Matcher, line string) bool {
	matches := re.FindStringSubmatch(line)
	if len(matches) == 0 {
		return false
	}
	if matcher.EntropyMin <= 0 {
		return true
	}
	entropyTarget := matches[0]
	if len(matches) > 1 {
		entropyTarget = matches[len(matches)-1]
	}
	return CalculateEntropy(entropyTarget) >= matcher.EntropyMin
}

func (e *Engine) scanFilePathRules(relPath string) []model.Finding {
	var findings []model.Finding
	for _, rule := range e.Rules {
		for _, matcher := range rule.Matchers {
			if matcher.Type != model.MatcherFilePath {
				continue
			}
			re, err := regexp.Compile(matcher.Pattern)
			if err != nil || !re.MatchString(filepath.ToSlash(relPath)) {
				continue
			}
			findings = append(findings, model.Finding{
				RuleID:      rule.ID,
				Title:       rule.Title,
				Severity:    rule.Severity,
				Description: rule.Description,
				Remediation: rule.Remediation,
				FilePath:    relPath,
				LineNumber:  1,
				MatchString: relPath,
				Timestamp:   time.Now(),
			})
		}
	}
	return findings
}

func (e *Engine) scanStructuredMatchers(content []byte, relPath, format string) []model.Finding {
	var parsed interface{}
	var err error
	if format == "json" {
		err = json.Unmarshal(content, &parsed)
	} else {
		err = yaml.Unmarshal(content, &parsed)
	}
	if err != nil {
		return nil
	}

	entries := flattenStructuredValues(parsed)
	var findings []model.Finding
	for _, rule := range e.Rules {
		for _, matcher := range rule.Matchers {
			if matcher.Type != model.MatcherConfigKey {
				continue
			}
			if matched, matchString := matcherMatchesStructuredValue(matcher, entries); matched {
				findings = append(findings, model.Finding{
					RuleID:      rule.ID,
					Title:       rule.Title,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					FilePath:    relPath,
					LineNumber:  1,
					MatchString: matchString,
					Timestamp:   time.Now(),
				})
			}
		}
	}
	return findings
}

type structuredEntry struct {
	KeyPath string
	Value   string
}

func flattenStructuredValues(v interface{}) []structuredEntry {
	var entries []structuredEntry
	var walk func(prefix string, value interface{})
	walk = func(prefix string, value interface{}) {
		switch typed := value.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				next := key
				if prefix != "" {
					next = prefix + "." + key
				}
				walk(next, typed[key])
			}
		case map[interface{}]interface{}:
			keys := make([]string, 0, len(typed))
			values := make(map[string]interface{}, len(typed))
			for key, val := range typed {
				keyString := fmt.Sprint(key)
				keys = append(keys, keyString)
				values[keyString] = val
			}
			sort.Strings(keys)
			for _, key := range keys {
				next := key
				if prefix != "" {
					next = prefix + "." + key
				}
				walk(next, values[key])
			}
		case []interface{}:
			for i, item := range typed {
				walk(fmt.Sprintf("%s[%d]", prefix, i), item)
			}
		case string:
			entries = append(entries, structuredEntry{KeyPath: prefix, Value: typed})
		case nil:
		default:
			entries = append(entries, structuredEntry{KeyPath: prefix, Value: fmt.Sprint(typed)})
		}
	}
	walk("", v)
	return entries
}

func matcherMatchesStructuredValue(matcher model.Matcher, entries []structuredEntry) (bool, string) {
	keySet := make(map[string]struct{}, len(matcher.ConfigKeys))
	for _, key := range matcher.ConfigKeys {
		keySet[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}

	var re *regexp.Regexp
	if matcher.Pattern != "" {
		compiled, err := regexp.Compile(matcher.Pattern)
		if err != nil {
			return false, ""
		}
		re = compiled
	}

	for _, entry := range entries {
		keyPath := strings.ToLower(entry.KeyPath)
		keyMatched := len(keySet) == 0
		for key := range keySet {
			if keyPath == key || strings.HasSuffix(keyPath, "."+key) {
				keyMatched = true
				break
			}
		}
		if !keyMatched {
			continue
		}
		if re == nil || re.MatchString(entry.Value) || re.MatchString(entry.KeyPath) {
			return true, fmt.Sprintf("%s=%s", entry.KeyPath, redactIfSensitive(entry.KeyPath, entry.Value))
		}
	}
	return false, ""
}

func redactIfSensitive(keyPath, value string) string {
	if regexp.MustCompile(`(?i)(api[_-]?key|token|jwt|password|secret|private[_-]?key|credential|passwd|auth)`).MatchString(keyPath) {
		return "*****"
	}
	return value
}

// scanConfigJson parses MCP JSON configurations to flag structural permission concerns.
func (e *Engine) scanConfigJson(content, relPath string) []model.Finding {
	var findings []model.Finding

	// Parse JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}

	// Auditing Claude Desktop config structure:
	// "mcpServers": {
	//   "server-name": {
	//     "command": "node",
	//     "args": ["..."],
	//     "env": { ... }
	//   }
	// }
	var mcpServers map[string]interface{}

	if serversVal, exists := parsed["mcpServers"]; exists {
		if serversMap, ok := serversVal.(map[string]interface{}); ok {
			mcpServers = serversMap
		}
	} else if _, exists := parsed["commands"]; exists || strings.Contains(relPath, "mcp.json") {
		// Possibly mcp.json format or single server config
		mcpServers = map[string]interface{}{"default": parsed}
	}

	for serverName, serverVal := range mcpServers {
		serverConfig, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}

		// Check command field
		commandVal, _ := serverConfig["command"].(string)
		argsVal, _ := serverConfig["args"].([]interface{})

		// Rule checks on commands and args
		if commandVal != "" {
			// Check for shell execution/permissions
			isShell := false
			if isShellCommand(commandVal) {
				isShell = true
			}

			// Auditing shell flags
			if isShell {
				findings = append(findings, model.Finding{
					RuleID:      "MCP-SEC-004",
					Title:       "Excessive Permissions: Raw Shell Execution",
					Severity:    model.SeverityHigh,
					Description: fmt.Sprintf("MCP server %q executes raw shell commands using command %q", serverName, commandVal),
					Remediation: "Avoid running command-line tools wrapped directly in raw shell processes. Create a dedicated executable tool instead.",
					FilePath:    relPath,
					LineNumber:  1,
					MatchString: fmt.Sprintf("Server: %s, Command: %s", serverName, commandVal),
					Timestamp:   time.Now(),
				})
			}

			// Auditing file system commands
			for _, argObj := range argsVal {
				argStr, ok := argObj.(string)
				if !ok {
					continue
				}
				// Look for broad paths (like "/" or "~" or root keys) passed into commands
				if argStr == "/" || argStr == "--allow-all" || argStr == "-A" {
					findings = append(findings, model.Finding{
						RuleID:      "MCP-SEC-004",
						Title:       "Excessive Permissions: Broad System Access",
						Severity:    model.SeverityCritical,
						Description: fmt.Sprintf("MCP server %q specifies broad argument access permission: %q", serverName, argStr),
						Remediation: "Restrict tool filesystem/network scopes to the minimum directory path necessary.",
						FilePath:    relPath,
						LineNumber:  1,
						MatchString: fmt.Sprintf("Server: %s, Command: %s, Flag: %s", serverName, commandVal, argStr),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return findings
}

func isShellCommand(command string) bool {
	switch strings.ToLower(filepath.Base(command)) {
	case "bash", "sh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	default:
		return false
	}
}

// deduplicateFindings aggregates findings of the same rule ID at the same path and line number, returning the most severe.
func (e *Engine) deduplicateFindings(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}

	type key struct {
		ruleID   string
		filePath string
		lineNum  int
	}

	seen := make(map[key]model.Finding)
	var result []model.Finding

	for _, f := range findings {
		k := key{ruleID: f.RuleID, filePath: f.FilePath, lineNum: f.LineNumber}
		if existing, exists := seen[k]; exists {
			// Compare severity and replace if higher
			if severityValue(f.Severity) > severityValue(existing.Severity) {
				seen[k] = f
			}
		} else {
			seen[k] = f
		}
	}

	// Preserving original-like order or stable order
	for _, f := range findings {
		k := key{ruleID: f.RuleID, filePath: f.FilePath, lineNum: f.LineNumber}
		if val, exists := seen[k]; exists {
			result = append(result, val)
			delete(seen, k)
		}
	}

	return result
}

// severityValue converts severity labels to integer values for logic evaluations.
func severityValue(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// GetDefaultRules returns the built-in catalog of security rules.
func GetDefaultRules() []model.Rule {
	return []model.Rule{
		{
			ID:          "MCP-SEC-002",
			Title:       "Unicode Homoglyph / Obfuscation Detected",
			Severity:    model.SeverityHigh,
			Description: "Flags potential unicode homoglyph attacks or hidden control sequences which bypass code review.",
			Remediation: "Standardize naming conventions to clean ASCII values and remove hidden Unicode entities.",
			Matchers: []model.Matcher{
				{
					Type:    model.MatcherRegex,
					Pattern: `[\x{200B}-\x{200D}\x{FEFF}\x{202A}-\x{202E}]`,
				},
			},
		},
		{
			ID:          "MCP-SEC-004",
			Title:       "Excessive Permissions: Raw Shell Execution",
			Severity:    model.SeverityHigh,
			Description: "MCP server configuration exposes direct command lines with shell processes.",
			Remediation: "Ensure external tools execute targeted subprocesses and avoid raw bash/cmd executors.",
			Matchers: []model.Matcher{
				{
					Type:       model.MatcherConfigKey,
					Pattern:    `(?i)^(bash|sh|cmd|powershell|pwsh)(\.exe)?$`,
					ConfigKeys: []string{"command"},
				},
			},
		},
		{
			ID:          "MCP-SEC-008",
			Title:       "Potential Secret Leakage Detected",
			Severity:    model.SeverityHigh,
			Description: "A high-entropy token, key, or credentials was found inside configuration/codebases.",
			Remediation: "Use environment variables or custom secure storage systems to inject credentials.",
			Matchers: []model.Matcher{
				{
					Type:       model.MatcherRegex,
					Pattern:    `(?i)(api_key|token|jwt|password|secret|private_key|credential)\s*[:=]\s*["']([^"']+)["']`,
					EntropyMin: 4.0,
					FileTypes:  []string{"env", "json", "yaml", "yml", "py", "js", "ts", "go", "sh", "bash"},
				},
			},
		},
		{
			ID:          "MCP-SEC-005",
			Title:       "Insecure Deletion Operations",
			Severity:    model.SeverityHigh,
			Description: "MCP server configuration or codebase uses broad file/directory deletion commands.",
			Remediation: "Ensure file deletion capabilities are strictly bounded, require double confirmation, or are removed entirely.",
			Matchers: []model.Matcher{
				{
					Type:      model.MatcherRegex,
					Pattern:   `(?i)(rm\s+-rf|delete\s+from|drop\s+database|os\.remove|fs\.unlink)`,
					FileTypes: []string{"json", "yaml", "yml", "py", "js", "ts", "go", "sh", "bash"},
				},
			},
		},
		{
			ID:          "MCP-SEC-006",
			Title:       "Unrestricted Network Commands",
			Severity:    model.SeverityHigh,
			Description: "MCP server executes broad network utilities like curl, wget, or exposes unrestricted network flags.",
			Remediation: "Limit outbound network calls using firewalls or dedicated API client libraries instead of raw terminal command invocations.",
			Matchers: []model.Matcher{
				{
					Type:      model.MatcherRegex,
					Pattern:   `(?i)\b(curl|wget|nc|nmap)\s+`,
					FileTypes: []string{"json", "yaml", "yml", "py", "js", "ts", "go", "sh", "bash"},
				},
			},
		},
		{
			ID:          "MCP-SEC-009",
			Title:       "Hardcoded Private Key Exposure",
			Severity:    model.SeverityCritical,
			Description: "A cryptographic private key block was found hardcoded in codebase or configuration assets.",
			Remediation: "Remove hardcoded cryptographic keys immediately and use secure hardware modules or vault configurations.",
			Matchers: []model.Matcher{
				{
					Type:    model.MatcherRegex,
					Pattern: `-----BEGIN [A-Z ]*PRIVATE KEY-----`,
				},
			},
		},
		{
			ID:          "MCP-SEC-014",
			Title:       "Insecure Tool Description Prompt Injection Warning",
			Severity:    model.SeverityHigh,
			Description: "Tool descriptions contain keywords attempting to jailbreak, override, or inject commands to LLMs.",
			Remediation: "Audit tool description templates and remove instructing phrases like 'ignore instructions' or 'bypass validations'.",
			Matchers: []model.Matcher{
				{
					Type:      model.MatcherRegex,
					Pattern:   `(?i)(ignore\s+previous\s+instructions|system\s+prompt|jailbreak|bypass\s+safety|act\s+as\s+administrator)`,
					FileTypes: []string{"json", "yaml", "yml", "py", "js", "ts", "go", "sh", "bash"},
				},
			},
		},
	}
}
