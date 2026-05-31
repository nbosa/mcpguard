package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcpguard/internal/rules/model"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		input float64 // Minimum expected entropy
		str   string
	}{
		{0.0, ""},
		{0.0, "aaaa"},
		{1.0, "abab"},
		{3.0, "abcdefgh"},
	}

	for _, tt := range tests {
		entropy := CalculateEntropy(tt.str)
		if entropy < tt.input {
			t.Errorf("CalculateEntropy(%q) = %f, expected at least %f", tt.str, entropy, tt.input)
		}
	}
}

func TestEngine_ScanFilePathAndConfigKeyMatchers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mcp.yaml")
	content := []byte(`
server:
  command: bash
  args:
    - -c
`)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	eng := NewEngine()
	eng.Rules = []model.Rule{
		{
			ID:          "TEST-PATH",
			Title:       "Path",
			Severity:    model.SeverityInfo,
			Description: "path",
			Remediation: "fix",
			Matchers: []model.Matcher{
				{Type: model.MatcherFilePath, Pattern: `mcp\.yaml$`},
			},
		},
		{
			ID:          "TEST-CONFIG",
			Title:       "Config",
			Severity:    model.SeverityHigh,
			Description: "config",
			Remediation: "fix",
			Matchers: []model.Matcher{
				{Type: model.MatcherConfigKey, ConfigKeys: []string{"command"}, Pattern: `bash`},
			},
		},
	}

	report, err := eng.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	seen := map[string]bool{}
	for _, finding := range report.Findings {
		seen[finding.RuleID] = true
	}
	if !seen["TEST-PATH"] || !seen["TEST-CONFIG"] {
		t.Fatalf("expected file_path and config_key findings, got %#v", report.Findings)
	}
}

func TestDefaultNetworkRuleDoesNotMatchFunctionDeclarations(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "main.go")
	if err := os.WriteFile(target, []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	eng := NewEngine()
	eng.LoadBuiltinRules()
	report, err := eng.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	for _, finding := range report.Findings {
		if finding.RuleID == "MCP-SEC-006" {
			t.Fatalf("network rule should not match function declaration: %#v", finding)
		}
	}
}

func TestEngine_LoadRulesFromDirectoryReplacesDuplicateRuleIDs(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	content := []byte(`
id: MCP-SEC-002
title: Custom Unicode Override
severity: LOW
description: Custom replacement.
remediation: Custom remediation.
matchers:
  - type: regex
    pattern: custom-pattern
`)
	if err := os.WriteFile(rulePath, content, 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	eng := NewEngine()
	eng.LoadBuiltinRules()
	if err := eng.LoadRulesFromDirectory(dir); err != nil {
		t.Fatalf("LoadRulesFromDirectory failed: %v", err)
	}

	count := 0
	var severity model.Severity
	for _, rule := range eng.Rules {
		if rule.ID == "MCP-SEC-002" {
			count++
			severity = rule.Severity
		}
	}
	if count != 1 || severity != model.SeverityLow {
		t.Fatalf("expected custom rule to replace builtin once, count=%d severity=%s", count, severity)
	}
}

func TestHasUnicodeObfuscation(t *testing.T) {
	tests := []struct {
		str  string
		want bool
	}{
		{"normal text", false},
		{"unicode\u200Btext", true}, // Zero-width space
		{"direction\u202Aoverride", true},
	}

	for _, tt := range tests {
		if got := HasUnicodeObfuscation(tt.str); got != tt.want {
			t.Errorf("HasUnicodeObfuscation(%q) = %v, want %v", tt.str, got, tt.want)
		}
	}
}

func TestIgnoreList_IsIgnored(t *testing.T) {
	r := strings.NewReader(`
# This is a comment
ignored_file.json
rules_dir/some_file.py:MCP-SEC-008
id:MCP-SEC-002
`)

	il, err := model.ParseIgnoreList(r)
	if err != nil {
		t.Fatalf("Failed to parse ignore list: %v", err)
	}

	tests := []struct {
		finding model.Finding
		want    bool
	}{
		{
			finding: model.Finding{RuleID: "MCP-SEC-004", FilePath: "ignored_file.json"},
			want:    true,
		},
		{
			finding: model.Finding{RuleID: "MCP-SEC-008", FilePath: "rules_dir/some_file.py"},
			want:    true,
		},
		{
			finding: model.Finding{RuleID: "MCP-SEC-004", FilePath: "rules_dir/some_file.py"},
			want:    false,
		},
		{
			finding: model.Finding{RuleID: "MCP-SEC-002", FilePath: "some_other_file.go"},
			want:    true,
		},
	}

	for i, tt := range tests {
		if got := il.IsIgnored(tt.finding); got != tt.want {
			t.Errorf("Test case %d: IsIgnored(%+v) = %v, want %v", i, tt.finding, got, tt.want)
		}
	}
}

func TestEngine_DeduplicateFindings(t *testing.T) {
	eng := NewEngine()

	findings := []model.Finding{
		{
			RuleID:     "MCP-SEC-002",
			Title:      "Obfuscation",
			Severity:   model.SeverityMedium,
			FilePath:   "test.js",
			LineNumber: 10,
			Timestamp:  time.Now(),
		},
		{
			RuleID:     "MCP-SEC-002",
			Title:      "Obfuscation High",
			Severity:   model.SeverityHigh,
			FilePath:   "test.js",
			LineNumber: 10,
			Timestamp:  time.Now(),
		},
		{
			RuleID:     "MCP-SEC-002",
			Title:      "Obfuscation Different Line",
			Severity:   model.SeverityMedium,
			FilePath:   "test.js",
			LineNumber: 11,
			Timestamp:  time.Now(),
		},
	}

	deduped := eng.deduplicateFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("Expected 2 findings after deduplication, got %d", len(deduped))
	}

	// The one on line 10 should be of High severity (highest priority)
	for _, f := range deduped {
		if f.LineNumber == 10 && f.Severity != model.SeverityHigh {
			t.Errorf("Expected High severity for line 10, got %s", f.Severity)
		}
	}
}
