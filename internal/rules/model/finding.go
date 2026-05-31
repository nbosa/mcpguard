package model

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Finding represents an individual vulnerability or security issue discovered by the scanner.
type Finding struct {
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	FilePath    string    `json:"file_path,omitempty"`
	LineNumber  int       `json:"line_number,omitempty"`
	MatchString string    `json:"match_string,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanReport aggregates all outputs of a scan session.
type ScanReport struct {
	Path         string    `json:"path"`
	StartTime    time.Time `json:"start_time"`
	DurationMs   int64     `json:"duration_ms"`
	Findings     []Finding `json:"findings"`
	TotalScanned int       `json:"total_scanned"`
}

// IgnoreRule holds information for ignoring specific rules or files.
type IgnoreRule struct {
	FilePath string // File path pattern to ignore (empty if global)
	RuleID   string // Rule ID to ignore (empty if all rules for that path)
}

// IgnoreList matches findings against user-configured ignore patterns.
type IgnoreList struct {
	Rules []IgnoreRule
}

// LoadIgnoreList reads a `.mcpguard-ignore` file.
func LoadIgnoreList(path string) (*IgnoreList, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return &IgnoreList{}, nil
	} else if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseIgnoreList(file)
}

// ParseIgnoreList parses an ignore list from an io.Reader.
func ParseIgnoreList(r io.Reader) (*IgnoreList, error) {
	scanner := bufio.NewScanner(r)
	var rules []IgnoreRule

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var rule IgnoreRule
		if strings.HasPrefix(line, "id:") {
			rule.RuleID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			rule.FilePath = strings.TrimSpace(parts[0])
			rule.RuleID = strings.TrimSpace(parts[1])
		} else {
			rule.FilePath = line
		}

		rules = append(rules, rule)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &IgnoreList{Rules: rules}, nil
}

// IsIgnored evaluates if a finding matches any of the ignore rules.
func (il *IgnoreList) IsIgnored(f Finding) bool {
	if il == nil {
		return false
	}
	for _, rule := range il.Rules {
		matchFile := false
		matchRule := false

		// Check file path match
		if rule.FilePath == "" {
			matchFile = true // Global rule
		} else {
			// Clean paths to ensure consistent comparisons
			cleanFile := filepath.Clean(f.FilePath)
			cleanPattern := filepath.Clean(rule.FilePath)

			// Simple suffix matching or glob matching
			if cleanFile == cleanPattern || strings.HasSuffix(cleanFile, string(filepath.Separator)+cleanPattern) {
				matchFile = true
			} else if matched, err := filepath.Match(rule.FilePath, f.FilePath); err == nil && matched {
				matchFile = true
			}
		}

		// Check rule ID match
		if rule.RuleID == "" {
			matchRule = true // Match all rules for this file path
		} else if f.RuleID == rule.RuleID {
			matchRule = true
		}

		if matchFile && matchRule {
			return true
		}
	}
	return false
}
