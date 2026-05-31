package model

import (
	"errors"
	"fmt"
	"regexp"
)

// Severity represents the classification level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// MatcherType defines how a rule targets files, ASTs, or configs.
type MatcherType string

const (
	MatcherRegex        MatcherType = "regex"
	MatcherFilePath     MatcherType = "file_path"
	MatcherConfigKey    MatcherType = "config_key"
	MatcherASTPattern   MatcherType = "ast_pattern"
	MatcherSchema       MatcherType = "schema_pattern"
	MatcherRuntimeEvent MatcherType = "runtime_event"
)

// Matcher defines criteria for identifying security risks.
type Matcher struct {
	Type        MatcherType `yaml:"type"`
	Pattern     string      `yaml:"pattern"`
	TargetField string      `yaml:"target_field,omitempty"`
	EntropyMin  float64     `yaml:"entropy_min,omitempty"`
	ConfigKeys  []string    `yaml:"config_keys,omitempty"`
	FileTypes   []string    `yaml:"file_types,omitempty"`
}

// Rule represents a security checklist rule defined in YAML.
type Rule struct {
	ID          string    `yaml:"id"`
	Title       string    `yaml:"title"`
	Severity    Severity  `yaml:"severity"`
	Description string    `yaml:"description"`
	Remediation string    `yaml:"remediation"`
	References  []string  `yaml:"references,omitempty"`
	Tags        []string  `yaml:"tags,omitempty"`
	Matchers    []Matcher `yaml:"matchers"`
}

// Validate checks the structural integrity and semantic correctness of a Rule.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return errors.New("rule id cannot be empty")
	}
	if r.Title == "" {
		return errors.New("rule title cannot be empty")
	}
	switch r.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		// valid
	default:
		return fmt.Errorf("invalid rule severity: %q", r.Severity)
	}
	if r.Description == "" {
		return errors.New("rule description cannot be empty")
	}
	if r.Remediation == "" {
		return errors.New("rule remediation cannot be empty")
	}
	if len(r.Matchers) == 0 {
		return errors.New("rule must contain at least one matcher")
	}

	for i, m := range r.Matchers {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("matcher %d is invalid: %w", i, err)
		}
	}
	return nil
}

// Validate checks if the matcher structure and parameters are correct.
func (m *Matcher) Validate() error {
	switch m.Type {
	case MatcherRegex, MatcherFilePath, MatcherConfigKey, MatcherASTPattern, MatcherSchema, MatcherRuntimeEvent:
		// valid
	default:
		return fmt.Errorf("unknown matcher type: %q", m.Type)
	}

	if m.Type == MatcherRegex || m.Type == MatcherFilePath || m.Type == MatcherASTPattern || m.Type == MatcherSchema || m.Type == MatcherRuntimeEvent {
		if m.Pattern == "" {
			return fmt.Errorf("pattern cannot be empty for matcher type %q", m.Type)
		}
		// Try to compile pattern if it's regex
		if m.Type == MatcherRegex || m.Type == MatcherFilePath {
			if _, err := regexp.Compile(m.Pattern); err != nil {
				return fmt.Errorf("invalid regular expression in pattern %q: %w", m.Pattern, err)
			}
		}
	}

	if m.Type == MatcherConfigKey && len(m.ConfigKeys) == 0 && m.Pattern == "" {
		return errors.New("config_key matcher must specify either config_keys or a pattern")
	}
	if m.EntropyMin < 0 {
		return errors.New("entropy_min cannot be negative")
	}

	return nil
}
