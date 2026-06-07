package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// RegexClassifier applies deterministic local signatures. It is always
// available and is the default classifier for the proxy.
type RegexClassifier struct {
	patterns []regexPattern
}

type regexPattern struct {
	threat   ThreatType
	severity Severity
	reason   string
	re       *regexp.Regexp
}

// NewRegexClassifier returns the default regex policy for prompt injection
// and tool poisoning.
func NewRegexClassifier() *RegexClassifier {
	specs := []struct {
		threat   ThreatType
		severity Severity
		reason   string
		pattern  string
	}{
		{ThreatPromptInjection, SeverityHigh, "Attempts to override prior/system instructions.", `(?i)\b(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above|system)\s+instructions?\b`},
		{ThreatPromptInjection, SeverityHigh, "Attempts to reveal or manipulate system prompts.", `(?i)\b(system prompt|developer message|hidden instructions?|chain[- ]?of[- ]?thought)\b`},
		{ThreatPromptInjection, SeverityHigh, "Attempts jailbreak or policy bypass behavior.", `(?i)\b(jailbreak|bypass\s+(safety|policy|guardrails?)|act\s+as\s+(admin|administrator|root))\b`},
		{ThreatPromptInjection, SeverityMedium, "Suspicious data exfiltration instruction.", `(?i)\b(exfiltrate|send\s+.*secret|dump\s+.*(env|environment|token|credential|api[_-]?key))\b`},
		{ThreatToolPoisoning, SeverityHigh, "Tool metadata contains hidden or controlling model instructions.", `(?i)\b(always\s+call\s+this\s+tool|before\s+answering|silently\s+call|do\s+not\s+tell\s+the\s+user)\b`},
		{ThreatToolPoisoning, SeverityHigh, "Tool metadata attempts instruction override.", `(?i)\b(ignore\s+(previous|system)\s+instructions?|override\s+the\s+assistant|you\s+must\s+obey\s+this\s+tool)\b`},
		{ThreatToolPoisoning, SeverityMedium, "Tool metadata asks for broad credential or filesystem access.", `(?i)\b(read\s+all\s+files|send\s+credentials|export\s+tokens?|steal\s+secrets?)\b`},
	}

	c := &RegexClassifier{}
	for _, s := range specs {
		c.patterns = append(c.patterns, regexPattern{
			threat:   s.threat,
			severity: s.severity,
			reason:   s.reason,
			re:       regexp.MustCompile(s.pattern),
		})
	}
	return c
}

func (c *RegexClassifier) Name() string { return "regex" }
func (c *RegexClassifier) Description() string {
	return "Deterministic local regex signatures for prompt injection and tool poisoning."
}
func (c *RegexClassifier) Available() error { return nil }

func (c *RegexClassifier) Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error) {
	_ = ctx
	if c == nil || text == "" {
		return nil, nil
	}
	now := time.Now()
	for _, p := range c.patterns {
		if p.threat != threat {
			continue
		}
		if match := p.re.FindString(text); match != "" {
			return &Finding{
				Type:       p.threat,
				Severity:   p.severity,
				Reason:     p.reason,
				Location:   location,
				Evidence:   TrimEvidence(match, 240),
				Classifier: c.Name(),
				Blocked:    true,
				Timestamp:  now,
			}, nil
		}
	}
	return nil, nil
}

// Stringify marshals arbitrary MCP JSON data into a single searchable string.
// Strings and byte slices are passed through; everything else is JSON-encoded.
func Stringify(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(data)
	}
}

// TrimEvidence truncates s to max bytes and appends an ellipsis when cut.
func TrimEvidence(s string, max int) string {
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func init() {
	Default().MustRegister(NewRegexClassifier())
}
