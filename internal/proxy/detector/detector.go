package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ThreatType identifies the class of proxy-blocking security event.
type ThreatType string

const (
	ThreatPromptInjection ThreatType = "prompt_injection"
	ThreatToolPoisoning   ThreatType = "tool_poisoning"
	ThreatRugPull         ThreatType = "rug_pull"
)

// Finding is emitted when the proxy blocks or observes suspicious MCP traffic.
type Finding struct {
	Type      ThreatType `json:"type"`
	Severity  string     `json:"severity"`
	Reason    string     `json:"reason"`
	Location  string     `json:"location,omitempty"`
	Evidence  string     `json:"evidence,omitempty"`
	Blocked   bool       `json:"blocked"`
	Timestamp time.Time  `json:"timestamp"`
}

type pattern struct {
	threat   ThreatType
	severity string
	reason   string
	re       *regexp.Regexp
}

// RegexDetector applies deterministic local signatures before any model check.
type RegexDetector struct {
	patterns []pattern
}

// NewRegexDetector returns the default regex policy for prompt injection and tool poisoning.
func NewRegexDetector() *RegexDetector {
	specs := []struct {
		threat   ThreatType
		severity string
		reason   string
		pattern  string
	}{
		{ThreatPromptInjection, "HIGH", "Attempts to override prior/system instructions.", `(?i)\b(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above|system)\s+instructions?\b`},
		{ThreatPromptInjection, "HIGH", "Attempts to reveal or manipulate system prompts.", `(?i)\b(system prompt|developer message|hidden instructions?|chain[- ]?of[- ]?thought)\b`},
		{ThreatPromptInjection, "HIGH", "Attempts jailbreak or policy bypass behavior.", `(?i)\b(jailbreak|bypass\s+(safety|policy|guardrails?)|act\s+as\s+(admin|administrator|root))\b`},
		{ThreatPromptInjection, "MEDIUM", "Suspicious data exfiltration instruction.", `(?i)\b(exfiltrate|send\s+.*secret|dump\s+.*(env|environment|token|credential|api[_-]?key))\b`},
		{ThreatToolPoisoning, "HIGH", "Tool metadata contains hidden or controlling model instructions.", `(?i)\b(always\s+call\s+this\s+tool|before\s+answering|silently\s+call|do\s+not\s+tell\s+the\s+user)\b`},
		{ThreatToolPoisoning, "HIGH", "Tool metadata attempts instruction override.", `(?i)\b(ignore\s+(previous|system)\s+instructions?|override\s+the\s+assistant|you\s+must\s+obey\s+this\s+tool)\b`},
		{ThreatToolPoisoning, "MEDIUM", "Tool metadata asks for broad credential or filesystem access.", `(?i)\b(read\s+all\s+files|send\s+credentials|export\s+tokens?|steal\s+secrets?)\b`},
	}

	d := &RegexDetector{}
	for _, spec := range specs {
		d.patterns = append(d.patterns, pattern{
			threat:   spec.threat,
			severity: spec.severity,
			reason:   spec.reason,
			re:       regexp.MustCompile(spec.pattern),
		})
	}
	return d
}

// AnalyzeText returns the first matching findings for a text payload.
func (d *RegexDetector) AnalyzeText(text, location string) []Finding {
	if d == nil || text == "" {
		return nil
	}

	var findings []Finding
	for _, p := range d.patterns {
		if match := p.re.FindString(text); match != "" {
			findings = append(findings, Finding{
				Type:      p.threat,
				Severity:  p.severity,
				Reason:    p.reason,
				Location:  location,
				Evidence:  trimEvidence(match),
				Blocked:   true,
				Timestamp: time.Now(),
			})
		}
	}
	return findings
}

// ModelClassifier is implemented by optional local LLM classifiers.
type ModelClassifier interface {
	Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error)
}

// Guard combines deterministic regex checks with an optional local model classifier.
type Guard struct {
	Regex *RegexDetector
	Model ModelClassifier
}

// NewGuard creates a detector guard. Model may be nil for regex-only operation.
func NewGuard(model ModelClassifier) *Guard {
	return &Guard{
		Regex: NewRegexDetector(),
		Model: model,
	}
}

// Analyze marshals arbitrary MCP JSON data and checks it for the requested threat type.
func (g *Guard) Analyze(ctx context.Context, threat ThreatType, value any, location string) []Finding {
	text := stringify(value)
	if strings.TrimSpace(text) == "" {
		return nil
	}

	var findings []Finding
	if g.Regex != nil {
		for _, finding := range g.Regex.AnalyzeText(text, location) {
			if finding.Type == threat {
				findings = append(findings, finding)
			}
		}
	}

	if g.Model != nil {
		if finding, err := g.Model.Classify(ctx, threat, text, location); err == nil && finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// NewRugPullFinding creates a standard block finding for schema drift.
func NewRugPullFinding(reason, location, evidence string) Finding {
	return Finding{
		Type:      ThreatRugPull,
		Severity:  "CRITICAL",
		Reason:    reason,
		Location:  location,
		Evidence:  trimEvidence(evidence),
		Blocked:   true,
		Timestamp: time.Now(),
	}
}

func stringify(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(value)
		}
		return string(data)
	}
}

func trimEvidence(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}
