// Package classifier defines the Classifier plugin contract and a process-wide
// registry used by the mcpguard stdio proxy.
//
// Built-in classifiers (regex, foundation-models) self-register on import via
// init(). External classifiers can be added by writing a Go package that
// calls Default().MustRegister() from its own init() and linking it into the
// binary. This is the official extension point for new threat detectors.
package classifier

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ThreatType identifies the class of security event a Finding represents.
type ThreatType string

const (
	ThreatPromptInjection ThreatType = "prompt_injection"
	ThreatToolPoisoning   ThreatType = "tool_poisoning"
	ThreatRugPull         ThreatType = "rug_pull"
)

// Severity ranks the impact of a finding. Ordered from highest to lowest.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Direction describes the request flow for a Finding observed by the proxy.
type Direction string

const (
	DirectionClientToUpstream Direction = "client_to_upstream"
	DirectionUpstreamToClient Direction = "upstream_to_client"
)

// Finding is emitted by a Classifier when it detects a threat or anomaly.
type Finding struct {
	Type       ThreatType `json:"type"`
	Severity   Severity   `json:"severity"`
	Reason     string     `json:"reason"`
	Location   string     `json:"location,omitempty"`
	Evidence   string     `json:"evidence,omitempty"`
	Classifier string     `json:"classifier"`
	RequestID  string     `json:"request_id,omitempty"`
	Direction  Direction  `json:"direction,omitempty"`
	Blocked    bool       `json:"blocked"`
	Timestamp  time.Time  `json:"timestamp"`
}

// Classifier is the contract every threat detector implements.
type Classifier interface {
	// Name returns a unique identifier (lowercase, hyphen-separated).
	Name() string
	// Description returns a human-readable summary of what this classifier does.
	Description() string
	// Available returns nil if the classifier is ready to use, or an error
	// explaining why it is not (e.g. model not installed, build tag missing).
	Available() error
	// Classify inspects text for the requested threat.
	// Returns (nil, nil) when no threat is detected.
	// Returns an error only for infrastructure failures (model unavailable,
	// context cancellation); the caller should log and continue.
	Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error)
}

// Registry holds classifiers indexed by Name. Safe for concurrent use.
type Registry struct {
	mu          sync.RWMutex
	classifiers map[string]Classifier
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{classifiers: make(map[string]Classifier)}
}

// Register adds a classifier. Returns an error if the name is empty, the
// classifier is nil, or the name is already taken.
func (r *Registry) Register(c Classifier) error {
	if c == nil {
		return fmt.Errorf("classifier: nil")
	}
	name := c.Name()
	if name == "" {
		return fmt.Errorf("classifier: empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.classifiers[name]; exists {
		return fmt.Errorf("classifier %q already registered", name)
	}
	r.classifiers[name] = c
	return nil
}

// MustRegister is like Register but panics on error. Intended for init() use
// only, where a registration conflict represents a programming error.
func (r *Registry) MustRegister(c Classifier) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Get returns the classifier with the given name, or an error listing the
// available names.
func (r *Registry) Get(name string) (Classifier, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.classifiers[name]
	if !ok {
		return nil, fmt.Errorf("classifier %q not found (available: %v)", name, r.Names())
	}
	return c, nil
}

// Names returns sorted classifier names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.classifiers))
	for name := range r.classifiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns all registered classifiers in deterministic (sorted) order.
func (r *Registry) All() []Classifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := r.Names()
	out := make([]Classifier, 0, len(names))
	for _, n := range names {
		out = append(out, r.classifiers[n])
	}
	return out
}

// defaultRegistry is the process-wide registry populated by built-in init().
var defaultRegistry = NewRegistry()

// Default returns the process-wide registry used by the proxy and CLI.
func Default() *Registry { return defaultRegistry }

// Analyze runs the supplied classifiers against arbitrary data and returns
// all findings. Non-string types are JSON-marshaled first. Classifiers that
// error are skipped (not fatal) so one bad plugin cannot block the proxy.
func Analyze(ctx context.Context, classifiers []Classifier, threat ThreatType, value any, location string) []Finding {
	text := Stringify(value)
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var findings []Finding
	for _, c := range classifiers {
		if c == nil {
			continue
		}
		f, err := c.Classify(ctx, threat, text, location)
		if err != nil || f == nil {
			continue
		}
		if f.Classifier == "" {
			f.Classifier = c.Name()
		}
		findings = append(findings, *f)
	}
	return findings
}
