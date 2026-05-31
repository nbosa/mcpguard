package stdio

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"mcpguard/internal/proxy/detector"
)

// Reporter writes proxy security events as JSON lines.
type Reporter struct {
	mu   sync.Mutex
	file *os.File
	out  io.Writer
}

// NewReporter creates a reporter. Findings are always mirrored to stderr.
func NewReporter(path string) (*Reporter, error) {
	reporter := &Reporter{out: os.Stderr}
	if path == "" {
		return reporter, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create proxy report: %w", err)
	}
	reporter.file = file
	return reporter, nil
}

// Write emits one finding as JSONL.
func (r *Reporter) Write(finding detector.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	line := append(data, '\n')
	if _, err := r.out.Write(line); err != nil {
		return err
	}
	if r.file != nil {
		_, err = r.file.Write(line)
	}
	return err
}

// Close closes the optional report file.
func (r *Reporter) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.file.Close()
}
