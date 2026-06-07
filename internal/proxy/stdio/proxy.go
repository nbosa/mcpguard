// Package stdio implements the mcpguard stdio MCP guard proxy. It forwards
// JSON-RPC traffic between a local MCP client and an upstream stdio MCP
// server, applying configurable threat classifiers and detecting tool list
// drift ("rug pull").
//
// Concurrency model:
//
//   - One goroutine reads the client and forwards requests to the upstream.
//   - One goroutine reads the upstream and demultiplexes responses to pending
//     requests (or forwards unsolicited messages and notifications to the
//     client).
//
// Both goroutines are owned by Run. A single context (typically wired to
// SIGINT/SIGTERM by the caller) cancels the whole pipeline, which kills the
// upstream process and flushes the report.
package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"mcpguard/internal/proxy/classifier"
)

const (
	// blockCode is the JSON-RPC error code returned for blocked requests/responses.
	blockCode = -32090

	// defaultRequestTimeout is the per-request timeout when Config.Timeout is zero.
	defaultRequestTimeout = 30 * time.Second

	// defaultMaxParseErrors is the abort threshold for persistent bad data.
	defaultMaxParseErrors = 10

	// maxScannerBuffer caps a single JSON-RPC message at 8 MiB.
	maxScannerBuffer = 8 * 1024 * 1024
)

// Config describes the local stdio proxy and the upstream MCP server process.
type Config struct {
	// UpstreamCommand is the executable to spawn (required).
	UpstreamCommand string
	// UpstreamArgs are the arguments to pass to UpstreamCommand.
	UpstreamArgs []string
	// UpstreamEnv are additional KEY=VALUE entries merged into the upstream
	// process environment (in addition to os.Environ()).
	UpstreamEnv []string
	// UpstreamCwd overrides the working directory of the upstream process.
	// Empty means inherit the proxy's cwd.
	UpstreamCwd string
	// ReportPath is an optional JSONL file for blocked/observed findings.
	// Empty means stderr only.
	ReportPath string
	// ClassifierNames lists the registered classifiers to apply, in order.
	// If empty, the built-in "regex" classifier is used.
	ClassifierNames []string
	// Timeout caps how long Run waits for an upstream response. Zero means
	// the default (30s).
	Timeout time.Duration
	// MaxParseErrors aborts the proxy after this many consecutive JSON
	// parse failures from either side. Zero means the default (10).
	MaxParseErrors int
}

// Proxy forwards JSON-RPC between a local MCP client and an upstream MCP server.
type Proxy struct {
	cfg         Config
	reporter    *Reporter
	classifiers []classifier.Classifier
	baseline    map[string]string
	baselineM   sync.Mutex
	pending     map[string]*pendingRequest
	pendingMu   sync.Mutex
	parseErrors int
	parseErrMu  sync.Mutex

	// Logger is the destination for status messages. Defaults to stderr.
	// Tests override this to capture output.
	Logger io.Writer
}

// pendingRequest tracks an in-flight client request awaiting an upstream response.
type pendingRequest struct {
	id     string // canonical JSON of the request ID
	method string
	respCh chan *Message
}

// New creates a stdio MCP proxy. ClassifierNames are resolved against the
// process-wide registry; an unknown name is an error.
func New(cfg Config) (*Proxy, error) {
	if cfg.UpstreamCommand == "" {
		return nil, fmt.Errorf("upstream command is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultRequestTimeout
	}
	if cfg.MaxParseErrors <= 0 {
		cfg.MaxParseErrors = defaultMaxParseErrors
	}

	classifiers, err := resolveClassifiers(cfg.ClassifierNames)
	if err != nil {
		return nil, err
	}

	reporter, err := NewReporter(cfg.ReportPath)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		cfg:         cfg,
		reporter:    reporter,
		classifiers: classifiers,
		pending:     make(map[string]*pendingRequest),
		Logger:      os.Stderr,
	}, nil
}

// Close releases report resources.
func (p *Proxy) Close() error {
	if p == nil || p.reporter == nil {
		return nil
	}
	return p.reporter.Close()
}

// Run starts the upstream process and proxies traffic until ctx is cancelled,
// the client closes stdin, or the upstream exits.
func (p *Proxy) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer) error {
	if p == nil {
		return errors.New("nil proxy")
	}
	cmd := exec.CommandContext(ctx, p.cfg.UpstreamCommand, p.cfg.UpstreamArgs...)
	if len(p.cfg.UpstreamEnv) > 0 {
		cmd.Env = append(os.Environ(), p.cfg.UpstreamEnv...)
	}
	if p.cfg.UpstreamCwd != "" {
		cmd.Dir = p.cfg.UpstreamCwd
	}

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// Upstream stderr is intentionally not mixed with proxy stderr.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}

	runErr := p.runWithPipes(ctx, clientIn, clientOut, upstreamIn, upstreamOut)

	// Shutdown: close stdin to upstream, wait briefly, then kill.
	_ = upstreamIn.Close()
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	// Reap the process (ignore error; we already have runErr).
	_ = cmd.Wait()
	return runErr
}

// runWithPipes proxies traffic using pre-existing pipes. Exposed for tests
// that drive the proxy with a fake upstream (no real subprocess).
func (p *Proxy) runWithPipes(ctx context.Context, clientIn io.Reader, clientOut io.Writer, upstreamIn io.WriteCloser, upstreamOut io.Reader) error {
	upstreamDone := make(chan struct{})
	upstreamErr := make(chan error, 1)
	clientDone := make(chan struct{})
	clientErr := make(chan error, 1)

	// Unblock the upstream scanner when ctx is cancelled, by closing the
	// upstream's read end. This is a no-op for non-closable readers and is
	// safe to call multiple times. This is what allows clean shutdown when
	// the upstream is hung.
	cancelWatcherDone := make(chan struct{})
	go func() {
		defer close(cancelWatcherDone)
		select {
		case <-ctx.Done():
			if c, ok := upstreamOut.(io.Closer); ok {
				_ = c.Close()
			}
		case <-upstreamDone:
			// demuxer exited on its own; nothing to do
		}
	}()

	// Goroutine 1: demux upstream -> client (and pending request channels).
	go func() {
		defer close(upstreamDone)
		p.demuxUpstream(ctx, upstreamOut, clientOut, upstreamErr)
	}()

	// Goroutine 2: client -> upstream.
	go func() {
		defer close(clientDone)
		p.pumpClient(ctx, clientIn, upstreamIn, clientOut)
		clientErr <- nil
	}()

	// Wait for either side to finish or context to be cancelled.
	var firstErr error
	select {
	case <-ctx.Done():
		firstErr = ctx.Err()
	case <-upstreamDone:
		select {
		case err := <-upstreamErr:
			if err != nil {
				firstErr = fmt.Errorf("upstream: %w", err)
			} else {
				firstErr = errors.New("upstream closed stdout")
			}
		default:
			firstErr = errors.New("upstream closed stdout")
		}
	case <-clientDone:
		if err, ok := <-clientErr; ok && err != nil {
			firstErr = fmt.Errorf("client: %w", err)
		} else {
			firstErr = errors.New("client closed stdin")
		}
	}

	// Drain goroutines.
	_ = upstreamIn.Close()
	<-upstreamDone
	<-clientDone
	<-cancelWatcherDone
	return firstErr
}

// pumpClient reads client lines, inspects each, and forwards to upstream.
func (p *Proxy) pumpClient(ctx context.Context, clientIn io.Reader, upstreamIn io.Writer, clientOut io.Writer) {
	scanner := bufio.NewScanner(clientIn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScannerBuffer)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := append([]byte(nil), scanner.Bytes()...)
		msg, err := parseMessage(line)
		if err != nil {
			p.recordParseError()
			p.report(classifier.Finding{
				Type:       classifier.ThreatPromptInjection,
				Severity:   classifier.SeverityHigh,
				Reason:     "Invalid client JSON-RPC message",
				Location:   "client",
				Evidence:   err.Error(),
				Classifier: "parser",
				Direction:  classifier.DirectionClientToUpstream,
				Blocked:    false,
				Timestamp:  time.Now(),
			})
			if p.parseErrorsExceeded() {
				fmt.Fprintln(p.Logger, "mcpguard: too many client parse errors; aborting")
				return
			}
			continue
		}

		if findings := p.inspectClient(ctx, msg); len(findings) > 0 {
			p.reportAll(findings)
			if msg.ID != nil {
				if err := writeJSONLine(clientOut, errorResponse(msg.ID, "mcpguard blocked request: "+findings[0].Reason)); err != nil {
					return
				}
			}
			continue
		}

		if _, err := upstreamIn.Write(append(line, '\n')); err != nil {
			fmt.Fprintf(p.Logger, "mcpguard: write upstream: %v\n", err)
			return
		}

		if msg.ID == nil {
			// Client notification: nothing to wait for.
			continue
		}

		p.handleRequestResponse(ctx, msg, clientOut)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(p.Logger, "mcpguard: client scanner: %v\n", err)
	}
}

// handleRequestResponse waits for the upstream response matching msg.ID and
// inspects/forwards it.
func (p *Proxy) handleRequestResponse(ctx context.Context, msg *Message, clientOut io.Writer) {
	idKey := string(canonicalJSON(msg.ID))
	req := &pendingRequest{
		id:     idKey,
		method: msg.Method,
		respCh: make(chan *Message, 1),
	}
	p.pendingMu.Lock()
	p.pending[idKey] = req
	p.pendingMu.Unlock()

	defer func() {
		p.pendingMu.Lock()
		delete(p.pending, idKey)
		p.pendingMu.Unlock()
	}()

	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	select {
	case resp, ok := <-req.respCh:
		if !ok {
			// Demuxer exited; request was never answered.
			p.report(classifier.Finding{
				Type:       classifier.ThreatToolPoisoning,
				Severity:   classifier.SeverityHigh,
				Reason:     "Upstream closed stdout before responding to request",
				Location:   "upstream",
				Classifier: "proxy",
				RequestID:  idKey,
				Direction:  classifier.DirectionUpstreamToClient,
				Blocked:    true,
				Timestamp:  time.Now(),
			})
			return
		}
		p.dispatchResponse(ctx, msg, resp, clientOut)
	case <-reqCtx.Done():
		if ctx.Err() != nil {
			return // global shutdown
		}
		p.report(classifier.Finding{
			Type:       classifier.ThreatToolPoisoning,
			Severity:   classifier.SeverityHigh,
			Reason:     fmt.Sprintf("Upstream did not respond within %s", p.cfg.Timeout),
			Location:   "upstream",
			Classifier: "proxy",
			RequestID:  idKey,
			Direction:  classifier.DirectionUpstreamToClient,
			Blocked:    true,
			Timestamp:  time.Now(),
		})
	}
}

// dispatchResponse inspects a matched upstream response and either blocks it
// (with an error response to the client) or forwards it as-is.
func (p *Proxy) dispatchResponse(ctx context.Context, req *Message, resp *Message, clientOut io.Writer) {
	blocked, findings, idKey := false, []classifier.Finding{}, ""
	if req.ID != nil {
		idKey = string(canonicalJSON(req.ID))
	}
	switch req.Method {
	case "tools/list":
		findings = append(findings, classifier.Analyze(ctx, p.classifiers, classifier.ThreatToolPoisoning, resp.Result, "upstream.tools/list.result")...)
		if findings = appendFindings(findings, p.detectRugPull(resp.Result, idKey)); len(findings) > 0 {
			blocked = true
		}
	case "tools/call":
		findings = append(findings, classifier.Analyze(ctx, p.classifiers, classifier.ThreatPromptInjection, resp.Result, "upstream.tools/call.result")...)
		if len(findings) > 0 {
			blocked = true
		}
	}
	if blocked {
		for i := range findings {
			findings[i].RequestID = idKey
			findings[i].Direction = classifier.DirectionUpstreamToClient
		}
		p.reportAll(findings)
		if err := writeJSONLine(clientOut, errorResponse(req.ID, "mcpguard blocked response: "+findings[0].Reason)); err != nil {
			fmt.Fprintf(p.Logger, "mcpguard: write client: %v\n", err)
		}
		return
	}
	if _, err := clientOut.Write(append(resp.Raw, '\n')); err != nil {
		fmt.Fprintf(p.Logger, "mcpguard: write client: %v\n", err)
	}
}

// demuxUpstream reads upstream lines and routes them to pending request
// channels (matched by ID) or forwards them to the client (notifications and
// unsolicited responses).
func (p *Proxy) demuxUpstream(ctx context.Context, upstreamOut io.Reader, clientOut io.Writer, errCh chan<- error) {
	scanner := bufio.NewScanner(upstreamOut)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScannerBuffer)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := append([]byte(nil), scanner.Bytes()...)
		msg, err := parseMessage(line)
		if err != nil {
			p.recordParseError()
			p.report(classifier.Finding{
				Type:       classifier.ThreatPromptInjection,
				Severity:   classifier.SeverityHigh,
				Reason:     "Invalid upstream JSON-RPC message",
				Location:   "upstream",
				Evidence:   err.Error(),
				Classifier: "parser",
				Direction:  classifier.DirectionUpstreamToClient,
				Blocked:    false,
				Timestamp:  time.Now(),
			})
			if p.parseErrorsExceeded() {
				fmt.Fprintln(p.Logger, "mcpguard: too many upstream parse errors; aborting")
				errCh <- errors.New("upstream parse error limit exceeded")
				return
			}
			continue
		}

		if msg.ID == nil {
			// Server notification or response to a non-pending request — forward.
			if _, err := clientOut.Write(append(line, '\n')); err != nil {
				fmt.Fprintf(p.Logger, "mcpguard: write client: %v\n", err)
			}
			continue
		}

		idKey := string(canonicalJSON(msg.ID))
		p.pendingMu.Lock()
		req, ok := p.pending[idKey]
		if ok {
			delete(p.pending, idKey)
		}
		p.pendingMu.Unlock()
		if ok {
			select {
			case req.respCh <- msg:
			case <-ctx.Done():
				return
			}
			continue
		}

		// No matching request: forward to client as a stray response.
		if _, err := clientOut.Write(append(line, '\n')); err != nil {
			fmt.Fprintf(p.Logger, "mcpguard: write client: %v\n", err)
		}
	}
	if err := scanner.Err(); err != nil {
		errCh <- err
		return
	}
	errCh <- nil
}

// inspectClient runs the configured classifiers over a client message.
func (p *Proxy) inspectClient(ctx context.Context, msg *Message) []classifier.Finding {
	if msg.Method != "tools/call" {
		return nil
	}
	findings := classifier.Analyze(ctx, p.classifiers, classifier.ThreatPromptInjection, msg.Params, "client.tools/call.params")
	for i := range findings {
		findings[i].RequestID = idKey(msg.ID)
		findings[i].Direction = classifier.DirectionClientToUpstream
	}
	return findings
}

// detectRugPull compares the current tools/list result against the baseline
// and returns a CRITICAL finding if it has drifted.
func (p *Proxy) detectRugPull(result json.RawMessage, idKey string) []classifier.Finding {
	snapshot := toolSnapshot(result)
	if len(snapshot) == 0 {
		return nil
	}

	p.baselineM.Lock()
	defer p.baselineM.Unlock()

	if p.baseline == nil {
		p.baseline = snapshot
		return nil
	}
	if equalSnapshot(p.baseline, snapshot) {
		return nil
	}

	now := time.Now()
	f := classifier.Finding{
		Type:       classifier.ThreatRugPull,
		Severity:   classifier.SeverityCritical,
		Reason:     "Upstream MCP tool list or schema changed after baseline",
		Location:   "upstream.tools/list.result",
		Evidence:   snapshotDiff(p.baseline, snapshot),
		Classifier: "rug-pull",
		RequestID:  idKey,
		Direction:  classifier.DirectionUpstreamToClient,
		Blocked:    true,
		Timestamp:  now,
	}
	return []classifier.Finding{f}
}

func (p *Proxy) reportAll(findings []classifier.Finding) {
	for _, f := range findings {
		p.report(f)
	}
}

func (p *Proxy) report(f classifier.Finding) {
	if p.reporter != nil {
		_ = p.reporter.Write(f)
	}
}

func (p *Proxy) recordParseError() {
	p.parseErrMu.Lock()
	p.parseErrors++
	p.parseErrMu.Unlock()
}

func (p *Proxy) parseErrorsExceeded() bool {
	p.parseErrMu.Lock()
	defer p.parseErrMu.Unlock()
	return p.parseErrors >= p.cfg.MaxParseErrors
}

// resolveClassifiers turns a list of registry names into Classifier values.
// Empty list means use the built-in "regex" classifier.
func resolveClassifiers(names []string) ([]classifier.Classifier, error) {
	reg := classifier.Default()
	if len(names) == 0 {
		c, err := reg.Get("regex")
		if err != nil {
			return nil, err
		}
		return []classifier.Classifier{c}, nil
	}
	out := make([]classifier.Classifier, 0, len(names))
	for _, n := range names {
		c, err := reg.Get(n)
		if err != nil {
			return nil, err
		}
		if err := c.Available(); err != nil {
			return nil, fmt.Errorf("classifier %q unavailable: %w", n, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// Message is a generic JSON-RPC message parsed from one line of stdio.
type Message struct {
	Raw    []byte
	ID     json.RawMessage
	Method string
	Params json.RawMessage
	Result json.RawMessage
}

func parseMessage(line []byte) (*Message, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return nil, err
	}
	msg := &Message{Raw: line}
	if id, ok := fields["id"]; ok {
		msg.ID = id
	}
	if method, ok := fields["method"]; ok {
		_ = json.Unmarshal(method, &msg.Method)
	}
	if params, ok := fields["params"]; ok {
		msg.Params = params
	}
	if result, ok := fields["result"]; ok {
		msg.Result = result
	}
	return msg, nil
}

func errorResponse(id json.RawMessage, message string) map[string]any {
	var idValue any
	_ = json.Unmarshal(id, &idValue)
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      idValue,
		"error": map[string]any{
			"code":    blockCode,
			"message": message,
		},
	}
}

func writeJSONLine(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func idKey(id json.RawMessage) string {
	if len(id) == 0 {
		return ""
	}
	return string(canonicalJSON(id))
}

func toolSnapshot(result json.RawMessage) map[string]string {
	var parsed struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Title       string          `json:"title,omitempty"`
			InputSchema json.RawMessage `json:"inputSchema,omitempty"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil
	}

	snapshot := make(map[string]string, len(parsed.Tools))
	for _, tool := range parsed.Tools {
		if tool.Name == "" {
			continue
		}
		record := map[string]json.RawMessage{
			"description": json.RawMessage(strJSON(tool.Description)),
			"title":       json.RawMessage(strJSON(tool.Title)),
			"inputSchema": canonicalJSON(tool.InputSchema),
		}
		snapshot[tool.Name] = string(canonicalJSON(mustJSON(record)))
	}
	return snapshot
}

func equalSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, val := range a {
		if b[key] != val {
			return false
		}
	}
	return true
}

func snapshotDiff(before, after map[string]string) string {
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}

	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)

	var changes []string
	for _, key := range ordered {
		switch {
		case before[key] == "":
			changes = append(changes, "added tool "+key)
		case after[key] == "":
			changes = append(changes, "removed tool "+key)
		case before[key] != after[key]:
			changes = append(changes, "changed tool "+key)
		}
	}
	return strings.Join(changes, "; ")
}

func canonicalJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw
	}
	return mustJSON(value)
}

func mustJSON(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}

func strJSON(s string) []byte {
	data, _ := json.Marshal(s)
	return data
}

func appendFindings[T any](dst []T, src []T) []T {
	if len(src) == 0 {
		return dst
	}
	return append(dst, src...)
}

var _ = bytes.Equal // keep "bytes" import (used elsewhere if needed)
