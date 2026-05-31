package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"mcpguard/internal/proxy/detector"
)

const blockCode = -32090

// Config describes the local stdio proxy and upstream MCP server process.
type Config struct {
	UpstreamCommand string
	UpstreamArgs    []string
	UpstreamEnv     []string
	ReportPath      string
	Guard           *detector.Guard
}

// Proxy forwards JSON-RPC between a local MCP client and an upstream MCP server.
type Proxy struct {
	cfg       Config
	reporter  *Reporter
	baseline  map[string]string
	baselineM sync.Mutex
}

// New creates a stdio MCP proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.UpstreamCommand == "" {
		return nil, fmt.Errorf("upstream command is required")
	}
	if cfg.Guard == nil {
		cfg.Guard = detector.NewGuard(nil)
	}
	reporter, err := NewReporter(cfg.ReportPath)
	if err != nil {
		return nil, err
	}
	return &Proxy{cfg: cfg, reporter: reporter}, nil
}

// Close releases report resources.
func (p *Proxy) Close() error {
	if p == nil || p.reporter == nil {
		return nil
	}
	return p.reporter.Close()
}

// Run starts the upstream process and proxies stdin/stdout JSON-RPC traffic.
func (p *Proxy) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer) error {
	cmd := exec.CommandContext(ctx, p.cfg.UpstreamCommand, p.cfg.UpstreamArgs...)
	if len(p.cfg.UpstreamEnv) > 0 {
		cmd.Env = append(os.Environ(), p.cfg.UpstreamEnv...)
	}

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = upstreamIn.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	upstreamScanner := bufio.NewScanner(upstreamOut)
	upstreamScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	clientScanner := bufio.NewScanner(clientIn)
	clientScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for clientScanner.Scan() {
		line := append([]byte(nil), clientScanner.Bytes()...)
		msg, err := parseMessage(line)
		if err != nil {
			p.report(detector.NewRugPullFinding("Invalid client JSON-RPC message", "client", err.Error()))
			continue
		}

		if findings := p.inspectClientMessage(ctx, msg); len(findings) > 0 {
			p.reportAll(findings)
			if msg.ID != nil {
				if err := writeJSONLine(clientOut, errorResponse(msg.ID, "mcpguard blocked request: "+findings[0].Reason)); err != nil {
					return err
				}
			}
			continue
		}

		if _, err := upstreamIn.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("write upstream: %w", err)
		}

		if msg.ID == nil {
			continue
		}

		response, err := p.readResponseForID(ctx, upstreamScanner, clientOut, msg)
		if err != nil {
			return err
		}
		if response == nil {
			continue
		}

		blocked, findings := p.inspectUpstreamResponse(ctx, msg, response)
		if blocked {
			p.reportAll(findings)
			if err := writeJSONLine(clientOut, errorResponse(msg.ID, "mcpguard blocked response: "+findings[0].Reason)); err != nil {
				return err
			}
			continue
		}

		if _, err := clientOut.Write(append(response.Raw, '\n')); err != nil {
			return fmt.Errorf("write client: %w", err)
		}
	}

	if err := clientScanner.Err(); err != nil {
		return err
	}
	return nil
}

func (p *Proxy) readResponseForID(ctx context.Context, scanner *bufio.Scanner, clientOut io.Writer, req *Message) (*Message, error) {
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line := append([]byte(nil), scanner.Bytes()...)
		msg, err := parseMessage(line)
		if err != nil {
			p.report(detector.NewRugPullFinding("Invalid upstream JSON-RPC message", "upstream", err.Error()))
			continue
		}
		if msg.ID != nil && bytes.Equal(canonicalJSON(msg.ID), canonicalJSON(req.ID)) {
			return msg, nil
		}
		if _, err := clientOut.Write(append(line, '\n')); err != nil {
			return nil, err
		}
	}
	return nil, scanner.Err()
}

func (p *Proxy) inspectClientMessage(ctx context.Context, msg *Message) []detector.Finding {
	if msg.Method != "tools/call" {
		return nil
	}
	return p.cfg.Guard.Analyze(ctx, detector.ThreatPromptInjection, msg.Params, "client.tools/call.params")
}

func (p *Proxy) inspectUpstreamResponse(ctx context.Context, req *Message, resp *Message) (bool, []detector.Finding) {
	switch req.Method {
	case "tools/list":
		var findings []detector.Finding
		findings = append(findings, p.cfg.Guard.Analyze(ctx, detector.ThreatToolPoisoning, resp.Result, "upstream.tools/list.result")...)
		if rugPull := p.detectRugPull(resp.Result); rugPull != nil {
			findings = append(findings, *rugPull)
		}
		return len(findings) > 0, findings
	case "tools/call":
		findings := p.cfg.Guard.Analyze(ctx, detector.ThreatPromptInjection, resp.Result, "upstream.tools/call.result")
		return len(findings) > 0, findings
	default:
		return false, nil
	}
}

func (p *Proxy) detectRugPull(result json.RawMessage) *detector.Finding {
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

	return ptr(detector.NewRugPullFinding("Upstream MCP tool list or schema changed after baseline", "upstream.tools/list.result", snapshotDiff(p.baseline, snapshot)))
}

func (p *Proxy) reportAll(findings []detector.Finding) {
	for _, finding := range findings {
		p.report(finding)
	}
}

func (p *Proxy) report(finding detector.Finding) {
	if p.reporter != nil {
		_ = p.reporter.Write(finding)
	}
}

// Message is a generic JSON-RPC message.
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

func ptr[T any](v T) *T {
	return &v
}
