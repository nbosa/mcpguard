package view

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mcpguard/internal/proxy/classifier"
)

// freeAddr returns a free TCP address on localhost. Useful for parallel-safe
// tests that bind a Server.
func freeAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	return addr
}

func startServer(t *testing.T, reportPath string, opts ...func(*Server)) (*Server, string) {
	t.Helper()
	addr := freeAddr(t)
	s := New(reportPath, addr)
	s.Logger = io.Discard
	s.PollInterval = 30 * time.Millisecond
	for _, o := range opts {
		o(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
		cancel()
	})
	return s, addr
}

func TestStartRejectsEmptyReportPath(t *testing.T) {
	s := New("", "127.0.0.1:0")
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected error for empty report path")
	}
}

func TestStartRejectsEmptyAddr(t *testing.T) {
	s := New("/tmp/x", "")
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestHandleIndexServesHTML(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.jsonl")
	if err := os.WriteFile(reportPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, addr := startServer(t, reportPath)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type: %s", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<title>mcpguard live view</title>") {
		t.Fatalf("body missing title; first 80 bytes: %q", body[:min(80, len(body))])
	}
	if !strings.Contains(string(body), "EventSource") {
		t.Fatal("body missing EventSource client code")
	}
}

func TestHandleIndex404OnUnknownPath(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	_, addr := startServer(t, reportPath)

	resp, err := http.Get("http://" + addr + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHealthzReturnsOK(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	_, addr := startServer(t, reportPath)

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body: %q", body)
	}
}

func TestSSEHelloEventOnConnect(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	_, addr := startServer(t, reportPath)

	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := newSSEEventStream(resp.Body)
	defer func() { cancel(); resp.Body.Close() }()

	ev := readSSEEvent(t, events, 2*time.Second)
	if ev.event != "hello" {
		t.Fatalf("expected hello, got %s", ev.event)
	}
	if !strings.Contains(ev.data, reportPath) {
		t.Fatalf("hello data missing path: %s", ev.data)
	}
}

func TestSSEStreamsExistingThenNewFindings(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")

	existing := classifier.Finding{
		Type:       classifier.ThreatPromptInjection,
		Severity:   classifier.SeverityHigh,
		Reason:     "seeded",
		Classifier: "regex",
		Blocked:    true,
		Timestamp:  time.Now().UTC(),
	}
	writeFinding(t, reportPath, existing)

	_, addr := startServer(t, reportPath)

	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := newSSEEventStream(resp.Body)
	defer func() { cancel(); resp.Body.Close() }()

	hello := readSSEEvent(t, events, 2*time.Second)
	if hello.event != "hello" {
		t.Fatalf("expected hello, got %s", hello.event)
	}

	findEv := readSSEEvent(t, events, 2*time.Second)
	if findEv.event != "finding" {
		t.Fatalf("expected finding, got %s", findEv.event)
	}
	var got classifier.Finding
	if err := json.Unmarshal([]byte(findEv.data), &got); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, findEv.data)
	}
	if got.Reason != "seeded" {
		t.Fatalf("unexpected seeded reason: %+v", got)
	}

	newF := classifier.Finding{
		Type:       classifier.ThreatToolPoisoning,
		Severity:   classifier.SeverityCritical,
		Reason:     "appended",
		Classifier: "rug-pull",
		Blocked:    true,
		Timestamp:  time.Now().UTC(),
	}
	appendFinding(t, reportPath, newF)

	findEv2 := readSSEEvent(t, events, 2*time.Second)
	if findEv2.event != "finding" {
		t.Fatalf("expected finding, got %s", findEv2.event)
	}
	if err := json.Unmarshal([]byte(findEv2.data), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Reason != "appended" {
		t.Fatalf("unexpected reason: %+v", got)
	}
	if got.Severity != classifier.SeverityCritical {
		t.Fatalf("unexpected severity: %s", got.Severity)
	}
}

func TestSSEHandlesFileTruncation(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")

	writeFinding(t, reportPath, classifier.Finding{Type: classifier.ThreatPromptInjection, Severity: classifier.SeverityHigh, Reason: "before-truncate", Classifier: "regex", Blocked: true, Timestamp: time.Now().UTC()})

	_, addr := startServer(t, reportPath)
	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := newSSEEventStream(resp.Body)
	defer func() { cancel(); resp.Body.Close() }()

	_ = readSSEEvent(t, events, 2*time.Second) // hello
	_ = readSSEEvent(t, events, 2*time.Second) // before-truncate

	if err := os.WriteFile(reportPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	appendFinding(t, reportPath, classifier.Finding{Type: classifier.ThreatRugPull, Severity: classifier.SeverityCritical, Reason: "after-truncate", Classifier: "rug-pull", Blocked: true, Timestamp: time.Now().UTC()})

	ev := readSSEEvent(t, events, 3*time.Second)
	if ev.event != "finding" {
		t.Fatalf("expected finding after truncate, got %s", ev.event)
	}
	var got classifier.Finding
	json.Unmarshal([]byte(ev.data), &got)
	if got.Reason != "after-truncate" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSSEHandlesMalformedLines(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	content := "not json\n" +
		`{"type":"prompt_injection","severity":"HIGH","reason":"valid","classifier":"regex","blocked":true,"timestamp":"2026-06-07T00:00:00Z"}` + "\n" +
		"also not json\n"
	if err := os.WriteFile(reportPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, addr := startServer(t, reportPath)
	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := newSSEEventStream(resp.Body)
	defer func() { cancel(); resp.Body.Close() }()

	_ = readSSEEvent(t, events, 2*time.Second) // hello
	ev := readSSEEvent(t, events, 2*time.Second)
	if ev.event != "finding" {
		t.Fatalf("expected finding, got %s", ev.event)
	}
	var got classifier.Finding
	json.Unmarshal([]byte(ev.data), &got)
	if got.Reason != "valid" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSSEMultipleClients(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	_, addr := startServer(t, reportPath)

	const numClients = 3
	type client struct {
		body   io.ReadCloser
		events <-chan sseEvent
		cancel func()
	}
	clients := make([]*client, numClients)
	var wg sync.WaitGroup
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := http.Get("http://" + addr + "/events")
			if err != nil {
				t.Errorf("client %d: %v", idx, err)
				return
			}
			events, cancel := newSSEEventStream(resp.Body)
			clients[idx] = &client{body: resp.Body, events: events, cancel: cancel}
			_ = readSSEEvent(t, events, 2*time.Second) // hello
		}(i)
	}
	wg.Wait()
	defer func() {
		for _, c := range clients {
			if c != nil {
				c.cancel()
				c.body.Close()
			}
		}
	}()

	appendFinding(t, reportPath, classifier.Finding{Type: classifier.ThreatPromptInjection, Severity: classifier.SeverityHigh, Reason: "broadcast", Classifier: "regex", Blocked: true, Timestamp: time.Now().UTC()})

	for i, c := range clients {
		if c == nil {
			t.Errorf("client %d: no body", i)
			continue
		}
		ev := readSSEEvent(t, c.events, 3*time.Second)
		if ev.event != "finding" {
			t.Errorf("client %d: expected finding, got %s", i, ev.event)
		}
	}
}

func TestSSEWaitsForFileToAppear(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "later.jsonl")

	_, addr := startServer(t, reportPath)
	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := newSSEEventStream(resp.Body)
	defer func() { cancel(); resp.Body.Close() }()

	_ = readSSEEvent(t, events, 2*time.Second) // hello

	if err := os.WriteFile(reportPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	appendFinding(t, reportPath, classifier.Finding{Type: classifier.ThreatPromptInjection, Severity: classifier.SeverityHigh, Reason: "late", Classifier: "regex", Blocked: true, Timestamp: time.Now().UTC()})

	ev := readSSEEvent(t, events, 5*time.Second)
	if ev.event != "finding" {
		t.Fatalf("expected finding, got %s", ev.event)
	}
}

func TestURLReturnsListenAddress(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	s, addr := startServer(t, reportPath)

	got := s.URL()
	if got != "http://"+addr {
		t.Fatalf("URL: %s, expected http://%s", got, addr)
	}
}

func TestShutdownStopsServer(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	s, addr := startServer(t, reportPath)

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	_, err := http.Get("http://" + addr + "/healthz")
	if err == nil {
		t.Fatal("expected error after shutdown")
	}
}

func TestPartialLineIsNotPublishedUntilComplete(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	_, addr := startServer(t, reportPath)

	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := newSSEEventStream(resp.Body)
	defer func() { cancel(); resp.Body.Close() }()
	_ = readSSEEvent(t, events, 2*time.Second) // hello

	f, err := os.OpenFile(reportPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"type":"prompt_injection","severity":"HIGH","reason":"partial`)
	f.Close()

	if ev := tryReadSSEEvent(t, events, 200*time.Millisecond); ev != nil {
		t.Fatalf("partial line was published: %+v", ev)
	}

	f, _ = os.OpenFile(reportPath, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(` line","classifier":"regex","blocked":true,"timestamp":"2026-06-07T00:00:00Z"}` + "\n")
	f.Close()

	ev := readSSEEvent(t, events, 2*time.Second)
	if ev.event != "finding" {
		t.Fatalf("expected finding, got %s", ev.event)
	}
	var got classifier.Finding
	json.Unmarshal([]byte(ev.data), &got)
	if got.Reason != "partial line" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestFormatReportPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/tmp/x.jsonl", "/tmp/x.jsonl"},
	}
	for _, c := range cases {
		if got := FormatReportPath(c.in); got != c.want {
			t.Errorf("FormatReportPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// sseEvent is one parsed Server-Sent Event.
type sseEvent struct {
	event string
	data  string
}

// newSSEEventStream starts a single reader goroutine that parses the SSE
// stream from body and delivers events on a channel. Tests can read
// multiple events sequentially. Call the returned cancel function to stop
// the goroutine.
func newSSEEventStream(body io.Reader) (<-chan sseEvent, func()) {
	ch := make(chan sseEvent, 16)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(body)
		scanner.Buffer(make([]byte, 0, 1024), 64*1024)
		var event, data string
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if event != "" {
					select {
					case ch <- sseEvent{event: event, data: data}:
					case <-done:
						return
					}
					event = ""
					data = ""
				}
			}
		}
	}()
	return ch, func() { close(done) }
}

func readSSEEvent(t *testing.T, ch <-chan sseEvent, d time.Duration) sseEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatalf("SSE channel closed before event")
		}
		return ev
	case <-time.After(d):
		t.Fatalf("timed out waiting for SSE event after %s", d)
	}
	return sseEvent{}
}

func tryReadSSEEvent(t *testing.T, ch <-chan sseEvent, d time.Duration) *sseEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			return nil
		}
		return &ev
	case <-time.After(d):
		return nil
	}
}

func writeFinding(t *testing.T, path string, f classifier.Finding) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFinding(t *testing.T, path string, f classifier.Finding) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if _, err := f2.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestEmbeddedHTMLNonEmpty(t *testing.T) {
	if indexHTML == "" {
		t.Fatal("index.html not embedded")
	}
	if !strings.Contains(indexHTML, "EventSource") {
		t.Fatal("embedded HTML missing EventSource")
	}
}

func TestNewDefaults(t *testing.T) {
	s := New("/x", "127.0.0.1:0")
	if s.PollInterval != DefaultPollInterval {
		t.Errorf("PollInterval: %v", s.PollInterval)
	}
	if s.Logger != os.Stderr {
		t.Error("Logger should default to stderr")
	}
	if s.subs == nil {
		t.Error("subs should be initialized")
	}
	if s.ReportPath != "/x" || s.Addr != "127.0.0.1:0" {
		t.Errorf("New: %+v", s)
	}
}

func TestMultipleSubscribersReceiveSameEvent(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "r.jsonl")
	os.WriteFile(reportPath, nil, 0o644)
	_, addr := startServer(t, reportPath)

	r1, _ := http.Get("http://" + addr + "/events")
	r2, _ := http.Get("http://" + addr + "/events")
	defer r1.Body.Close()
	defer r2.Body.Close()
	ev1, cancel1 := newSSEEventStream(r1.Body)
	ev2, cancel2 := newSSEEventStream(r2.Body)
	defer cancel1()
	defer cancel2()

	_ = readSSEEvent(t, ev1, 2*time.Second) // hello
	_ = readSSEEvent(t, ev2, 2*time.Second) // hello

	appendFinding(t, reportPath, classifier.Finding{Type: classifier.ThreatPromptInjection, Severity: classifier.SeverityHigh, Reason: "fanout", Classifier: "regex", Blocked: true, Timestamp: time.Now().UTC()})

	got1 := readSSEEvent(t, ev1, 2*time.Second)
	got2 := readSSEEvent(t, ev2, 2*time.Second)
	if got1.event != "finding" || got2.event != "finding" {
		t.Fatalf("fanout failed: %+v / %+v", got1, got2)
	}
}

// Suppress unused import warnings if helpers aren't used.
var _ = fmt.Sprintf
