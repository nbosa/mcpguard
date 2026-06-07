// Package view serves an HTML live view of proxy findings streamed from a
// JSONL report file. The file is tailed at Server.PollInterval; new lines
// are parsed as classifier.Finding and pushed to all connected SSE clients
// in real time.
//
// The HTTP server is intentionally minimal: a single-page app served at /
// and an SSE stream at /events. No JavaScript framework, no build step —
// the entire UI is a single embedded HTML file.
package view

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"mcpguard/internal/proxy/classifier"
)

// indexHTML is the single-page UI, embedded at build time so the binary is
// self-contained.
//
//go:embed index.html
var indexHTML string

// DefaultPort is the default listen port for the view server.
const DefaultPort = 7337

// DefaultPollInterval is how often the file tailer checks for new content.
const DefaultPollInterval = 200 * time.Millisecond

// SSEBufferSize is the per-client buffered channel size. Slow clients may
// miss findings if they fall more than this many events behind; we drop the
// oldest in that case (with a server-side log).
const SSEBufferSize = 128

// MaxHistorySize is the maximum number of recent findings kept in memory
// for replay to late-connecting clients.
const MaxHistorySize = 1000

// Server serves the live view. Construct with New, call Start to begin
// serving, call Shutdown to stop.
type Server struct {
	// ReportPath is the JSONL file to tail. Required.
	ReportPath string
	// Addr is the listen address (e.g. "127.0.0.1:7337").
	Addr string
	// PollInterval is how often to check the file for new content.
	// Zero means DefaultPollInterval.
	PollInterval time.Duration
	// Logger receives status messages. nil means stderr.
	Logger io.Writer
	// OpenURL, if non-empty, is printed to the Logger once the server is
	// up. Callers may use it to open the browser.
	OpenURL string

	mu      sync.Mutex
	subs    map[chan classifier.Finding]struct{}
	history []classifier.Finding

	httpServer *http.Server
	listener   net.Listener
}

// New returns a Server configured with the given report path and listen
// address.
func New(reportPath, addr string) *Server {
	return &Server{
		ReportPath:   reportPath,
		Addr:         addr,
		PollInterval: DefaultPollInterval,
		Logger:       os.Stderr,
		subs:         make(map[chan classifier.Finding]struct{}),
		history:      make([]classifier.Finding, 0, MaxHistorySize),
	}
}

// Start binds the listener, registers HTTP handlers, and spawns the file
// tailer. It returns once the server is listening; it does not block.
// Call Shutdown to stop the server.
func (s *Server) Start(ctx context.Context) error {
	if s.ReportPath == "" {
		return fmt.Errorf("view: ReportPath is required")
	}
	if s.Addr == "" {
		return fmt.Errorf("view: Addr is required")
	}
	if s.PollInterval <= 0 {
		s.PollInterval = DefaultPollInterval
	}

	lis, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("view: listen on %s: %w", s.Addr, err)
	}
	s.listener = lis

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/events", s.handleSSE)
	mux.HandleFunc("/healthz", s.handleHealth)

	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go s.tailFile(ctx)

	go func() {
		if err := s.httpServer.Serve(lis); err != nil && err != http.ErrServerClosed {
			s.logf("view: serve: %v\n", err)
		}
	}()

	return nil
}

// Shutdown stops the HTTP server and (best-effort) the file tailer.
// Safe to call multiple times.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// URL returns the URL clients should open. Empty if Start was not called
// or the listener has not bound yet.
func (s *Server) URL() string {
	if s.listener == nil {
		return ""
	}
	return "http://" + s.listener.Addr().String()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, indexHTML)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok")
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send a hello event so the client knows the connection is live and
	// which file is being tailed.
	hello := fmt.Sprintf(`{"report":%q}`, s.ReportPath)
	if !writeSSE(w, flusher, "hello", hello) {
		return
	}

	// Replay recent history so a client connecting after the proxy has
	// already started still sees existing findings. This snapshot is
	// taken before we subscribe, so we don't miss new findings either
	// (any finding published during the snapshot is delivered via the
	// live channel).
	snapshot := s.snapshotHistory()
	for _, f := range snapshot {
		data, err := json.Marshal(f)
		if err != nil {
			continue
		}
		if !writeSSE(w, flusher, "finding", string(data)) {
			return
		}
	}

	ch := make(chan classifier.Finding, SSEBufferSize)
	s.subscribe(ch)
	defer s.unsubscribe(ch)

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case f, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(f)
			if err != nil {
				continue
			}
			if !writeSSE(w, flusher, "finding", string(data)) {
				return
			}
		}
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event, data string) bool {
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func (s *Server) subscribe(ch chan classifier.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[ch] = struct{}{}
}

func (s *Server) unsubscribe(ch chan classifier.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, ch)
}

func (s *Server) publish(f classifier.Finding) {
	s.mu.Lock()
	// Maintain a bounded ring buffer of recent findings for replay to
	// late-connecting clients.
	s.history = append(s.history, f)
	if len(s.history) > MaxHistorySize {
		s.history = s.history[len(s.history)-MaxHistorySize:]
	}
	// Publish to all current subscribers.
	for ch := range s.subs {
		select {
		case ch <- f:
		default:
			// Channel full; drop the new finding. Slow client.
			s.logf("view: dropping finding for slow client (channel full)\n")
		}
	}
	s.mu.Unlock()
}

// snapshotHistory returns a copy of the recent-findings buffer at the
// moment of the call. Used by SSE handlers to replay history on connect.
func (s *Server) snapshotHistory() []classifier.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.history) == 0 {
		return nil
	}
	out := make([]classifier.Finding, len(s.history))
	copy(out, s.history)
	return out
}

// tailFile polls the report file at PollInterval and publishes any new
// complete JSONL lines. It handles:
//   - File does not exist yet (waits for the proxy to create it).
//   - File truncation / recreation by the proxy (offset resets).
//   - Partial lines (offset does not advance until newline is seen).
func (s *Server) tailFile(ctx context.Context) {
	var offset int64
	announcedWait := false

	for {
		if ctx.Err() != nil {
			return
		}

		// Read all currently-available complete lines.
		n, exhausted, err := s.readNewLines(offset, func(line []byte) {
			var f classifier.Finding
			if jerr := json.Unmarshal(bytes.TrimSpace(line), &f); jerr == nil {
				s.publish(f)
			} else {
				s.logf("view: skip malformed line: %v\n", jerr)
			}
		})
		if err != nil {
			s.logf("view: read %s: %v\n", s.ReportPath, err)
		}
		if n > 0 {
			offset += n
			announcedWait = false
		}

		// If we read a complete pass without hitting EOF on a non-empty
		// partial line, we're caught up. Sleep before the next poll.
		if exhausted || ctx.Err() != nil {
			if !sleep(ctx, s.PollInterval) {
				return
			}
			continue
		}

		// Partial line at EOF: wait for more bytes.
		if !announcedWait && offset == 0 {
			s.logf("view: waiting for %s to be created by the proxy…\n", s.ReportPath)
			announcedWait = true
		}
		if !sleep(ctx, s.PollInterval) {
			return
		}
	}
}

// readNewLines reads from the file starting at fromOffset, invokes onLine
// for each complete line (terminated by \n), and returns the number of
// bytes consumed. The third return is true when the file is fully drained
// (caller can sleep), false when a partial line is pending (caller should
// poll again without advancing).
func (s *Server) readNewLines(fromOffset int64, onLine func([]byte)) (int64, bool, error) {
	f, err := os.Open(s.ReportPath)
	if err != nil {
		return 0, true, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return 0, true, err
	}

	// Handle truncation/recreation: if the file is smaller than where we
	// last read, start over from the beginning.
	startOffset := fromOffset
	if fi.Size() < fromOffset {
		startOffset = 0
	}
	if fi.Size() == startOffset {
		return 0, true, nil
	}

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return 0, true, err
	}

	reader := bufio.NewReader(f)
	var consumed int64
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				// Complete line
				consumed += int64(len(line))
				onLine(line)
			} else {
				// Partial line at EOF: do not advance offset; the
				// remaining bytes will be re-read on the next poll
				// once the producer flushes the rest of the line.
				return consumed, false, nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return consumed, true, nil
			}
			return consumed, true, err
		}
	}
}

func (s *Server) logf(format string, args ...interface{}) {
	if s.Logger == nil {
		return
	}
	fmt.Fprintf(s.Logger, format, args...)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// FormatReportPath returns a path relative-friendly display name for the
// given report path (used in CLI status messages).
func FormatReportPath(p string) string {
	if p == "" {
		return ""
	}
	if home, err := os.UserHomeDir(); err == nil {
		if strings.HasPrefix(p, home) {
			return "~" + strings.TrimPrefix(p, home)
		}
	}
	return p
}
