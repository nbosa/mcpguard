package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

// ClientSession manages communication with an MCP server subprocess using JSON-RPC over stdio.
type ClientSession struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	idSec   uint64
	pending map[uint64]chan []byte
	mu      sync.Mutex
	closed  bool
}

// JsonRpcRequest defines the payload structure sent to the server.
type JsonRpcRequest struct {
	JsonRPC string      `json:"jsonrpc"`
	ID      uint64      `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// JsonRpcResponse defines the payload structure received from the server.
type JsonRpcResponse struct {
	JsonRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   interface{}     `json:"error,omitempty"`
}

// Tool defines an MCP tool definition returned from the server.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Title       string      `json:"title,omitempty"`
	InputSchema interface{} `json:"inputSchema"`
}

// ConnectToStdioServer spawns the server process and performs the MCP initialize handshake.
func ConnectToStdioServer(ctx context.Context, command string, args []string, env []string) (*ClientSession, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	session := &ClientSession{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		pending: make(map[uint64]chan []byte),
	}

	go session.readLoop()

	// Handshake: Send initialize request
	var initResult map[string]interface{}
	err = session.Call(ctx, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "mcpguard-prober",
			"version": "0.1.0",
		},
	}, &initResult)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("initialization handshake failed: %w", err)
	}

	// Send initialized notification
	_ = session.Notify("notifications/initialized", map[string]interface{}{})

	return session, nil
}

func (s *ClientSession) readLoop() {
	scanner := bufio.NewScanner(s.stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var resp JsonRpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}

		s.mu.Lock()
		ch, exists := s.pending[resp.ID]
		if exists {
			ch <- line
			delete(s.pending, resp.ID)
		}
		s.mu.Unlock()
	}
	s.Close()
}

// Call executes a request/response JSON-RPC call.
func (s *ClientSession) Call(ctx context.Context, method string, params interface{}, result interface{}) error {
	id := atomic.AddUint64(&s.idSec, 1)
	ch := make(chan []byte, 1)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("session is closed")
	}
	s.pending[id] = ch
	s.mu.Unlock()

	req := JsonRpcRequest{
		JsonRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	_, err = s.stdin.Write(append(reqBytes, '\n'))
	s.mu.Unlock()
	if err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return err
	}

	select {
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return ctx.Err()
	case resLine := <-ch:
		if resLine == nil {
			return fmt.Errorf("session closed before response")
		}
		var resp JsonRpcResponse
		if err := json.Unmarshal(resLine, &resp); err != nil {
			return err
		}
		if resp.Error != nil {
			return fmt.Errorf("JSON-RPC error: %v", resp.Error)
		}
		return json.Unmarshal(resp.Result, result)
	}
}

// Notify sends a notification JSON-RPC call without expecting a response.
func (s *ClientSession) Notify(method string, params interface{}) error {
	req := JsonRpcRequest{
		JsonRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("session is closed")
	}
	_, err = s.stdin.Write(append(reqBytes, '\n'))
	s.mu.Unlock()
	return err
}

// ListTools lists all tools exposed by the MCP server.
func (s *ClientSession) ListTools(ctx context.Context) ([]Tool, error) {
	var res struct {
		Tools []Tool `json:"tools"`
	}
	err := s.Call(ctx, "tools/list", map[string]interface{}{}, &res)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// CallTool invokes a specific tool on the MCP server.
func (s *ClientSession) CallTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	err := s.Call(ctx, "tools/call", map[string]interface{}{
		"name":      name,
		"arguments": args,
	}, &res)
	if err != nil {
		return "", err
	}
	if len(res.Content) > 0 {
		return res.Content[0].Text, nil
	}
	return "", nil
}

// Close terminates pipes and kills the server process.
func (s *ClientSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for id, ch := range s.pending {
		close(ch)
		delete(s.pending, id)
	}
	s.mu.Unlock()

	_ = s.stdin.Close()
	_ = s.stdout.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.cmd.Wait()
	return nil
}
