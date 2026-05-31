package dynamic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"mcpguard/internal/dynamic/client"
	"mcpguard/internal/dynamic/prober"
	"mcpguard/internal/dynamic/rugpull"
	"mcpguard/internal/rules/model"
)

func TestDynamicProberAndRugpull(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Build the mock server
	tempDir, err := os.MkdirTemp("", "mcp-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockServerPath := filepath.Join(tempDir, "mock_server")
	buildCmd := exec.Command("go", "build", "-o", mockServerPath, "../../tests/fixtures/mock_server.go")
	buildCmd.Dir = "."
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mock server: %v, output: %s", err, string(output))
	}

	// 2. Connect to the mock server with rugpull enabled
	session, err := client.ConnectToStdioServer(ctx, mockServerPath, []string{"--simulate-rugpull"}, nil)
	if err != nil {
		t.Fatalf("failed to connect to stdio mock server: %v", err)
	}
	defer session.Close()

	// 3. Take baseline snapshot
	beforeSnapshot, err := rugpull.TakeSchemaSnapshot(ctx, session)
	if err != nil {
		t.Fatalf("failed to take baseline snapshot: %v", err)
	}

	if _, exists := beforeSnapshot["hello"]; !exists {
		t.Errorf("expected tool 'hello' to exist in baseline snapshot")
	}

	// 4. Run initial prober checks
	findings, err := prober.RunProbes(ctx, session, "mock_server.json")
	if err != nil {
		t.Fatalf("failed to run initial prober checks: %v", err)
	}

	// 5. Trigger the simulated rugpull
	_, err = session.CallTool(ctx, "trigger_rugpull", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to invoke trigger_rugpull: %v", err)
	}

	// 6. Take post-execution snapshot
	afterSnapshot, err := rugpull.TakeSchemaSnapshot(ctx, session)
	if err != nil {
		t.Fatalf("failed to take post-execution snapshot: %v", err)
	}

	// 7. Diff schemas
	rugpullFindings := rugpull.DiffSchemas(beforeSnapshot, afterSnapshot, "mock_server.json")
	findings = append(findings, rugpullFindings...)

	// 8. Assertions
	hasRugpullFinding := false
	for _, f := range findings {
		if f.RuleID == "MCP-SEC-030" && f.Severity == model.SeverityCritical {
			hasRugpullFinding = true
		}
	}

	if !hasRugpullFinding {
		t.Errorf("expected to find a CRITICAL rug pull schema mutation finding (MCP-SEC-030)")
	}
}
