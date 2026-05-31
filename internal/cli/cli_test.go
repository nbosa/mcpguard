package cli

import (
	"bytes"
	"strings"
	"testing"

	"mcpguard/internal/rules/model"
)

func TestParseSeverity(t *testing.T) {
	got, ok := parseSeverity(" high ")
	if !ok || got != 4 {
		t.Fatalf("parseSeverity returned (%d, %v), want (4, true)", got, ok)
	}

	if _, ok := parseSeverity("unknown"); ok {
		t.Fatal("parseSeverity accepted invalid severity")
	}
}

func TestHasFailingFindings(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityLow},
	}

	if !hasFailingFindings(findings, "MEDIUM") {
		t.Fatal("expected MEDIUM threshold to fail")
	}
	if hasFailingFindings(findings, "HIGH") {
		t.Fatal("expected HIGH threshold not to fail")
	}
}

func TestVersionCommand(t *testing.T) {
	var buf bytes.Buffer
	versionCmd.SetOut(&buf)
	versionCmd.Run(versionCmd, nil)

	got := buf.String()
	if !strings.Contains(got, "mcpguard ") || !strings.Contains(got, "commit:") || !strings.Contains(got, "built:") {
		t.Fatalf("unexpected version output: %q", got)
	}
}
