package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mcpguard/internal/rules/model"
)

func TestGenerateReport(t *testing.T) {
	rep := &model.ScanReport{
		Path:         "some/path",
		StartTime:    time.Now(),
		DurationMs:   42,
		TotalScanned: 10,
		Findings: []model.Finding{
			{
				RuleID:      "MCP-SEC-002",
				Title:       "Unicode Obfuscation",
				Severity:    model.SeverityHigh,
				Description: "Obfuscation detected",
				Remediation: "Fix it",
				FilePath:    "file.go",
				LineNumber:  22,
				MatchString: "insecure content",
				Timestamp:   time.Now(),
			},
		},
	}

	formats := []string{"json", "markdown", "html", "sarif"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			err := GenerateReport(&buf, rep, format)
			if err != nil {
				t.Fatalf("GenerateReport failed for format %s: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Errorf("GenerateReport wrote 0 bytes for format %s", format)
			}
		})
	}
}

func TestGenerateReport_NormalizesFormat(t *testing.T) {
	rep := &model.ScanReport{Path: "some/path", StartTime: time.Now()}

	var buf bytes.Buffer
	if err := GenerateReport(&buf, rep, " JSON "); err != nil {
		t.Fatalf("GenerateReport should accept trimmed case-insensitive format: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("GenerateReport wrote 0 bytes")
	}
}

func TestGenerateReport_EscapesMarkdownCells(t *testing.T) {
	rep := &model.ScanReport{
		Path: "some|path",
		Findings: []model.Finding{
			{
				RuleID:      "MCP-SEC-999",
				Title:       "Pipe",
				Severity:    model.SeverityLow,
				Description: "contains | pipe",
				Remediation: "remove | pipe",
				FilePath:    "file|name.go",
				LineNumber:  1,
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateReport(&buf, rep, "markdown"); err != nil {
		t.Fatalf("GenerateReport markdown failed: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, `contains \| pipe`) {
		t.Fatalf("markdown output did not escape table pipe: %s", got)
	}
}
