package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"mcpguard/internal/rules/model"
)

// GenerateReport formats the ScanReport into the selected output format and writes to w.
func GenerateReport(w io.Writer, report *model.ScanReport, format string) error {
	switch stringsToLower(format) {
	case "json":
		return writeJSON(w, report)
	case "markdown", "md":
		return writeMarkdown(w, report)
	case "sarif":
		return writeSARIF(w, report)
	case "html":
		return writeHTML(w, report)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

func stringsToLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func writeJSON(w io.Writer, r *model.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeMarkdown(w io.Writer, r *model.ScanReport) error {
	fmt.Fprintln(w, "# mcpguard Scan Report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- **Scan Target:** `%s`\n", escapeMarkdownCell(r.Path))
	fmt.Fprintf(w, "- **Scanned Files:** %d\n", r.TotalScanned)
	fmt.Fprintf(w, "- **Scan Duration:** %d ms\n", r.DurationMs)
	fmt.Fprintf(w, "- **Findings:** %d\n\n", len(r.Findings))

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "### No security issues detected.")
		return nil
	}

	fmt.Fprintf(w, "| Rule ID | Severity | File | Line | Description | Remediation |\n")
	fmt.Fprintf(w, "| :--- | :--- | :--- | :--- | :--- | :--- |\n")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "| `%s` | **%s** | `%s` | %d | %s | %s |\n",
			escapeMarkdownCell(f.RuleID), f.Severity, escapeMarkdownCell(f.FilePath), f.LineNumber, escapeMarkdownCell(f.Description), escapeMarkdownCell(f.Remediation))
	}
	return nil
}

func escapeMarkdownCell(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// SARIF Structures
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	ShortDescription SarifDescription `json:"shortDescription"`
	Help             SarifDescription `json:"help"`
}

type SarifDescription struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SarifDescription `json:"message"`
	Locations []SarifLocation  `json:"locations"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, r *model.ScanReport) error {
	sarifRules := []SarifRule{}
	ruleSeen := make(map[string]bool)

	sarifResults := []SarifResult{}

	for _, f := range r.Findings {
		if !ruleSeen[f.RuleID] {
			ruleSeen[f.RuleID] = true
			sarifRules = append(sarifRules, SarifRule{
				ID:               f.RuleID,
				ShortDescription: SarifDescription{Text: f.Title},
				Help:             SarifDescription{Text: f.Remediation},
			})
		}

		level := "warning"
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
			level = "error"
		} else if f.Severity == model.SeverityLow || f.Severity == model.SeverityInfo {
			level = "note"
		}

		sarifResults = append(sarifResults, SarifResult{
			RuleID: f.RuleID,
			Level:  level,
			Message: SarifDescription{
				Text: fmt.Sprintf("%s. Remediation: %s", f.Description, f.Remediation),
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{URI: f.FilePath},
						Region:           SarifRegion{StartLine: f.LineNumber},
					},
				},
			},
		})
	}

	log := SarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:    "mcpguard",
						Version: "0.1.0",
						Rules:   sarifRules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func writeHTML(w io.Writer, r *model.ScanReport) error {
	const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mcpguard Scan Report</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #6366f1;
            --border-color: #334155;

            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #10b981;
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }
        header {
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 {
            margin: 0;
            font-size: 2.25rem;
            background: linear-gradient(to right, #818cf8, #a5b4fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin-top: 0.5rem;
        }
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        .finding-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, border-color 0.2s;
        }
        .finding-card:hover {
            transform: translateY(-2px);
            border-color: #475569;
        }
        .finding-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            font-size: 0.75rem;
            font-weight: 700;
            border-radius: 9999px;
            text-transform: uppercase;
            margin-bottom: 1rem;
        }
        .badge-CRITICAL { background-color: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge-HIGH { background-color: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge-MEDIUM { background-color: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge-LOW { background-color: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
        .badge-INFO { background-color: rgba(16, 185, 129, 0.2); color: var(--info); border: 1px solid var(--info); }

        .finding-header {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .finding-meta {
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }
        .finding-meta code {
            background: rgba(0,0,0,0.2);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
        }
        .finding-remediation {
            background: rgba(0, 0, 0, 0.15);
            border-left: 4px solid var(--primary);
            padding: 1rem;
            border-radius: 0 8px 8px 0;
            margin-top: 1rem;
        }
        .no-findings {
            text-align: center;
            padding: 4rem;
            color: var(--text-muted);
            border: 2px dashed var(--border-color);
            border-radius: 12px;
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>mcpguard Scan Dashboard</h1>
            <div style="color: var(--text-muted); margin-top: 0.25rem;">Security analysis for Model Context Protocol servers</div>
        </div>
        <div>
            <span style="font-size: 0.875rem; color: var(--text-muted);">Generated: {{.FormattedTime}}</span>
        </div>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <div style="color: var(--text-muted); font-size: 0.875rem;">Scan Target</div>
            <div class="stat-value" style="font-size: 1.25rem; word-break: break-all; margin-top: 1rem;">{{.Path}}</div>
        </div>
        <div class="stat-card">
            <div style="color: var(--text-muted); font-size: 0.875rem;">Files Audited</div>
            <div class="stat-value">{{.TotalScanned}}</div>
        </div>
        <div class="stat-card">
            <div style="color: var(--text-muted); font-size: 0.875rem;">Total Findings</div>
            <div class="stat-value" style="color: {{if .Findings}}var(--high){{else}}var(--info){{end}}">{{len .Findings}}</div>
        </div>
        <div class="stat-card">
            <div style="color: var(--text-muted); font-size: 0.875rem;">Duration</div>
            <div class="stat-value">{{.DurationMs}} ms</div>
        </div>
    </div>

    <h2>Findings</h2>
    <div class="findings-list">
        {{range .Findings}}
        <div class="finding-card">
            <span class="finding-badge badge-{{.Severity}}">{{.Severity}}</span>
            <div class="finding-header">{{.Title}}</div>
            <div class="finding-meta">
                Rule ID: <code>{{.RuleID}}</code> &bull; File: <code>{{.FilePath}}:{{.LineNumber}}</code>
            </div>
            <div>{{.Description}}</div>
            {{if .MatchString}}
            <div style="margin-top: 0.5rem; font-family: monospace; background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 6px; font-size: 0.875rem; overflow-x: auto;">
                {{.MatchString}}
            </div>
            {{end}}
            <div class="finding-remediation">
                <strong>Remediation:</strong> {{.Remediation}}
            </div>
        </div>
        {{else}}
        <div class="no-findings">
            <h3>🎉 Scan Clean</h3>
            <p>No vulnerabilities or security issues were discovered in this scope.</p>
        </div>
        {{end}}
    </div>
</body>
</html>`

	t, err := template.New("html_report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	data := struct {
		*model.ScanReport
		FormattedTime string
	}{
		ScanReport:    r,
		FormattedTime: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	return t.Execute(w, data)
}
