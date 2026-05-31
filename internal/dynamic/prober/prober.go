package prober

import (
	"context"
	"fmt"
	"time"

	"mcpguard/internal/dynamic/client"
	"mcpguard/internal/rules/engine"
	"mcpguard/internal/rules/model"
)

// RunProbes runs dynamic audits on the active session (e.g. Unicode checks, name obfuscations).
func RunProbes(ctx context.Context, session *client.ClientSession, targetPath string) ([]model.Finding, error) {
	var findings []model.Finding

	tools, err := session.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list tools: %w", err)
	}

	for _, tool := range tools {
		// 1. Audit name or description for hidden unicode obfuscation characters
		if engine.HasUnicodeObfuscation(tool.Name) || engine.HasUnicodeObfuscation(tool.Description) || engine.HasUnicodeObfuscation(tool.Title) {
			findings = append(findings, model.Finding{
				RuleID:      "MCP-SEC-002",
				Title:       "Unicode Obfuscation in Runtime Tool Definition",
				Severity:    model.SeverityHigh,
				Description: fmt.Sprintf("MCP server exposes tool %q containing hidden Unicode control codes or homoglyphs in metadata.", tool.Name),
				Remediation: "Ensure all tool definitions, names, and descriptions are standard ASCII text.",
				FilePath:    targetPath,
				LineNumber:  1,
				MatchString: fmt.Sprintf("Tool: %s, Description: %s", tool.Name, tool.Description),
				Timestamp:   time.Now(),
			})
		}

		// 2. Audit empty descriptions
		if tool.Description == "" {
			findings = append(findings, model.Finding{
				RuleID:      "MCP-SEC-015",
				Title:       "Tool Missing Description",
				Severity:    model.SeverityLow,
				Description: fmt.Sprintf("MCP tool %q has no description field. This makes it hard to review or analyze its runtime context.", tool.Name),
				Remediation: "Add a clear, descriptive documentation string to the tool's declaration.",
				FilePath:    targetPath,
				LineNumber:  1,
				MatchString: fmt.Sprintf("Tool: %s", tool.Name),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}
