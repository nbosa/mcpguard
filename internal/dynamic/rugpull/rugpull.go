package rugpull

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"mcpguard/internal/dynamic/client"
	"mcpguard/internal/rules/model"
)

// TakeSchemaSnapshot lists all tools from the server and serializes their input schemas for snapshotting.
func TakeSchemaSnapshot(ctx context.Context, session *client.ClientSession) (map[string]string, error) {
	tools, err := session.ListTools(ctx)
	if err != nil {
		return nil, err
	}

	snapshot := make(map[string]string)
	for _, tool := range tools {
		schemaBytes, err := json.Marshal(tool.InputSchema)
		if err != nil {
			snapshot[tool.Name] = fmt.Sprintf("invalid_schema_serialization: %v", err)
			continue
		}
		snapshot[tool.Name] = string(schemaBytes)
	}

	return snapshot, nil
}

// DiffSchemas compares two snapshots and generates findings for deleted, added, or modified tool schemas.
func DiffSchemas(before, after map[string]string, targetPath string) []model.Finding {
	var findings []model.Finding

	// Check for deleted or modified tools
	for name, beforeSchema := range before {
		afterSchema, exists := after[name]
		if !exists {
			findings = append(findings, model.Finding{
				RuleID:      "MCP-SEC-030",
				Title:       "Rug Pull Attack: Tool Deregistered",
				Severity:    model.SeverityCritical,
				Description: fmt.Sprintf("MCP tool %q was unregistered or removed during runtime session execution.", name),
				Remediation: "Ensure server does not modify its exposed tool lists dynamically after connection setup.",
				FilePath:    targetPath,
				LineNumber:  1,
				MatchString: fmt.Sprintf("Tool removed: %s", name),
				Timestamp:   time.Now(),
			})
			continue
		}

		if beforeSchema != afterSchema {
			findings = append(findings, model.Finding{
				RuleID:      "MCP-SEC-030",
				Title:       "Rug Pull Attack: Tool Schema Mutated",
				Severity:    model.SeverityCritical,
				Description: fmt.Sprintf("MCP tool %q has modified its input parameter schema dynamically at runtime. Before: %s. After: %s.", name, beforeSchema, afterSchema),
				Remediation: "Validate that tool schemas are statically declared and remain immutable during runtime connection.",
				FilePath:    targetPath,
				LineNumber:  1,
				MatchString: fmt.Sprintf("Tool: %s, Schema changed", name),
				Timestamp:   time.Now(),
			})
		}
	}

	// Check for newly added tools
	for name := range after {
		if _, exists := before[name]; !exists {
			findings = append(findings, model.Finding{
				RuleID:      "MCP-SEC-030",
				Title:       "Rug Pull Attack: Dynamic Tool Registered",
				Severity:    model.SeverityHigh,
				Description: fmt.Sprintf("MCP tool %q was registered dynamically at runtime after initial connection setup.", name),
				Remediation: "Verify the server does not register new tools dynamically without restarting the session.",
				FilePath:    targetPath,
				LineNumber:  1,
				MatchString: fmt.Sprintf("New tool registered: %s", name),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}
