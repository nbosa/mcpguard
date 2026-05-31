package model

import (
	"testing"
)

func TestRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: Rule{
				ID:          "MCP-SEC-001",
				Title:       "Test Rule",
				Severity:    SeverityHigh,
				Description: "A security check description",
				Remediation: "Fix it",
				Matchers: []Matcher{
					{
						Type:    MatcherRegex,
						Pattern: `[a-z]+`,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing id",
			rule: Rule{
				Title:       "Test Rule",
				Severity:    SeverityHigh,
				Description: "A security check description",
				Remediation: "Fix it",
				Matchers: []Matcher{
					{
						Type:    MatcherRegex,
						Pattern: `[a-z]+`,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid severity",
			rule: Rule{
				ID:          "MCP-SEC-001",
				Title:       "Test Rule",
				Severity:    Severity("INVALID"),
				Description: "A security check description",
				Remediation: "Fix it",
				Matchers: []Matcher{
					{
						Type:    MatcherRegex,
						Pattern: `[a-z]+`,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing matchers",
			rule: Rule{
				ID:          "MCP-SEC-001",
				Title:       "Test Rule",
				Severity:    SeverityHigh,
				Description: "A security check description",
				Remediation: "Fix it",
			},
			wantErr: true,
		},
		{
			name: "invalid regex pattern",
			rule: Rule{
				ID:          "MCP-SEC-001",
				Title:       "Test Rule",
				Severity:    SeverityHigh,
				Description: "A security check description",
				Remediation: "Fix it",
				Matchers: []Matcher{
					{
						Type:    MatcherRegex,
						Pattern: `[a-z`, // unclosed bracket
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Rule.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
