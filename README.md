# mcpguard

> The security linter and watchdog for Model Context Protocol (MCP) servers — delivered as a fast, single-binary Go tool from local dev to CI/CD.

`mcpguard` audits MCP configurations and codebases to identify security risks such as excessive permissions, raw shell execution, Unicode obfuscation/homoglyph attacks, runtime tool schema drift, and exposed credentials using both static analysis and a rule matching engine.

---

## Key Features

- **Static Analyzer**: Scans configurations (`claude_desktop_config.json`, `mcp.json`) and source directories without execution.
- **Entropy-Based Secret Detection**: Employs Shannon Entropy calculations combined with pattern matchers to detect credentials, tokens, and private keys.
- **Obfuscation Detection**: Automatically flags zero-width characters, homoglyphs, and directional overrides.
- **Ignore Rules**: Robust False-Positive suppression using standard ignore patterns via a `.mcpguard-ignore` file.
- **Multiple Output Formats**: Export findings directly to JSON, Markdown tables, HTML dashboards, or SARIF 2.1.0 for GitHub Code Scanning.
- **Runtime Probing**: Connects to stdio MCP servers and detects runtime tool metadata issues or schema mutations.
- **Guard Proxy**: Runs as a local stdio MCP proxy in front of an upstream MCP server and blocks prompt injection, tool poisoning, and rug-pull schema drift.
- **CI Integrations**: Includes GitHub Actions, GitLab CI, and pre-commit hook metadata.
- **Zero Telemetry / Privacy-First**: 100% self-contained. Scans are computed purely locally.

---

## Installation

Ensure you have Go 1.23+ installed, then build the executable from source:

```bash
go build -o mcpguard ./cmd/mcpguard
```

Release builds can stamp version metadata:

```bash
go build -o mcpguard \
  -ldflags "-X mcpguard/internal/cli.Version=0.1.0 -X mcpguard/internal/cli.Commit=$(git rev-parse --short HEAD) -X mcpguard/internal/cli.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./cmd/mcpguard
```

To run tests:

```bash
go test ./...
```

---

## CLI Usage Reference

The primary command is `scan`, which checks the target directory against built-in and custom rule sets:

```bash
./mcpguard scan [path] [flags]
```

The dynamic prober can connect to a stdio MCP server defined in a Claude Desktop config:

```bash
./mcpguard probe --config claude_desktop_config.json --server filesystem --format json
```

Run the guard proxy in front of an upstream stdio MCP server:

```bash
./mcpguard proxy --upstream-command node --upstream-arg /path/to/server.js --proxy-report mcpguard-proxy.jsonl
```

Or proxy a server from a Claude Desktop config:

```bash
./mcpguard proxy --config claude_desktop_config.json --server filesystem --proxy-report mcpguard-proxy.jsonl
```

The proxy always applies local regex detection. Optional Apple Foundation Models classification can be enabled in a platform-specific build; see `docs/proxy.md`.
For measuring classifier quality and false-positive risk, see `docs/foundation-model-evals.md`.

Print build metadata with either command:

```bash
./mcpguard version
./mcpguard --version
```

### Flags

| Flag | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `--rules-dir` | string | Path to a directory containing custom YAML rules. | `""` (Built-in only) |
| `--format` | string | Output report format: `json`, `markdown`, `html`, `sarif`. | `"markdown"` |
| `--output` | string | Output file path. Writes to standard output if omitted. | `""` (Stdout) |
| `--fail-severity` | string | Minimum severity to trigger non-zero exit code (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`). | `"HIGH"` |

### Exit Codes

- `0`: Scan finished cleanly with no rules matching or exceeding the `--fail-severity` threshold.
- `1`: Scan completed and found vulnerabilities matching or exceeding the threshold.
- `2`: System execution error (e.g. invalid arguments, unreadable configurations).

---

## Writing Custom Rules

You can extend `mcpguard` by adding custom rules in YAML files. Place them in a folder and supply it using the `--rules-dir` flag:

```yaml
id: MCP-SEC-101
title: "Unsafe Command Executable"
severity: CRITICAL
description: "Flags direct invocation of system-level utilities in tool configurations."
remediation: "Ensure the tool uses dedicated client adapters instead of raw host binaries."
references:
  - "https://owasp.org/www-project-top-ten/"
tags:
  - config
  - command-execution
matchers:
  - type: config_key
    config_keys: ["command"]
    pattern: "^(bash|sh|cmd|powershell|pwsh)(\\.exe)?$"
```

Custom rules with the same ID as a built-in rule replace the built-in rule deterministically. This lets teams tune policy locally without duplicate findings.

---

## Ignore/Suppression Rules (`.mcpguard-ignore`)

Create a `.mcpguard-ignore` file at the root of your scanned directory to suppress false positives or accepted risks:

```text
# Ignore a file completely
test/mock_config.json

# Ignore a specific rule in a specific file
src/insecure_script.py:MCP-SEC-008

# Ignore a rule globally
id:MCP-SEC-002
```

See `.mcpguard-ignore.example` for a starter file.

---

## CI/CD Pipeline Integration

### GitHub Actions

Save the following definition to execute a scan on pull requests and view findings under Security Alerts:

```yaml
name: MCP Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Codebase
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build Scanner
        run: go build -o mcpguard ./cmd/mcpguard

      - name: Execute Security Scan
        run: ./mcpguard scan . --format sarif --output results.sarif --fail-severity HIGH

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

This repository also includes:

- `action.yml` for using mcpguard as a composite GitHub Action.
- `.github/workflows/ci.yml` for project CI.
- `.gitlab-ci.yml` for GitLab CI.
- `.pre-commit-hooks.yaml` for pre-commit integration.

---

## Development

Useful checks before opening a pull request:

```bash
gofmt -w ./cmd ./internal ./tests
go test ./...
go build ./cmd/mcpguard
```

The scanner is privacy-first: scans run locally and do not call external APIs. Dependency downloads may happen during normal Go builds or CI setup.
