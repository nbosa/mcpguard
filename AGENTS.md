
# mcpguard — MCP Security Scanner (Go Stack Architecture Brief)

> **Note (v0.2):** This file is retained as a design history / vision
> document. The current v0.2 scope is **stdio MCP guard proxy only** —
> see the top-level `README.md` and `docs/proxy.md` for what is actually
> built and shipped. The static analyzer, dynamic prober, rules engine,
> and reporting layer described below were removed in the v0.2 focus
> refactor in favour of simplicity and correctness. The classifier
> plugin system (see "Plugin strategy" below) survives as the extension
> point used today by `regex` and `foundation-models`.

You are a senior Go architect and security engineer with deep expertise in
AI/LLM security, Model Context Protocol (MCP), DevSecOps, and security tooling.
Your task is to design a production-ready, open-source architecture for
**mcpguard** — a dedicated MCP security scanner implemented in Go.

---

## Project Vision

> "The security linter + runtime watchdog for MCP servers —
>  delivered as a fast, single-binary Go tool from local dev to CI/CD."

mcpguard must be:
- Fully open-source and self-hosted; no telemetry, no external API calls during scan.
- Delivered as a static Go binary for Linux, macOS, and Windows.
- Usable as a CLI tool, CI/CD pipeline step, pre-commit hook, and optional long-running daemon.
- Extensible via community-contributed YAML rules and Go plugins/adapters where appropriate.
- Aligned with MCPLIB-31 attack taxonomy and OWASP MCP Top 10.

---

## Threat Landscape Context

MCP servers are privileged integration points between LLM agents and external tools/resources.
Known and relevant attack vectors include:
- Tool poisoning via hidden instructions in tool descriptions or metadata.
- Rug pull attacks where tool schemas change after trust establishment.
- Unauthorized tool registration or tool list manipulation.
- Excessive permissions such as filesystem, shell, or unrestricted network access.
- Missing auth / weak OAuth / public exposure of MCP endpoints.
- Supply chain attacks via malicious packages or dependencies.
- Cross-origin escalation and context leakage across connected servers.
- Secret leakage from source code, config files, and environment files.
- Transport insecurity across stdio, SSE, and streamable HTTP.
- Schema drift and runtime behavior changes after initial approval.

The scanner must support a broad taxonomy of 31 attack methods, mapped to
standardized rule IDs and remediation guidance.

---

## Core Components to Design

### 1. Static Analyzer
Analyze MCP server source code and configuration files without executing the server.

Must handle:
- Config formats: `claude_desktop_config.json`, `mcp.json`, Docker Compose YAML, `.env`, shell exports.
- Tool definition scanning: detect prompt injection, Unicode obfuscation, invisible characters, and suspicious descriptions.
- Secret detection: regex + entropy analysis for API keys, JWTs, private keys, tokens, and credentials.
- Permission surface auditing: identify shell execution, arbitrary filesystem access, and unrestricted network calls.
- Supply chain checks: detect risky package names, suspicious dependencies, and known malicious versions.
- Implementation must support parsing Go, Node.js, Python, and generic YAML/JSON configs.

### 2. Dynamic Prober
Connect to a live MCP server and test runtime behavior.

Must handle:
- Transport support using the official MCP Go SDK:
  - stdio transport
  - SSE / EventSource transport
  - streamable HTTP transport
- Rug pull detection: snapshot tool schemas at connect-time and diff after interactions.
- Tool poisoning probes: crafted payloads to surface hidden instructions or suspicious behavior.
- Auth bypass testing: attempt unauthenticated or weakly authenticated access.
- Cross-origin escalation testing: detect leakage between connected servers or sessions.
- Concurrent probing across multiple targets using goroutines and context cancellation.

### 3. Rules Engine
Core logic that maps findings to standard frameworks.

Must handle:
- YAML-based rule definitions.
- Rule schema fields: id, title, severity, description, remediation, references, tags, matchers.
- Severity levels: CRITICAL / HIGH / MEDIUM / LOW / INFO.
- Matchers: regex, file path, config key, AST pattern, schema pattern, runtime event pattern.
- False-positive suppression via `.mcpguard-ignore`.
- Loading built-in and custom rules from directories.
- Deterministic rule conflict resolution and deduplication.

### 4. Reporting and Integration
Output and delivery layer.

Must handle:
- Output formats: JSON, Markdown, HTML, SARIF 2.1.0.
- GitHub Actions integration via composite action.
- GitLab CI template.
- Pre-commit hook.
- Exit codes: 0 clean, 1 findings, 2 scan error.
- Optional machine-readable output for downstream automations.

---

## Technology Stack

Use Go-first, production-friendly libraries and patterns:

```text
Language:       Go 1.23+
CLI framework:   Cobra or Cobra+Viper, or a minimal custom CLI if justified
Config:         encoding/json, gopkg.in/yaml.v3, env parsing helpers
Validation:     custom validators and typed structs
Concurrency:    goroutines, channels, errgroup, context cancellation
MCP SDK:        official github.com/modelcontextprotocol/go-sdk
Parsing:        tree-sitter Go bindings or lightweight AST/custom parsers where appropriate
Reporting:      templates/html, JSON encoding, SARIF generation
Testing:        go test, fuzzing, table-driven tests, integration tests with DVMCP
Packaging:      static binary, Docker, Homebrew/Scoop releases
Docs:           MkDocs or Hugo, generated from repo docs
CI:             GitHub Actions
```

---

## Repository Structure

```text
mcpguard/
├── cmd/
│   └── mcpguard/
│       └── main.go
├── internal/
│   ├── cli/
│   ├── config/
│   ├── static/
│   │   ├── parser/
│   │   ├── scanner/
│   │   └── secrets/
│   ├── dynamic/
│   │   ├── client/
│   │   ├── prober/
│   │   └── rugpull/
│   ├── rules/
│   │   ├── model/
│   │   ├── engine/
│   │   └── builtin/
│   ├── report/
│   └── util/
├── pkg/                     # optional public packages if needed
├── tests/
│   ├── fixtures/
│   ├── integration/
│   └── fuzz/
├── docs/
├── .github/workflows/
├── action.yml
├── go.mod
├── go.sum
└── .mcpguard-ignore.example
```

---

## MVP Delivery Phases

### Phase 1 — Static Core
Deliver:
- Config parser for MCP config formats and common project layouts.
- Tool scanner for prompt injection, Unicode obfuscation, and suspicious instructions.
- Secret detector with regex + entropy scoring.
- CLI command: `mcpguard scan <path>`.
- JSON and Markdown reports.
- Table-driven unit tests with malicious fixtures.

### Phase 2 — Rules Engine
Deliver:
- Typed rule structs and YAML loader.
- Built-in rules for top-priority MCPLIB attacks.
- Ignore/suppression file parsing.
- Severity scoring, deduplication, and conflict resolution.
- HTML report generation.

### Phase 3 — Dynamic Prober and CI/CD
Deliver:
- MCP client using official Go SDK.
- Live probing over stdio/SSE/HTTP.
- Rug pull detection via schema snapshots and diffs.
- GitHub Actions and SARIF export.
- Pre-commit integration.
- Documentation and release pipeline for static binaries.

---

## Design Constraints

1. Privacy-first: no telemetry, no third-party API calls during scans.
2. Fast: static scan of a single config or repo should complete in under 2 seconds for common cases.
3. Single-binary distribution: `go build` or `goreleaser` output must be easy to install.
4. Extensible: adding a rule should not require recompiling the binary.
5. Deterministic: repeated scans on the same input should produce stable results.
6. Secure-by-default: deny ambiguous behavior unless explicitly allowed.
7. Cross-platform: Linux, macOS, Windows support.
8. Support real-world MCP servers written in Go, Python, Node.js, and mixed environments.

---

## Your Task

Produce the following:

1. Detailed architecture for each component: static analyzer, dynamic prober,
   rules engine, and reporting/integration.
2. Go data model design for rule definitions and findings.
3. A complete YAML rule schema design using Go structs and validation logic.
4. A data flow diagram for `mcpguard scan .` from CLI input to exit code.
5. Key design decisions and tradeoffs:
   - CLI framework choice.
   - Plugin strategy for custom rules/scanners.
   - Concurrency model for probing.
   - Handling multiple MCP server implementation languages.
   - Conflict resolution when multiple rules match the same finding.
6. Project risk register with mitigation strategies.
7. Skeleton code for:
   - `cmd/mcpguard/main.go`
   - `internal/rules/model/*.go`
   - `internal/rules/engine/*.go`
   - `internal/cli/*.go`
   with idiomatic Go interfaces, structs, and doc comments.

Be concrete. Prefer implementation choices over abstract recommendations.
Where tradeoffs exist, present both options and recommend one.
