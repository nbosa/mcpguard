# Architectural Design

`mcpguard` is a fast, security-first command-line tool implemented in Go. It operates without external runtime dependencies or internet connectivity, ensuring data privacy and local-only scanning behavior.

---

## Architecture Blueprint

```
                    ┌────────────────────────┐
                    │      mcpguard CLI      │
                    └───────────┬────────────┘
                                │
          ┌─────────────────────┴─────────────────────┐
          ▼                                           ▼
┌──────────────────┐                        ┌──────────────────┐
│ Static Analyzer  │                        │  Dynamic Prober  │
│ (Local Code/Cfg) │                        │ (Live Probe/SDK) │
└─────────┬────────┘                        └─────────┬────────┘
          │                                           │
          │             ┌──────────────┐              │
          └────────────►│ Rules Engine ◄──────────────┘
                        └──────┬───────┘
                               │ (Suppressions via Ignore List)
                               ▼
                        ┌──────────────┐
                        │ Reporter API │
                        └──────┬───────┘
                               ▼
                 [JSON / MD / HTML / SARIF]

MCP client ──stdio──► Guard Proxy ──stdio──► Upstream MCP server
                         │
                         └── regex + optional Foundation Models detector
```

---

## Core Components

### 1. Static Analyzer
The Static Analyzer walks the target directories recursively and applies non-executable inspections:
- **Configuration Parser**: Parses JSON/YAML configuration formats (e.g. Claude Desktop config structure or custom `mcp.json`). It analyzes server execution commands, arguments, and environment variables to flag insecure command lines or raw shell processes.
- **Shannon Entropy Secret Detector**: Scans string literals and variable declarations for high-entropy sequences (e.g. API keys, base64 strings). It uses the Shannon Entropy calculation formula:
  $$H(X) = - \sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
  Strings with length $>12$ and entropy values $\ge 4.0$ are flagged as potential credentials.
- **Unicode Obfuscation Scanner**: Looks for non-ASCII characters, invisible unicode control characters (such as directional overrides `\x{202A}-\x{202E}` or zero-width spaces `\x{200B}-\x{200D}`) to prevent supply chain and review bypass attacks.

### 2. Dynamic Prober
The Dynamic Prober interfaces with live MCP servers over JSON-RPC stdio. SSE and streamable HTTP transports remain extension points behind the same session/prober boundary.
- **Rug Pull Detector**: Takes structural snapshots of registered tools before and after test actions to identify unauthorized schema additions or changes.
- **Fuzzing and Injections**: Employs prompt injection payloads and extreme value test vectors to observe unexpected behavior or context leaks.

### 3. Guard Proxy
The Guard Proxy runs as a local stdio MCP server and forwards JSON-RPC traffic to an upstream stdio MCP server.
- **Request Filtering**: Blocks suspicious `tools/call` arguments before they reach the upstream server.
- **Response Filtering**: Blocks poisoned tool metadata or prompt-injection text in tool results before it reaches the client.
- **Rug Pull Enforcement**: Stores the first `tools/list` snapshot as baseline and blocks later schema/list drift.
- **Detection Stack**: Regex runs in every build. Apple Foundation Models classification is available behind the optional `foundationmodels` build tag on supported macOS systems.

### 4. Rules Engine
The Rules Engine parses YAML-based rule manifests, validates their semantic structure, and executes them against identified target blocks.
- **Ignore List**: Evaluates a `.mcpguard-ignore` file path matching pattern list to suppress user-suppressed warnings.
- **Deduplication and Conflict Resolution**: Consolidates matches targeting the exact same line numbers and file paths by ranking their severity levels and reporting the highest risk.

---

## `mcpguard scan .` Data Flow

```
CLI args/flags
  -> validate format and fail severity
  -> load built-in rules
  -> overlay custom YAML rules by deterministic rule ID replacement
  -> load .mcpguard-ignore from the target root
  -> walk target files while skipping hidden, generated, binary, and oversized files
  -> parse JSON/YAML configs and run config_key matchers
  -> run file_path and regex matchers line-by-line
  -> run built-in secret entropy and Unicode obfuscation detectors
  -> suppress ignored findings
  -> deduplicate same rule/file/line, keeping the highest severity
  -> render JSON, Markdown, HTML, or SARIF
  -> exit 0 for clean, 1 for threshold findings, 2 for execution errors
```

## Design Decisions

- **CLI framework**: Cobra is used because subcommands, required flags, and CI-friendly help output are already needed. The command handlers return typed errors rather than calling `os.Exit`, keeping behavior testable.
- **Custom extensions**: YAML rules are the primary plugin surface. If a custom rule reuses a built-in rule ID, it replaces the built-in deterministically, which allows local policy overrides without duplicate findings.
- **Static analysis strategy**: The scanner favors lightweight parsers and structured JSON/YAML traversal over language-specific ASTs for the MVP. Language AST adapters can be added behind the same matcher model when a rule requires semantic parsing.
- **Dynamic probing strategy**: Probes run through a cancellable context and a session abstraction. Each transport should implement the same small client operations: initialize, list tools, and call tool.
- **Conflict resolution**: Findings are keyed by rule ID, file path, and line. Duplicate matches keep the highest severity and preserve first-seen report order.

## Risk Register

| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| Regex-based rules can produce false positives. | Users may ignore noisy results. | Support `.mcpguard-ignore`, severity thresholds, file type scoping, and custom rule overrides. |
| Dynamic probing may execute side-effecting tools. | Live systems could be modified. | Current probes list tools and only call the explicit `trigger_rugpull` fixture hook. Future active probes should require opt-in flags. |
| Large repos can contain binary/generated files. | Slow scans and unreadable findings. | Skip common generated directories, binary extensions, hidden files, and files over 5 MiB. |
| MCP transport behavior evolves. | Prober compatibility may drift. | Keep transport code isolated in `internal/dynamic/client` and cover protocol fixtures in integration tests. |
| Secret detection can leak sensitive values in reports. | Reports may expose credentials. | Redact structured sensitive values and report generic masked matches for entropy findings. |
