# mcpguard

> A stdio MCP guard proxy — local, single-binary, with a pluggable threat-classifier system.

`mcpguard proxy` sits between a local MCP client and an upstream stdio MCP
server. It inspects every `tools/call` request and `tools/list` response,
blocks prompt injection, tool poisoning, and rug-pull schema drift, and
writes findings as JSONL.

Built-in classifiers:

- **`regex`** — deterministic local regex signatures (always on).
- **`foundation-models`** — Apple Foundation Models classifier (macOS only,
  opt-in via `-tags foundationmodels`).

New classifiers register themselves by implementing the `Classifier` interface
in `internal/proxy/classifier` and adding their `init()` to the binary.

---

## Install

```bash
go install github.com/nbosa/mcpguard/cmd/mcpguard@latest
```

Or build from source:

```bash
go build -o mcpguard ./cmd/mcpguard
```

Release builds stamp version metadata:

```bash
go build -o mcpguard \
  -ldflags "-X mcpguard/internal/cli.Version=0.1.0 -X mcpguard/internal/cli.Commit=$(git rev-parse --short HEAD) -X mcpguard/internal/cli.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./cmd/mcpguard
```

To enable the Apple Foundation Models classifier:

```bash
CGO_ENABLED=1 go build -tags foundationmodels -o mcpguard ./cmd/mcpguard
```

---

## Usage

```text
mcpguard [command]

Available Commands:
  completion        Generate the autocompletion script for the specified shell
  help              Help about any command
  list-classifiers  List registered threat classifiers and their availability
  proxy             Run a stdio MCP guard proxy in front of an upstream MCP server
  version           Print mcpguard version information
  view              Live HTML viewer for a proxy JSONL report
```

### `mcpguard proxy`

Run a stdio MCP guard proxy. The proxy reads JSON-RPC requests from stdin,
inspects them, forwards them to the upstream server, inspects responses,
and writes the filtered stream to stdout. Blocked requests/responses
return JSON-RPC error code `-32090`.

```bash
# Proxy an explicit command
mcpguard proxy \
  --upstream-command node \
  --upstream-arg /path/to/server.js \
  --proxy-report mcpguard-proxy.jsonl

# Or load a server from a Claude Desktop / mcp.json style config
mcpguard proxy \
  --config claude_desktop_config.json \
  --server filesystem \
  --proxy-report mcpguard-proxy.jsonl
```

#### Flags

| Flag | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `--upstream-command` | string | Upstream stdio MCP server command | `""` |
| `--upstream-arg` | string (repeatable) | Argument to pass to `--upstream-command` | `[]` |
| `--upstream-env` | string (repeatable) | Env var in `KEY=VALUE` form | `[]` |
| `--upstream-cwd` | string | Working directory for the upstream process | `""` (inherits) |
| `--proxy-report` | string | Optional JSONL file for findings | `""` (stderr only) |
| `--classifier` | string (repeatable) | Classifier to apply | `regex` |
| `--timeout` | int | Per-request upstream timeout (ms) | `30000` |
| `--max-parse-errors` | int | Abort after this many parse failures | `10` |
| `--config` | string | Path to a Claude Desktop / mcp.json style config | `""` |
| `--server` | string | Server name to proxy from `--config` | `""` |

#### Claude Desktop integration

Point Claude Desktop at the local proxy instead of the upstream server:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "/usr/local/bin/mcpguard",
      "args": [
        "proxy",
        "--config",
        "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json",
        "--server",
        "filesystem",
        "--proxy-report",
        "/tmp/mcpguard-proxy.jsonl"
      ]
    }
  }
}
```

#### Signal handling

`mcpguard proxy` translates `SIGINT` and `SIGTERM` into a clean shutdown:
the upstream process is killed, the report is flushed, and the proxy exits
with status 0.

### `mcpguard list-classifiers`

Lists the registered classifiers and whether they are available on this host
and in this build.

```bash
$ mcpguard list-classifiers
Registered classifiers:
  foundation-models — unavailable: rebuild on macOS with CGO_ENABLED=1 and -tags foundationmodels
    Local Apple Foundation Models classifier (requires macOS + -tags foundationmodels build).
  regex — available
    Deterministic local regex signatures for prompt injection and tool poisoning.
```

### `mcpguard view`

Tails a JSONL report file (the one written by `mcpguard proxy --proxy-report
PATH`) and serves a real-time HTML viewer over HTTP. New findings appear in
the browser as the proxy writes them. The HTML is embedded in the binary —
no JavaScript build step, no external assets, single-file dark-mode UI.

```bash
# In one terminal: run the proxy and write findings to a file
mcpguard proxy --config claude_desktop_config.json --server filesystem \
  --proxy-report /tmp/mcpguard.jsonl

# In another terminal: open the live viewer
mcpguard view --report /tmp/mcpguard.jsonl
# → http://127.0.0.1:7337 (open in any browser)
```

#### Flags

| Flag | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `--report` | string | Path to the proxy JSONL report file (required) | `""` |
| `--port` | int | HTTP listen port | `7337` |
| `--no-browser` | bool | Suppress the open-browser hint | `false` |

#### Endpoints

| Path | Description |
| :--- | :--- |
| `GET /` | Single-page HTML viewer (embedded) |
| `GET /events` | SSE stream of findings (see schema below) |
| `GET /healthz` | `200 ok` if the server is up |

#### Behavior

- **Replay on connect**: a client connecting after the proxy has already
  written findings will receive the last 1,000 events first, then live
  updates. This is bounded in memory and bounded by the SSEBufferSize per
  client.
- **File truncation**: when the proxy restarts and recreates the report
  file, the view detects the truncation and resets its offset.
- **Polling**: 200ms by default. Configurable via the internal package
  (`view.PollInterval`).
- **Multiple clients**: each connected browser tab is independent;
  disconnect/reconnect at will.

### `mcpguard version`

Prints build metadata (version, commit, build date).

---

## Detection

The proxy applies the configured classifiers to:

- Client `tools/call` request `params` (prompt injection check).
- Upstream `tools/list` response `result` (tool poisoning + rug-pull check).
- Upstream `tools/call` response `result` (prompt injection check).

A request is blocked when **any** classifier returns a finding. The
`--classifier` flag accepts a list (repeatable); the first valid name is
used as the default.

Blocked requests/responses always return JSON-RPC error code `-32090`:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32090,
    "message": "mcpguard blocked request: Attempts to override prior/system instructions."
  }
}
```

Each finding is also written as a JSONL line to stderr and (when
configured) to `--proxy-report`:

```json
{
  "type": "prompt_injection",
  "severity": "HIGH",
  "reason": "Attempts to override prior/system instructions.",
  "location": "client.tools/call.params",
  "evidence": "ignore all previous instructions",
  "classifier": "regex",
  "request_id": "1",
  "direction": "client_to_upstream",
  "blocked": true,
  "timestamp": "2026-06-07T04:07:29Z"
}
```

### Threat types

| Type | Severity default | Where |
| :--- | :--- | :--- |
| `prompt_injection` | HIGH | `client.tools/call.params` and `upstream.tools/call.result` |
| `tool_poisoning` | HIGH | `upstream.tools/list.result` |
| `rug_pull` | CRITICAL | `upstream.tools/list.result` (schema drift vs baseline) |

---

## Writing a custom classifier

A classifier is any type that implements the `Classifier` interface in
`internal/proxy/classifier`:

```go
type Classifier interface {
    Name() string
    Description() string
    Available() error
    Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error)
}
```

Register it from your package's `init()`:

```go
package myclassifier

import "mcpguard/internal/proxy/classifier"

type myClassifier struct{}

func (c *myClassifier) Name() string { return "my-detector" }
func (c *myClassifier) Description() string { return "..." }
func (c *myClassifier) Available() error { return nil }
func (c *myClassifier) Classify(ctx context.Context, threat classifier.ThreatType, text, location string) (*classifier.Finding, error) {
    if /* detect something */ {
        return &classifier.Finding{
            Type:       threat,
            Severity:   classifier.SeverityHigh,
            Reason:     "...",
            Location:   location,
            Evidence:   "...",
            Classifier: c.Name(),
            Blocked:    true,
            Timestamp:  time.Now(),
        }, nil
    }
    return nil, nil
}

func init() {
    classifier.Default().MustRegister(&myClassifier{})
}
```

Import the package from `cmd/mcpguard/main.go` and rebuild.

---

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

---

## Project status

`mcpguard` v0.2 is a focused, single-purpose tool. It does exactly one
thing: a stdio MCP guard proxy. Earlier scope (static scanner, dynamic
prober, SARIF reports) was removed in favour of simplicity and correctness.
