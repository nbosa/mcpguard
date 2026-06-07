# MCP Guard Proxy

`mcpguard proxy` runs as a local stdio MCP server that forwards traffic to
an upstream stdio MCP server. MCP clients connect to the local proxy
instead of connecting directly to the upstream server.

```
MCP client <-> mcpguard proxy <-> upstream stdio MCP server
```

The proxy blocks and reports:

- **Prompt injection** in `tools/call` arguments and tool results.
- **Tool poisoning** in `tools/list` tool names, titles, descriptions,
  and schemas.
- **Rug-pull** behavior when the upstream tool list or tool schemas change
  after the first baseline `tools/list`.

Blocked requests and responses return JSON-RPC error code `-32090`.
Findings are written as JSON lines to stderr and, when configured, to
`--proxy-report`.

## Usage

Proxy an explicit command:

```bash
mcpguard proxy \
  --upstream-command node \
  --upstream-arg /path/to/server.js \
  --proxy-report mcpguard-proxy.jsonl
```

Proxy a server from a Claude Desktop / mcp.json style config:

```bash
mcpguard proxy \
  --config claude_desktop_config.json \
  --server filesystem \
  --proxy-report mcpguard-proxy.jsonl
```

Claude Desktop-style client config can point to the local proxy:

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

## Classifiers

The proxy is classifier-agnostic. By default it applies the `regex`
classifier (deterministic local signatures).

Available classifiers:

- `regex` — always on, no setup.
- `foundation-models` — Apple Foundation Models (macOS-only, build with
  `CGO_ENABLED=1 go build -tags foundationmodels`).

List and inspect the ones built into your binary:

```bash
mcpguard list-classifiers
```

Apply multiple classifiers:

```bash
mcpguard proxy \
  --upstream-command node \
  --upstream-arg server.js \
  --classifier regex \
  --classifier foundation-models
```

## Live HTML viewer

`mcpguard view` tails the proxy's JSONL report and serves a real-time
HTML viewer over HTTP. Open the printed URL in any browser to see
findings stream in as the proxy writes them. The UI is a single
embedded HTML page (no JS build, no external assets, dark mode by
default) and supports:

- Severity colour-coding (CRITICAL → INFO).
- Pause / clear / autoscroll controls.
- Real-time SSE push with replay of the last 1,000 events for
  late-connecting clients.
- Multiple browser tabs sharing the same view server.

See `README.md` and the `mcpguard view --help` output for the full
flag list.

## Concurrency model

The proxy uses two goroutines:

1. A client reader that inspects each client request, forwards it to the
   upstream, and waits for the matching response.
2. An upstream demuxer that routes responses to pending request channels
   or forwards unsolicited messages (notifications) directly to the
   client.

This allows the client to pipeline multiple requests without proxy-side
serialization. Each request has its own per-request timeout (default 30s,
override with `--timeout`).

## Signal handling

`SIGINT` and `SIGTERM` cancel the proxy's context, which:

1. Closes the upstream's stdin pipe (so it sees EOF and shuts down).
2. Sends `SIGKILL` if the upstream does not exit within the
   process-kill window.
3. Flushes the reporter.

On graceful shutdown the proxy exits with status 0.

## Limits and robustness

- Each JSON-RPC line is capped at 8 MiB (`--max-line-size` is fixed).
- After `--max-parse-errors` consecutive malformed lines from either side
  the proxy aborts (default 10). This guards against infinite loops on
  persistent bad data.
- Per-request timeout is configurable; on timeout a CRITICAL finding is
  emitted and the pending request is dropped.

## Detection

See `README.md` for the threat-type table and JSONL finding schema.

For the Apple Foundation Models classifier eval methodology, see the
historical `docs/foundation-model-evals.md` content (kept for reference,
not regenerated in this refactor).
