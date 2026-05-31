# MCP Guard Proxy

`mcpguard proxy` runs as a local stdio MCP server that forwards traffic to an upstream stdio MCP server. MCP clients connect to the local proxy instead of connecting directly to the upstream server.

```
MCP client <-> mcpguard proxy <-> upstream stdio MCP server
```

The proxy blocks and reports:

- Prompt injection in `tools/call` arguments and tool results.
- Tool poisoning in `tools/list` tool names, titles, descriptions, and schemas.
- Rug-pull behavior when the upstream tool list or tool schemas change after the first baseline `tools/list`.

Blocked requests and responses return JSON-RPC error code `-32090`. Findings are written as JSON lines to stderr and, when configured, to `--proxy-report`.

## Usage

Proxy an explicit command:

```bash
mcpguard proxy \
  --upstream-command node \
  --upstream-arg /path/to/server.js \
  --proxy-report mcpguard-proxy.jsonl
```

Proxy a server from a Claude Desktop config:

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

## Detection

Regex detection is always enabled and runs locally without external API calls.

Foundation Models classification is optional because `github.com/blacktop/go-foundationmodels` is macOS-specific and requires Apple Foundation Models support, Apple Intelligence, CGO, and a newer Go toolchain than the cross-platform default build. To build an Apple-only binary with this classifier:

```bash
go get github.com/blacktop/go-foundationmodels@v0.1.8
CGO_ENABLED=1 go build -tags foundationmodels -o mcpguard ./cmd/mcpguard
```

Then run:

```bash
mcpguard proxy --foundation-models --config claude_desktop_config.json --server filesystem
```

The model classifier is additive: regex findings block immediately, and model findings block when the local Foundation Models classifier returns `BLOCK`.

See `foundation-model-evals.md` for the eval methodology used to measure blocking effectiveness, false positives, and latency before enabling Foundation Models in production.
