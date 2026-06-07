// Command mcpguard is a stdio MCP guard proxy. It forwards JSON-RPC traffic
// between a local MCP client and an upstream stdio MCP server, applying
// configurable threat classifiers and detecting tool-list drift (rug pull).
//
// Usage:
//
//	mcpguard proxy --upstream-command node --upstream-arg /path/to/server.js
//	mcpguard list-classifiers
//	mcpguard version
package main

import "mcpguard/internal/cli"

func main() {
	cli.Execute()
}
