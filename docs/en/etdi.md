# The ETDI format — mcp-guard v0.6.0

**ETDI** — *Extended Tool Description & Integrity* — is the descriptor format
mcp-guard pins.

The idea is simple: a tool description is executable content. The model reads
it and acts on it. If it changes, behaviour changes. A tool surface that
changes without anyone noticing is an integrity failure, so mcp-guard freezes
it.

## The document

```json
{
  "etdi": "1.0",
  "server": {"name": "workspace", "version": "1.4.2"},
  "tools": [
    {
      "name": "read_file",
      "title": "Read file",
      "description": "Read a UTF-8 text file from the workspace.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "path": {"type": "string", "description": "Workspace relative path"},
          "max_bytes": {"type": "integer"}
        },
        "required": ["path"]
      }
    }
  ]
}
```

| Field | Required | Rules |
| --- | --- | --- |
| `etdi` | yes | Dotted version string, currently `1.0`. |
| `server.name` | no | String. Prefixes tool identities in the manifest. |
| `server.version` | no | String. |
| `tools` | yes | Non-empty array of tool descriptors. |
| `tools[].name` | yes | `^[A-Za-z0-9_.\-]{1,64}$`, unique within the document. |
| `tools[].title` | no | String. |
| `tools[].description` | yes in practice | String, max 4096 characters. |
| `tools[].inputSchema` | no | JSON-Schema-ish object. `type` must be `object`. |
| `tools[].inputSchema.properties` | no | Object of property schemas. |
| `tools[].inputSchema.required` | no | Array of strings; every entry must exist in `properties`. |

A property schema may declare `type` (string or array of strings), `enum`,
`default` and `description`.

## The pin manifest

```bash
mcp-guard pin-manifest create --input tools.json --output pins.json
```

```json
{
  "manifest_version": "1.0",
  "etdi_version": "1.0",
  "generator": "mcp-guard/0.6.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "server": {"name": "workspace", "version": "1.4.2"},
  "tools": [
    {
      "server": "workspace",
      "tool": "read_file",
      "name": "read_file",
      "description": "Read a UTF-8 text file from the workspace.",
      "required": ["path"],
      "parameters": [
        {"name": "max_bytes", "type": "integer", "required": false},
        {"name": "path", "type": "string", "required": true}
      ],
      "schema": {"type": "object", "properties": {"...": {}}},
      "description_sha256": "…",
      "schema_sha256": "…",
      "tool_sha256": "…"
    }
  ],
  "manifest_sha256": "…"
}
```

### Digests

All digests are SHA-256 over a **canonical JSON** encoding (sorted keys, no
whitespace, UTF-8):

| Digest | Covers |
| --- | --- |
| `description_sha256` | The tool description text. |
| `schema_sha256` | The `inputSchema` object. |
| `tool_sha256` | Name + description + `inputSchema` together. |
| `manifest_sha256` | The whole `tools` array of the manifest. |

Canonical encoding is what makes digests reproducible across machines and
across Python versions — the same document always produces the same hash.

## Verifying

```bash
mcp-guard pin-manifest verify --pins pins.json --input tools.json
```

The comparison reports four statuses:

| Status | Meaning | Rule |
| --- | --- | --- |
| `unchanged` | The tool matches its pin. | — |
| `drift` | The schema, description, required set or parameter types moved. | `ETDI-001`, `ETDI-004`, `ETDI-005`, `ETDI-006` |
| `added` | A tool is advertised that the manifest does not pin. | `ETDI-002` |
| `removed` | A pinned tool is no longer advertised. | `ETDI-003` |

Specific change kinds are reported inside a `drift` record:

| Kind | Meaning |
| --- | --- |
| `schema` | The input schema digest changed. |
| `description` | The description changed. |
| `required_added` | A parameter became required. |
| `required_removed` | A parameter is no longer required. |
| `parameter_added` / `parameter_removed` | The parameter set moved. |
| `type_widened` | A parameter now accepts a superset of its previous types. |
| `type_changed` | A parameter changed type in a non-widening way. |

`type_widened` is called out separately because it is the quiet one: a
parameter that accepted `string` now accepting `string | number` is how a
schema starts accepting payloads nobody reviewed.

## Pinning inside a check

```bash
mcp-guard check transcript.json --etdi tools.json --pins pins.json
```

The pinning plugin then reports drift as part of the normal report, with the
same severities and the same exit code behaviour.

## Recommended workflow

1. **Discover.** Export the tool surface into an ETDI document.
2. **Review.** Read the descriptions — that is where the prompt injection
   lives.
3. **Pin.** `mcp-guard pin-manifest create`.
4. **Commit.** Store the manifest next to the code, in version control.
5. **Verify in CI.** `mcp-guard pin-manifest verify` on every build. A change
   to the surface must be a reviewed commit, not a surprise.

Never re-pin automatically. The value of the pin is that a change costs a
human decision.
