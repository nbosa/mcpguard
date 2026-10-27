# Policy reference — mcp-guard v0.6.0

Policies are TOML documents with three sections: `[meta]`, `[settings]` and
`[[rule]]`. The built-in default lives in
`src/mcp_guard/data/default_policy.toml` and can be copied as a starting
point.

```bash
mcp-guard policy-lint my-policy.toml
mcp-guard check transcript.json --policy my-policy.toml
```

## `[meta]`

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | Policy name. |
| `version` | string | no | Policy version. Semantic versions are expected. |
| `locale` | string | no | Language tag for operator-facing messages. |

## `[settings]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `fail_on` | severity | `HIGH` | Findings at or above this level fail the run. |
| `warn_on` | severity | `MEDIUM` | Findings at or above this level warn. |
| `redact_evidence` | bool | `true` | Redact credential material from evidence. |
| `max_evidence_chars` | int | `240` | Maximum evidence length. |
| `strict` | bool | `true` | Treat unknown settings as errors. |

Severity values: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## `[settings.etdi]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `require_pins` | bool | `true` | Require a pin manifest when an ETDI document is present. |
| `fail_on_drift` | bool | `true` | Report drift as `CRITICAL` instead of `MEDIUM`. |
| `allow_unpinned` | bool | `false` | Tolerate advertised tools that are not pinned. |

## `[settings.path]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `sensitive_names` | list[string] | see default | Directory names that indicate credential material. |
| `sensitive_files` | list[string] | see default | Glob patterns for credential file names. |
| `system_prefixes` | list[string] | see default | Absolute prefixes that indicate host reconnaissance. |
| `allowed_roots` | list[string] | `[]` | When non-empty, every path must live under one of these roots. |
| `sensitive_root` | string | `"~"` | The base directory that path escapes are measured against. |

## `[settings.ansi]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_ansi` | bool | `false` | Keep ANSI escape sequences. |
| `max_output_chars` | int | `100000` | Truncate longer payloads; `0` disables. |
| `strip_control_chars` | bool | `true` | Remove residual C0 control characters. |
| `detect_bidi` | bool | `true` | Detect bidirectional text overrides. |

## `[settings.canary]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `tokens` | list[string] | `[]` | Canary tokens planted in the environment. |
| `egress_tools` | list[string] | see default | Tools that can send data out of the environment. |
| `entropy_threshold` | float | `4.2` | Shannon bits per character above which a blob is "encoded". |
| `min_blob_len` | int | `40` | Minimum blob length before entropy analysis applies. |
| `scan_results` | bool | `true` | Also scan tool results, not just call arguments. |
| `block_on_match` | bool | `true` | Treat a canary match as `CRITICAL`. |

### How egress is decided

A tool call is treated as *egress* when its name or `server.tool` name appears
in `egress_tools`, or when the request metadata lists it under
`egress_tools`. A canary in an egress call is `CANARY-008` (critical) rather
than `CANARY-001`.

### How canary matching works

1. **Exact** — the token appears verbatim in the payload.
2. **Case-insensitive** — the token appears with different casing.
3. **Shape-normalised** — the token appears with different separators
   (`CANARY-AB12-CD34` matches `CANARY_AB12_CD34` and `canaryab12cd34`).

## `[[rule]]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `id` | string | required | Rule id, e.g. `PATH-001`. Must match `[A-Z][A-Z0-9_]*-\d{3}`. |
| `plugin` | string | required | Plugin that owns the rule, or `custom`. |
| `enabled` | bool | `true` | Enable or disable the rule. |
| `severity` | severity | plugin default | Override the severity. |
| `message` | string | plugin default | Override the operator-facing message. |
| `regex` | string | — | For `custom` rules: the pattern to match. |
| `target` | string | `any` | What the regex is evaluated against. |
| `description` | string | — | Free-text note. |

### Examples

```toml
# Escalate a rule.
[[rule]]
id = "PATH-007"
plugin = "path_shape"
severity = "HIGH"

# Silence a rule.
[[rule]]
id = "ANSI-001"
plugin = "ansi_sanitize"
enabled = false

# Add a rule of your own.
[[rule]]
id = "CUSTOM-001"
plugin = "custom"
severity = "HIGH"
regex = "\\b[a-z0-9-]+\\.corp\\.internal\\b"
target = "any"
message = "Internal host name referenced in the payload"
```

## Lint codes

| Code | Severity | Meaning |
| --- | --- | --- |
| `POL-000` | CRITICAL | The document is not valid TOML / not a table. |
| `POL-001` | LOW | Unknown top-level or rule key. |
| `POL-002` | LOW | Unknown settings key. |
| `POL-003` | HIGH | `[meta] name` is missing. |
| `POL-004` | CRITICAL | Invalid severity value. |
| `POL-005` | CRITICAL | Duplicate rule id. |
| `POL-006` | CRITICAL | The rule id is unknown to that plugin. |
| `POL-007` | CRITICAL | Unknown plugin. |
| `POL-008` | CRITICAL | Invalid regex. |
| `POL-009` | CRITICAL | Rule id is missing. |
| `POL-010` | CRITICAL | Rule plugin is missing. |
| `POL-011` | LOW | `warn_on` is stricter than `fail_on`. |
| `POL-012` | LOW | `meta.version` is not semantic. |
| `POL-013` | HIGH | A setting has the wrong type or an out-of-range value. |
| `POL-014` | HIGH | The rule id does not match the expected format. |
| `POL-015` | HIGH | Unknown rule target. |
| `POL-016` | LOW | A built-in rule id is reused with a custom regex. |
| `POL-017` | LOW | `settings.canary.tokens` is empty. |
