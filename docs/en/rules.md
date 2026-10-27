# Rule catalogue — mcp-guard v0.6.0

mcp-guard ships **38 built-in rules** across four plugins. Every rule has a
stable identifier, a default severity, a remediation hint, and can be
enabled, disabled, re-severity'd or re-worded from a policy.

Severity levels, lowest to highest: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## ETDI pinning (`etdi_pinning`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `ETDI-001` | CRITICAL | Tool input schema drifted from its pin. |
| `ETDI-002` | HIGH | An advertised tool is not covered by the pin manifest. |
| `ETDI-003` | HIGH | A pinned tool disappeared from the advertised surface. |
| `ETDI-004` | MEDIUM | A tool description changed since pinning. |
| `ETDI-005` | CRITICAL | A tool gained a required parameter. |
| `ETDI-006` | HIGH | A tool parameter type widened since pinning. |
| `ETDI-007` | HIGH | The ETDI document is malformed or unusable. |
| `ETDI-008` | MEDIUM | The pin manifest is missing or version-mismatched. |
| `ETDI-009` | LOW | The pin manifest digest does not match its content. |
| `ETDI-010` | CRITICAL | The server identity or version drifted from its pin. |

**Notes.** `ETDI-001` and `ETDI-005` are the load-bearing ones: a changed input
schema or a new required argument changes what the agent will send, so it
changes behaviour. `ETDI-004` (description drift) is the prompt-injection
surface — a description is read by the model, not by the parser.

## ANSI sanitization (`ansi_sanitize`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `ANSI-001` | MEDIUM | An ANSI escape sequence was found in tool output. |
| `ANSI-002` | HIGH | An OSC sequence was found (title or hyperlink spoofing). |
| `ANSI-003` | CRITICAL | An OSC 52 clipboard-write sequence was found. |
| `ANSI-004` | MEDIUM | A cursor / screen control sequence was found. |
| `ANSI-005` | HIGH | Concealed or overwritten text was found (backspace, carriage return, CSI 8). |
| `ANSI-006` | HIGH | Bidirectional text control characters were found (Trojan Source). |
| `ANSI-007` | MEDIUM | Raw control characters were found in the output. |
| `ANSI-008` | LOW | The output exceeds `settings.ansi.max_output_chars` and will be truncated. |

**Notes.** `ANSI-003` is critical because OSC 52 silently replaces the
operator's clipboard — a classic "copy this and paste it" trap.
`ANSI-005` covers text that *renders* as one thing and *contains* another:
`visible\x08\x08\x08hidden` and `harmless\r\x1b[2K\rreal` both hide content.

## Path shapes (`path_shape`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `PATH-001` | CRITICAL | The path escapes the home / base directory. |
| `PATH-002` | CRITICAL | The path targets a sensitive credential location. |
| `PATH-003` | HIGH | The path uses a device (`\\.\`) or UNC namespace. |
| `PATH-004` | HIGH | The path hides traversal behind percent-encoding. |
| `PATH-005` | HIGH | The path uses an NTFS alternate data stream (`file:stream`). |
| `PATH-006` | HIGH | The path uses a Windows reserved device name (`CON`, `NUL`, `COM1`). |
| `PATH-007` | MEDIUM | The path targets a system location (`/etc`, `/proc`, …). |
| `PATH-008` | MEDIUM | The path contains control characters or a NUL byte. |
| `PATH-009` | MEDIUM | The path is drive-relative (`C:foo`). |
| `PATH-010` | LOW | The path uses trailing dot or space obfuscation. |
| `PATH-011` | HIGH | The path is outside `settings.path.allowed_roots`. |

**Notes.** `PATH-001` fires for `~/.ssh/../../etc/passwd` and for relative
traversal such as `../../etc/passwd` (relative paths are measured against the
base directory, which is the home directory by default).

`PATH-010` covers `report.txt.` and `report.txt ` — on Windows those address
the same file as `report.txt`, so a naive extension allow-list is bypassed.

URLs are **not** paths: `https://example.invalid/a` is not examined by the
path rules (it is still scanned by the canary rules).

## Canary exfiltration (`canary_exfil`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `CANARY-001` | CRITICAL | A configured canary token was detected in the payload. |
| `CANARY-002` | CRITICAL | A canary-shaped marker (`CANARY-XXXX-XXXX`) was detected. |
| `CANARY-003` | CRITICAL | Credential material was detected in the payload. |
| `CANARY-004` | HIGH | A high-entropy blob was detected in the payload. |
| `CANARY-005` | MEDIUM | A JWT-like token was detected in the payload. |
| `CANARY-006` | HIGH | A URL with embedded credentials was detected. |
| `CANARY-007` | HIGH | An environment or credential dump indicator was detected. |
| `CANARY-008` | CRITICAL | A canary marker was sent to an egress-capable tool. |
| `CANARY-009` | HIGH | A base64 blob decodes to credential material. |
| `CANARY-010` | HIGH | A canary token was returned by a tool. |

**Notes.** `CANARY-008` is the sharpest signal: the tool name is listed in
`settings.canary.egress_tools`, and a canary marker is inside the outgoing
arguments. That is manipulation with a proof, not a heuristic.

`CANARY-004` is a *heuristic* and the noisiest rule. Its thresholds are
`settings.canary.entropy_threshold` (Shannon bits per character, default
`4.2`) and `settings.canary.min_blob_len` (default `40`). Raise the threshold
or lower the severity if it is too chatty for your corpus.

## Custom rules

A policy may add its own rules. A rule with a `regex` is evaluated by the
engine against the configured `target`:

```toml
[[rule]]
id = "CUSTOM-001"
plugin = "custom"
severity = "HIGH"
regex = "\\b[a-z0-9-]+\\.corp\\.internal\\b"
target = "any"
message = "Internal host name referenced in the payload"
```

| `target` | Evaluated against |
| --- | --- |
| `any` (default) | call arguments, result content and the transcript |
| `arguments` / `calls` | call arguments only |
| `content` / `results` | result content only |
| `transcript` | the transcript only |

Custom rules are matched after the plugins run, and their findings are
redacted and truncated like every other finding.

## Overriding rules

```toml
[[rule]]
id = "PATH-007"
plugin = "path_shape"
severity = "HIGH"
message = "Path targets a system location"

[[rule]]
id = "ANSI-001"
plugin = "ansi_sanitize"
enabled = false
```

An override must name the plugin that owns the rule; `policy-lint` reports
`POL-006` when the id is unknown to that plugin and no `regex` is supplied.
