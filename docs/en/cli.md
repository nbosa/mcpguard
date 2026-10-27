# CLI reference — mcp-guard v0.6.0

> Simplified Chinese: [../zh-CN/cli.md](../zh-CN/cli.md)

```
mcp-guard <command> [options]
```

| Exit code | Meaning |
| --- | --- |
| `0` | Success — no blocking findings. |
| `1` | Findings reached the policy threshold. |
| `2` | Usage error, unreadable input, or an internal failure. |

Every command supports `--format text` (default) and `--format json`.

---

## `mcp-guard check`

Run every enabled plugin over a transcript.

```
mcp-guard check [TARGET] [--policy PATH] [--fail-on LEVEL]
                            [--pins PATH] [--etdi PATH]
                            [--plugin NAME]... [--format text|json] [--quiet]
```

| Option | Description |
| --- | --- |
| `TARGET` | Path to a JSON transcript, or `-` for stdin (the default). |
| `--policy PATH` | Policy file. Without it, the built-in default is used. |
| `--fail-on LEVEL` | Override `settings.fail_on` for this run. |
| `--pins PATH` | ETDI pin manifest to verify the tool surface against. |
| `--etdi PATH` | ETDI document describing the live tool surface. |
| `--plugin NAME` | Restrict the run to the given plugin. Repeatable. |
| `--quiet` | Print only the verdict. |

**Transcript format.**

```json
{
  "agent": "release-bot",
  "calls":   [{"server": "workspace", "tool": "read_file", "arguments": {"path": "a.txt"}}],
  "results": [{"server": "workspace", "tool": "read_file", "content": "..."}],
  "transcript": "free-form text",
  "metadata": {"etdi": {...}, "pins": {...}}
}
```

`tool_calls` / `tool_results` / `messages` are accepted as aliases.

**Output (text).**

```
policy: mcp-guard-default (0.6.0)
verdict: FAIL  (max severity: CRITICAL)
findings: 3

  [CRITICAL] PATH-001 (path_shape): Path escapes the home/base directory
      location: calls[0].arguments.path
      evidence: ../../.ssh/id_rsa
      fix: Confine filesystem access to the working tree; reject upward traversal.
```

**Output (JSON).** A `CheckReport`: `verdict`, `policy`, `summary`
(`total`, `max_severity`, `by_severity`, `by_plugin`), `stats` and `findings`.
Each finding carries `rule_id`, `plugin`, `severity`, `message`, `evidence`,
`location`, `remediation` and `metadata`.

---

## `mcp-guard policy-lint`

Validate a policy file before you rely on it.

```
mcp-guard policy-lint [POLICY] [--strict] [--format text|json]
```

| Option | Description |
| --- | --- |
| `POLICY` | Policy file. Without it, the built-in default is linted. |
| `--strict` | Treat warnings as errors (exit `1`). |

Reports structural problems (`POL-0xx`) and semantic problems such as an
unknown plugin (`POL-007`) or an unknown rule id (`POL-006`).

---

## `mcp-guard selftest`

Run the in-product verification suite. No external input needed.

```
mcp-guard selftest [--verbose] [--format text|json]
```

Exercises every plugin's `self_test()`, lints the default policy, round-trips
a pin manifest, and checks that a clean transcript passes while a hostile one
fails. Exit `1` if any case fails.

---

## `mcp-guard pin-manifest`

Manage the frozen fingerprint of a tool surface.

```
mcp-guard pin-manifest create --input TOOLS [--output PINS] [--generated-at TS]
mcp-guard pin-manifest verify --pins PINS --input TOOLS [--format text|json]
mcp-guard pin-manifest show   --pins PINS [--format text|json]
```

| Action | Description |
| --- | --- |
| `create` | Build a pin manifest from an ETDI document. |
| `verify` | Compare a live ETDI document against the pins. |
| `show` | Print the contents of a pin manifest. |

`--input -` reads the ETDI document from stdin. `verify` exits `1` when the
surface drifted, added a tool or lost a tool.

---

## `mcp-guard sanitize-output`

Strip terminal escape sequences from a payload before rendering it.

```
mcp-guard sanitize-output [FILE] [--keep-ansi] [--keep-control] [--keep-bidi]
                          [--max-chars N] [--fail-on-change] [--format text|json]
```

| Option | Description |
| --- | --- |
| `FILE` | Payload file, or `-` for stdin (the default). |
| `--keep-ansi` | Keep ANSI escape sequences. |
| `--keep-control` | Keep residual C0 control characters. |
| `--keep-bidi` | Keep bidirectional override characters. |
| `--max-chars N` | Truncate the sanitized output. |
| `--fail-on-change` | Exit `1` when the payload was modified. |

Removes ANSI escape sequences (CSI, OSC, DCS, and their 8-bit forms), resolves
backspace and carriage-return overwrite tricks, and strips bidirectional
override characters.

---

## `mcp-guard canary-check`

Scan a payload for canary markers and credential material.

```
mcp-guard canary-check [FILE] [--policy PATH] [--token TOKEN]... [--format text|json]
```

| Option | Description |
| --- | --- |
| `FILE` | Payload file, or `-` for stdin (the default). |
| `--policy PATH` | Policy file (default: the built-in one). |
| `--token TOKEN` | Additional canary token to look for. Repeatable. |

The payload is treated as an *outbound* body. A configured token produces
`CANARY-001`; a generic `CANARY-XXXX-XXXX` marker produces `CANARY-002`;
credentials produce `CANARY-003`.

---

## Pipelines

```bash
# Fail a CI job when the agent goes off-policy.
mcp-guard check transcript.json --policy examples/policy.toml || exit 1

# Verify that a server still exposes the surface we pinned.
mcp-guard pin-manifest verify --pins pins.json --input live-tools.json

# Sanitize before printing to a shared terminal.
tool-output | mcp-guard sanitize-output

# Gate a canary into the environment and assert it never leaves.
mcp-guard canary-check --token "$CANARY" --policy policy.toml < outgoing.json
```
