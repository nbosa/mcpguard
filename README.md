# mcp-guard

A security guardrail and runtime proxy for Model Context Protocol (MCP) agents.

`mcp-guard` has two halves that share one policy model, one rule catalogue and
one severity scale:

- **Runtime.** `mcp-guard proxy` sits between an MCP client and an upstream MCP
  server. It decides which tool calls are allowed, refuses the ones that are
  not, and writes every decision into a tamper-evident audit log.
- **Offline.** `mcp-guard check` runs the same guard plugins over a recorded
  transcript, so a policy can be exercised against known traffic without
  standing up a server.

The core package has **zero external runtime dependencies**: Python 3.11 and
the standard library are enough for the scanner, the policy engine, the audit
chain and every plugin. The `proxy` extra adds the MCP SDK, which is needed
only for the runtime half.

## Install

```bash
pip install mcp-guard          # the offline half, standard library only
pip install "mcp-guard[proxy]" # the runtime half as well
```

The package installs a single console script, `mcp-guard`. Every example below
assumes it is on your `PATH`.

## The runtime half

Put the proxy in front of the upstream server. Everything after `--` is the
upstream command:

```bash
mcp-guard proxy --policy examples/policy.toml --audit audit.jsonl -- \
    python -m my_upstream_server
```

The proxy starts an MCP server on stdio, relays the client's handshake to the
upstream, and then mediates every subsequent request. For each `tools/call` it
evaluates the tool name and the arguments against the policy before anything
reaches the upstream. A refused call never leaves the machine, and the refusal
is written to the audit log like any other decision.

The policy is a YAML document. A minimal one looks like this:

```yaml
version: "1.0"
rules:
  - id: allow-read
    tool: read_file
    action: allow
    arguments:
      path:
        type: string
        required: true
        max_length: 512
  - id: deny-everything-else
    action: deny
```

Tools that the policy does not list are denied, so a policy is a complete
description of what the agent may do rather than a list of exceptions to an
open default.

### The audit log

Every decision becomes one JSON Lines record. Each record carries the SHA-256
hash of the previous record, and -- when a key is configured -- a keyed HMAC
over its own contents. A record that has been edited, removed or reordered
breaks the chain, and the chain is verified with a separate command:

```bash
mcp-guard keygen --out audit.key
mcp-guard verify-audit audit.jsonl --audit-key-file audit.key
```

`verify-audit` reports one of five outcomes: `OK`, `BROKEN` (the chain does
not verify), `WARN` (the log verifies but carries no keyed signature),
`KEY` (the log is keyed but the key is unknown) and `REFUSED` (a legacy
unkeyed log was found where a keyed one was required). A key can be rotated
onto a new file without rewriting the log:

```bash
mcp-guard rotate-key --audit audit.jsonl --new-key-file audit.key
```

### ETDI pinning

A tool surface that is advertised today may be a different surface tomorrow.
`mcp-guard pin-manifest` freezes the fingerprint of a tool listing, and the
proxy then refuses to serve a listing that has drifted away from the pins:

```bash
mcp-guard pin-manifest create --input examples/etdi-tools.json --output pins.json
mcp-guard pin-manifest verify --pins pins.json --input examples/etdi-tools.json
```

Drift is reported as `CRITICAL`, so it blocks the request rather than merely
warning about it.

## The offline half

The scanner reads a transcript document -- calls, results and free text -- and
runs the guard plugins over it:

```bash
mcp-guard check examples/transcript.json --policy examples/policy.toml
mcp-guard check examples/transcript.json --format json
```

A transcript is JSON. The document has a `calls` array, an optional `results`
array and an optional `transcript` string; the alternative names `tool_calls`,
`tool_results` and `messages` are accepted as well. See
[`examples/transcript.json`](examples/transcript.json) for the shape.

Policies can be checked before they are used:

```bash
mcp-guard policy-lint examples/policy.toml
```

`policy-lint` reads a YAML file as a runtime policy and a TOML file as an
offline scan policy. It reports structural and semantic problems -- an unknown
setting, a duplicated rule id, a rule id that no plugin owns, an invalid
severity, an invalid regular expression -- with a stable code for each.

Two single-purpose commands round the offline half out. `sanitize-output`
strips terminal escape sequences, overwrite tricks and bidirectional overrides
from a payload, which is what makes an agent's output safe to print in a
terminal:

```bash
mcp-guard sanitize-output payload.txt --fail-on-change
```

`canary-check` looks for canary tokens and honeypot URIs in a payload, so that
a leak can be detected in traffic that has already been recorded:

```bash
mcp-guard canary-check payload.txt --token "CANARY-XXXX-XXXX"
```

Finally, `mcp-guard selftest` exercises the proxy, the audit chain, the canary
detector, every plugin, the default policy and the sample transcripts. It is
the fastest way to confirm that an installation works.

## The plugins

Four plugins do the inspecting. They are the same objects in both halves: the
offline scanner runs them over a transcript, and the proxy runs them over the
live traffic.

| Plugin | Rule ids | What it looks for |
| --- | --- | --- |
| `etdi_pinning` | `ETDI-001` to `ETDI-009` | A tool surface that has drifted away from its pin manifest. |
| `ansi_sanitize` | `ANSI-001` to `ANSI-008` | Terminal escape sequences, overwrite tricks, bidirectional overrides and other control characters. |
| `path_shape` | `PATH-001` to `PATH-011` | Paths that escape the working directory or point at credential material. |
| `canary_exfil` | `CANARY-001` to `CANARY-010` | Canary tokens, encoded blobs, credentials in URLs and other signs of exfiltration. |

Every finding carries a severity from the fixed scale `INFO`, `LOW`, `MEDIUM`,
`HIGH`, `CRITICAL`. The policy decides where the line is: the built-in
default fails a run at `HIGH` and warns at `MEDIUM`, and
`fail_on = "MEDIUM"` in a policy makes the run stricter. The full rule
catalogue is in the [rules reference](docs/en/rules.md).

The plugins run in a fixed order -- pins first, content inspection last --
because a tool that has drifted is worth refusing before its arguments are
looked at.

## The commands

| Command | What it does |
| --- | --- |
| `mcp-guard proxy` | Run the policy-enforcing proxy in front of an upstream MCP server. |
| `mcp-guard check` | Check a transcript for policy violations. |
| `mcp-guard policy-lint` | Validate a policy file. |
| `mcp-guard selftest` | Run the built-in verification suite. |
| `mcp-guard pin-manifest` | Create, verify or show an ETDI pin manifest. |
| `mcp-guard sanitize-output` | Strip terminal escape sequences from a payload. |
| `mcp-guard canary-check` | Look for canary tokens in a payload. |
| `mcp-guard verify-audit` | Verify the hash chain and the keyed HMAC chain of an audit log. |
| `mcp-guard rotate-key` | Rotate the key of an audit log onto a new key file. |
| `mcp-guard keygen` | Create a new audit chain key file. |

`run`, `verify` and `verify-log` remain available as aliases of `proxy` and
`verify-audit`.

The exit codes are shared by the whole command line: `0` for success, `1` for
a run that found a policy violation or a broken audit chain, `2` for a usage
error or unreadable input, and `3` for an audit log that cannot be
authenticated. The full list is in the [CLI reference](docs/en/cli.md).

## The default policy

The built-in default policy is conservative, and it is meant to be copied
rather than used as-is. It fails on `HIGH`, warns on `MEDIUM`, redacts
credential material from evidence, and treats the following as sensitive:
directory names such as `.ssh`, `.aws`, `.gnupg`, `.kube` and `.docker`; file
names such as `id_rsa`, `.env` and `*.pem`; and the system prefixes `/etc`,
`/proc`, `/sys`, `/dev`, `/boot`, `/var/run`, `/var/log` and `/root`.

The built-in default is also shipped as a file,
`src/mcp_guard/data/default_policy.toml`, so that it can be copied and
edited; the [policy reference](docs/en/policy.md) documents every key.

Three worked policies ship with the repository:
[`examples/policy.toml`](examples/policy.toml) confines every path to a single
root and fails on `MEDIUM`;
[`examples/policy.default-deny.yaml`](examples/policy.default-deny.yaml) allows
nothing but a named set of tools; and
[`examples/policy.list-paths.yaml`](examples/policy.list-paths.yaml) permits
listing without permitting reading.

## Security

The proxy enforces the policy engine, blocks canary-token exfiltration,
guards the policy's own regular expressions against a denial of service,
constrains the paths a tool may name, and writes a verifiable audit chain. The
[security model](SECURITY.md) states what that does and does not cover, and
the [security guide](docs/en/security.md) describes the operational side.

To report a vulnerability, see the reporting section of
[SECURITY.md](SECURITY.md).

## Documentation

| Topic | Reference |
| --- | --- |
| Architecture | [docs/en/architecture.md](docs/en/architecture.md) |
| Rules | [docs/en/rules.md](docs/en/rules.md) |
| Command line | [docs/en/cli.md](docs/en/cli.md) |
| Policy | [docs/en/policy.md](docs/en/policy.md) |
| ETDI pinning | [docs/en/etdi.md](docs/en/etdi.md) |
| Security | [docs/en/security.md](docs/en/security.md) |

The unified architecture of both halves is described in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/mcp-guard selftest
```

The test suite runs against the checkout without an installation, so
`.venv/bin/pytest` works in a bare clone as well. The contribution guide,
including the process for adding a rule or a plugin, is in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

The package metadata is in [pyproject.toml](pyproject.toml).
