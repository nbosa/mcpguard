# Security model — mcp-guard v0.6.0

> Simplified Chinese: [../zh-CN/security.md](../zh-CN/security.md)

## 1. What mcp-guard is

mcp-guard is a **detection and audit layer**. It reads what an MCP agent
sends to its tools and what those tools return, and it reports deviations from
a declared policy.

## 2. What mcp-guard is not

* It is **not a sandbox**. It does not confine a tool's privileges.
* It is **not a firewall**. It does not mediate the network.
* It is **not a substitute for OS isolation.** A container, a seccomp profile
  and a read-only filesystem still belong between an untrusted tool and the
  host.
* It does **not** stop an attacker who controls the agent binary. It reports
  on what the agent does; it does not constrain it.

Treat mcp-guard as an additional tripwire, not as a control.

## 3. Threat model

| Adversary | Capability | What mcp-guard sees |
| --- | --- | --- |
| **Malicious tool server** | Controls the tool output it returns | ANSI sequences, hidden text, credential material, canaries in the payload |
| **Compromised tool description** | Changes the description or schema of a live tool | Schema drift, new required parameters, reworded descriptions |
| **Prompt-injected agent** | Issues tool calls with attacker-chosen arguments | Path traversal, credential paths, egress of canaries and secrets |
| **Crafted payload author** | Chooses the exact spelling of a path or string | Normalisation defeats the spelling: encoded traversal, ADS, reserved names |

Out of scope: attacks on the host operating system, attacks on the mcp-guard
process itself, and attacks that require the attacker to also control the
policy file.

## 4. Trust boundaries

```
        ┌──────────────── trusted: your policy, the pinned manifest ────────────────┐
        │                                                                          │
  agent │   calls / arguments            results / content                     │ mcp-guard
   ─────┤──────────────────────────────► ───────────────────────────────►       ├────►
        │                                                                          │
        └──────────────── untrusted: everything from the tool side ────────────────┘
```

mcp-guard treats everything on the tool side as hostile input. It is designed
to be safe to run on attacker-controlled strings.

## 5. Properties of the implementation

### 5.1 No side effects

Path canonicalization is purely lexical: no `open`, no `stat`, no `os.path.realpath`,
no symlink resolution, no network. The guard cannot be tricked into touching
the filesystem by a crafted path, because it never touches the filesystem.

The only file access in the whole tool is reading the policy, the transcript
and the ETDI/pin files — all of which are named by the operator, not by the
payload.

### 5.2 Evidence redaction

Findings quote the offending payload, which frequently contains the very secret
the guard is protecting. Every finding's evidence passes through
`core.redact.redact()` before it leaves the engine. Known credential material
(AWS keys, GitHub and Slack tokens, private key blocks, JWTs, URL credentials,
assigned secrets) is replaced with `<redacted:kind>` markers.

Evidence is then truncated to `settings.max_evidence_chars` and control
characters are escaped, so a report is safe to print in a terminal or store in
a log.

Set `redact_evidence = false` only if you have a reason to see raw evidence —
and understand that the report then becomes a secret.

### 5.3 Determinism

No randomness, no clock dependence in rule evaluation, no network. The same
input produces the same findings in the same order. This is what makes pin
manifests reproducible and audit logs comparable.

The only timestamp in the system is `generated_at` in a pin manifest, which is
supplied by the caller.

### 5.4 Fail loud, not silent

A plugin that raises an exception is converted into an `ENGINE-000` finding.
The run continues, the report still lists every other finding, and the audit
trail records that a check did not complete. A crash never turns into "no
findings".

### 5.5 Fail closed by default

* The default policy fails on `HIGH`.
* `settings.etdi.require_pins` defaults to `true`: an ETDI document without a
  pin manifest is itself a finding (`ETDI-008`).
* `settings.canary.block_on_match` defaults to `true`.
* The path plugin fails on credential paths (`PATH-002`, `CRITICAL`) and on
  base-directory escapes (`PATH-001`, `CRITICAL`).

### 5.6 Policy integrity

A policy is as trusted as the file it comes from. `policy-lint` reports
unknown plugins, unknown rule ids, invalid regexes and type errors, so a
typo in a policy surfaces as an error rather than as silently disabled
protection.

## 6. Known limitations

1. **Lexical only.** `~/link-to-etc` cannot be resolved without filesystem
   access, which mcp-guard deliberately avoids. Use `allowed_roots` to
   constrain the reachable set instead.
2. **URLs are not paths.** `https://host/%2e%2e/etc` is not examined by the
   path rules. It is still scanned by the canary rules.
3. **Entropy is a heuristic.** `CANARY-004` will eventually fire on a
   legitimate high-entropy string such as a hash or a minified asset.
   Tune `entropy_threshold` / `min_blob_len`, or lower the severity.
4. **Egress depends on naming.** `CANARY-008` only fires for tools listed in
   `settings.canary.egress_tools`. Keep that list current.
5. **Description review is still human work.** Pinning detects that a
   description changed; it does not judge whether the new description is
   safe. Read the diff.
6. **No protection for the tool side.** mcp-guard cannot detect a server that
   lies in its result content in a way that does not match a rule.

## 7. Reporting a finding

Findings are designed to be actionable in a ticket. Each one carries a stable
rule id, a severity, a location (`calls[2].arguments.path`), a redacted
evidence string and a remediation hint. The rule id is stable across releases
and can be used to suppress, escalate or track a specific check.
