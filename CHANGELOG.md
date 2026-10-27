# Changelog

All notable changes to `mcp-guard` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release channel is named in the version banner: `mcp-guard --version`
prints the semantic version and the channel codename, for example
`mcp-guard 1.0.0 (oss)`.

## [1.0.0] - 2026-10-27

The first public, MIT-licensed release of `mcp-guard`. The release channel
codename is `oss`.

### Added

- A unified command line interface with ten commands covering both halves of
  the product: `proxy`, `verify-audit`, `rotate-key`, `keygen`, `check`,
  `policy-lint`, `selftest`, `pin-manifest`, `sanitize-output` and
  `canary-check`. The former names `run`, `verify` and `verify-log` remain
  available as aliases of `proxy` and `verify-audit`.
- The runtime proxy. `mcp-guard proxy` sits between an MCP client and an
  upstream MCP server, evaluates every `tools/call` against the policy before
  the request leaves the machine, filters the tool listing, and relays
  upstream notifications.
- The policy engine. Policies are YAML documents with a deny-by-default
  posture: a tool that the policy does not list is refused. Tool names are
  normalised with Unicode NFKC before a rule is looked up, so a homoglyph
  cannot be used to step around a denial. Undeclared arguments are refused
  unless a rule opts into them.
- The audit chain. Every decision is written as one JSON Lines record that
  carries the SHA-256 hash of the previous record and, when a key is
  configured, a keyed HMAC over its own contents. `verify-audit` distinguishes
  five outcomes, and `rotate-key` moves a log onto a new key without
  rewriting it.
- Four guard plugins, shared by the runtime and the offline halves:
  `etdi_pinning` (ETDI-001 to ETDI-009), `ansi_sanitize` (ANSI-001 to
  ANSI-008), `path_shape` (PATH-001 to PATH-011) and `canary_exfil`
  (CANARY-001 to CANARY-010).
- ETDI pinning. `pin-manifest` freezes the fingerprint of a tool surface, and
  both the proxy and the scanner refuse a listing that has drifted away from
  the pins. Drift is reported at `CRITICAL`.
- A load-time guard against a regular expression denial of service. A policy
  pattern is checked by a static analysis of the standard library's own
  parser and by a timed probe, and either one can refuse it.
- `selftest`, a built-in verification suite that exercises the proxy, the
  audit chain, the canary detector, every plugin, the default policy and the
  sample transcripts.
- A zero-dependency core. The scanner, the policy engine, the audit chain and
  every plugin need nothing beyond Python 3.11 and the standard library; the
  MCP SDK is confined to the `proxy` extra.
- Release documentation: an English README, changelog, security policy,
  contribution guide, and architecture reference.
- `check_secrets.py`, a standalone hygiene scanner that reads the whole
  repository, including itself, and reports the shape of personal data and
  credential material without ever printing the value it found.

### Changed

- The release is published under the `oss` channel codename, and the
  packaging metadata declares the MIT licence and the Python 3.11 floor.
- The built-in default policy is mirrored by a file,
  `src/mcp_guard/data/default_policy.toml`, so that it can be copied and
  edited rather than only used as it is.

### Security

- A tool that the policy does not list is denied by default. The previous
  behaviour of allowing an unlisted tool was removed.
- The content-relaying methods -- `resources/*`, `prompts/*` and
  `completion/*` -- are denied unless a policy names them in `methods.allow`,
  so that an upstream which has been talked into serving a prompt injection
  cannot reach the client unfiltered.
- A JSON-RPC batch array is rejected at the proxy boundary, because a batch
  must never bypass the single-request policy checks.
- The audit chain carries a keyed HMAC as well as a hash chain. A log that
  verifies but carries no keyed signature is reported as `WARN` rather than
  `OK`, and a legacy unkeyed log is refused where a keyed one is required.
- A matched canary token is written to the audit log as a fingerprint, never
  as the token itself.


## [0.6.0] - 2026-09-30

The release that preceded the public one. It carried the architecture that
`1.0.0` publishes: the proxy, the policy engine, the audit chain, the four
plugins and the unified command line.

### Added

- The runtime proxy and the policy engine with a deny-by-default posture.
- The audit chain, with the hash chain first and the keyed HMAC added after
  it.
- The four guard plugins: `etdi_pinning`, `ansi_sanitize`, `path_shape` and
  `canary_exfil`.
- ETDI pinning through `pin-manifest`.
- The unified command line, replacing the separate entry points with the
  `proxy`, `check`, `policy-lint`, `selftest`, `pin-manifest`,
  `sanitize-output` and `canary-check` commands.

### Security

- The canary exfiltration detector, which refuses an outbound call that
  carries a registered canary token and writes only the token's fingerprint
  to the log.
- The path guard, which refuses a path that escapes the working directory or
  that names credential material.
- The regular expression guard, which refuses a policy pattern that could
  stall the proxy.


## [0.5.0] - 2026-08-15

The first release with a coherent scanner and policy model, before the
plugins were split out of the engine.

### Added

- The offline transcript scanner and the policy document model.
- The severity scale `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` and the
  `fail_on` and `warn_on` thresholds.
- Policy linting with stable diagnostic codes.
