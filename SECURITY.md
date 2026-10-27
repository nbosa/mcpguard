# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.0 (channel `oss`) | yes |
| older releases | no |

Security fixes are published for the latest release only. The project follows
Semantic Versioning, so a fix that changes behaviour in a breaking way will be
published as a new major version rather than as a patch to `1.0.0`.

The core package is Python 3.11 and the standard library. The `proxy` extra
pulls in the MCP SDK, which is a third-party dependency with its own release
cadence; the security posture of the proxy depends on that SDK as well.

## Reporting a vulnerability

Report a suspected vulnerability privately. Do not open a public issue for it.

The preferred channel is a **GitHub Security Advisory** on the repository:
use *Security* -> *Report a vulnerability*. That opens a private thread that
only the maintainers can read, and it leaves the discussion attached to the
release it affects.

The alternative is the maintainer address `security@example.com`. That address
is the placeholder from RFC 2606: replace it with the real maintainer address
when you publish this file for your own deployment. It is deliberately not a
real address, because a file that ships a live mailbox is a file that starts
receiving unwanted mail.

Please include, as far as you can:

- the version and channel of `mcp-guard` you are running;
- the policy document, or the part of it that the issue depends on, with any
  real values replaced by synthetic ones;
- the smallest transcript, request or payload that reproduces the issue;
- what an attacker gains.

Please report issues that you have found through fuzzing or through reading
the code as well as issues that you have exploited. The maintainers aim to
acknowledge a report within five working days, to keep the reporter informed
while the issue is being worked on, and to publish a fix or a mitigation for a
confirmed issue.

## The security model

`mcp-guard` is a guardrail: it decides whether a tool call is allowed to
happen, and it records what it decided. It is not a sandbox, and it does not
contain an agent that has already been compromised. The model below is what
the project does and does not claim.

### What the runtime enforces

**The policy engine.** Every `tools/call` is evaluated before the request
reaches the upstream server. The evaluation order is fixed: the session TTL,
then whether the tool is listed at all, then the rate limit, then the canary
check, then a denial, then an approval requirement, then the argument
constraints. A tool that the policy does not list is refused, so a policy is a
complete description of what may happen rather than a list of exceptions to an
open default.

**Default-deny on the content-relaying methods.** The methods that carry
upstream content to the client -- `resources/*`, `prompts/*` and
`completion/*` -- are refused unless a policy names them in `methods.allow`.
An upstream that has been talked into serving a prompt injection therefore
cannot reach the client through them by default.

**Batch rejection.** A JSON-RPC batch array is refused at the proxy boundary.
A batch must never be a way around the single-request policy checks.

**Name normalisation.** Tool names are normalised with Unicode NFKC before a
rule is looked up, so a full-width or compatibility-character spelling of a
denied name finds the same rule. When two policy rules collide under that
normalisation, the denial wins.

**Argument constraints.** Arguments are checked against the type, length,
pattern and enumeration constraints of the tool rule. An undeclared argument
is refused unless the rule allows undeclared arguments explicitly, and a
value nested deeper than the walker accepts is refused before the walk starts.

**The canary guard.** A canary token is a value planted in the agent's
environment or behind a decoy endpoint, so that its appearance in an outbound
call proves the agent was talked into exfiltrating. A registered token found
in an outbound call is refused even when the policy would otherwise allow the
tool, because the token is the evidence, not the tool. The token itself never
reaches the audit log: the decision text carries a fingerprint of it.

**The path guard.** A path that escapes the working directory, or that names
credential material -- a private key, a cloud credential file, a container
registry credential -- is refused. The sensitive directory names, sensitive
file patterns and system prefixes are policy settings, and `allowed_roots`
confines every path to a chosen root when it is set.

**The regular expression guard.** A policy pattern with a nested quantifier
turns a short client value into minutes of backtracking, and the client is
the one who pays for it while the connection waits. Every pattern is checked
at load time by two independent guards: a static analysis of the standard
library's own parser, which is closed and therefore refuses a construct it
cannot model, and a timed probe that measures the pattern against a
synthetic adversarial value. A pattern can be used anyway by setting
`allow_unsafe_regex: true` on the constraint, which is off by default and is
announced on stderr when the policy is loaded.

**The audit chain.** Every decision becomes one JSON Lines record. Each record
carries the SHA-256 hash of the previous record and, on a keyed log, a
keyed HMAC over its own contents. The plain chain detects a local edit; the
keyed chain detects a whole-file rewrite and the removal of the head of the
log. Checkpoint and key-rotation records live in the same chain. A log that
verifies but carries no keyed signature is reported as `WARN`, and a legacy
unkeyed log is refused where a keyed one is required, because stripping the
keyed fields leaves exactly such a file.

### What the offline half enforces

The same plugins run over a recorded transcript. `check` reports what the
policy would have decided, `policy-lint` reports a policy that is structurally
or semantically wrong, `pin-manifest` freezes a tool surface so that drift can
be detected, `sanitize-output` makes a payload safe to print in a terminal,
and `canary-check` looks for canary tokens in traffic that has already been
recorded.

### Severity and thresholds

Findings carry one of five severities: `INFO`, `LOW`, `MEDIUM`, `HIGH`,
`CRITICAL`. The order is defined explicitly rather than lexically, so that a
threshold such as `fail_on = "HIGH"` means what it says. The built-in default
fails a run at `HIGH` and warns at `MEDIUM`. In the proxy, a plugin finding of
`HIGH` or `CRITICAL` blocks the request.

### Secrets in this repository

The repository ships a hygiene scanner, `check_secrets.py`, which reads the
whole tree -- including itself -- and reports the shape of personal data and
credential material without ever printing the value it found. The shapes it
knows are private key headers, cloud and package-manager access tokens,
credentials assigned to a name, mail addresses on domains that are not
reserved for documentation, and absolute paths into home directories. Names
that RFC 2606 reserves for documentation are allowed, and the scanner holds
no personal identifier of any kind.

## Explicit non-goals

The following are outside the scope of this project. They are stated so that
nobody deploys `mcp-guard` expecting something it does not do.

- **`mcp-guard` is not a sandbox.** It does not confine the agent process, does
  not isolate the filesystem and does not limit what the agent's own code can
  do. It mediates MCP traffic. A tool that runs arbitrary code inside the
  agent's own process is outside what a proxy can decide.
- **It is not an operating-system or container isolation layer.** Use the
  facilities of the platform for that.
- **It is not a network firewall.** The proxy relays to one upstream server
  over stdio. It does not filter the agent's other network traffic.
- **It does not authenticate MCP clients.** It assumes that the process that
  connects to it is the agent it is meant to guard. Authentication belongs in
  front of the proxy.
- **It does not replace the upstream server's own authorization.** A policy
  can only narrow what the upstream would have allowed; it cannot widen it.
- **It is not a general data-loss-prevention system.** It detects a defined
  set of shapes, not arbitrary sensitive data.
- **It does not detect prompt injection in prose.** It detects structural
  shapes -- a path, an escape sequence, a token, a drifted tool surface. It
  does not read English and decide that a sentence is an attack.
- **It does not encrypt the audit log at rest.** The chain makes tampering
  detectable, not unreadable. Protect the log file, and the key file, with
  ordinary file permissions and with whatever the platform offers; the key
  file is created with mode `0600`.
- **It does not defend against a compromised proxy host.** An attacker who
  controls the machine, the process or the key file is outside the model.
- **It is not a certified product.** There is no formal verification of the
  implementation and no third-party security assessment behind this
  document.
