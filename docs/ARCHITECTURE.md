# Architecture

`mcp-guard` is one product with two halves. The **runtime half** is a proxy
that mediates live MCP traffic between a client and an upstream server. The
**offline half** is a scanner that runs the same guard plugins over a recorded
transcript.

The two halves are not two products that happen to ship together. They share
one policy model, one rule catalogue, one severity scale and one set of
plugin objects. The runtime half is the offline half's decision procedure
applied to a stream instead of to a file.

```
                       +-------------------------------+
                       |          the policy          |
                       |  (one model, two front ends)  |
                       +---------------+---------------+
                                       |
             +-------------------------+-------------------------+
             |                                                   |
   +---------v---------+                             +-----------v-----------+
   |  the runtime half |                             |   the offline half   |
   |                   |                             |                      |
   |  proxy            |                             |  GuardEngine         |
   |    |              |                             |    |                 |
   |    +--> PolicyEngine  <---- shared rules --->   |    +--> registry     |
   |    |                                              |          |          |
   |    +--> audit chain                                |          +--> 4 plugins
   |    |                                              |                      |
   |    +--> upstream transport                        |                      |
   +-------------------+------------------------------+----------------------+
                       |
              a decision, and a record of it
```

## The runtime half

The runtime half is a chain of four parts. Each part does one job and hands
a decision to the next.

### The proxy

`mcp_guard.proxy.MCPGuardProxy` is an MCP server that runs on standard input
and output, in front of another MCP server. The upstream is a child process;
its command line is whatever follows `--` on the command line.

The proxy starts the upstream, reads the client's own `initialize` request,
completes the handshake against the upstream within the initialisation
timeout, and then serves the client from a downstream server whose
capabilities mirror the upstream's. From that point on, the client talks to
the proxy and the proxy talks to the upstream.

Two requests are judged. Every other method is either relayed without
judgement, when the policy allows it, or refused.

### The policy engine

`mcp_guard.policy.PolicyEngine` decides whether a call happens. It holds the
loaded policy and the state of the session: the TTL, the per-tool rate
limits, the maximum number of calls, and the canary hook.

`evaluate(tool_name, arguments)` runs the checks in a fixed order, and the
order is part of the contract:

1. **The session TTL.** An expired session refuses everything, including the
   calls it would otherwise allow.
2. **Is the tool listed at all?** A tool that the policy does not list is
   denied. This is the default-deny posture: a policy describes the whole of
   what may happen.
3. **The rate limit.** The limit is checked before the canary, so that a
   client cannot spend its budget probing the argument constraints for free.
4. **The canary hook.** A registered canary token in the outbound arguments
   is refused even when the policy would allow the tool, because the token is
   the evidence rather than the tool.
5. **The rule's action.** An explicit denial wins.
6. **The approval requirement.** A rule that requires an explicit approval
   stops here.
7. **The argument constraints.** The call is counted against the budget
   whether or not the arguments turn out to be acceptable, and then the
   arguments are checked against the rule.

Tool names are normalised with Unicode NFKC before a rule is looked up, so a
full-width or compatibility-character spelling of a denied name finds the same
rule. When two rules collide under that normalisation, the denial wins.

The engine also answers two questions that are not about a single call:
`advertises(tool_name)` says whether a tool may appear in the listing at all,
and `method_allowed(method)` says whether a non-tool MCP method may be
relayed. The methods that carry upstream content to the client --
`resources/*`, `prompts/*` and `completion/*` -- are denied unless a policy
names them explicitly.

### The audit chain

`mcp_guard.audit` writes one JSON Lines record per decision. Every record
carries:

- `timestamp`, `session_id`, `method`, `tool_name`, `arguments`,
  `decision`, `reason` and `upstream_latency_ms` -- what happened;
- `outcome` -- what happened end to end. The `decision` says what the
  policy said; the `outcome` says whether the call was allowed, blocked,
  timed out or answered with an upstream error. A reader of the log must be
  able to tell those apart without parsing the reason text.
- `prev_hash` and `hash` -- the SHA-256 chain, which detects a local edit;
- `chain`, `key_id`, `prev_mac` and `mac` -- the keyed HMAC chain, which
  detects a whole-file rewrite and the removal of the head of the log.

The MAC is computed over the record without the `hash`, `mac` and `prev_mac`
fields, with the previous MAC fed in separately by concatenation. Checkpoint
records and key-rotation records live in the same chain, so a rotation cannot
be used to start a fresh chain without it showing.

Before a record is written, its arguments are redacted and its reason is
scrubbed, so that a credential that reached the message from anywhere at all
does not reach the log. A matched canary token is written as a fingerprint
rather than as the token.

### The upstream transport

`mcp_guard.upstream` owns the child process and the pipes. It reads the
upstream's output as lines and enforces a bound on the length of a single
line. An over-long line is discarded and the request is abandoned, but the
upstream is left running and the next request is served as usual -- one bad
answer does not take the session down.

Every call to the upstream runs under a deadline: `--upstream-timeout` for an
ordinary request and `--upstream-init-timeout` for the handshake. A timeout
is evidence, so it is written to the log like any other decision, with the
outcome that says the upstream never answered.

## The offline half

The offline half is simpler: one engine, one registry, four plugins.

`mcp_guard.core.engine.GuardEngine.check(request)` takes a `CheckRequest` --
the calls, the results and the metadata of a transcript -- and returns a
`CheckReport`. It builds the plugin set, runs every plugin over the request,
runs the policy's custom rules, and applies the policy's thresholds.

`mcp_guard.core.registry` holds the two things that define the plugin set:
`PLUGIN_CLASSES`, which maps a plugin name to its class, and `PLUGIN_ORDER`,
which is the evaluation order. The order runs from the cheapest and most
structural check to the most expensive content inspection:

| Position | Plugin | Rule ids | Checks |
| --- | --- | --- | --- |
| 1 | `etdi_pinning` | `ETDI-001` to `ETDI-009` | that the advertised tool surface still matches its pin manifest |
| 2 | `ansi_sanitize` | `ANSI-001` to `ANSI-008` | terminal escape sequences, overwrite tricks, bidirectional overrides and residual control characters |
| 3 | `path_shape` | `PATH-001` to `PATH-011` | that a path does not escape the working directory and does not name credential material |
| 4 | `canary_exfil` | `CANARY-001` to `CANARY-010` | canary tokens, encoded blobs, credentials in URLs and other signs of exfiltration |

The runtime half uses the same four plugins, but not all four at the same
place. The proxy runs `etdi_pinning` on the tool listing, `path_shape` and
`canary_exfil` on the outbound arguments, and `canary_exfil` and
`ansi_sanitize` on the returned content. The offline engine runs all four
over the whole transcript, because a transcript has no separate argument and
result phases.

## The data flow

### `tools/list`

```
client                      proxy                      upstream
   |                          |                            |
   |--- tools/list ---------->|                            |
   |                          |-- method allowed? --------->|   (no  -> refuse)
   |                          |                            |
   |                          |--- list_tools -------------->|
   |                          |<-- the tool listing --------|
   |                          |                            |
   |                          |  etdi_pinning: has the      |
   |                          |  listing drifted from the   |
   |                          |  pins?  (yes -> refuse)      |
   |                          |                            |
   |                          |  keep the tools the policy |
   |                          |  advertises; hide the rest  |
   |                          |                            |
   |                          |  audit: allow, with the     |
   |                          |  advertised and hidden      |
   |                          |  tool names                |
   |<-- the filtered listing-|                            |
```

The listing is filtered rather than refused: a tool that the policy denies is
simply not advertised, so the client cannot see it and cannot ask for it. The
audit record names both the advertised tools and the hidden ones, so the log
shows what was withheld rather than only what was served.

A pin drift is different. It is reported at `CRITICAL` and refuses the whole
listing, because a surface that has changed underneath the pins is not a
listing with one bad entry in it.

### `tools/call`

```
client                      proxy                      upstream
   |                          |                            |
   |--- tools/call ---------->|                            |
   |                          |                            |
   |                          |  1. a batch array is refused|
   |                          |  2. method allowed?         |
   |                          |  3. PolicyEngine.evaluate() |
   |                          |       ttl, listed, rate,    |
   |                          |       canary, denied,       |
   |                          |       approval, arguments   |
   |                          |                            |
   |                          |  4. path_shape over the     |
   |                          |     arguments              |
   |                          |  5. canary_exfil over the   |
   |                          |     arguments              |
   |                          |                            |
   |                          |--- call_tool --------------->|
   |                          |<-- the result --------------|
   |                          |                            |
   |                          |  6. canary_exfil over the   |
   |                          |     result                 |
   |                          |  7. ansi_sanitize over the  |
   |                          |     result                 |
   |                          |                            |
   |                          |  8. audit                  |
   |<-- the result or the error|                            |
```

Steps 1 to 5 happen before the request reaches the upstream, so a refused
call never leaves the machine. Step 4 and step 5 block on a finding of `HIGH`
or `CRITICAL`; a lower severity is informational in the proxy, and the
offline thresholds decide what it means there.

Step 6 and step 7 happen after the upstream has answered, because a leak can
be in what comes back and not only in what goes out. A canary in the result
refuses the call; a sanitisation only rewrites the text.

Every path out of the handler writes an audit record, including the paths
that end in an error. A timeout is recorded with the outcome that says the
upstream never answered, and an upstream error is recorded with the outcome
that says the upstream failed.

## The plugin contract

A plugin is a class that derives from `mcp_guard.core.plugin.GuardPlugin`.

```python
class GuardPlugin:
    name: str = "base"          # the stable identifier and the policy settings key
    settings_key: str = ""      # the policy block this plugin reads, when it differs
    version: str = "0.0.0"      # bumped independently of the release version
    RULES: dict[str, dict[str, Any]] = {}

    def analyze(self, request) -> list[Finding]:
        """Inspect a request and return findings."""

    def self_test(self) -> list[SelfTestCase]:
        """Run the plugin's own assertions."""
```

The contract has three parts.

**The catalogue.** `RULES` maps a rule id to a severity, an operator-facing
message and a remediation hint. A policy may enable, disable, re-severity or
re-message any rule of the plugin that owns it, without touching code. The
lookup is scoped to the owning plugin, so a custom rule that reuses a
built-in id cannot disable the built-in rule.

**The inspection.** `analyze` receives a `CheckRequest` and returns the
findings. It must not raise for malformed input: a plugin that raises takes
the whole run down, so it returns a finding or nothing. It reads its own
settings through the `PluginContext`, which carries the policy, the settings
block and the home directory that path escapes are measured against.

**The emission.** A plugin does not construct findings directly. It calls
`emit(findings, rule_id, ...)`, which resolves the rule against the policy
and appends nothing when the rule is disabled. That is what makes
`enabled = false` in a policy work, and it keeps the severity override and
the message override in one place.

A new plugin is registered in `PLUGIN_CLASSES` and added to `PLUGIN_ORDER`,
and it carries its own `self_test` cases so that `mcp-guard selftest` covers
it.

## The severity model

There are five severities, in this order:

`INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`

The order is defined explicitly rather than derived from the names, because
the names do not sort into that order lexicographically: `"CRITICAL" < "HIGH" <
"INFO"` as text, which would make a threshold mean the wrong thing.

The severity decides two things.

**What fails a run.** The policy carries `fail_on` and `warn_on`. The
built-in default fails at `HIGH` and warns at `MEDIUM`. A finding below
`warn_on` is reported and does not change the exit code.

**What blocks a request.** In the proxy, a plugin finding of `HIGH` or
`CRITICAL` stops the request. A lower severity is informational there. The
policy engine's own decisions -- deny, allow, approval required, rate
limited, TTL expired -- are a separate vocabulary, because a policy decision
is not a finding and does not carry a severity.

The two vocabularies meet in one place: the audit record's `decision` field
holds the policy engine's answer, and a plugin that blocks a request records
a denial with the finding's message as the reason.

## How the two halves relate

The halves share five things, and each sharing is deliberate.

**The policy model.** The runtime policy and the scan policy are different
documents in different formats, but they are parsed by the same machinery and
they mean the same things: a rule id, an action, a severity, a target. A
policy written for one half is readable by the other, and the plugin settings
blocks have the same names on both sides.

**The plugins.** The same four plugin objects run in both halves. This is
what makes the offline scanner useful: a rule that fires on a recorded
transcript is the rule that will fire on the live traffic.

**The severities.** One scale, one set of names, one ordering, on both sides.
A threshold written in a scan policy means the same thing as a threshold in
a runtime policy.

**The redaction.** The redactor that writes the audit record and the
redactor that shapes the evidence of a finding are the same module. A value
that is kept out of the evidence is kept out of the log.

**The self-test.** The plugins carry their own assertions, and the same
assertions run in `mcp-guard selftest` and in the test suite.

The halves also differ in one important way, and the difference is a
deliberate design decision rather than an accident. The runtime half is
**fail-closed**: when a decision is uncertain, it refuses and says why. The
offline half is **fail-open with a report**: when it cannot decide, it says
so in the finding rather than stopping, because the point of the offline
half is to tell an operator what is in a transcript. A scanner that refused
to finish would not tell an operator anything.

## The module map

| Module | Role |
| --- | --- |
| `mcp_guard.version` | The single source of truth for the version and the channel codename. |
| `mcp_guard.proxy` | The runtime proxy and the handlers that judge the requests. |
| `mcp_guard.policy` | The runtime policy model, the policy engine and the session guard. |
| `mcp_guard.audit` | The hash chain, the keyed HMAC chain and the verification. |
| `mcp_guard.keys` | The key files, the key ring and the key resolution. |
| `mcp_guard.canary` | The canary detector and the exfiltration methods. |
| `mcp_guard.redos` | The load-time guard against a regular expression denial of service. |
| `mcp_guard.upstream` | The upstream process, the pipes and the line bound. |
| `mcp_guard.core.engine` | The offline engine: one request in, one report out. |
| `mcp_guard.core.registry` | The plugin classes and the evaluation order. |
| `mcp_guard.core.plugin` | The plugin contract. |
| `mcp_guard.core.policy` | The scan policy model and the built-in default. |
| `mcp_guard.core.lint` | The policy linter and its diagnostic codes. |
| `mcp_guard.core.manifest` | The ETDI pin manifest. |
| `mcp_guard.core.severity` | The severity scale. |
| `mcp_guard.core.redact` | The redaction of credential material. |
| `mcp_guard.plugins` | The four plugins. |
| `mcp_guard.cli` | The unified command line, one module per command. |
