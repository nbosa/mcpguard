# Architecture — mcp-guard v0.6.0

> Simplified Chinese: [../zh-CN/architecture.md](../zh-CN/architecture.md)

## 1. Design goals

mcp-guard is built around five constraints:

1. **One engine, many capabilities.** Guard logic lives in plugins; the engine
   only orchestrates. Adding a capability never means touching the engine.
2. **Deterministic.** The same input always produces the same findings, in the
   same order, with the same identifiers. Auditing requires reproducibility.
3. **Side-effect free.** No filesystem access, no network, no `stat`, no
   symlink resolution. The guard must be safe to run on hostile input.
4. **Policy-driven.** Severity, thresholds, enabled rules and plugin behaviour
   are all data, not code.
5. **No crash becomes a blind spot.** A plugin that raises is converted into an
   `ENGINE-000` finding so the audit trail is never silently truncated.

## 2. Package layout

```
src/mcp_guard/
├── __init__.py            public API re-exports
├── __main__.py            `python -m mcp_guard`
├── version.py             single source of truth for the version
├── core/
│   ├── severity.py        ordered severity model
│   ├── result.py          Finding / Verdict / CheckReport
│   ├── request.py         ToolCall / ToolResult / CheckRequest
│   ├── textutil.py        canonical JSON, hashing, entropy
│   ├── redact.py          evidence redaction
│   ├── policy.py          policy model + TOML loader
│   ├── lint.py            policy linter
│   ├── plugin.py          plugin base class, rule resolution
│   ├── registry.py        plugin registry
│   ├── engine.py          GuardEngine
│   ├── etdi.py            ETDI document schema
│   ├── manifest.py        ETDI pin manifest
│   └── samples.py         built-in sample payloads
├── plugins/
│   ├── etdi_pinning.py
│   ├── ansi_sanitize.py
│   ├── path_shape.py
│   └── canary_exfil.py
├── cli/
│   ├── main.py            argparse dispatcher
│   ├── common.py          shared CLI helpers
│   ├── output.py          rendering + exit codes
│   └── cmd_*.py           one module per subcommand
└── data/
    └── default_policy.toml
```

`core/` never imports from `plugins/` except through `registry.py`, and plugins
never import each other. This keeps the dependency graph a tree.

## 3. The request model

Everything a guard run may inspect is normalised into a `CheckRequest`:

```python
@dataclass
class CheckRequest:
    agent: str
    calls: list[ToolCall]      # agent -> tool invocations
    results: list[ToolResult]  # tool -> agent payloads
    transcript: str            # free-form conversational text
    metadata: dict             # etdi, pins, egress_tools, ...
```

`CheckRequest.from_dict()` accepts several transcript dialects:

| Input | Meaning |
| --- | --- |
| `calls` / `tool_calls` | tool invocations |
| `results` / `tool_results` | tool payloads |
| `messages` | collapsed into `transcript` |
| `metadata.etdi`, `metadata.pins` | ETDI document and pin manifest |
| `metadata.etdi_path`, `metadata.pins_path` | same, read from disk |

Keeping one normalised shape means plugins never have to know where a payload
came from.

## 4. The engine

```python
engine = GuardEngine(policy=policy)          # default policy
engine = GuardEngine(policy=policy, plugin_names=["path_shape"])
report = engine.check(CheckRequest.from_dict(document))
```

`GuardEngine.check()` performs five steps:

1. **Run plugins.** Each plugin returns a list of `Finding`. Exceptions are
   caught and turned into `ENGINE-000`.
2. **Run custom rules.** Policy rules that declare a `regex` are evaluated
   against call arguments, result content and the transcript, according to
   their `target`.
3. **Redact.** Evidence passes through `core.redact.redact()`, which replaces
   known credential material with `<redacted:kind>` markers.
4. **Truncate.** Evidence is capped at `settings.max_evidence_chars` and
   control characters are escaped so the report is safe to print.
5. **Decide.** The verdict is `FAIL` when the highest severity reaches
   `fail_on`, `WARN` when it reaches `warn_on`, otherwise `PASS`.

Findings are sorted by severity (descending), then plugin, then rule id — a
stable order that diffs cleanly between runs.

## 5. The plugin contract

```python
class GuardPlugin:
    name: str            # "path_shape"
    settings_key: str    # "path" - the [settings.path] policy block
    version: str
    RULES: dict[str, dict]   # rule catalogue

    def analyze(self, request) -> list[Finding]: ...
    def self_test(self) -> list[SelfTestCase]: ...
```

Each plugin owns a catalogue of rules:

```python
RULES = {
    "PATH-001": {
        "severity": "CRITICAL",
        "message": "Path escapes the home/base directory",
        "remediation": "Confine filesystem access to the working tree; ...",
    },
}
```

A policy override for the same id replaces `enabled`, `severity` and
`message`. The plugin never sees the policy's raw structure — it asks for a
resolved rule:

```python
rule = self.rule("PATH-001")
if not rule.enabled:
    return []
```

`self.emit(findings, "PATH-001", evidence=..., location=...)` builds the
finding with the resolved severity and returns `None` when the rule is
disabled, so plugins stay short.

### Settings lookup

`settings_key` decouples the plugin name from the policy block name:
`path_shape` reads `[settings.path]`, `etdi_pinning` reads `[settings.etdi]`.
`Policy.plugin_settings()` accepts either spelling, so callers do not have to
know which one a plugin uses.

## 6. Adding a plugin

1. Create `src/mcp_guard/plugins/<name>.py` with a `GuardPlugin` subclass.
2. Declare `name`, `settings_key`, `version` and `RULES`.
3. Implement `analyze()`.
4. Register it in `core/registry.py` (`PLUGIN_CLASSES` and `PLUGIN_ORDER`).
5. Add a `[settings.<key>]` block to the default policy.
6. Write tests and a `self_test()` method.

The engine, the CLI and the linter pick it up automatically. `policy-lint`
learns the new rule ids from the plugin catalogue, so an override referring to
a non-existent rule is caught as `POL-006`.

## 7. Data flow for a typical CI run

```
$ mcp-guard check transcript.json --format json
  │
  ├─ parse transcript            core/request.py
  ├─ load policy                 core/policy.py
  ├─ run 4 plugins               plugins/*.py
  ├─ run custom rules            core/engine.py
  ├─ redact + truncate           core/redact.py, core/textutil.py
  ├─ compute verdict             core/engine.py
  └─ render + exit code          cli/output.py
```

Exit code `1` on `FAIL` makes the command a drop-in CI gate.
