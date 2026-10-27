"""The embedded smoke test behind ``mcp-guard selftest``.

A release that cannot say whether it works is not a release.  This module
carries twelve vectors that exercise the properties the 0.5 line is actually
sold on, and runs them in well under a second:

* the **scalar** traversal -- a path that climbs out of its prefix is refused;
* the **list** traversal -- the same path, hidden in a list, is refused too
  (this is what 0.5 added and 0.4 did not have);
* the **audit log integrity** around U+2028 -- a Unicode line separator in a
  client value must not cut a record in half, and the log must still verify;
* the **budget** -- a session that runs out of calls is refused, and a call
  that was refused still costs the client its attempt;
* the **oversize upstream line** -- a line over the bound is discarded, and
  the buffer that holds it never grows.

Everything runs **in process**: there is no upstream server to start, no
socket, no subprocess.  That is what keeps the whole thing under a second and
what makes it usable as a container health check or a CI gate.

Every vector is independent: it builds its own engine, its own audit log and
its own temporary directory, so one vector that fails never hides another.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .audit import STATUS_OK, AuditLog, verify_log
from .keys import AuditKey
from .policy import (
    ALLOW,
    DENY,
    RATE_LIMITED,
    Policy,
    PolicyEngine,
    PolicyError,
    ToolRule,
    load_policy,
)
from .proxy import UPSTREAM_OVERSIZE_CODE, UPSTREAM_TIMEOUT_CODE
from .upstream import LineSplitter, OversizeLine

#: The character that cut an audit record in half before the 0.4.1 fix.
#: ``canonical_json`` writes it literally (``ensure_ascii=False``), and
#: ``str.splitlines()`` honours it -- so a log that is split with it loses a
#: record.
U2028 = "\u2028"

#: The policy the vectors run against.  It is built as a document rather than
#: loaded from a file, so the selftest needs nothing but itself.
POLICY_DOCUMENT: dict[str, Any] = {
    "version": 1,
    "default_action": "deny",
    "tools": {
        "read_file": {
            "action": "allow",
            "arguments": {
                "path": {
                    "type": "string",
                    "required": True,
                    "path_prefix": "./workspace",
                }
            },
        },
        "read_files": {
            "action": "allow",
            "arguments": {
                "files": {
                    "type": "array",
                    "required": True,
                    "path_prefix": "./workspace",
                }
            },
        },
        "read_note": {
            "action": "allow",
            "arguments": {
                "note": {"type": "string", "required": True},
                "mode": {"type": "string", "enum": ["short", "long"]},
            },
        },
        "ping": {
            "action": "allow",
            "max_calls": 2,
        },
        "strict_ping": {
            "action": "allow",
            "max_calls": 1,
            "arguments": {
                "name": {"type": "string", "required": True, "regex": "^ok$"},
            },
        },
        "run_shell": {
            "action": "deny",
            "reason": "shell access is not permitted by policy",
        },
    },
}


@dataclass(frozen=True)
class VectorResult:
    """The outcome of one vector."""

    name: str
    group: str
    description: str
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        """The result as a JSON friendly mapping."""
        return {
            "name": self.name,
            "group": self.group,
            "description": self.description,
            "ok": self.ok,
            "detail": self.detail,
        }


@dataclass
class SelfTestReport:
    """The outcome of every vector of one run."""

    vectors: list[VectorResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def passed(self) -> list[VectorResult]:
        """The vectors that passed."""
        return [vector for vector in self.vectors if vector.ok]

    @property
    def failed(self) -> list[VectorResult]:
        """The vectors that failed."""
        return [vector for vector in self.vectors if not vector.ok]

    @property
    def ok(self) -> bool:
        """Did every vector pass?"""
        return not self.failed

    @property
    def exit_code(self) -> int:
        """0 when every vector passed, 1 when one did not."""
        return 0 if self.ok else 1

    def as_dict(self) -> dict[str, Any]:
        """The report as a JSON friendly mapping."""
        return {
            "tool": "mcp-guard selftest",
            "version": __version__,
            "ok": self.ok,
            "passed": len(self.passed),
            "failed": len(self.failed),
            "duration_ms": round(self.duration_ms, 3),
            "vectors": [vector.as_dict() for vector in self.vectors],
        }


def _engine(base_dir: Path) -> PolicyEngine:
    """A fresh engine over the selftest policy."""
    policy = Policy.model_validate(POLICY_DOCUMENT)
    return PolicyEngine(policy, session_id="selftest", base_dir=base_dir)


def _key() -> AuditKey:
    """The audit key of the selftest.

    It is a fixed, published, throw-away value: the selftest writes into a
    temporary directory that is deleted afterwards, and a key that never
    leaves the process cannot be a secret that leaks.  The key is deterministic
    so that the selftest is reproducible, but it MUST NOT be used for any log
    that outlives the test run -- anyone who reads this source can forge a
    chain signed with it.
    """
    return AuditKey.from_material(b"mcp-guard-selftest-key-0123456789abcdef")


# -- the vectors ------------------------------------------------------------

def _vector_scalar_traversal_denied(base: Path) -> tuple[bool, str]:
    """A scalar path that climbs out of its prefix is refused."""
    engine = _engine(base)
    decision = engine.evaluate("read_file", {"path": "../../etc/passwd"})
    if decision.decision != DENY:
        return False, f"expected a refusal, got {decision.decision!r}"
    if not decision.violations:
        return False, "the refusal carried no violation to explain it"
    return True, decision.violations[0]


def _vector_scalar_path_allowed(base: Path) -> tuple[bool, str]:
    """A scalar path that stays inside its prefix is allowed."""
    engine = _engine(base)
    decision = engine.evaluate("read_file", {"path": "workspace/notes.txt"})
    if decision.decision != ALLOW:
        return False, f"expected an allow, got {decision.decision!r}: {decision.reason}"
    return True, "the path stays inside ./workspace"


def _vector_list_traversal_denied(base: Path) -> tuple[bool, str]:
    """The same traversal, hidden in a list, is refused (the 0.5 property)."""
    engine = _engine(base)
    decision = engine.evaluate(
        "read_files", {"files": ["workspace/notes.txt", "../../etc/passwd"]}
    )
    if decision.decision != DENY:
        return False, f"expected a refusal, got {decision.decision!r}"
    if not any("files[1]" in violation for violation in decision.violations):
        return False, f"the refusal did not name the offending element: {decision.violations!r}"
    return True, decision.violations[0]


def _vector_list_paths_allowed(base: Path) -> tuple[bool, str]:
    """A list of paths that all stay inside the prefix is allowed."""
    engine = _engine(base)
    decision = engine.evaluate(
        "read_files", {"files": ["workspace/a.txt", "workspace/b.txt", "workspace/c.txt"]}
    )
    if decision.decision != ALLOW:
        return False, f"expected an allow, got {decision.decision!r}: {decision.reason}"
    return True, "all three elements stay inside ./workspace"


def _vector_list_element_type_denied(base: Path) -> tuple[bool, str]:
    """An element of the wrong type is a violation, not a skipped element."""
    engine = _engine(base)
    decision = engine.evaluate("read_files", {"files": ["workspace/a.txt", 42]})
    if decision.decision != DENY:
        return False, f"expected a refusal, got {decision.decision!r}"
    if not any("files[1]" in violation for violation in decision.violations):
        return False, f"the refusal did not name the offending element: {decision.violations!r}"
    return True, decision.violations[0]


def _vector_u2028_audit_log_verifies(base: Path) -> tuple[bool, str]:
    """A U+2028 in a client value must not cut the audit record in half."""
    log_path = base / "audit-u2028.jsonl"
    key = _key()
    with AuditLog(log_path, "selftest-u2028", key=key, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="read_note",
            arguments={"note": f"before{U2028}after"},
            decision="allow",
            reason="allowed by policy",
        )
    text = log_path.read_text(encoding="utf-8")
    if U2028 not in text:
        return False, "the separator did not reach the log literally"
    result = verify_log(log_path, key=key)
    if result.status != STATUS_OK:
        return False, f"the log did not verify: {result.status}: {result.reason}"
    if result.records != 1:
        return False, f"expected one record, got {result.records}"
    return True, "the record stayed whole and the chain verifies"


def _vector_u2028_refusal_record_verifies(base: Path) -> tuple[bool, str]:
    """The record of a *refusal* that quotes U+2028 must verify as well."""
    engine = _engine(base)
    decision = engine.evaluate("read_note", {"note": f"before{U2028}after", "mode": "nope"})
    if decision.decision != DENY:
        return False, f"expected a refusal, got {decision.decision!r}"
    if U2028 in decision.reason:
        return False, "the refusal reason carries a raw line separator"
    log_path = base / "audit-u2028-refusal.jsonl"
    key = _key()
    with AuditLog(log_path, "selftest-u2028-refusal", key=key, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="read_note",
            arguments={"note": f"before{U2028}after", "mode": "nope"},
            decision=decision.decision,
            reason=decision.reason,
        )
    result = verify_log(log_path, key=key)
    if result.status != STATUS_OK:
        return False, f"the log did not verify: {result.status}: {result.reason}"
    return True, "the refusal is quoted escaped and the log still verifies"


def _vector_budget_exhaustion(base: Path) -> tuple[bool, str]:
    """A session that runs out of calls is refused, not served."""
    engine = _engine(base)
    first = engine.evaluate("ping", {})
    second = engine.evaluate("ping", {})
    third = engine.evaluate("ping", {})
    if first.decision != ALLOW or second.decision != ALLOW:
        return False, f"the first two calls were not allowed: {first.decision}, {second.decision}"
    if third.decision != RATE_LIMITED:
        return False, f"expected the cap to refuse the third call, got {third.decision!r}"
    return True, third.reason


def _vector_refused_call_is_charged(base: Path) -> tuple[bool, str]:
    """A call that was refused for a bad argument still costs the attempt."""
    engine = _engine(base)
    refused = engine.evaluate("strict_ping", {"name": "not-ok"})
    if refused.decision != DENY:
        return False, f"expected a refusal, got {refused.decision!r}"
    if engine.guard.calls_for("strict_ping") != 1:
        return False, (
            f"the refused call was not charged: {engine.guard.calls_for('strict_ping')} attempt(s)"
        )
    afterwards = engine.evaluate("strict_ping", {"name": "ok"})
    if afterwards.decision != RATE_LIMITED:
        return False, f"expected the budget to be spent, got {afterwards.decision!r}"
    return True, "the refused call was charged and the budget is spent"


def _vector_oversize_line_discarded(base: Path) -> tuple[bool, str]:
    """A line over the bound is discarded and reported."""
    splitter = LineSplitter(max_chars=100)
    results = splitter.feed("x" * 500)
    oversize = [item for item in results if isinstance(item, OversizeLine)]
    if not oversize:
        return False, "the oversize line was not reported"
    if oversize[0].chars < 100:
        return False, f"the report undercounts the line: {oversize[0].chars} characters"
    if "".join(item for item in results if isinstance(item, str)):
        return False, "the oversize line was also handed on as a line"
    return True, f"the line was discarded after {oversize[0].chars} characters"


def _vector_oversize_buffer_bounded(base: Path) -> tuple[bool, str]:
    """The buffer that holds an oversize line never grows without bound."""
    splitter = LineSplitter(max_chars=100)
    splitter.feed("x" * 100_000)
    if len(splitter.buffer) > 100:
        return False, f"the buffer grew to {len(splitter.buffer)} characters"
    if splitter.discarded < 100_000:
        return False, f"only {splitter.discarded} characters were counted as discarded"
    if UPSTREAM_OVERSIZE_CODE == UPSTREAM_TIMEOUT_CODE:
        return False, "the oversize line and the timeout share one error code"
    return True, (
        f"the buffer stayed at {len(splitter.buffer)} characters, "
        f"{splitter.discarded} discarded, error code {UPSTREAM_OVERSIZE_CODE}"
    )


def _vector_r01_pattern_refused(base: Path) -> tuple[bool, str]:
    """A nested quantifier is refused when the policy is loaded."""
    policy_path = base / "policy-redos.yaml"
    policy_path.write_text(
        "version: 1\n"
        "default_action: deny\n"
        "tools:\n"
        "  read_file:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      path:\n"
        "        type: string\n"
        "        regex: '(a+)+'\n",
        encoding="utf-8",
    )
    try:
        load_policy(policy_path)
    except PolicyError as exc:
        if "denial-of-service risk" not in str(exc):
            return False, f"the policy was refused for the wrong reason: {exc}"
        return True, "the nested quantifier was refused at load time"
    return False, "the nested quantifier was accepted"


def _vector_canary_exfil_denied(base: Path) -> tuple[bool, str]:
    """A registered canary token in an outbound call is refused."""
    from .canary import CanaryGuardHook, NativeCanaryDetector

    detector = NativeCanaryDetector(registered_tokens=["CNR-selftest-canary-token-alpha"])
    policy = Policy(tools={"echo": ToolRule(action="allow")})
    engine = PolicyEngine(policy, "selftest", canary_hook=CanaryGuardHook(detector))
    decision = engine.evaluate("echo", {"body": "hello CNR-selftest-canary-token-alpha"})
    if decision.decision != "deny":
        return False, f"canary token was not denied: decision was {decision.decision}"
    return True, "canary token leak was intercepted and refused with deny"


def _vector_audit_keyed_chain(base: Path) -> tuple[bool, str]:
    """Keyed HMAC audit log creates an unbroken, verifiable hash chain."""
    from .audit import STATUS_OK, AuditLog, verify_log

    log_path = base / "audit-selftest.jsonl"
    test_key = b"selftest-audit-hmac-key-01234567"
    writer = AuditLog(log_path, "selftest-session", key=test_key, warn=False)
    writer.append(
        method="tools/call",
        tool_name="read_file",
        arguments={"path": "sandbox/ok.txt"},
        decision="allow",
        reason="ok",
    )
    writer.checkpoint(final=True)
    writer.close()
    result = verify_log(log_path, key=test_key)
    if result.status != STATUS_OK:
        return False, f"keyed audit log verification failed with status {result.status}"
    return True, "keyed HMAC audit log verified clean"


def _vector_four_plugins_smoke(base: Path) -> tuple[bool, str]:
    """The four guard plugins detect path escapes, ANSI injection, canary exfiltration and pin drift."""
    from .core.plugin import PluginContext
    from .core.policy import default_policy as def_pol
    from .core.request import CheckRequest, ToolCall
    from .plugins.ansi_sanitize import sanitize_text
    from .plugins.canary_exfil import CanaryExfilPlugin
    from .plugins.etdi_pinning import ETDIPinningPlugin
    from .plugins.path_shape import PathShapePlugin

    ctx = PluginContext(policy=def_pol(), settings={}, home_dir=str(base))

    # 1. path_shape: a traversal out of the working directory.
    path_findings = PathShapePlugin(ctx).analyze(
        CheckRequest(calls=[ToolCall(tool="read_file", arguments={"path": "../../etc/passwd"})])
    )
    if not any(f.rule_id.startswith("PATH-") for f in path_findings):
        return False, "path_shape failed to detect a traversal"

    # 2. ansi_sanitize: an escape sequence is stripped.
    cleaned = sanitize_text("text\x1b[31mred\x1b[0m").text
    if "\x1b" in cleaned:
        return False, "ansi_sanitize failed to strip escape codes"

    # 3. canary_exfil: a canary marker in an outbound call is detected.
    canary_findings = CanaryExfilPlugin(ctx).analyze(
        CheckRequest(calls=[ToolCall(tool="test", arguments={"data": "CANARY-1122-3344"})])
    )
    if not any(f.rule_id.startswith("CANARY-") for f in canary_findings):
        return False, "canary_exfil failed to detect a canary marker"

    # 4. etdi_pinning: a tool surface that drifts from its pins is detected.
    etdi_findings = ETDIPinningPlugin(ctx).analyze(
        CheckRequest(
            metadata={
                "etdi": {
                    "server": {"name": "workspace", "version": "1.0.0"},
                    "tools": [{"name": "read_file", "inputSchema": {"type": "object"}}],
                },
                "pins": {
                    "server": {"name": "workspace", "version": "1.0.0"},
                    "tools": [{"name": "other_tool", "inputSchema": {"type": "object"}}],
                },
            }
        )
    )
    if not any(f.rule_id.startswith("ETDI-") for f in etdi_findings):
        return False, "etdi_pinning failed to detect a pin drift"

    return True, "the four guard plugins are operational"


#: The twelve vectors of the selftest, in the order they are run.
VECTORS: tuple[tuple[str, str, str, Callable[[Path], tuple[bool, str]]], ...] = (
    (
        "scalar-traversal-denied",
        "path",
        "a scalar path that climbs out of its prefix is refused",
        _vector_scalar_traversal_denied,
    ),
    (
        "scalar-path-allowed",
        "path",
        "a scalar path that stays inside its prefix is allowed",
        _vector_scalar_path_allowed,
    ),
    (
        "list-traversal-denied",
        "path",
        "the same traversal, hidden in a list, is refused",
        _vector_list_traversal_denied,
    ),
    (
        "list-paths-allowed",
        "path",
        "a list of paths that all stay inside the prefix is allowed",
        _vector_list_paths_allowed,
    ),
    (
        "list-element-type-denied",
        "path",
        "an element of the wrong type is a violation, not a skipped element",
        _vector_list_element_type_denied,
    ),
    (
        "u2028-audit-log-verifies",
        "audit",
        "a U+2028 in a client value does not cut the audit record in half",
        _vector_u2028_audit_log_verifies,
    ),
    (
        "u2028-refusal-record-verifies",
        "audit",
        "the record of a refusal that quotes U+2028 verifies as well",
        _vector_u2028_refusal_record_verifies,
    ),
    (
        "budget-exhaustion",
        "budget",
        "a session that runs out of calls is refused",
        _vector_budget_exhaustion,
    ),
    (
        "refused-call-is-charged",
        "budget",
        "a call that was refused still costs the client its attempt",
        _vector_refused_call_is_charged,
    ),
    (
        "oversize-line-discarded",
        "upstream",
        "a line over the bound is discarded and reported",
        _vector_oversize_line_discarded,
    ),
    (
        "oversize-buffer-bounded",
        "upstream",
        "the buffer that holds an oversize line never grows without bound",
        _vector_oversize_buffer_bounded,
    ),
    (
        "r01-pattern-refused",
        "regex",
        "a nested quantifier is refused when the policy is loaded",
        _vector_r01_pattern_refused,
    ),
    (
        "canary-exfil-denied",
        "canary",
        "a registered canary token in an outbound call is refused",
        _vector_canary_exfil_denied,
    ),
    (
        "audit-keyed-chain",
        "audit",
        "a keyed HMAC audit log creates an unbroken chain",
        _vector_audit_keyed_chain,
    ),
    (
        "four-plugins-smoke",
        "plugins",
        "the 4-plugin engine inspects paths, ansi, canary and etdi",
        _vector_four_plugins_smoke,
    ),
)


def run_selftest() -> SelfTestReport:
    """Run every vector and return the report."""
    started = time.perf_counter()
    report = SelfTestReport()
    with tempfile.TemporaryDirectory(prefix="mcp-guard-selftest-") as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        for name, group, description, vector in VECTORS:
            try:
                ok, detail = vector(base)
            except Exception as exc:  # a vector that raises has failed, not crashed
                ok, detail = False, f"the vector raised {type(exc).__name__}: {exc}"
            report.vectors.append(
                VectorResult(name=name, group=group, description=description, ok=ok, detail=detail)
            )
    report.duration_ms = (time.perf_counter() - started) * 1000.0
    return report


def render_human(report: SelfTestReport) -> str:
    """The report as the text an operator reads."""
    lines = [
        f"mcp-guard selftest: {len(report.vectors)} vector(s), "
        f"{len(report.passed)} passed, {len(report.failed)} failed "
        f"in {report.duration_ms:.1f}ms"
    ]
    for vector in report.vectors:
        status = "OK  " if vector.ok else "FAIL"
        lines.append(f"  {status} {vector.group}/{vector.name}")
        lines.append(f"          {vector.description}")
        if vector.detail:
            lines.append(f"          {vector.detail}")
    if report.ok:
        lines.append("  all vectors passed")
    else:
        lines.append(f"  {len(report.failed)} vector(s) failed")
    return "\n".join(lines)
