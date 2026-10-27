"""The guard engine: runs plugins over a request and aggregates findings.

Design notes:

* A crashing plugin must never take the whole run down. Failures are converted
  into ``ENGINE-000`` findings so an audit trail is never silently truncated.
* Evidence is redacted and truncated according to policy before it leaves the
  engine, so downstream consumers (CLI, JSON reports, CI logs) never see raw
  secrets.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Iterator

from .plugin import GuardPlugin
from .policy import Policy, default_policy
from .redact import redact
from .registry import build_plugins
from .request import CheckRequest
from .result import CheckReport, Finding, Verdict
from .severity import Severity
from .textutil import truncate, visible_repr

__all__ = ["GuardEngine", "MAX_CUSTOM_FINDINGS", "MAX_CUSTOM_TARGET_CHARS"]

#: Upper bound on the number of findings a single custom rule may produce.
#:
#: Without a cap a short payload such as ``"a" * 10_000`` against the rule
#: ``regex = "a"`` would produce ten thousand findings and turn a single
#: policy mistake into a denial of service (AUD-18).
MAX_CUSTOM_FINDINGS = 1000

#: Upper bound on the number of characters a custom rule scans per target.
#:
#: Bounding the scanned text keeps a pathological pattern from running over an
#: unbounded payload (AUD-18).
MAX_CUSTOM_TARGET_CHARS = 1_000_000


class GuardEngine:
    """Evaluate a :class:`CheckRequest` against a policy with a plugin set."""

    def __init__(
        self,
        policy: Policy | None = None,
        plugins: Iterable[GuardPlugin] | None = None,
        plugin_names: Iterable[str] | None = None,
    ) -> None:
        self.policy = policy if policy is not None else default_policy()
        if plugins is not None:
            self.plugins = list(plugins)
        else:
            self.plugins = build_plugins(self.policy, plugin_names)

    # -- public API -------------------------------------------------------
    def check(self, request: CheckRequest) -> CheckReport:
        """Run every plugin plus the policy's custom rules over ``request``."""
        findings: list[Finding] = []

        for plugin in self.plugins:
            try:
                produced = plugin.analyze(request) or []
            except Exception as exc:  # pragma: no cover - defensive
                # A crashed plugin means a guard did *not* run.  Reporting that
                # as a low-severity note would let the report claim "PASS"
                # while a protection was silently missing, so the failure is
                # raised to HIGH and forces a failing verdict (AUD-07).
                findings.append(
                    Finding(
                        rule_id="ENGINE-000",
                        plugin=plugin.name,
                        severity=Severity.HIGH,
                        message=(
                            f"plugin '{plugin.name}' failed: {type(exc).__name__}: {exc}"
                        ),
                        metadata={"plugin_error": True},
                    )
                )
                continue
            findings.extend(produced)

        findings.extend(self._custom_findings(request))

        processed = [self._finalize(finding) for finding in findings]
        processed.sort(key=lambda item: (-item.severity.rank, item.plugin, item.rule_id))

        verdict = self._verdict(processed)
        stats: dict[str, Any] = {
            "agent": request.agent,
            "calls": len(request.calls),
            "results": len(request.results),
            "transcript_chars": len(request.transcript),
            "plugins": [plugin.name for plugin in self.plugins],
            "metadata_keys": sorted(request.metadata.keys()),
        }
        return CheckReport(
            findings=processed,
            verdict=verdict,
            policy_name=self.policy.name,
            policy_version=self.policy.version,
            stats=stats,
        )

    def check_dict(self, document: dict[str, Any]) -> CheckReport:
        """Convenience wrapper: build a request from ``document`` and check it."""
        return self.check(CheckRequest.from_dict(document))

    # -- internals --------------------------------------------------------
    def _verdict(self, findings: list[Finding]) -> Verdict:
        if not findings:
            return Verdict.PASS
        # A plugin that crashed means the scan is incomplete, so the run can
        # never be reported as a pass -- whatever the policy thresholds say
        # (AUD-07).
        if any(finding.rule_id == "ENGINE-000" for finding in findings):
            return Verdict.FAIL
        highest = max(finding.severity for finding in findings)
        if highest >= self.policy.fail_on:
            return Verdict.FAIL
        if highest >= self.policy.warn_on:
            return Verdict.WARN
        return Verdict.PASS

    def _finalize(self, finding: Finding) -> Finding:
        evidence = finding.evidence or ""
        if evidence:
            if self.policy.redact_evidence:
                evidence = redact(evidence)
            evidence = truncate(
                visible_repr(evidence, max(self.policy.max_evidence_chars, 16)),
                max(self.policy.max_evidence_chars, 16),
            )
        metadata = finding.metadata or {}
        if metadata and self.policy.redact_evidence:
            # The metadata dictionary is copied verbatim into the report, so
            # it needs the same redaction as the evidence (AUD-06).
            metadata = {
                key: redact(value) if isinstance(value, str) else value
                for key, value in metadata.items()
            }
        return Finding(
            rule_id=finding.rule_id,
            plugin=finding.plugin,
            severity=finding.severity,
            message=finding.message,
            evidence=evidence,
            location=finding.location,
            remediation=finding.remediation,
            metadata=metadata,
        )

    def _custom_findings(self, request: CheckRequest) -> list[Finding]:
        findings: list[Finding] = []
        for spec in self.policy.rules:
            if not spec.enabled or not spec.regex:
                continue
            try:
                pattern = re.compile(spec.regex)
            except re.error:  # pragma: no cover - validated at load time
                continue
            for location, text in _custom_targets(request, spec.target):
                if len(findings) >= MAX_CUSTOM_FINDINGS:
                    break
                for match in _bounded_finditer(pattern, text):
                    findings.append(
                        Finding(
                            rule_id=spec.id,
                            plugin=spec.plugin or "custom",
                            severity=spec.severity,
                            message=spec.message or f"custom rule {spec.id} matched",
                            evidence=match.group(0),
                            location=location,
                            remediation="Review the custom policy rule and the matched payload.",
                            metadata={"custom": True, "target": spec.target},
                        )
                    )
                    if len(findings) >= MAX_CUSTOM_FINDINGS:
                        break
        return findings


def _custom_targets(request: CheckRequest, target: str) -> list[tuple[str, str]]:
    """Return ``(location, text)`` pairs for a custom rule target."""
    pairs: list[tuple[str, str]] = []
    want_arguments = target in ("any", "arguments", "calls")
    want_content = target in ("any", "content", "results")
    want_transcript = target in ("any", "transcript")

    if want_arguments:
        for index, call in enumerate(request.calls):
            pairs.append((f"calls[{index}].arguments", call.arguments_text()))
    if want_content:
        for index, result in enumerate(request.results):
            pairs.append((f"results[{index}].content", result.content))
    if want_transcript:
        pairs.append(("transcript", request.transcript))
    return pairs


def _bounded_finditer(pattern: re.Pattern, text: str) -> Iterator[re.Match]:
    """Yield regex matches up to bounded text length, skipping catastrophic ReDoS patterns."""
    from ..redos import describe_risk

    if describe_risk(pattern.pattern) is not None:
        return
    text = text[:MAX_CUSTOM_TARGET_CHARS]
    yield from pattern.finditer(text)

