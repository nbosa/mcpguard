"""mcp-guard: unified security guardrails for Model Context Protocol agents.

This package is the single, merged release of two previously separate trees.

**The runtime half** is a policy-enforcing stdio proxy:

* :class:`~mcp_guard.proxy.MCPGuardProxy` sits between an MCP client and one
  upstream MCP server, evaluates every ``tools/call`` against a policy, and
  filters ``tools/list`` so a denied tool is never advertised;
* :class:`~mcp_guard.audit.AuditLog` writes a tamper-evident, keyed
  HMAC-SHA256 audit chain;
* :mod:`mcp_guard.policy` is the runtime policy engine, :mod:`mcp_guard.redos`
  the load-time regular-expression safety guard, :mod:`mcp_guard.canary` the
  outbound canary-exfiltration detector.

**The offline half** is a transcript and manifest scanner:

* :class:`~mcp_guard.core.engine.GuardEngine` runs four modular plugins --
  ``etdi_pinning``, ``ansi_sanitize``, ``path_shape`` and ``canary_exfil`` --
  over a recorded transcript;
* :func:`~mcp_guard.core.manifest.build_pin_manifest` freezes and verifies the
  tool surface an ETDI document describes.

Both halves are pure Python 3.11+ standard library: the package has **no
runtime dependencies**.  The MCP SDK is needed only to actually speak the
protocol, and even then only for the ``proxy`` subcommand.

Typical use::

    from mcp_guard import GuardEngine, CheckRequest

    engine = GuardEngine()
    report = engine.check(CheckRequest.from_dict(transcript))
    if not report.ok:
        ...
"""

from __future__ import annotations

from typing import Any

from . import redact
from .audit import AuditLog, AuditError, VerifyResult, verify_log
from .canary import CanaryGuardHook, CanaryHook, NativeCanaryDetector
from .core.engine import GuardEngine
from .core.etdi import parse_etdi, validate_etdi
from .core.manifest import build_pin_manifest, verify_pin_manifest
from .core.plugin import GuardPlugin, PluginContext, SelfTestCase
from .core.policy import (
    Policy as ScanPolicy,
    PolicyError as ScanPolicyError,
    PolicyIssue,
    default_policy,
    load_policy_text,
    parse_policy,
)
from .core.registry import PLUGIN_ORDER, plugin_metadata
from .core.request import CheckRequest, ToolCall, ToolResult
from .core.result import CheckReport, Finding, Verdict
from .core.severity import Severity
from .policy import ALLOW, DENY, Decision, Policy, PolicyEngine, load_policy
from .redact import redact_arguments, scrub_reason
from .version import RELEASE_CODENAME, VERSION, VERSION_STRING, __version__

__all__ = [
    "VERSION",
    "VERSION_STRING",
    "__version__",
    "RELEASE_CODENAME",
    # -- runtime half ----------------------------------------------------
    "ALLOW",
    "DENY",
    "Decision",
    "Policy",
    "PolicyEngine",
    "load_policy",
    "AuditLog",
    "AuditError",
    "VerifyResult",
    "verify_log",
    "CanaryGuardHook",
    "CanaryHook",
    "NativeCanaryDetector",
    "redact_arguments",
    "scrub_reason",
    # -- offline half ----------------------------------------------------
    "Severity",
    "Verdict",
    "Finding",
    "CheckReport",
    "ScanPolicy",
    "ScanPolicyError",
    "PolicyIssue",
    "default_policy",
    "load_scan_policy",
    "parse_policy",
    "CheckRequest",
    "ToolCall",
    "ToolResult",
    "GuardEngine",
    "GuardPlugin",
    "PluginContext",
    "SelfTestCase",
    "PLUGIN_ORDER",
    "plugin_metadata",
    "build_pin_manifest",
    "verify_pin_manifest",
    "parse_etdi",
    "validate_etdi",
    "redact",
    # -- lazily imported (the proxy needs the optional MCP SDK) -----------
    "MCPGuardProxy",
    "ProxyConfig",
]

#: The scan-policy loader under a name that cannot be confused with the
#: runtime policy loader :func:`load_policy`.
load_scan_policy = load_policy_text


def __getattr__(name: str) -> Any:
    """Import the proxy lazily.

    :mod:`mcp_guard.proxy` needs the optional MCP SDK for the transport.  The
    SDK is *not* a runtime dependency of this package, so importing the proxy
    at package-import time would make ``import mcp_guard`` fail on a machine
    that only wants the offline scanner.  The proxy is therefore resolved on
    first use.
    """
    if name in ("MCPGuardProxy", "ProxyConfig"):
        from . import proxy as _proxy

        return getattr(_proxy, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
