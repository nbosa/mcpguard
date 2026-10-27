"""The stdio proxy: mcp-guard sits between an MCP client and one upstream server.

Both sides speak stdio.  Every ``tools/call`` is evaluated against the policy
*before* it is forwarded, and every ``tools/list`` is filtered so a denied tool is
never advertised.  Framing, handshake and version negotiation are the official
MCP SDK's job; the upstream *process* is launched by :mod:`mcp_guard.upstream`
so the proxy can terminate it.

The MCP SDK is an **optional** dependency.  ``mcp-guard`` itself needs nothing
but the standard library: the offline scanner, the policy engine, the audit
chain and the linter all run without the SDK installed.  Only the ``proxy``
subcommand needs it, and it says so in a clean error message when it is
missing.
"""

from __future__ import annotations

import os
import secrets
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, TextIO

try:  # pragma: no cover - exercised by the environments that have the SDK
    import anyio
    import mcp_types as types
    from mcp.client.session import ClientSession
    from mcp.server.lowlevel.server import Server, ServerRequestContext
    from mcp.server.stdio import stdio_server
    from mcp.shared.exceptions import MCPError

    HAVE_MCP_SDK = True
except ImportError:  # pragma: no cover - the SDK is optional
    anyio = None  # type: ignore[assignment]
    types = None  # type: ignore[assignment]
    ClientSession = None  # type: ignore[assignment]
    Server = None  # type: ignore[assignment]
    ServerRequestContext = None  # type: ignore[assignment]
    stdio_server = None  # type: ignore[assignment]
    HAVE_MCP_SDK = False

    class MCPError(Exception):  # type: ignore[no-redef]
        """The MCP SDK's error type, used when the SDK is not installed.

        The proxy raises this for a request it refuses.  With the SDK
        installed the real ``mcp.shared.exceptions.MCPError`` is used, so the
        error keeps its wire representation; without the SDK the class still
        exists, so no code path can raise ``NameError`` (F-10).
        """

        def __init__(self, code: int = 0, message: str = "", data: Any = None) -> None:
            super().__init__(message)
            self.code = code
            self.message = message
            self.data = data


#: F-10: the error the proxy raises for a request it refuses.  The name is
#: defined here, so the batch-rejection branch can never raise ``NameError``.
McpError = MCPError

from . import upstream as upstream_module
from .audit import OUTCOME_TIMEOUT, OUTCOME_UPSTREAM_ERROR, AuditLog
from .policy import APPROVAL_REQUIRED, DENY, RATE_LIMITED, TTL_EXPIRED, Decision, Policy, PolicyEngine
from .upstream import Upstream, UpstreamLineTooLarge

#: JSON-RPC error codes, all in the implementation defined range -32000..-32099,
#: and the method names recorded in the audit log for a call and a listing.
JSONRPC_ERROR_CODES: dict[str, int] = {
    DENY: -32001,
    APPROVAL_REQUIRED: -32002,
    RATE_LIMITED: -32003,
    TTL_EXPIRED: -32004,
}
TOOL_CALL = "tools/call"
TOOL_LIST = "tools/list"

#: The JSON-RPC error code of a request the upstream never answered.
UPSTREAM_TIMEOUT_CODE = -32005

#: The JSON-RPC error code of a request whose answer was **discarded** because
#: the upstream wrote a line over the R-13 bound (``MAX_LINE_CHARS``).
#:
#: It is a code of its own, not ``UPSTREAM_TIMEOUT_CODE``: the upstream was
#: fast, it simply produced an answer the proxy cannot use, and an operator
#: has to tell the two apart -- one is a slow upstream, the other is a
#: misbehaving one.
UPSTREAM_OVERSIZE_CODE = -32006

#: How long the upstream may take to answer one request, in seconds.
DEFAULT_UPSTREAM_TIMEOUT = 120.0

#: How long the upstream may take to complete the ``initialize`` handshake, in
#: seconds.  The handshake is a phase of its own: a request deadline that is
#: generous for a tool call is far too generous for a handshake.
DEFAULT_UPSTREAM_INIT_TIMEOUT = 30.0

#: The exit code of a proxy that could not complete the handshake with its
#: upstream and therefore refused the client.  It is a code of its own: 1 is
#: "the audit log is broken", 2 is "you used me wrong", 3 is "I could not
#: authenticate this" -- none of them is "my upstream never said hello".
EXIT_UPSTREAM_INIT = 4

#: How long the proxy waits for the client's own ``initialize`` request after
#: the upstream handshake has failed, before it gives up on the client too.
CLIENT_HANDSHAKE_WAIT = 5.0

#: The method name of the MCP handshake, in the audit log.
INITIALIZE = "initialize"

@dataclass
class ProxyConfig:
    """Everything the proxy needs to run."""

    upstream_command: list[str]
    policy: Policy
    audit_path: Path | None = None
    ttl_seconds: int | None = None
    session_id: str = field(default_factory=lambda: secrets.token_hex(16))
    base_dir: Path = field(default_factory=Path.cwd)
    stderr: TextIO = sys.stderr
    #: The key file, the key ring (every key the log was signed with), whether to
    #: force the legacy unkeyed chain, and the checkpoint interval.
    audit_key_file: Path | None = None
    audit_keyring: Path | None = None
    audit_legacy: bool = False
    checkpoint_interval: int | None = None
    #: How long the upstream may take to answer one request, in seconds.
    #: ``None`` means no deadline; a hung upstream would then wedge the proxy.
    upstream_timeout: float | None = DEFAULT_UPSTREAM_TIMEOUT
    #: How long the upstream may take to complete the ``initialize`` handshake,
    #: in seconds.  ``None`` means no deadline; a hung upstream would then
    #: wedge the proxy before it ever answers the client.
    upstream_init_timeout: float | None = DEFAULT_UPSTREAM_INIT_TIMEOUT
    canary_hook: Any | None = None
    canary_bundle: Path | None = None
    etdi_pins: dict[str, Any] | None = None
    etdi_pins_path: Path | None = None
    plugin_settings: dict[str, Any] | None = None
    plugins_enabled: bool = True

    def __post_init__(self) -> None:
        if not self.upstream_command:
            raise ValueError("upstream_command must not be empty")
        self.base_dir = Path(self.base_dir)

class MCPGuardProxy:
    """A policy enforcing MCP proxy over stdio."""

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        canary_hook = config.canary_hook
        if canary_hook is None and config.canary_bundle:
            from .canary import CanaryGuardHook, NativeCanaryDetector
            canary_hook = CanaryGuardHook(NativeCanaryDetector.from_bundle(config.canary_bundle))

        self.engine = PolicyEngine(
            config.policy,
            session_id=config.session_id,
            base_dir=config.base_dir,
            ttl_seconds=config.ttl_seconds,
            canary_hook=canary_hook,
        )
        # Modular 4-plugin engine integration
        from .core.plugin import PluginContext
        from .core.policy import default_policy as default_plugin_policy
        from .plugins.etdi_pinning import ETDIPinningPlugin
        from .plugins.path_shape import PathShapePlugin
        from .plugins.canary_exfil import CanaryExfilPlugin
        from .plugins.ansi_sanitize import ANSISanitizePlugin

        plugin_pol = default_plugin_policy()
        plugin_ctx = PluginContext(
            policy=plugin_pol,
            settings=config.plugin_settings or {},
            home_dir=str(config.base_dir),
        )
        self.etdi_plugin = ETDIPinningPlugin(plugin_ctx)
        self.path_plugin = PathShapePlugin(plugin_ctx)
        self.canary_plugin = CanaryExfilPlugin(plugin_ctx)
        self.ansi_plugin = ANSISanitizePlugin(plugin_ctx)
        self.audit = (
            AuditLog(
                config.audit_path,
                config.session_id,
                key_file=config.audit_key_file,
                keyring=config.audit_keyring,
                legacy=config.audit_legacy,
                # Since 0.4 an audit log must be keyed unless --legacy-unkeyed.
                require_keyed=not config.audit_legacy,
                checkpoint_interval=config.checkpoint_interval,
                warn=config.audit_key_file is None and config.audit_keyring is None,
            )
            if config.audit_path
            else None
        )
        self._upstream: ClientSession | None = None
        self._upstream_process: Upstream | None = None
        self._client_session: Any = None

    # -- lifecycle --------------------------------------------------------
    async def run(self) -> int:
        """Run the proxy until stdin reaches EOF or a termination signal arrives."""
        exit_code = 0
        try:
            async with anyio.create_task_group() as task_group:
                task_group.start_soon(self._watch_signals, task_group.cancel_scope)
                exit_code = await self._serve()
                # The serving is over.  The signal watcher waits for a signal
                # that will never come now, and it would keep the task group
                # -- and with it the process -- alive for ever.
                task_group.cancel_scope.cancel()
        finally:
            if self.audit is not None:
                self.audit.close()
        return exit_code

    async def _watch_signals(self, cancel_scope: anyio.CancelScope) -> None:
        """Cancel the proxy on SIGINT/SIGTERM so the upstream can be reaped."""
        try:
            with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                async for _signum in signals:
                    cancel_scope.cancel()
                    # The SDK reads the client's stdin in a worker thread that
                    # cannot be interrupted, so reap the upstream and leave.
                    with anyio.CancelScope(shield=True):
                        if self._upstream_process is not None:
                            await self._upstream_process.shutdown()
                        if self.audit is not None:
                            self.audit.close()
                        os._exit(0)
                    return
        except (NotImplementedError, RuntimeError):  # pragma: no cover - platform dependent
            return

    async def _serve(self) -> int:
        """Launch the upstream and relay messages between it and the client."""
        async with Upstream(
            self.config.upstream_command,
            cwd=str(self.config.base_dir),
            errlog=self.config.stderr,
        ) as upstream:
            self._upstream_process = upstream
            async with ClientSession(
                upstream.read_stream,
                upstream.write_stream,
                message_handler=self._on_upstream_notification,
            ) as session:
                # The handshake has a deadline of its own: an upstream that
                # never answers it must not leave the client waiting.
                try:
                    with anyio.fail_after(self.config.upstream_init_timeout):
                        await session.initialize()
                except TimeoutError:
                    reason = (
                        f"the upstream did not complete the initialize handshake within "
                        f"{self._init_timeout_text()}: the client was refused"
                    )
                    return await self._refuse_handshake(reason)
                self._upstream = session
                # The TTL starts once the upstream is ready, not at process start.
                self.engine.guard.start()
                server = self._build_server(session)
                async with stdio_server() as (client_read, client_write):
                    await server.run(
                        client_read,
                        client_write,
                        server.create_initialization_options(),
                    )
        return 0

    async def _refuse_handshake(self, reason: str) -> int:
        """Answer the client's handshake with an error and give up.

        The client asked for a handshake; it gets an answer -- a JSON-RPC error
        -- instead of waiting for ever.  The refusal is audited like any other
        decision, and the proxy leaves with a documented exit code.
        """
        self._audit(
            method=INITIALIZE,
            tool_name=None,
            arguments={},
            decision="deny",
            reason=reason,
        )
        await self._answer_client_initialize(reason)
        return EXIT_UPSTREAM_INIT

    async def _answer_client_initialize(self, reason: str) -> None:
        """Send the client a JSON-RPC error for its own ``initialize`` request.

        The transport is handled here rather than through the SDK's
        ``stdio_server``: that helper owns the client's stdin and stdout and
        only gives them back when the whole server has finished, which is
        exactly what cannot happen here -- the client is waiting for the
        answer that is being written now.
        """
        error = types.ErrorData(
            code=UPSTREAM_TIMEOUT_CODE,
            message=f"upstream timeout: {reason}",
            data={
                "code": UPSTREAM_TIMEOUT_CODE,
                "reason": reason,
                "session_id": self.config.session_id,
            },
        )
        try:
            with anyio.fail_after(CLIENT_HANDSHAKE_WAIT):
                request = await self._read_client_initialize()
                if request is None:
                    return
                response = types.JSONRPCError(jsonrpc="2.0", id=request.id, error=error)
                sys.stdout.write(response.model_dump_json(by_alias=True, exclude_unset=True))
                sys.stdout.write("\n")
                sys.stdout.flush()
        except TimeoutError:  # the client never asked: there is nobody to answer
            return
        except Exception:  # pragma: no cover - the client may already be gone
            return

    async def _read_client_initialize(self) -> types.JSONRPCRequest | None:
        """The client's own ``initialize`` request, read from our stdin."""
        while True:
            line = await anyio.to_thread.run_sync(sys.stdin.readline, abandon_on_cancel=True)
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                message = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
            except Exception:
                continue
            if isinstance(message, types.JSONRPCRequest) and message.method == INITIALIZE:
                return message

    # -- server construction ---------------------------------------------
    def _build_server(self, upstream: ClientSession) -> Server:
        """Create the downstream server, mirroring the upstream's capabilities."""
        capabilities = upstream.server_capabilities
        handlers: dict[str, Any] = {
            "on_list_tools": self._on_list_tools,
            "on_call_tool": self._on_call_tool,
        }
        if capabilities.resources is not None:
            handlers["on_list_resources"] = self._on_list_resources
            handlers["on_list_resource_templates"] = self._on_list_resource_templates
            handlers["on_read_resource"] = self._on_read_resource
        if capabilities.prompts is not None:
            handlers["on_list_prompts"] = self._on_list_prompts
            handlers["on_get_prompt"] = self._on_get_prompt
        if capabilities.completions is not None:
            handlers["on_completion"] = self._on_completion
        return Server(name="mcp-guard", version=_version(), **handlers)

    # -- helpers ----------------------------------------------------------
    def _timeout_text(self) -> str:
        """The deadline as it is written into a reason and an error message."""
        timeout = self.config.upstream_timeout
        return "no deadline" if timeout is None else f"{timeout:g}s"

    def _init_timeout_text(self) -> str:
        """The handshake deadline as it is written into a reason."""
        timeout = self.config.upstream_init_timeout
        return "no deadline" if timeout is None else f"{timeout:g}s"

    async def _call_upstream(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Call the upstream and fail the call when its answer is discarded.

        The upstream's line bound (R-13) discards a line that is over
        ``MAX_LINE_CHARS``.  The request that was waiting for that answer has
        to be **answered** -- with an error, never with half an answer -- so
        the call is watched for a discard while it is in flight.  The upstream
        is left running: the next request is served as usual.
        """
        session = self._upstream
        process = self._upstream_process
        if session is None or process is None:
            return await getattr(session, method)(*args, **kwargs)
        seen = process.discarded_lines
        result: dict[str, Any] = {}
        failure: dict[str, Exception] = {}
        done = anyio.Event()
        completed = False

        async def call() -> None:
            nonlocal completed
            try:
                result["value"] = await getattr(session, method)(*args, **kwargs)
            finally:
                completed = True
                done.set()

        async def watch() -> None:
            while True:
                # The event is read before the count is checked, so a discard
                # that happens between the two is not missed: the event is
                # replaced after every discard, and the count only grows.
                event = process.discard_event
                if process.discarded_lines > seen:
                    if not completed:
                        failure["error"] = UpstreamLineTooLarge(process.last_discarded_chars)
                    done.set()
                    return
                await event.wait()

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(call)
            task_group.start_soon(watch)
            await done.wait()
            task_group.cancel_scope.cancel()
        if "error" in failure:
            raise failure["error"]
        return result["value"]

    def _audit(
        self, *, method: str, tool_name: str | None, arguments: Any, decision: str,
        reason: str, upstream_latency_ms: float | None = None,
        outcome: str | None = None,
    ) -> None:
        if self.audit is None:
            return
        from .redact import redact_arguments, scrub_reason
        scrubbed_args = redact_arguments(arguments)
        clean_reason = scrub_reason(reason)
        self.audit.append(
            method=method,
            tool_name=tool_name,
            arguments=scrubbed_args,
            decision=decision,
            reason=clean_reason,
            upstream_latency_ms=upstream_latency_ms,
            outcome=outcome,
        )

    def _refuse(self, decision: Decision) -> MCPError:
        """Turn a policy decision into a structured JSON-RPC error."""
        code = JSONRPC_ERROR_CODES.get(decision.decision, JSONRPC_ERROR_CODES[DENY])
        data: dict[str, Any] = {
            "code": decision.code,
            "reason": decision.reason,
            "session_id": self.config.session_id,
        }
        if decision.violations:
            data["violations"] = list(decision.violations)
        return MCPError(code=code, message=f"{decision.code}: {decision.reason}", data=data)

    def _check_method_allowed(self, method: str) -> None:
        allowed, reason = self.engine.method_allowed(method)
        if not allowed:
            raise MCPError(
                code=JSONRPC_ERROR_CODES[DENY],
                message=f"{DENY}: {reason}",
                data={"code": DENY, "reason": reason, "session_id": self.config.session_id},
            )

    # -- the guard plugins ------------------------------------------------
    @staticmethod
    def _plugin_blockers(findings: list[Any]) -> list[str]:
        """The messages of the findings that have to stop the request.

        A plugin finding of ``HIGH`` or ``CRITICAL`` severity blocks the
        request; a lower severity is informational and is not acted on here.
        """
        from .core.severity import Severity

        return [
            finding.message
            for finding in findings
            if finding.severity >= Severity.HIGH
        ]

    def _plugin_deny(self, reason: str) -> MCPError:
        """Turn a plugin finding into a structured JSON-RPC error."""
        return MCPError(
            code=JSONRPC_ERROR_CODES[DENY],
            message=f"{DENY}: {reason}",
            data={
                "code": DENY,
                "reason": reason,
                "session_id": self.config.session_id,
            },
        )

    async def _on_upstream_notification(self, message: Any) -> None:
        """Relay a server-initiated notification from the upstream to the client."""
        if isinstance(message, Exception):
            return
        session = self._client_session
        if session is None:
            return
        try:
            await session.send_notification(message)
        except Exception:  # pragma: no cover - the client may already be gone
            return

    def _discard_reason(self, chars: int) -> str:
        """The reason of a discarded answer, as it goes into the log."""
        return (
            f"the upstream sent a line of more than {upstream_module.MAX_LINE_CHARS} characters "
            f"without a newline (at least {chars} characters were discarded): the answer was "
            "discarded and the request was abandoned"
        )

    def _discard_error(self, reason: str) -> MCPError:
        """The JSON-RPC error of a discarded answer."""
        return MCPError(
            code=UPSTREAM_OVERSIZE_CODE,
            message=f"upstream response too large: {reason}",
            data={
                "code": UPSTREAM_OVERSIZE_CODE,
                "reason": reason,
                "session_id": self.config.session_id,
            },
        )

    # -- tools/list -------------------------------------------------------
    async def _on_list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        self._client_session = ctx.session
        self._check_method_allowed(TOOL_LIST)
        assert self._upstream is not None
        started = time.perf_counter()
        try:
            with anyio.fail_after(self.config.upstream_timeout):
                result = await self._call_upstream("list_tools", params=params)
        except TimeoutError:
            latency = (time.perf_counter() - started) * 1000.0
            reason = (
                f"the upstream did not answer within {self._timeout_text()}: the listing was "
                "abandoned"
            )
            self._audit(
                method=TOOL_LIST,
                tool_name=None,
                arguments={},
                decision="allow",
                reason=reason,
                upstream_latency_ms=latency,
            )
            raise MCPError(
                code=UPSTREAM_TIMEOUT_CODE,
                message=f"upstream timeout: {reason}",
                data={
                    "code": UPSTREAM_TIMEOUT_CODE,
                    "reason": reason,
                    "session_id": self.config.session_id,
                },
            ) from None
        except UpstreamLineTooLarge as exc:
            latency = (time.perf_counter() - started) * 1000.0
            reason = self._discard_reason(exc.chars)
            self._audit(
                method=TOOL_LIST,
                tool_name=None,
                arguments={},
                decision="allow",
                reason=reason,
                upstream_latency_ms=latency,
            )
            raise self._discard_error(reason) from None
        latency = (time.perf_counter() - started) * 1000.0

        # ETDI pinning plugin inspection on tools/list
        if getattr(self.config, "plugins_enabled", True) and (
            getattr(self.config, "etdi_pins", None) or getattr(self.config, "etdi_pins_path", None)
        ):
            from .core.request import CheckRequest

            etdi_doc = {
                "server": {"name": "upstream", "version": "1.0"},
                "tools": [
                    {
                        "name": tool.name,
                        "description": getattr(tool, "description", "") or "",
                        "inputSchema": getattr(tool, "inputSchema", {}) or {},
                    }
                    for tool in result.tools
                ],
            }
            req = CheckRequest(
                metadata={
                    "etdi": etdi_doc,
                    "pins": getattr(self.config, "etdi_pins", None),
                    "pins_path": getattr(self.config, "etdi_pins_path", None),
                }
            )
            etdi_findings = self.etdi_plugin.analyze(req)
            crit_findings = self._plugin_blockers(etdi_findings)
            if crit_findings:
                reason = f"ETDI pin drift: {'; '.join(crit_findings)}"
                self._audit(
                    method=TOOL_LIST,
                    tool_name=None,
                    arguments={},
                    decision="deny",
                    reason=reason,
                    upstream_latency_ms=latency,
                )
                raise self._plugin_deny(reason)

        visible = []
        hidden = []
        for tool in result.tools:
            if self.engine.advertises(tool.name):
                visible.append(tool)
            else:
                hidden.append(tool.name)
        self._audit(
            method=TOOL_LIST,
            tool_name=None,
            arguments={"advertised": [tool.name for tool in visible], "hidden": hidden},
            decision="allow",
            reason=(
                f"advertised {len(visible)} tool(s), hid {len(hidden)} tool(s) denied by policy"
                if hidden
                else f"advertised {len(visible)} tool(s)"
            ),
            upstream_latency_ms=latency,
        )
        return types.ListToolsResult(tools=visible, next_cursor=result.next_cursor)

    # -- tools/call -------------------------------------------------------
    async def _on_call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        # SECURITY (OPUS-06): Reject batch array requests at proxy level.
        # JSON-RPC batch arrays must never bypass single-request policy checks.
        if isinstance(params, (list, tuple)):
            raise McpError(
                code=-32600,
                message="JSON-RPC batch requests are rejected by policy",
            )

        self._client_session = ctx.session
        self._check_method_allowed(TOOL_CALL)
        assert self._upstream is not None
        tool_name = params.name
        arguments: Mapping[str, Any] = params.arguments or {}

        decision = self.engine.evaluate(tool_name, arguments)
        if decision.is_error:
            self._audit(
                method=TOOL_CALL,
                tool_name=tool_name,
                arguments=arguments,
                decision=decision.decision,
                reason=decision.reason,
                upstream_latency_ms=None,
            )
            raise self._refuse(decision)

        # Invoke plugins on tools/call: path_shape + canary_exfil
        if getattr(self.config, "plugins_enabled", True):
            from .core.request import CheckRequest, ToolCall

            call_req = CheckRequest(
                calls=[ToolCall(tool=tool_name, arguments=dict(arguments))]
            )
            # 1. path_shape plugin
            path_blockers = self._plugin_blockers(self.path_plugin.analyze(call_req))
            if path_blockers:
                reason = f"path shape violation: {'; '.join(path_blockers)}"
                self._audit(
                    method=TOOL_CALL,
                    tool_name=tool_name,
                    arguments=arguments,
                    decision=DENY,
                    reason=reason,
                    upstream_latency_ms=None,
                )
                raise self._plugin_deny(reason)

            # 2. canary_exfil plugin
            canary_blockers = self._plugin_blockers(self.canary_plugin.analyze(call_req))
            if canary_blockers:
                reason = f"canary exfiltration detected: {'; '.join(canary_blockers)}"
                self._audit(
                    method=TOOL_CALL,
                    tool_name=tool_name,
                    arguments=arguments,
                    decision=DENY,
                    reason=reason,
                    upstream_latency_ms=None,
                )
                raise self._plugin_deny(reason)

        started = time.perf_counter()
        try:
            with anyio.fail_after(self.config.upstream_timeout):
                result = await self._call_upstream("call_tool", tool_name, dict(arguments))
        except TimeoutError:
            # A timeout is evidence, so it goes into the log like any other
            # decision: the call was allowed by the policy, the upstream just
            # never answered.
            latency = (time.perf_counter() - started) * 1000.0
            reason = (
                f"the upstream did not answer within {self._timeout_text()}: the call was "
                "abandoned and the upstream was never reached again"
            )
            self._audit(
                method=TOOL_CALL,
                tool_name=tool_name,
                arguments=arguments,
                decision="allow",
                reason=reason,
                upstream_latency_ms=latency,
                outcome=OUTCOME_TIMEOUT,
            )
            raise MCPError(
                code=UPSTREAM_TIMEOUT_CODE,
                message=f"upstream timeout: {reason}",
                data={
                    "code": UPSTREAM_TIMEOUT_CODE,
                    "reason": reason,
                    "session_id": self.config.session_id,
                },
            ) from None
        except UpstreamLineTooLarge as exc:
            # The answer was discarded, so the call is abandoned -- but the
            # upstream is left alone and the next request is served as usual.
            latency = (time.perf_counter() - started) * 1000.0
            reason = self._discard_reason(exc.chars)
            self._audit(
                method=TOOL_CALL,
                tool_name=tool_name,
                arguments={},
                decision="allow",
                reason=reason,
                upstream_latency_ms=latency,
                outcome=OUTCOME_UPSTREAM_ERROR,
            )
            raise self._discard_error(reason) from None
        except MCPError as exc:
            latency = (time.perf_counter() - started) * 1000.0
            self._audit(
                method=TOOL_CALL,
                tool_name=tool_name,
                arguments=arguments,
                decision="allow",
                reason=f"the upstream returned an error: {exc.message}",
                upstream_latency_ms=latency,
                outcome=OUTCOME_UPSTREAM_ERROR,
            )
            raise
        latency = (time.perf_counter() - started) * 1000.0

        # Invoke plugins on tool responses: canary_exfil + ansi_sanitize
        if getattr(self.config, "plugins_enabled", True) and isinstance(
            getattr(result, "content", None), list
        ):
            from .core.request import CheckRequest, ToolResult
            from .plugins.ansi_sanitize import sanitize_text

            for item in result.content:
                text_val = getattr(item, "text", None)
                if not isinstance(text_val, str) or not text_val:
                    continue
                res_req = CheckRequest(
                    results=[ToolResult(tool=tool_name, content=text_val)]
                )
                res_blockers = self._plugin_blockers(self.canary_plugin.analyze(res_req))
                if res_blockers:
                    reason = f"canary leak in the tool response: {'; '.join(res_blockers)}"
                    self._audit(
                        method=TOOL_CALL,
                        tool_name=tool_name,
                        arguments=arguments,
                        decision=DENY,
                        reason=reason,
                        upstream_latency_ms=latency,
                    )
                    raise self._plugin_deny(reason)
                # Apply ANSI sanitization.  ``sanitize_text`` returns a
                # ``SanitizeResult``; the sanitized text is its ``text``.
                sanitized = sanitize_text(text_val).text
                if sanitized != text_val:
                    try:
                        item.text = sanitized
                    except Exception:  # pragma: no cover - frozen models
                        pass

        self._audit(
            method=TOOL_CALL,
            tool_name=tool_name,
            arguments=arguments,
            decision="allow",
            reason=decision.reason,
            upstream_latency_ms=latency,
        )
        return result

    # -- pass-through methods are generated below ------------------------

#: Every MCP method the proxy relays without judging it: the handler name the SDK
#: looks for, the MCP method name the policy filters, and how the request
#: parameters turn into a call on the upstream client session.  Six handlers that
#: differ only in those three things are six rows of a table, not six methods.
PASSTHROUGH: dict[str, tuple[str, str, Any]] = {
    "on_list_resources": ("resources/list", "list_resources", lambda p: {"params": p}),
    "on_list_resource_templates": ("resources/templates/list", "list_resource_templates", lambda p: {"params": p}),
    "on_read_resource": ("resources/read", "read_resource", lambda p: (p.uri,)),
    "on_list_prompts": ("prompts/list", "list_prompts", lambda p: {"params": p}),
    "on_get_prompt": ("prompts/get", "get_prompt", lambda p: (p.name, p.arguments)),
    "on_completion": ("completion/complete", "complete", lambda p: (p.ref, p.argument, p.context_arguments)),
}

def _passthrough(method: str, name: str, call: Any) -> Any:
    """Build one relaying handler: filter the method, then forward the request."""

    async def handler(self: "MCPGuardProxy", ctx: ServerRequestContext[Any], params: Any) -> Any:
        self._client_session = ctx.session
        self._check_method_allowed(method)
        assert self._upstream is not None
        return await getattr(self._upstream, name)(**call(params))

    return handler

for _name, (_method, _upstream_call, _args) in PASSTHROUGH.items():
    setattr(MCPGuardProxy, _name, _passthrough(_method, _upstream_call, _args))

def _version() -> str:
    from . import __version__

    return __version__

async def run_proxy(config: ProxyConfig) -> int:
    """Convenience wrapper: build the proxy and run it."""
    proxy = MCPGuardProxy(config)
    return await proxy.run()
