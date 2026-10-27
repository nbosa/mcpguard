"""Launching and supervising the upstream MCP server process.

Started directly rather than through the SDK's ``stdio_client`` helper for one
reason: the helper does not hand out the process handle, and the proxy must be
able to terminate the upstream.  Shutdown follows the MCP lifecycle -- close its
stdin, give it a moment, kill only a process that ignores that.

The MCP SDK is an optional dependency of ``mcp-guard``; it is imported here
because this module is part of the proxy transport, and the proxy is the only
part of the package that needs the SDK.
"""

from __future__ import annotations

import sys
from contextlib import suppress
from typing import Any, Iterable, Iterator, Mapping, NamedTuple, Sequence, TextIO

try:  # pragma: no cover - exercised by the environments that have the SDK
    import anyio
    import mcp_types as types
    from anyio.streams.text import TextReceiveStream
    from mcp.client.stdio import get_default_environment
    from mcp.os.posix.utilities import terminate_posix_process_tree
    from mcp.shared.message import SessionMessage

    HAVE_MCP_SDK = True
except ImportError:  # pragma: no cover - the SDK is optional
    anyio = None  # type: ignore[assignment]
    types = None  # type: ignore[assignment]
    TextReceiveStream = None  # type: ignore[assignment]
    get_default_environment = None  # type: ignore[assignment]
    terminate_posix_process_tree = None  # type: ignore[assignment]
    SessionMessage = None  # type: ignore[assignment]
    HAVE_MCP_SDK = False

#: How long the upstream may take to exit after its stdin was closed, and how
#: often that exit is polled.
GRACE_SECONDS = 5.0
POLL_INTERVAL = 0.05

#: The most characters one line of the upstream's stdout may have.  A
#: character is at most four UTF-8 bytes, so this bounds the pending buffer at
#: 32 MiB.  An upstream that never emits a newline must not be able to grow
#: the buffer without bound.
MAX_LINE_CHARS = 8 * 1024 * 1024


class UpstreamLineTooLarge(Exception):
    """A line of the upstream was over :data:`MAX_LINE_CHARS` and was discarded.

    The line itself is never kept: the reader drains it to the next newline
    without buffering it, so the memory the proxy uses does not depend on how
    large the offending line was.  ``chars`` is the number of characters that
    had been discarded when the overflow was noticed -- a lower bound on the
    length of the offending line.
    """

    def __init__(self, chars: int) -> None:
        super().__init__(
            f"the upstream sent a line of more than {MAX_LINE_CHARS} characters without a newline"
        )
        self.chars = chars


class OversizeLine(NamedTuple):
    """A line of the upstream that was over :data:`MAX_LINE_CHARS`.

    ``chars`` is the number of characters that had been discarded **when the
    overflow was noticed**.  The line itself is never kept: the rest of it is
    drained to the next newline and thrown away.  The number is therefore a
    lower bound on the length of the offending line -- the drain may still
    have a long way to go when the report is made.
    """

    chars: int


class LineSplitter:
    """Splits the stdout of the upstream into lines, and reports the oversize ones.

    A line that is over ``max_chars`` is **not** buffered: the rest of it is
    drained to the next newline without being kept, and it is reported as an
    :class:`OversizeLine`.  The memory this needs therefore does not depend
    on how large the offending line was -- it is bounded by ``max_chars`` and
    the size of one chunk.

    The report is made **as soon as the overflow is noticed**, not when the
    line finally ends: an upstream that never emits the newline must not keep
    the client waiting, and the client is answered as soon as the proxy knows
    that the answer it is waiting for is too large.
    """

    def __init__(self, max_chars: int | None = None) -> None:
        # The bound is looked up when the splitter is made, not when this
        # module is imported: a test that lowers ``MAX_LINE_CHARS`` has to
        # lower the bound the reader really uses.
        self.max_chars = MAX_LINE_CHARS if max_chars is None else max_chars
        #: The characters of the line that is being read.
        self.buffer = ""
        #: The state of a line that is being discarded: the characters counted
        #: so far, and whether the newline that ends it is still to come.
        self.discarding = False
        self.discarded = 0

    def feed(self, chunk: str) -> list[str | OversizeLine]:
        """Add ``chunk`` and return the lines (and the reports) it completed."""
        results: list[str | OversizeLine] = []
        if self.discarding:
            # Drain the rest of the oversize line without buffering it.  The
            # report was already made when the overflow was noticed.
            newline = chunk.find("\n")
            if newline == -1:
                self.discarded += len(chunk)
                return results
            self.discarded += newline
            chunk = chunk[newline + 1:]
            self.discarding = False
        self.buffer += chunk
        while True:
            newline = self.buffer.find("\n")
            if newline == -1:
                if len(self.buffer) > self.max_chars:
                    # The line is already over the bound and has no newline
                    # yet: report it now, drop what is buffered, and drain the
                    # rest of it without keeping it.
                    results.append(OversizeLine(len(self.buffer)))
                    self.discarded = len(self.buffer)
                    self.buffer = ""
                    self.discarding = True
                break
            line = self.buffer[:newline]
            self.buffer = self.buffer[newline + 1:]
            if len(line) > self.max_chars:
                results.append(OversizeLine(len(line)))
                self.discarded += len(line)
                continue
            results.append(line)
        return results

    def close(self) -> list[str | OversizeLine]:
        """The reports of a line that the stream ended in the middle of.

        The overflow was already reported when it was noticed, so nothing is
        reported again here -- but the characters that were discarded are
        counted in :attr:`discarded`.
        """
        if not self.discarding:
            return []
        self.discarding = False
        return []


def split_lines(
    chunks: Iterable[str], max_chars: int | None = None
) -> Iterator[str | OversizeLine]:
    """The complete lines of ``chunks``, and the oversize ones as they are found.

    Every line is yielded whole, exactly as it was written, including the
    empty ones (the caller drops them).
    """
    splitter = LineSplitter(max_chars)
    for chunk in chunks:
        yield from splitter.feed(chunk)
    yield from splitter.close()


class Upstream:
    """The upstream MCP server process and the pipes to it."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        errlog: TextIO = sys.stderr,
    ) -> None:
        if not command:
            raise ValueError("the upstream command must not be empty")
        self.command = list(command)
        self.env = env
        self.cwd = cwd
        self.errlog = errlog
        self.process: Any = None
        self.read_stream: Any = None
        self.write_stream: Any = None
        self._read_stream_writer: Any = None
        self._write_stream_reader: Any = None
        self._task_group: Any = None
        self._closed = False
        #: How many lines were discarded because they were over the bound, and
        #: how many characters the last one had.  The proxy watches the count:
        #: a discard that happens while a request is in flight is the answer
        #: to that request, and the request has to be answered with an error.
        self.discarded_lines = 0
        self.last_discarded_chars = 0
        self._discard_event: anyio.Event | None = None

    @property
    def discard_event(self) -> anyio.Event:
        """The event that is set when a line is discarded.

        The event is replaced by a fresh one after every discard, so a waiter
        that arrives later waits for the *next* discard instead of waking up
        for an old one.  The count in :attr:`discarded_lines` is what says
        whether a discard is new for the waiter.
        """
        if self._discard_event is None:
            self._discard_event = anyio.Event()
        return self._discard_event

    def _note_discard(self, chars: int) -> None:
        """Record that a line of ``chars`` characters was discarded."""
        self.discarded_lines += 1
        self.last_discarded_chars = chars
        event = self._discard_event
        if event is not None:
            event.set()
            self._discard_event = anyio.Event()

    async def __aenter__(self) -> "Upstream":
        self.process = await anyio.open_process(
            self.command,
            env=get_default_environment() | dict(self.env or {}),
            stderr=self.errlog,
            cwd=self.cwd,
            start_new_session=True,
        )
        self._read_stream_writer, self.read_stream = anyio.create_memory_object_stream[
            SessionMessage | Exception
        ](0)
        self.write_stream, self._write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)
        self._task_group = anyio.create_task_group()
        await self._task_group.__aenter__()
        self._task_group.start_soon(self._stdout_reader, self._read_stream_writer)
        self._task_group.start_soon(self._stdin_writer, self._write_stream_reader)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        try:
            await self.shutdown()
        finally:
            await self._task_group.__aexit__(exc_type, exc, tb)
        return False

    async def _stdout_reader(self, read_stream_writer: Any) -> None:
        """Forward the JSON-RPC messages of the upstream to the client session.

        A line that is over :data:`MAX_LINE_CHARS` is **discarded**, not fatal.
        The rest of the line is drained to the next newline without being
        buffered -- the memory the proxy uses does not depend on how large the
        offending line was -- the discard is counted, and the reader carries
        on with the next line.  The proxy watches the count and answers the
        request that was waiting for the discarded line with an error, so the
        client is never left waiting and never gets half an answer.
        """
        assert self.process is not None and self.process.stdout is not None
        stream = TextReceiveStream(self.process.stdout, encoding="utf-8", errors="replace")
        splitter = LineSplitter(MAX_LINE_CHARS)

        async def handle(lines: list[str | OversizeLine]) -> None:
            for line in lines:
                if isinstance(line, OversizeLine):
                    self._note_discard(line.chars)
                    continue
                if not line.strip():
                    continue
                # SECURITY (OPUS-06): Reject JSON-RPC batch array requests explicitly.
                # If a batch array ever parses successfully here, individual requests could bypass checks.
                stripped = line.strip()
                if stripped.startswith("["):
                    with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                        await read_stream_writer.send(ValueError("JSON-RPC batch requests are rejected by policy"))
                    continue
                try:
                    message = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
                except Exception as exc:  # a malformed message is surfaced, not fatal
                    with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                        await read_stream_writer.send(exc)
                    continue
                with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                    await read_stream_writer.send(SessionMessage(message=message))

        async for chunk in stream:
            await handle(splitter.feed(chunk))
        await handle(splitter.close())
        # The upstream closed its stdout: the session must see the end of the
        # connection rather than wait for a reply that will never come.
        with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
            await read_stream_writer.aclose()

    async def _stdin_writer(self, write_stream_reader: Any) -> None:
        """Forward the JSON-RPC messages of the client session to the upstream."""
        assert self.process is not None and self.process.stdin is not None
        async with write_stream_reader:
            async for session_message in write_stream_reader:
                payload = session_message.message.model_dump_json(by_alias=True, exclude_unset=True)
                with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError, OSError):
                    await self.process.stdin.send((payload + "\n").encode("utf-8"))

    async def shutdown(self) -> None:
        """Stop the upstream: close its stdin, wait, then kill it if it lingers."""
        if self.process is None or self._closed:
            return
        self._closed = True
        with suppress(OSError, anyio.ClosedResourceError, anyio.BrokenResourceError):
            if self.process.stdin is not None:
                await self.process.stdin.aclose()
        with anyio.move_on_after(GRACE_SECONDS):
            while self.process.returncode is None:
                await anyio.sleep(POLL_INTERVAL)
        if self.process.returncode is None:
            await terminate_posix_process_tree(self.process)
