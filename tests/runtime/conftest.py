"""Shared fixtures for the runtime test suite.

The runtime half is the proxy, the policy engine, the audit chain and the
canary detector.  The fixtures here start a real proxy in front of the demo
server, so the tests exercise the same code path an operator uses.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Sequence

import anyio
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"
DEMO_SERVER = REPO_ROOT / "demo" / "danger_server.py"

if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from mcp import ClientSession, StdioServerParameters, stdio_client  # noqa: E402


def child_environment() -> dict[str, str]:
    """An environment in which ``mcp_guard`` is importable without an install."""
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{SOURCE_ROOT}{os.pathsep}{existing}" if existing else str(SOURCE_ROOT)
    )
    return environment


def proxy_command(
    policy: str | Path,
    audit: str | Path | None = None,
    extra: Sequence[str] = (),
    upstream: Sequence[str] | None = None,
) -> list[str]:
    """Build the command line of the proxy."""
    command = [sys.executable, "-m", "mcp_guard", "proxy", "--policy", str(policy)]
    if audit is not None:
        command += ["--audit", str(audit)]
    command += list(extra)
    command += ["--"]
    command += list(upstream if upstream is not None else [sys.executable, str(DEMO_SERVER)])
    return command


@asynccontextmanager
async def proxy_session(
    policy: str | Path,
    audit: str | Path | None = None,
    extra: Sequence[str] = (),
    base_dir: str | Path | None = None,
) -> AsyncIterator[ClientSession]:
    """Run the proxy and yield a client session that talks to it."""
    command = proxy_command(policy, audit, extra)
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(base_dir if base_dir is not None else REPO_ROOT),
        env=child_environment(),
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


def run_async(function: Callable[[], Any]) -> Any:
    """Run an async function from a synchronous test."""
    return anyio.run(function)


@pytest.fixture
def repo_root() -> Path:
    """The root of the repository."""
    return REPO_ROOT


@pytest.fixture
def write_policy(tmp_path: Path) -> Callable[[str], Path]:
    """Write a policy document to a temporary file and return its path."""

    def _write(document: str) -> Path:
        path = tmp_path / "policy.yaml"
        path.write_text(document, encoding="utf-8")
        return path

    return _write
