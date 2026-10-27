"""Shared pytest fixtures for the mcp-guard test suite."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_guard.core.engine import GuardEngine  # noqa: E402
from mcp_guard.core.plugin import PluginContext  # noqa: E402
from mcp_guard.core.policy import default_policy, parse_policy  # noqa: E402
from mcp_guard.core.request import CheckRequest  # noqa: E402
from mcp_guard.core.samples import (  # noqa: E402
    CLEAN_TRANSCRIPT,
    SAMPLE_ETDI,
    SAMPLE_TRANSCRIPT,
)


@pytest.fixture
def repo_root() -> Path:
    return ROOT


def build_plugin(plugin_class, settings: dict | None = None, policy=None):
    """Instantiate a plugin with merged policy settings and a fixed home dir."""
    active = policy if policy is not None else default_policy()
    merged = {
        **active.plugin_settings(plugin_class.settings_block()),
        **(settings or {}),
    }
    context = PluginContext(
        policy=active,
        settings=merged,
        home_dir="/" "home/bob",
    )
    return plugin_class(context)


@pytest.fixture
def policy():
    return default_policy()


@pytest.fixture
def engine(policy) -> GuardEngine:
    return GuardEngine(policy=policy)


@pytest.fixture
def sample_transcript() -> dict:
    return json.loads(json.dumps(SAMPLE_TRANSCRIPT))


@pytest.fixture
def clean_transcript() -> dict:
    return json.loads(json.dumps(CLEAN_TRANSCRIPT))


@pytest.fixture
def sample_etdi() -> dict:
    return json.loads(json.dumps(SAMPLE_ETDI))


@pytest.fixture
def make_policy():
    """Build a policy from an inline TOML document."""

    def _make(document: str):
        import tomllib

        return parse_policy(tomllib.loads(document))[0]

    return _make


@pytest.fixture
def request_from():
    """Build a CheckRequest from a plain dictionary."""

    def _make(document: dict) -> CheckRequest:
        return CheckRequest.from_dict(document)

    return _make


@pytest.fixture
def make_plugin():
    """Instantiate a plugin with merged policy settings and a fixed home dir."""

    def _make(plugin_class, settings: dict | None = None, policy=None):
        return build_plugin(plugin_class, settings=settings, policy=policy)

    return _make


@pytest.fixture
def run_plugin():
    """Run a plugin over a request and return the findings.

    ``operator`` carries values that only the operator may supply -- a path to
    a pin manifest, for instance.  A transcript is never allowed to name a
    local file (AUD-14), so those values travel in a separate channel.
    """

    def _run(
        plugin_class,
        document: dict,
        settings: dict | None = None,
        policy=None,
        operator: dict | None = None,
    ):
        plugin = build_plugin(plugin_class, settings=settings, policy=policy)
        request = CheckRequest.from_dict(document)
        if operator:
            request.trusted.update(operator)
        return plugin.analyze(request)

    return _run
