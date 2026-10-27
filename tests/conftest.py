"""Shared pytest configuration for the mcp-guard test suite.

The package is imported from ``src/`` so that the tests run against the
checkout without an installation.  The rest of the configuration lives in the
sub-directories:

* ``tests/runtime/`` -- the runtime proxy, policy engine, audit chain and
  canary detector;
* ``tests/scanner/`` -- the offline transcript scanner and its plugins;
* ``tests/audit/`` -- the independent audit suites, which are written against
  the public behaviour rather than against an implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def pytest_configure(config):
    """Declare the markers the suites use."""
    config.addinivalue_line(
        "markers", "slow: a test that starts an MCP server or a subprocess"
    )
