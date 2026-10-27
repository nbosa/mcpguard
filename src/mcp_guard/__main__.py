"""Allow ``python -m mcp_guard`` to run the unified command line interface."""

from __future__ import annotations

from .cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
