"""Guard plugins.

Each capability lives in its own module and is registered in
:mod:`mcp_guard.core.registry`. Plugins never import each other; they only
depend on :mod:`mcp_guard.core`.
"""

__all__ = [
    "ansi_sanitize",
    "canary_exfil",
    "etdi_pinning",
    "path_shape",
]
