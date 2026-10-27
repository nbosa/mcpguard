"""Core building blocks of mcp-guard.

This package intentionally keeps ``__init__.py`` free of submodule imports: the plugin
modules import from :mod:`mcp_guard.core` while the registry imports the plugin
modules, and an eager import here would create an import cycle.

Submodules:
    severity    - ordered severity model
    result      - finding / verdict / report data model
    request     - normalized "what is being checked" structures
    textutil    - canonicalisation, hashing, entropy helpers
    redact      - evidence redaction
    policy      - policy model + TOML loader
    lint        - policy linter
    plugin      - plugin base class + rule resolution
    registry    - plugin registry / builder
    engine      - the guard engine that runs plugins
    etdi        - ETDI document schema validation
    manifest    - ETDI pin manifest build / verify
"""

__all__ = [
    "severity",
    "result",
    "request",
    "textutil",
    "redact",
    "policy",
    "lint",
    "plugin",
    "registry",
    "engine",
    "etdi",
    "manifest",
]
