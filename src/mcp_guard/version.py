"""Single source of truth for the ``mcp-guard`` version.

Every artifact -- the CLI banner, the pin-manifest generator string, the
packaging metadata and the documentation -- reads the version from this
module, so the release cannot describe itself with a stale number.
"""

from __future__ import annotations

__all__ = ["VERSION", "VERSION_STRING", "__version__", "RELEASE_CODENAME"]

#: Semantic version tuple.
VERSION = (1, 0, 0)

#: Dotted version string, e.g. ``"1.0.0"``.
VERSION_STRING = ".".join(str(part) for part in VERSION)

#: PEP 440 style alias.
__version__ = VERSION_STRING

#: Release channel marker used in banners and manifests.
RELEASE_CODENAME = "oss"
