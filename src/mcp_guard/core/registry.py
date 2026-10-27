"""Plugin registry.

Plugins are discovered from a static table so that ``mcp-guard`` has a stable,
auditable capability surface. Adding a capability means adding a module and one
registry entry.
"""

from __future__ import annotations

from typing import Any, Iterable

from mcp_guard.plugins.ansi_sanitize import ANSISanitizePlugin
from mcp_guard.plugins.canary_exfil import CanaryExfilPlugin
from mcp_guard.plugins.etdi_pinning import ETDIPinningPlugin
from mcp_guard.plugins.path_shape import PathShapePlugin

from .plugin import GuardPlugin, PluginContext
from .policy import Policy

__all__ = [
    "PLUGIN_CLASSES",
    "PLUGIN_ORDER",
    "UnknownPluginError",
    "UnknownPlugin",
    "build_plugins",
    "known_plugin_names",
    "plugin_rule_catalogue",
    "plugin_metadata",
    "validate_plugin_names",
]

#: Plugin identifier -> implementation, in canonical evaluation order.
PLUGIN_CLASSES: dict[str, type[GuardPlugin]] = {
    "etdi_pinning": ETDIPinningPlugin,
    "ansi_sanitize": ANSISanitizePlugin,
    "path_shape": PathShapePlugin,
    "canary_exfil": CanaryExfilPlugin,
}

#: Canonical evaluation order (pins first, content inspection last).
PLUGIN_ORDER: tuple[str, ...] = ("etdi_pinning", "ansi_sanitize", "path_shape", "canary_exfil")


class UnknownPluginError(ValueError):
    """Raised when a plugin name is not registered."""


class UnknownPlugin(GuardPlugin):
    """Placeholder for a plugin name that is not registered.

    The placeholder exists so that a typo can never *silently* disable the
    guard surface (AUD-08).  It is always present in the plugin list, and it
    always fails, which the engine turns into an ``ENGINE-000`` finding and a
    failing verdict.  The CLI rejects the same name up front with a clear
    message, so the placeholder is only reachable through the library API.
    """

    name = "unknown"

    def __init__(self, requested_name: str, context: PluginContext) -> None:
        super().__init__(context)
        self.requested_name = requested_name

    def analyze(self, request) -> list:
        raise UnknownPluginError(
            f"unknown plugin '{self.requested_name}' "
            f"(known: {', '.join(PLUGIN_ORDER)})"
        )


def known_plugin_names() -> tuple[str, ...]:
    """Return the names of all registered plugins."""
    return PLUGIN_ORDER


def validate_plugin_names(names: Iterable[str] | None) -> list[str]:
    """Return the subset of ``names`` that is not a registered plugin.

    Raises:
        UnknownPluginError: when any name is unknown.
    """
    if not names:
        return []
    unknown = [name for name in names if name not in PLUGIN_CLASSES]
    if unknown:
        raise UnknownPluginError(
            f"unknown plugin(s): {', '.join(unknown)} "
            f"(known: {', '.join(PLUGIN_ORDER)})"
        )
    return list(names)


def build_plugins(
    policy: Policy,
    names: Iterable[str] | None = None,
) -> list[GuardPlugin]:
    """Instantiate the plugins selected by ``names`` (all of them by default).

    Unknown names are represented by an :class:`UnknownPlugin` placeholder so
    that the returned list is never silently empty.
    """
    selected = list(names) if names else list(PLUGIN_ORDER)
    context_for = lambda name: PluginContext(  # noqa: E731 - tiny local helper
        policy=policy,
        settings=policy.plugin_settings(PLUGIN_CLASSES[name].settings_block()),
        home_dir=_home_dir(),
    )
    plugins: list[GuardPlugin] = []
    for name in PLUGIN_ORDER:
        if name not in selected:
            continue
        plugin_class = PLUGIN_CLASSES.get(name)
        if plugin_class is None:
            continue
        plugins.append(plugin_class(context_for(name)))
    for name in selected:
        if name in PLUGIN_CLASSES:
            continue
        plugins.append(
            UnknownPlugin(
                name,
                PluginContext(policy=policy, settings={}, home_dir=_home_dir()),
            )
        )
    return plugins


def plugin_rule_catalogue() -> dict[str, dict[str, dict]]:
    """Return ``plugin -> rule_id -> rule definition`` for every plugin."""
    catalogue: dict[str, dict[str, dict]] = {}
    for name, plugin_class in PLUGIN_CLASSES.items():
        catalogue[name] = {
            rule_id: dict(definition)
            for rule_id, definition in (plugin_class.RULES or {}).items()
        }
    return catalogue


def plugin_metadata() -> list[dict[str, str]]:
    """Return a serialisable description of the plugin surface."""
    return [
        {
            "name": name,
            "version": PLUGIN_CLASSES[name].version,
            "rules": ",".join(sorted((PLUGIN_CLASSES[name].RULES or {}).keys())),
        }
        for name in PLUGIN_ORDER
    ]


def _home_dir() -> str:
    import os

    return os.path.expanduser("~")
