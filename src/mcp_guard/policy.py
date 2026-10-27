"""The policy model, the YAML loader and the decision engine.

The policy document is parsed into plain dataclasses that validate themselves,
so a typo is a hard error naming the offending key, never a silently ignored
rule.  The engine is the single place where "may this tool call happen?" is
decided; the proxy only translates the returned :class:`Decision` into a wire
response.

The module has **no runtime dependencies**: the YAML subset the policy schema
uses is read by :mod:`mcp_guard.yamlmini`, and the schema itself is validated
by :mod:`mcp_guard._model`.
"""

from __future__ import annotations

import math
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping

from . import yamlmini as yaml
from ._model import (
    Model,
    ValidationError,
    coerce_bool,
    coerce_float,
    coerce_int,
    coerce_str,
)
from .paths import PathViolation, check_path
from .redos import DEFAULT_MAX_REGEX_INPUT, check_pattern, describe_risk
from .redact import fingerprint
from .state import SessionGuard

#: Every decision the engine can return, each of which appears in an audit record.
ALLOW = "allow"
DENY = "deny"
APPROVAL_REQUIRED = "approval_required"
RATE_LIMITED = "rate_limited"
TTL_EXPIRED = "ttl_expired"
DECISIONS = (ALLOW, DENY, APPROVAL_REQUIRED, RATE_LIMITED, TTL_EXPIRED)

#: The MCP method prefixes that relay upstream content to the client without a
#: tool rule of their own.  They are denied by default; see
#: :meth:`PolicyEngine.method_allowed` (G-13).
PASSTHROUGH_METHOD_PREFIXES = ("resources/", "prompts/", "completion/")

#: The deepest nesting an argument value may have before the policy walker
#: refuses it.  The walk is recursive, so an unbounded depth is an unbounded
#: amount of stack (G-05).
MAX_ARGUMENT_DEPTH = 32


def _value_depth(value: Any, _current: int = 0) -> int:
    """The nesting depth of ``value``, counted in containers."""
    if _current > MAX_ARGUMENT_DEPTH + 1:
        # Stop counting: the value is already over the bound and the exact
        # depth is not interesting.
        return _current
    if isinstance(value, dict):
        if not value:
            return _current
        return max(_value_depth(item, _current + 1) for item in value.values())
    if isinstance(value, (list, tuple)):
        if not value:
            return _current
        return max(_value_depth(item, _current + 1) for item in value)
    return _current

class PolicyError(Exception):
    """Raised when a policy file cannot be read, parsed or validated."""

_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str), "boolean": lambda v: isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
    "null": lambda v: v is None,
}

def _enum_contains(value: Any, allowed: Iterable[Any]) -> bool:
    """Membership test that does not confuse ``True`` with ``1``."""
    for candidate in allowed:
        if isinstance(value, bool) != isinstance(candidate, bool):
            continue
        if value == candidate:
            return True
    return False


# ---------------------------------------------------------------------------
# document readers
# ---------------------------------------------------------------------------


def _optional_type(value: Any, loc: tuple[Any, ...]) -> str | None:
    """Read the ``type`` field: a known JSON type name, or nothing."""
    if value is None:
        return None
    text = coerce_str(value, loc)
    if text not in _TYPE_CHECKS:
        raise ValidationError.one(
            loc, f"unknown type {text!r}; expected one of {sorted(_TYPE_CHECKS)}"
        )
    return text


def _optional_regex(value: Any, loc: tuple[Any, ...]) -> str | None:
    """Read the ``regex`` field: a pattern that compiles, or nothing."""
    if value is None:
        return None
    text = coerce_str(value, loc)
    try:
        re.compile(text)
    except re.error as exc:
        raise ValidationError.one(loc, f"invalid regular expression {text!r}: {exc}") from None
    return text


def _optional_enum(value: Any, loc: tuple[Any, ...]) -> list[Any] | None:
    """Read the ``enum`` field: a list of accepted values, or nothing."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValidationError.one(loc, f"expected a list, got {type(value).__name__}")
    return list(value)


def _optional_child(
    data: Mapping[str, Any],
    keys: tuple[str, ...],
    name: str,
    loc: tuple[Any, ...],
) -> "ArgumentConstraint | None":
    """Read a nested constraint, accepting any of its spellings."""
    for key in keys:
        if data.get(key) is None:
            continue
        if key != name:
            # ``element`` is the alias of ``items``; both may not be given.
            for other in keys:
                if other != key and data.get(other) is not None:
                    raise ValidationError.one(
                        loc,
                        f"{key!r} and {other!r} cannot both be given; they name the same constraint",
                    )
        return ArgumentConstraint.from_dict(data[key], loc + (name,))
    return None


def _argument_map(value: Any, loc: tuple[Any, ...]) -> dict[str, ArgumentConstraint]:
    """Read the ``arguments`` section of a tool rule."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError.one(loc, f"expected a mapping, got {type(value).__name__}")
    return {
        coerce_str(name, loc): ArgumentConstraint.from_dict(constraint, loc + (name,))
        for name, constraint in value.items()
    }


def _string_list(value: Any, loc: tuple[Any, ...]) -> list[str]:
    """Read a list of strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError.one(loc, f"expected a list, got {type(value).__name__}")
    return [coerce_str(item, loc + (index,)) for index, item in enumerate(value)]


def _tool_map(value: Any, loc: tuple[Any, ...]) -> dict[str, ToolRule]:
    """Read the ``tools`` section of a policy.

    Tool names are normalised with NFKC so that a rule written with a
    confusable spelling is found by the same normalisation the client's name
    goes through.  When two rules collide under that normalisation the
    stricter one wins: a ``deny`` always beats an ``allow`` (F-05).
    """
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError.one(loc, f"expected a mapping, got {type(value).__name__}")
    tools: dict[str, ToolRule] = {}
    for name, rule in value.items():
        text = coerce_str(name, loc)
        parsed = ToolRule.from_dict(rule, loc + (text,))
        normalised = unicodedata.normalize("NFKC", text)
        existing = tools.get(normalised)
        if existing is None:
            tools[normalised] = parsed
        elif existing.action == DENY or parsed.action == DENY:
            tools[normalised] = parsed if parsed.action == DENY else existing
        else:
            tools[normalised] = parsed
    return tools

#: The maximum number of nested element levels a policy may declare.
#:
#: ``items``/``element`` may be nested (a list of lists of paths); ``keys`` and
#: ``values`` may be nested the same way.  The depth is counted in levels of
#: children, so ``items: {items: {...}}`` is two levels.  A policy that nests
#: deeper than this is refused when it is loaded, not when it is evaluated.
MAX_ELEMENT_DEPTH = 4


@dataclass
class ArgumentConstraint(Model):
    """Constraints applied to a single tool argument.

    A constraint describes one *value*.  An argument is not always a scalar:
    a tool may take a list of paths (``git_add_many(files=[...])``) or a map
    of paths to contents.  A constraint can therefore describe the children of
    the value as well:

    * ``items`` (also written ``element``) constrains every element of a list,
    * ``keys`` constrains every key of a mapping,
    * ``values`` constrains every value of a mapping.

    ``path_prefix`` and ``regex`` describe a *string*.  When the value is a
    list they are applied to **every element**: the list is checked path by
    path, and an element that is not a string is a violation rather than a
    silently skipped element.  That is the difference between 0.4 and 0.5:
    in 0.4 a list was never descended into, so a list of paths could carry a
    traversal that no constraint ever looked at.
    """

    FIELDS = frozenset(
        {
            "type",
            "required",
            "regex",
            "allow_unsafe_regex",
            "max_regex_input",
            "enum",
            "min_length",
            "max_length",
            "min",
            "max",
            "path_prefix",
            "items",
            "element",
            "keys",
            "values",
        }
    )

    type: str | None = None
    required: bool = False
    regex: str | None = None
    allow_unsafe_regex: bool = False
    max_regex_input: int | None = None
    enum: list[Any] | None = None
    min_length: int | None = None
    max_length: int | None = None
    min: float | None = None
    max: float | None = None
    path_prefix: str | None = None
    items: "ArgumentConstraint | None" = None
    keys: "ArgumentConstraint | None" = None
    values: "ArgumentConstraint | None" = None

    # -- construction -----------------------------------------------------
    @classmethod
    def _build(cls, data: Mapping[str, Any], loc: tuple[Any, ...]) -> "ArgumentConstraint":
        constraint = cls()
        constraint.type = _optional_type(data.get("type"), loc + ("type",))
        constraint.required = (
            coerce_bool(data["required"], loc + ("required",))
            if "required" in data
            else False
        )
        constraint.regex = _optional_regex(data.get("regex"), loc + ("regex",))
        constraint.allow_unsafe_regex = (
            coerce_bool(data["allow_unsafe_regex"], loc + ("allow_unsafe_regex",))
            if "allow_unsafe_regex" in data
            else False
        )
        constraint.max_regex_input = (
            coerce_int(data["max_regex_input"], loc + ("max_regex_input",), minimum=1)
            if data.get("max_regex_input") is not None
            else None
        )
        constraint.enum = _optional_enum(data.get("enum"), loc + ("enum",))
        constraint.min_length = (
            coerce_int(data["min_length"], loc + ("min_length",), minimum=0)
            if data.get("min_length") is not None
            else None
        )
        constraint.max_length = (
            coerce_int(data["max_length"], loc + ("max_length",), minimum=0)
            if data.get("max_length") is not None
            else None
        )
        constraint.min = (
            coerce_float(data["min"], loc + ("min",)) if data.get("min") is not None else None
        )
        constraint.max = (
            coerce_float(data["max"], loc + ("max",)) if data.get("max") is not None else None
        )
        constraint.path_prefix = (
            coerce_str(data["path_prefix"], loc + ("path_prefix",))
            if data.get("path_prefix") is not None
            else None
        )
        constraint.items = _optional_child(data, ("items", "element"), "items", loc)
        constraint.keys = _optional_child(data, ("keys",), "keys", loc)
        constraint.values = _optional_child(data, ("values",), "values", loc)
        constraint._validate(loc)
        return constraint

    # -- validation -------------------------------------------------------
    def _validate(self, loc: tuple[Any, ...]) -> None:
        """Apply the checks that span more than one field."""
        self._safe_regex(loc)
        self._consistent_ranges(loc)
        self._children_match_the_declared_type(loc)
        self._children_are_sane(loc)

    def _safe_regex(self, loc: tuple[Any, ...]) -> None:
        """Refuse a regex that could stall the proxy (R-01), at load time.

        Two checks run, and a pattern has to pass both.

        The **static** check parses the pattern and walks the parsed tree.  It
        refuses the shapes that are known to blow up, and it fails closed: a
        pattern built from an opcode the walker does not model is refused
        rather than accepted on the strength of an opinion the module cannot
        form (G-03).

        The **dynamic** probe then *measures* the pattern: it matches the
        compiled pattern against a short synthetic value under a wall-clock
        budget.  A static analyser cannot enumerate the space of catastrophic
        patterns, so the pattern that the analysis reasons about incorrectly
        is caught by the measurement instead (G-01).

        ``allow_unsafe_regex: true`` turns both off for one constraint; it is
        off by default and it is announced on stderr when the policy is
        loaded.
        """
        if self.regex is None or self.allow_unsafe_regex:
            return
        risk = check_pattern(self.regex)
        if risk is None:
            return
        raise ValidationError.one(
            loc + ("regex",),
            f"the regular expression {self.regex!r} is a denial-of-service risk ({risk}): it "
            "can stall the proxy on a short client value.  Rewrite it, or set "
            "allow_unsafe_regex: true on this constraint to use it anyway.",
        )

    def _consistent_ranges(self, loc: tuple[Any, ...]) -> None:
        for bound_name in ("min", "max"):
            val = getattr(self, bound_name)
            if val is not None and (math.isnan(val) or not math.isfinite(val)):
                raise ValidationError.one(
                    loc + (bound_name,), f"{bound_name} must be a finite number, got {val!r}"
                )
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValidationError.one(loc, "min must be less than or equal to max")
        if (
            self.min_length is not None
            and self.max_length is not None
            and self.min_length > self.max_length
        ):
            raise ValidationError.one(loc, "min_length must be less than or equal to max_length")

    def _children_match_the_declared_type(self, loc: tuple[Any, ...]) -> None:
        """Refuse a policy that says ``type: string`` and ``items:`` at once."""
        if self.items is not None and self.type is not None and self.type != "array":
            raise ValidationError.one(
                loc,
                f"'items' needs type 'array' (or no type at all), not {self.type!r}",
            )
        for name in ("keys", "values"):
            child = getattr(self, name)
            if child is not None and self.type is not None and self.type != "object":
                raise ValidationError.one(
                    loc, f"{name!r} needs type 'object' (or no type at all), not {self.type!r}"
                )

    def _children_are_sane(self, loc: tuple[Any, ...]) -> None:
        """Refuse a nested constraint that says something meaningless."""
        for name in ("items", "keys", "values"):
            child = getattr(self, name)
            if child is None:
                continue
            if child.required:
                raise ValidationError.one(
                    loc,
                    f"required is not meaningful inside {name!r}: every child is present by construction",
                )
        if self._nesting_depth() > MAX_ELEMENT_DEPTH:
            raise ValidationError.one(
                loc,
                f"element constraints may not be nested more than {MAX_ELEMENT_DEPTH} levels deep",
            )

    def _nesting_depth(self) -> int:
        """The number of child levels below this constraint."""
        depths = [
            child._nesting_depth() + 1
            for child in (self.items, self.keys, self.values)
            if child is not None
        ]
        return max(depths) if depths else 0

    def check(self, value: Any, *, name: str, base_dir: Path) -> list[str]:
        """Return the list of violations for ``value`` (empty when acceptable)."""
        return self._check(value, label=name, base_dir=base_dir, depth=0)

    def _check(self, value: Any, *, label: str, base_dir: Path, depth: int) -> list[str]:
        """Check one value; ``label`` names it in the violations, ``depth`` counts the child levels."""
        violations: list[str] = []

        if self.type is not None and not _TYPE_CHECKS[self.type](value):
            violations.append(f"argument {label!r} must be of type {self.type}, got {type(value).__name__}")
            return violations

        if self.enum is not None and not _enum_contains(value, self.enum):
            # G-02: The offending value is never rendered into the message.
            # The violation text reaches the audit log, the client and every
            # downstream reader of it, and the value a policy exists to reject
            # is exactly the value that must not be preserved.  The shape of
            # the value is reported instead.
            violations.append(
                f"argument {label!r} must be one of {self.enum!r}, got a value of type "
                f"{type(value).__name__} (fingerprint {fingerprint(value)})"
            )

        # ``path_prefix`` and ``regex`` describe a string.  A list is a list of
        # strings, so the constraint is applied to every element; a list of
        # anything else is a violation, never an unchecked element.
        targets: list[tuple[str, Any]] = (
            [(f"{label}[{index}]", element) for index, element in enumerate(value)]
            if isinstance(value, list)
            else [(label, value)]
        )

        if self.regex is not None:
            limit = (
                self.max_regex_input
                if self.max_regex_input is not None
                else DEFAULT_MAX_REGEX_INPUT
            )
            for target_label, target in targets:
                if not isinstance(target, str):
                    violations.append(f"argument {target_label!r} must be a string to match the regex {self.regex!r}")
                elif len(target) > limit:
                    # The engine backtracks over the value, so the value is
                    # capped: a long value is refused instead of being matched.
                    violations.append(
                        f"argument {target_label!r} is longer than the {limit} characters the regex "
                        f"{self.regex!r} may be applied to"
                    )
                # SECURITY: fullmatch anchors at both ends. A change to
                # re.match would silently turn every unanchored policy regex
                # into a prefix match — do not change without an anchor audit.
                elif re.fullmatch(self.regex, target) is None:
                    violations.append(f"argument {target_label!r} does not match the regex {self.regex!r}")

        if self.min_length is not None or self.max_length is not None:
            if isinstance(value, (str, list, tuple)):
                # G-02: the length is derived from the rejected value, so it is
                # not reported either.  Only the bound the operator wrote is.
                if self.min_length is not None and len(value) < self.min_length:
                    violations.append(f"argument {label!r} is shorter than min_length {self.min_length}")
                if self.max_length is not None and len(value) > self.max_length:
                    violations.append(f"argument {label!r} is longer than max_length {self.max_length}")

        if self.min is not None or self.max is not None:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                violations.append(f"argument {label!r} must be a number to satisfy the range constraint")
            else:
                # G-04: the bounds are finite by construction -- the model
                # validator refuses NaN and infinity -- but a value that
                # arrived over the wire can still be a NaN, and every
                # comparison against a NaN is false.  A NaN would therefore
                # slip through a range constraint that rejects it.  The
                # runtime check closes that hole.
                if not math.isfinite(value):
                    violations.append(
                        f"argument {label!r} must be a finite number to satisfy the range constraint"
                    )
                else:
                    if self.min is not None and value < self.min:
                        violations.append(f"argument {label!r} is below min {self.min}")
                    if self.max is not None and value > self.max:
                        violations.append(f"argument {label!r} is above max {self.max}")

        if self.path_prefix is not None:
            for target_label, target in targets:
                if not isinstance(target, str):
                    violations.append(f"argument {target_label!r} must be a string path to satisfy path_prefix")
                else:
                    try:
                        check_path(target, self.path_prefix, base_dir)
                    except PathViolation as exc:
                        violations.append(
                            f"argument {target_label!r} violates path_prefix {self.path_prefix!r}: {exc.message}"
                        )

        violations.extend(self._check_children(value, label=label, base_dir=base_dir, depth=depth))
        return violations

    def _check_children(self, value: Any, *, label: str, base_dir: Path, depth: int) -> list[str]:
        """Apply the declared child constraints to the children of ``value``."""
        violations: list[str] = []

        if self.items is not None:
            if not isinstance(value, list):
                violations.append(
                    f"argument {label!r} must be a list to satisfy the items constraint, "
                    f"got {type(value).__name__}"
                )
            elif depth >= MAX_ELEMENT_DEPTH:
                violations.append(
                    f"argument {label!r} nests element constraints deeper than the maximum "
                    f"of {MAX_ELEMENT_DEPTH}"
                )
            else:
                for index, element in enumerate(value):
                    violations.extend(
                        self.items._check(
                            element, label=f"{label}[{index}]", base_dir=base_dir, depth=depth + 1
                        )
                    )

        if self.keys is not None:
            if not isinstance(value, dict):
                violations.append(
                    f"argument {label!r} must be a mapping to satisfy the keys constraint, "
                    f"got {type(value).__name__}"
                )
            elif depth >= MAX_ELEMENT_DEPTH:
                violations.append(
                    f"argument {label!r} nests element constraints deeper than the maximum "
                    f"of {MAX_ELEMENT_DEPTH}"
                )
            else:
                for key in value:
                    violations.extend(
                        self.keys._check(
                            key, label=f"{label} key {key!r}", base_dir=base_dir, depth=depth + 1
                        )
                    )

        if self.values is not None:
            if not isinstance(value, dict):
                violations.append(
                    f"argument {label!r} must be a mapping to satisfy the values constraint, "
                    f"got {type(value).__name__}"
                )
            elif depth >= MAX_ELEMENT_DEPTH:
                violations.append(
                    f"argument {label!r} nests element constraints deeper than the maximum "
                    f"of {MAX_ELEMENT_DEPTH}"
                )
            else:
                for key, item in value.items():
                    violations.extend(
                        self.values._check(
                            item, label=f"{label} value for {key!r}", base_dir=base_dir, depth=depth + 1
                        )
                    )

        return violations

@dataclass
class ToolRule(Model):
    """The rule for a single tool."""

    FIELDS = frozenset(
        {
            "action",
            "reason",
            "require_approval",
            "rate_limit_per_minute",
            "max_calls",
            "allow_undeclared_arguments",
            "arguments",
        }
    )

    action: str = "allow"
    reason: str | None = None
    require_approval: bool = False
    rate_limit_per_minute: int | None = None
    max_calls: int | None = None
    allow_undeclared_arguments: bool = False
    arguments: dict[str, ArgumentConstraint] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in ("allow", "deny"):
            raise ValueError(f"unknown action {self.action!r}; expected 'allow' or 'deny'")
        if self.require_approval and self.action == "deny":
            raise ValueError("require_approval cannot be combined with action 'deny'")

    @classmethod
    def _build(cls, data: Mapping[str, Any], loc: tuple[Any, ...]) -> "ToolRule":
        rule = cls()
        action = coerce_str(data.get("action", "allow"), loc + ("action",))
        if action not in ("allow", "deny"):
            raise ValidationError.one(
                loc + ("action",), f"unknown action {action!r}; expected 'allow' or 'deny'"
            )
        rule.action = action
        rule.reason = (
            coerce_str(data["reason"], loc + ("reason",))
            if data.get("reason") is not None
            else None
        )
        rule.require_approval = (
            coerce_bool(data["require_approval"], loc + ("require_approval",))
            if "require_approval" in data
            else False
        )
        rule.rate_limit_per_minute = (
            coerce_int(data["rate_limit_per_minute"], loc + ("rate_limit_per_minute",), minimum=1)
            if data.get("rate_limit_per_minute") is not None
            else None
        )
        rule.max_calls = (
            coerce_int(data["max_calls"], loc + ("max_calls",), minimum=1)
            if data.get("max_calls") is not None
            else None
        )
        rule.allow_undeclared_arguments = (
            coerce_bool(data["allow_undeclared_arguments"], loc + ("allow_undeclared_arguments",))
            if "allow_undeclared_arguments" in data
            else False
        )
        rule.arguments = _argument_map(data.get("arguments"), loc + ("arguments",))
        if rule.require_approval and rule.action == "deny":
            raise ValidationError.one(
                loc, "require_approval cannot be combined with action 'deny'"
            )
        return rule


@dataclass
class MethodPolicy(Model):
    """Policy for the non-tool MCP methods that are relayed to the upstream."""

    FIELDS = frozenset({"allow", "deny"})

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    @classmethod
    def _build(cls, data: Mapping[str, Any], loc: tuple[Any, ...]) -> "MethodPolicy":
        policy = cls()
        policy.allow = _string_list(data.get("allow"), loc + ("allow",))
        policy.deny = _string_list(data.get("deny"), loc + ("deny",))
        return policy


@dataclass
class SessionPolicy(Model):
    """Policy for the lifetime and the global budget of the session."""

    FIELDS = frozenset({"ttl_seconds", "max_calls"})

    ttl_seconds: int | None = None
    max_calls: int | None = None

    @classmethod
    def _build(cls, data: Mapping[str, Any], loc: tuple[Any, ...]) -> "SessionPolicy":
        policy = cls()
        policy.ttl_seconds = (
            coerce_int(data["ttl_seconds"], loc + ("ttl_seconds",), minimum=1)
            if data.get("ttl_seconds") is not None
            else None
        )
        policy.max_calls = (
            coerce_int(data["max_calls"], loc + ("max_calls",), minimum=1)
            if data.get("max_calls") is not None
            else None
        )
        return policy


@dataclass
class Policy(Model):
    """A parsed policy document."""

    FIELDS = frozenset({"version", "default_action", "session", "methods", "tools"})

    version: int = 1
    default_action: str = "deny"
    session: SessionPolicy = field(default_factory=SessionPolicy)
    methods: MethodPolicy = field(default_factory=MethodPolicy)
    tools: dict[str, ToolRule] = field(default_factory=dict)

    #: Path of the file this policy was loaded from, if any.
    source: str | None = None

    @classmethod
    def _build(cls, data: Mapping[str, Any], loc: tuple[Any, ...]) -> "Policy":
        policy = cls()
        policy.version = (
            coerce_int(data["version"], loc + ("version",)) if "version" in data else 1
        )
        default_action = coerce_str(data.get("default_action", "deny"), loc + ("default_action",))
        if default_action != "deny":
            raise ValidationError.one(
                loc + ("default_action",),
                "default_action must be 'deny'; unlisted tools are always denied",
            )
        policy.default_action = default_action

        # A section that holds nothing but comments reads as ``None``.  Every
        # example policy in this repository is written that way, and the
        # default-deny example tells the operator to start from it -- so
        # refusing the file would refuse the file the documentation hands out.
        # An empty section means an empty section; a mistyped one is refused.
        session = data.get("session")
        policy.session = (
            SessionPolicy.from_dict(session, loc + ("session",))
            if session is not None
            else SessionPolicy()
        )
        methods = data.get("methods")
        policy.methods = (
            MethodPolicy.from_dict(methods, loc + ("methods",))
            if methods is not None
            else MethodPolicy()
        )
        policy.tools = _tool_map(data.get("tools"), loc + ("tools",))
        return policy


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one tool call against the policy."""

    decision: str
    code: str
    reason: str
    violations: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        """``True`` when the call may be forwarded to the upstream."""
        return self.decision == ALLOW

    @property
    def is_error(self) -> bool:
        """``True`` when the call must be refused."""
        return not self.allowed

def _format_validation_error(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(item) for item in error['loc']) or '<document>'}: {error['msg']}"
        for error in exc.errors()
    )


def _walk_child(constraint: ArgumentConstraint, path: str) -> Iterator[tuple[str, ArgumentConstraint]]:
    """A constraint and the constraints nested inside it."""
    yield path, constraint
    for name in ("items", "keys", "values"):
        child = getattr(constraint, name)
        if child is not None:
            yield from _walk_child(child, f"{path}.{name}")


def _announce_unsafe_regexes(policy: Policy) -> None:
    """Say out loud that a policy uses the escape hatch of the R-01 guard."""
    for tool_name, rule in policy.tools.items():
        for argument_name, constraint in rule.arguments.items():
            for path, child in _walk_child(
                constraint, f"tools.{tool_name}.arguments.{argument_name}"
            ):
                if not child.allow_unsafe_regex or child.regex is None:
                    continue
                print(
                    f"mcp-guard: warning: {path}.regex uses allow_unsafe_regex: the pattern "
                    f"{child.regex!r} may stall the proxy on a short client value",
                    file=sys.stderr,
                )


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy file, or raise :class:`PolicyError`."""
    policy_path = Path(path)
    try:
        raw = policy_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {policy_path}") from None
    except IsADirectoryError:
        raise PolicyError(f"policy file is a directory: {policy_path}") from None
    except OSError as exc:
        raise PolicyError(f"policy file {policy_path} could not be read: {exc}") from None

    try:
        document = yaml.safe_load(raw)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise PolicyError(f"policy file {policy_path} is not valid YAML: {exc}") from None

    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise PolicyError( f"policy file {policy_path} must contain a mapping at the top level, "
                                   f"got {type(document).__name__}"
        )

    try:
        policy = Policy.model_validate(document)
    except ValidationError as exc:
        raise PolicyError(f"policy file {policy_path} is invalid: {_format_validation_error(exc)}") from None

    policy.source = str(policy_path)
    _announce_unsafe_regexes(policy)
    return policy

class PolicyEngine:
    """Evaluates tool calls against a :class:`Policy` and the session state."""

    def __init__(
        self, policy: Policy, session_id: str, base_dir: str | Path | None = None,
        ttl_seconds: int | None = None, clock: Callable[[], float] = time.monotonic,
        canary_hook: Any | None = None,
    ) -> None:
        self.policy = policy
        self.session_id = session_id
        self.base_dir = Path(base_dir) if base_dir is not None else Path.cwd()
        effective_ttl = ttl_seconds if ttl_seconds is not None else policy.session.ttl_seconds
        self.guard = SessionGuard(
            session_id,
            ttl_seconds=effective_ttl,
            clock=clock,
            session_max_calls=policy.session.max_calls,
        )
        self.canary_hook = canary_hook
        # OPUS-02: The policy's own tool names are normalised too, so that a
        # rule written with a full-width or otherwise confusable spelling is
        # found by the same normalisation the client's name goes through.
        # F-05: When normalising tool names with NFKC, deny-overrides must win
        # if multiple policy rules collide under NFKC normalisation.
        self._normalised_tools: dict[str, ToolRule] = {}
        for name, rule in policy.tools.items():
            norm_name = unicodedata.normalize("NFKC", name)
            if norm_name in self._normalised_tools:
                existing = self._normalised_tools[norm_name]
                if rule.action == DENY or existing.action == DENY:
                    self._normalised_tools[norm_name] = rule if rule.action == DENY else existing
                else:
                    self._normalised_tools[norm_name] = rule
            else:
                self._normalised_tools[norm_name] = rule

    def register_canary_hook(self, hook: Any) -> None:
        """Register an outbound canary exfiltration blocking hook."""
        self.canary_hook = hook

    def rule_for(self, tool_name: str) -> ToolRule | None:
        """The rule for ``tool_name``, or ``None`` when the tool is unlisted.

        OPUS-02: Tool names are normalised with Unicode NFKC, so a
        full-width spelling of a name, or one built from compatibility
        characters, finds the same rule as the plain spelling.  A client
        cannot use a homoglyph to step around a rule that denies it.
        """
        norm_name = unicodedata.normalize("NFKC", tool_name)
        rule = self._normalised_tools.get(norm_name)
        if rule is not None:
            return rule
        return self.policy.tools.get(tool_name)

    def advertises(self, tool_name: str) -> bool:
        """Whether the tool may be advertised to the client by ``tools/list``."""
        rule = self.rule_for(tool_name)
        return rule is not None and rule.action != "deny"

    def visible_tools(self, tool_names: Iterable[str]) -> list[str]:
        """Filter ``tool_names`` down to the ones the policy does not deny."""
        return [name for name in tool_names if self.advertises(name)]

    def method_allowed(self, method: str) -> tuple[bool, str]:
        """Whether a non-tool MCP method may be relayed to the upstream.

        G-13: The surfaces that relay upstream *content* to the client --
        ``resources/*``, ``prompts/*`` and ``completion/*`` -- are denied by
        default.  A policy has to name them in ``methods.allow`` before they
        are relayed.  They carry no tool rule of their own, so nothing else
        in the policy constrains what comes back through them, and an
        upstream that has been talked into serving a prompt injection would
        otherwise reach the client unfiltered.
        """
        methods = self.policy.methods
        if method in methods.deny:
            return False, f"method {method!r} is denied by policy"
        if methods.allow:
            if method not in methods.allow:
                return False, f"method {method!r} is not in the policy allow list"
            return True, ""
        if method.startswith(PASSTHROUGH_METHOD_PREFIXES):
            return False, (
                f"method {method!r} relays upstream content and is denied by default; "
                "name it in methods.allow to relay it"
            )
        return True, ""

    def check_arguments(self, rule: ToolRule, arguments: Mapping[str, Any]) -> list[str]:
        """Validate ``arguments`` against the constraints of ``rule``."""
        violations: list[str] = []
        # G-05: A client value nested deeper than the walker can safely go is
        # refused before the walk starts.  The redactor that writes the audit
        # record has its own bound; this is the bound on the decision path.
        depth = _value_depth(arguments)
        if depth > MAX_ARGUMENT_DEPTH:
            violations.append(
                f"the argument value is nested {depth} levels deep, which is over the "
                f"{MAX_ARGUMENT_DEPTH} levels the policy walker accepts"
            )
            return violations
        # OPUS-04 & F-08: Refuse undeclared arguments unless the tool rule explicitly allows them.
        declared = set(rule.arguments) if rule.arguments else set()
        extra = set(arguments) - declared
        if extra and not getattr(rule, "allow_undeclared_arguments", False):
            if declared:
                violations.append(
                    f"undeclared argument(s) {', '.join(sorted(extra))!r}: only {sorted(declared)} are allowed"
                )
            else:
                violations.append(
                    f"undeclared argument(s) {', '.join(sorted(extra))!r}: tool declares no arguments and allow_undeclared_arguments is false"
                )
        if rule.arguments:
            for name, constraint in rule.arguments.items():
                if name not in arguments:
                    if constraint.required:
                        violations.append(f"argument {name!r} is required but missing")
                    continue
                violations.extend(constraint.check(arguments[name], name=name, base_dir=self.base_dir))
        return violations

    def evaluate(self, tool_name: str, arguments: Mapping[str, Any] | None = None) -> Decision:
        """Decide a call, in order: TTL, listed, rate limits, canary check, denied, approval, limits, args."""
        arguments = dict(arguments or {})

        expiry_reason = self.guard.expiry_reason()
        if expiry_reason is not None:
            return Decision(TTL_EXPIRED, TTL_EXPIRED, expiry_reason)

        rule = self.rule_for(tool_name)
        if rule is None:
            return Decision(
                DENY,
                DENY,
                f"tool {tool_name!r} is not listed in the policy (default deny)",
            )

        # F-14: Check rate limits before recording canary calls
        limit_reason = self.guard.check_rate_limit(
            tool_name, rule.rate_limit_per_minute, rule.max_calls
        )
        if limit_reason is not None:
            return Decision(RATE_LIMITED, RATE_LIMITED, limit_reason)

        # The canary hook is evaluated next: a leak of a canary token is refused
        # even for a tool the policy would otherwise allow, because the token
        # is the evidence, not the tool.
        if self.canary_hook is not None:
            canary_decision, _detection = self.canary_hook.evaluate_call(tool_name, arguments)
            if canary_decision.decision == DENY:
                self.guard.record_call(tool_name)
                return canary_decision

        if rule.action == "deny":
            return Decision(
                DENY,
                DENY,
                rule.reason or f"tool {tool_name!r} is denied by policy",
            )

        if rule.require_approval:
            return Decision(
                APPROVAL_REQUIRED,
                APPROVAL_REQUIRED,
                rule.reason or f"tool {tool_name!r} requires an explicit approval before it may run",
            )

        # The attempt costs budget, whether or not the arguments turn out to be
        # acceptable: a client that may probe the argument constraints for free
        # is exactly the probing a rate limit is there to stop.
        self.guard.record_call(tool_name)

        violations = self.check_arguments(rule, arguments)
        if violations:
            return Decision(DENY, DENY, "; ".join(violations), violations=tuple(violations))

        return Decision(ALLOW, ALLOW, rule.reason or f"tool {tool_name!r} is allowed by policy")
