"""The static policy analyser behind ``mcp-guard policy-lint``.

A policy file is the one piece of ``mcp-guard`` that a human writes by hand,
so it is the one piece that can be wrong in a way no test can see.  This module
looks at the policy **as written** -- the parsed YAML document, not the
validated model -- and reports the mistakes that are cheap to make and
expensive to discover in production:

``PL-SCHEMA``
    the document does not validate against the policy schema.
``PL-R01``
    a regular expression with a nested quantifier, which is a denial-of-service
    risk (the same shape the loader refuses).
``PL-R01-ESCAPE``
    a constraint that turns the R-01 guard off with ``allow_unsafe_regex``.
``PL-REGEX-UNANCHORED``
    a regular expression that carries no explicit anchor and therefore only
    matches a prefix if it is ever used outside the engine's full match.
``PL-PATH-PREFIX-BROAD``
    a ``path_prefix`` that contains the whole filesystem (``/``) or the whole
    working directory (``.``) -- a containment that contains nothing.
``PL-LIST-ELEMENT-UNCONSTRAINED``
    a list parameter whose elements are not constrained at all.
``PL-LIST-PATH-UNCONSTRAINED``
    a parameter that takes a list of paths, where no element of the list is
    constrained to a prefix or a pattern.
``PL-SYMLINK-ESCAPE``
    a ``path_prefix`` that reaches outside itself through a symlink.
``PL-PATH-PREFIX-MISSING``
    a ``path_prefix`` that does not exist on this machine (a note: the check is
    skipped rather than failed).
``PL-NO-TOOLS``
    a policy that lists no tools at all, so every call is denied by the default.

The analyser is **document level**: it never calls :func:`mcp_guard.policy.
load_policy`, because that function refuses an R-01 pattern -- and a linter that
stops at the first problem cannot report the second one.  The document is
parsed here, the schema is checked here, and every rule runs on the raw
document, so one run reports *every* problem in the file.

Nothing in this module executes a client-supplied value: the regex check is the
same static, non-executing analysis the loader uses.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from . import yamlmini as yaml

from . import __version__
from ._model import ValidationError
from .policy import Policy
from .redos import describe_risk

#: The three severities a finding can have.  They map onto the SARIF levels
#: ``error``, ``warning`` and ``note`` one to one.
ERROR = "error"
WARNING = "warning"
NOTE = "note"

#: The metadata of every rule, in the order they are reported.
RULES: dict[str, dict[str, str]] = {
    "PL-SCHEMA": {
        "name": "PolicySchema",
        "severity": ERROR,
        "short": "The policy file does not validate against the policy schema.",
        "full": (
            "A policy that does not validate is refused by the proxy at start-up, so the "
            "mistake is found at the worst possible moment.  The message names the offending "
            "key and what was expected there."
        ),
    },
    "PL-R01": {
        "name": "NestedQuantifier",
        "severity": ERROR,
        "short": "The regular expression is a denial-of-service risk (R-01).",
        "full": (
            "A regular expression with a nested quantifier -- (a+)+, (a|aa)+, (.*a){10,} -- turns "
            "a short client value into minutes of backtracking.  The pattern lives in the "
            "operator's policy, but the client is the one who pays for it: the proxy is stuck in "
            "the regex engine while the connection waits.  The loader refuses such a pattern."
        ),
    },
    "PL-R01-ESCAPE": {
        "name": "UnsafeRegexEscapeHatch",
        "severity": WARNING,
        "short": "The constraint turns the R-01 guard off.",
        "full": (
            "allow_unsafe_regex: true makes the loader use a pattern that can stall the proxy.  "
            "It is announced on stderr when the policy is loaded, but it is a standing liability "
            "for whoever inherits the policy file."
        ),
    },
    "PL-REGEX-UNANCHORED": {
        "name": "UnanchoredRegex",
        "severity": WARNING,
        "short": "The regular expression carries no explicit anchor.",
        "full": (
            "The engine matches a policy regex with re.fullmatch, so the pattern is anchored "
            "whether it says so or not.  A pattern without an explicit anchor is one that will "
            "match a prefix the moment it is reused with re.match or re.search -- in a rewrite "
            "rule, a log filter, or a future version of the engine."
        ),
    },
    "PL-PATH-PREFIX-BROAD": {
        "name": "BroadPathPrefix",
        "severity": ERROR,
        "short": "The path_prefix contains everything.",
        "full": (
            "A path_prefix of '/' or '.' does not contain the workspace, it contains the whole "
            "filesystem or the whole working directory.  A path constraint that contains "
            "everything is not a path constraint: it is a comment that reads like one."
        ),
    },
    "PL-LIST-ELEMENT-UNCONSTRAINED": {
        "name": "UnconstrainedListElements",
        "severity": ERROR,
        "short": "The list is accepted element by element without a single constraint.",
        "full": (
            "A list parameter with no items constraint, no regex, no path_prefix, no enum and no "
            "length bound accepts every element it is given.  The list is the shape a traversal "
            "hides in, so an unconstrained list is an unconstrained argument."
        ),
    },
    "PL-LIST-PATH-UNCONSTRAINED": {
        "name": "UnconstrainedListPaths",
        "severity": WARNING,
        "short": "The list of paths is not constrained to a prefix or a pattern.",
        "full": (
            "This parameter takes a list of paths, and the elements are constrained -- but not on "
            "the path.  A list of strings that may be any string is a list of paths that may be "
            "anywhere: add a path_prefix or a regex to the items constraint."
        ),
    },
    "PL-SYMLINK-ESCAPE": {
        "name": "SymlinkEscape",
        "severity": WARNING,
        "short": "The path_prefix reaches outside itself through a symlink.",
        "full": (
            "The prefix contains a symlink whose target is outside the prefix, so the directory "
            "the operator believes they are containing is not the directory the operating system "
            "will open.  The proxy resolves a path before it compares it, so this is refused at "
            "run time -- but the policy says something the filesystem does not."
        ),
    },
    "PL-PATH-PREFIX-MISSING": {
        "name": "MissingPathPrefix",
        "severity": NOTE,
        "short": "The path_prefix does not exist on this machine.",
        "full": (
            "The prefix was not found, so the symlink check was skipped.  This is a note and not "
            "a failure: the policy may be linted on a machine that is not the one that runs it."
        ),
    },
    "PL-NO-TOOLS": {
        "name": "NoTools",
        "severity": NOTE,
        "short": "The policy lists no tools, so every call is denied.",
        "full": (
            "default_action is always 'deny', so a policy with no tools refuses every call.  "
            "That may be exactly what was meant -- but it is worth a second look."
        ),
    },
    "PL-METHODS-CONTENT-RELAYED": {
        "name": "MethodsContentRelayed",
        "severity": WARNING,
        "short": "The policy relays a method that returns upstream content.",
        "full": (
            "resources/*, prompts/* and completion/* relay content from the upstream to the "
            "client without a tool rule of their own, so nothing in the policy constrains what "
            "comes back through them.  They are denied by default; naming one in methods.allow "
            "turns it on deliberately."
        ),
    },
    "PL-APPROVAL-NO-CHANNEL": {
        "name": "ApprovalNoChannel",
        "severity": NOTE,
        "short": "The rule requires an approval that mcp-guard cannot obtain.",
        "full": (
            "require_approval refuses the call, and there is no approval artefact the proxy "
            "checks, so the call stays refused.  The behaviour is safe; the name is misleading."
        ),
    },
    "PL-CONFUSABLE-TOOL-NAME": {
        "name": "ConfusableToolName",
        "severity": ERROR,
        "short": "Two tool rule names collide under Unicode NFKC normalisation.",
        "full": (
            "When tool names normalise to the same key under Unicode NFKC, policy rules can shadow "
            "each other.  Deny-overrides wins at runtime, but colliding tool rule names in policy "
            "are an error that must be resolved explicitly."
        ),
    },
}

#: The maximum number of directory entries the symlink scan looks at.  The
#: scan is a convenience, not a proof: it must not turn a lint of a policy
#: file into a walk of a large tree.
MAX_SYMLINK_SCAN_ENTRIES = 2000

#: The words that make an argument name look like it holds a path.  A parameter
#: called 'files' that holds a list is a list of paths whether the policy says
#: so or not.
PATH_NAME_WORDS = frozenset(
    {
        "path", "paths", "file", "files", "filename", "filenames", "filepath",
        "filepaths", "dir", "dirs", "directory", "directories", "folder",
        "folders", "src", "source", "dest", "destination", "target", "targets",
        "root", "roots", "location", "locations", "tree", "repo",
    }
)


@dataclass(frozen=True)
class Finding:
    """One problem the analyser found in a policy file."""

    rule_id: str
    severity: str
    message: str
    location: str
    line: int | None = None
    help_text: str | None = None

    @property
    def rule(self) -> dict[str, str]:
        """The metadata of the rule this finding belongs to."""
        return RULES[self.rule_id]


@dataclass
class LintReport:
    """Every finding of one policy file, plus where the file came from."""

    path: str
    findings: list[Finding] = field(default_factory=list)

    def of_severity(self, severity: str) -> list[Finding]:
        """The findings of one severity."""
        return [finding for finding in self.findings if finding.severity == severity]

    @property
    def errors(self) -> list[Finding]:
        """The error level findings."""
        return self.of_severity(ERROR)

    @property
    def warnings(self) -> list[Finding]:
        """The warning level findings."""
        return self.of_severity(WARNING)

    @property
    def notes(self) -> list[Finding]:
        """The note level findings."""
        return self.of_severity(NOTE)

    def counts(self) -> dict[str, int]:
        """How many findings of each severity there are."""
        return {
            ERROR: len(self.errors),
            WARNING: len(self.warnings),
            NOTE: len(self.notes),
        }

    def exit_code(self, *, strict: bool = False) -> int:
        """0 when nothing failed, 1 when something did.

        A warning is not a failure by default: a policy that uses
        ``allow_unsafe_regex`` on purpose is a policy that works.  ``strict``
        makes a warning fail too, for a pipeline that wants a clean report.
        """
        if self.errors:
            return 1
        if strict and self.warnings:
            return 1
        return 0


# -- the document walk -----------------------------------------------------

@dataclass(frozen=True)
class _Constraint:
    """One constraint of a policy document, with where it sits in the file."""

    path: str
    tuple_path: tuple[Any, ...]
    node: Mapping[str, Any]
    kind: str


@dataclass(frozen=True)
class _Argument:
    """One argument of a tool, with every constraint nested inside it."""

    tool: str
    argument: str
    path: str
    tuple_path: tuple[Any, ...]
    root: Mapping[str, Any]
    constraints: tuple[_Constraint, ...]

    @property
    def name(self) -> str:
        """The name of the argument, for the messages."""
        return self.argument


def _walk_constraint(
    node: Any, path: str, tuple_path: tuple[Any, ...], kind: str
) -> Iterator[_Constraint]:
    """Yield ``node`` and every constraint nested inside it."""
    if not isinstance(node, Mapping):
        return
    yield _Constraint(path, tuple_path, node, kind)
    child = node.get("items")
    child_key = "items"
    if not isinstance(child, Mapping):
        child = node.get("element")
        child_key = "element"
    if isinstance(child, Mapping):
        yield from _walk_constraint(
            child, f"{path}.{child_key}", tuple_path + (child_key,), "items"
        )
    for name in ("keys", "values"):
        nested = node.get(name)
        if isinstance(nested, Mapping):
            yield from _walk_constraint(
                nested, f"{path}.{name}", tuple_path + (name,), name
            )


def _walk_arguments(document: Mapping[str, Any]) -> Iterator[_Argument]:
    """Yield every argument of every tool of a policy document."""
    tools = document.get("tools")
    if not isinstance(tools, Mapping):
        return
    for tool_name, rule in tools.items():
        if not isinstance(rule, Mapping):
            continue
        arguments = rule.get("arguments")
        if not isinstance(arguments, Mapping):
            continue
        for argument_name, constraint in arguments.items():
            base = f"tools.{tool_name}.arguments.{argument_name}"
            base_tuple = ("tools", tool_name, "arguments", argument_name)
            constraints = tuple(_walk_constraint(constraint, base, base_tuple, "argument"))
            yield _Argument(
                tool=str(tool_name),
                argument=str(argument_name),
                path=base,
                tuple_path=base_tuple,
                root=constraint if isinstance(constraint, Mapping) else {},
                constraints=constraints,
            )


# -- line numbers ----------------------------------------------------------

def _line_index(text: str) -> dict[tuple[Any, ...], int]:
    """Map every path of a YAML document to the line it starts on.

    The index is built from the *composed* node tree, so a path that does not
    exist in the document is simply absent from it -- a missing line number is
    never a crash.
    """
    try:
        root = yaml.compose(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        return {}
    index: dict[tuple[Any, ...], int] = {}

    def walk(node: Any, path: tuple[Any, ...]) -> None:
        index[path] = node.start_mark.line + 1
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                key = getattr(key_node, "value", None)
                if not isinstance(key, (str, int, float, bool)):
                    continue
                walk(value_node, path + (key,))
        elif isinstance(node, yaml.SequenceNode):
            for index_, item in enumerate(node.value):
                walk(item, path + (index_,))

    if root is not None:
        walk(root, ())
    return index


def _line_for(index: Mapping[tuple[Any, ...], int], tuple_path: tuple[Any, ...]) -> int | None:
    """The line of ``tuple_path``, trying the ``items``/``element`` alias."""
    line = index.get(tuple_path)
    if line is not None:
        return line
    for alias in ("element", "items"):
        if tuple_path and tuple_path[-1] == alias:
            other = tuple_path[:-1] + ("items" if alias == "element" else "element",)
            line = index.get(other)
            if line is not None:
                return line
    return None


def _key_line(
    index: Mapping[tuple[Any, ...], int], constraint: "_Constraint", key: str
) -> int | None:
    """The line of one key of a constraint, falling back to the constraint.

    A finding about ``regex`` should point at the line the regex is written
    on, not at the line the constraint starts on: the operator is looking for
    the offending text.
    """
    line = _line_for(index, constraint.tuple_path + (key,))
    if line is not None:
        return line
    return _line_for(index, constraint.tuple_path)


# -- the individual rules --------------------------------------------------

def _is_escaped(pattern: str, position: int) -> bool:
    """Is the character at ``position`` escaped by an odd number of backslashes?"""
    backslashes = 0
    cursor = position - 1
    while cursor >= 0 and pattern[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _anchored_at_start(pattern: str) -> bool:
    """Does the pattern start with an explicit anchor?"""
    return pattern.startswith("^") or pattern.startswith("\\A")


def _anchored_at_end(pattern: str) -> bool:
    """Does the pattern end with an explicit anchor?"""
    if pattern.endswith("$") and not _is_escaped(pattern, len(pattern) - 1):
        return True
    if pattern.endswith("\\Z") and not _is_escaped(pattern, len(pattern) - 2):
        return True
    return False


def _is_broad_prefix(prefix: str) -> bool:
    """Is the prefix the whole filesystem or the whole working directory?"""
    normalised = posixpath.normpath(prefix.strip())
    return normalised in (".", "/", "//", "..") or normalised.startswith("../")


def _looks_like_a_path(name: str) -> bool:
    """Does the argument name look like it holds a path?

    The name is split into words on the separators and on the camel case
    boundaries, so ``readFiles``, ``read_files`` and ``read-files`` are all
    read plus files.
    """
    words: set[str] = set()
    for chunk in name.replace("-", "_").replace(".", "_").split("_"):
        if not chunk:
            continue
        current = ""
        for character in chunk:
            if character.isupper() and current:
                words.add(current.lower())
                current = character
            else:
                current += character
        if current:
            words.add(current.lower())
    return bool(words & PATH_NAME_WORDS)


def _subtree_has(constraints: Sequence[_Constraint], key: str) -> bool:
    """Does any constraint of the subtree carry ``key``?"""
    return any(key in constraint.node for constraint in constraints)


def _is_list_argument(argument: _Argument) -> bool:
    """Is the argument a list?"""
    root = argument.root
    if root.get("type") == "array":
        return True
    return any(constraint.kind == "items" for constraint in argument.constraints)


# -- the symlink check -----------------------------------------------------

def _literal_chain(prefix: Path, base: Path) -> list[Path]:
    """The prefix's components, *without* resolving the symlinks in them."""
    if prefix.is_absolute():
        current = Path(prefix.anchor)
        parts = prefix.parts[1:]
    else:
        current = base
        parts = prefix.parts
    chain = [current]
    for part in parts:
        current = current / part
        chain.append(current)
    return chain


def _outside(target: Path, container: Path) -> bool:
    """Is ``target`` outside ``container``?"""
    try:
        return target != container and not target.is_relative_to(container)
    except ValueError:  # pragma: no cover - different drives on Windows
        return True


def _symlink_escapes(prefix: str, base: Path) -> tuple[list[str], bool]:
    """The symlinks that take ``prefix`` outside itself, and whether it exists."""
    prefix_path = Path(prefix)
    resolved = (base / prefix_path).resolve() if not prefix_path.is_absolute() else prefix_path.resolve()
    escapes: list[str] = []

    for element in _literal_chain(prefix_path, base)[1:]:
        try:
            if not element.is_symlink():
                continue
            target = element.resolve()
        except OSError:  # pragma: no cover - a broken symlink
            continue
        if _outside(target, resolved):
            escapes.append(
                f"the prefix {prefix!r} contains the symlink {str(element)!r}, which points to "
                f"{str(target)!r}, outside the prefix"
            )

    if resolved.is_dir():
        scanned = 0
        try:
            for root, dirs, files in os.walk(resolved, followlinks=False):
                for name in dirs + files:
                    if scanned >= MAX_SYMLINK_SCAN_ENTRIES:
                        break
                    scanned += 1
                    entry_path = Path(root) / name
                    try:
                        if not entry_path.is_symlink():
                            continue
                        target = entry_path.resolve()
                    except OSError:  # pragma: no cover - a broken symlink
                        continue
                    if _outside(target, resolved):
                        rel = entry_path.relative_to(resolved)
                        escapes.append(
                            f"the prefix {prefix!r} contains the symlink {entry_path.name!r}, which "
                            f"points to {str(target)!r}, outside the prefix"
                        )
                if scanned >= MAX_SYMLINK_SCAN_ENTRIES:
                    break
        except OSError:  # pragma: no cover - the directory is not readable
            pass

    return escapes, resolved.exists()


# -- the report builders ---------------------------------------------------

def _finding(
    rule_id: str,
    message: str,
    location: str,
    line: int | None,
    help_text: str | None = None,
) -> Finding:
    """Build a finding, taking its severity from the rule metadata."""
    return Finding(
        rule_id=rule_id,
        severity=RULES[rule_id]["severity"],
        message=message,
        location=location,
        line=line,
        help_text=help_text,
    )


def _schema_findings(
    document: Mapping[str, Any], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """The schema errors of a policy document, minus the ones the R-01 rule owns."""
    findings: list[Finding] = []
    try:
        Policy.model_validate(dict(document))
    except ValidationError as exc:
        for error in exc.errors():
            message = error.get("msg", "")
            location_tuple = tuple(error.get("loc", ()))
            location = ".".join(str(part) for part in location_tuple) or "<document>"
            line = _line_for(index, location_tuple)
            if "denial-of-service risk" in message:
                # The R-01 rule reports this one with the exact path of the
                # constraint; reporting it twice would only make the operator
                # read it twice.
                continue
            findings.append(
                _finding(
                    "PL-SCHEMA",
                    f"{location}: {message}",
                    location,
                    line,
                    help_text="Fix the key, or consult the policy schema in README.md section 4.",
                )
            )
    return findings


def _regex_findings(
    arguments: Sequence[_Argument], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """The R-01 and the anchoring findings of every regex in the document."""
    findings: list[Finding] = []
    for argument in arguments:
        for constraint in argument.constraints:
            regex = constraint.node.get("regex")
            if not isinstance(regex, str):
                continue
            line = _key_line(index, constraint, "regex")
            risk = describe_risk(regex)
            escaped = constraint.node.get("allow_unsafe_regex") is True
            if risk is not None:
                if escaped:
                    findings.append(
                        _finding(
                            "PL-R01-ESCAPE",
                            f"the regular expression {regex!r} is a denial-of-service risk "
                            f"({risk}) and this constraint turns the R-01 guard off with "
                            "allow_unsafe_regex: true",
                            constraint.path,
                            line,
                            help_text=(
                                "Rewrite the pattern without a nested quantifier.  The escape hatch "
                                "is announced on stderr every time the policy is loaded."
                            ),
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            "PL-R01",
                            f"the regular expression {regex!r} is a denial-of-service risk "
                            f"({risk}): it can stall the proxy on a short client value",
                            constraint.path,
                            line,
                            help_text=(
                                "Rewrite it without a nested quantifier, or set "
                                "allow_unsafe_regex: true on this constraint to use it anyway."
                            ),
                        )
                    )
            if not _anchored_at_start(regex) and not _anchored_at_end(regex):
                findings.append(
                    _finding(
                        "PL-REGEX-UNANCHORED",
                        f"the regular expression {regex!r} carries no explicit anchor; it is "
                        "anchored only by the engine's full match",
                        constraint.path,
                        line,
                        help_text=(
                            "Anchor it with ^ and $ (or \\A and \\Z) so that it still matches a "
                            "prefix if it is ever reused with re.match or re.search."
                        ),
                    )
                )
    return findings


def _path_prefix_findings(
    arguments: Sequence[_Argument],
    index: Mapping[tuple[Any, ...], int],
    base: Path,
) -> list[Finding]:
    """The broad prefix and the symlink findings of every path_prefix."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for argument in arguments:
        for constraint in argument.constraints:
            prefix = constraint.node.get("path_prefix")
            if not isinstance(prefix, str):
                continue
            line = _key_line(index, constraint, "path_prefix")
            if _is_broad_prefix(prefix):
                findings.append(
                    _finding(
                        "PL-PATH-PREFIX-BROAD",
                        f"the path_prefix {prefix!r} contains everything: it is the whole "
                        "filesystem or the whole working directory, not a boundary",
                        constraint.path,
                        line,
                        help_text=(
                            "Point the prefix at the directory the tool is meant to work in, "
                            "for example './workspace'."
                        ),
                    )
                )
            if prefix in seen:
                continue
            seen.add(prefix)
            escapes, exists = _symlink_escapes(prefix, base)
            for message in escapes:
                findings.append(
                    _finding(
                        "PL-SYMLINK-ESCAPE",
                        message,
                        constraint.path,
                        line,
                        help_text=(
                            "The proxy resolves a path before it compares it, so the escape is "
                            "refused at run time.  The policy should still not describe a "
                            "directory that is not the one the filesystem holds."
                        ),
                    )
                )
            if not exists:
                findings.append(
                    _finding(
                        "PL-PATH-PREFIX-MISSING",
                        f"the path_prefix {prefix!r} does not exist under {str(base)!r}, so the "
                        "symlink check was skipped",
                        constraint.path,
                        line,
                    )
                )
    return findings


def _list_findings(
    arguments: Sequence[_Argument], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """The findings of the lists whose elements are not constrained."""
    findings: list[Finding] = []
    for argument in arguments:
        if not _is_list_argument(argument):
            continue
        line = _line_for(index, argument.tuple_path)
        has_items = any(constraint.kind == "items" for constraint in argument.constraints)
        # G-06: a *type* is not a constraint on the content of an element.
        # ``items: {type: string}`` still lets a client put a path, a URL or
        # a credential in the slot, so it does not count.
        has_semantic_items = any(
            constraint.kind == "items"
            and any(
                k in constraint.node
                for k in ("regex", "path_prefix", "enum", "min", "max", "min_length", "max_length")
            )
            for constraint in argument.constraints
        )
        constrained = (
            has_semantic_items
            or _subtree_has(argument.constraints, "regex")
            or _subtree_has(argument.constraints, "path_prefix")
            or _subtree_has(argument.constraints, "enum")
        )
        if not constrained:
            # G-06: a length bound on the *list* is not a constraint on its
            # elements.  ``type: array`` with ``max_length: 10`` still lets a
            # client put anything at all in each of the ten slots, so it is
            # reported here like any other unconstrained list.
            findings.append(
                _finding(
                    "PL-LIST-ELEMENT-UNCONSTRAINED",
                    f"the argument {argument.name!r} is a list whose elements are not "
                    "constrained at all: no items, no regex, no path_prefix, no enum and no "
                    "length bound",
                    argument.path,
                    line,
                    help_text=(
                        "Add an items constraint (items: {type: string, path_prefix: ...}) so "
                        "that every element of the list is checked.  A length bound on the list "
                        "itself does not constrain the elements."
                    ),
                )
            )
            continue
        path_constrained = _subtree_has(argument.constraints, "path_prefix") or _subtree_has(
            argument.constraints, "regex"
        )
        if _looks_like_a_path(argument.name) and not path_constrained:
            findings.append(
                _finding(
                    "PL-LIST-PATH-UNCONSTRAINED",
                    f"the argument {argument.name!r} takes a list of paths, but no element of "
                    "the list is constrained to a prefix or a pattern",
                    argument.path,
                    line,
                    help_text=(
                        "Add path_prefix (or a regex) to the items constraint, so that the list "
                        "stays inside the workspace element by element."
                    ),
                )
            )
    return findings


def _methods_findings(
    document: Mapping[str, Any], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """The findings about the methods the policy relays (G-13).

    ``resources/*``, ``prompts/*`` and ``completion/*`` relay upstream content
    to the client without a tool rule of their own.  They are denied by
    default, and a policy that wants them has to say so.  The linter says so
    too, so that an operator who expected them to be relayed finds out from
    the linter rather than from a refused request.
    """
    findings: list[Finding] = []
    methods = document.get("methods")
    if not isinstance(methods, Mapping):
        return findings
    allow = methods.get("allow")
    allowed = {value for value in allow if isinstance(value, str)} if isinstance(allow, list) else set()
    line = _line_for(index, ("methods",))
    for prefix in ("resources/", "prompts/", "completion/"):
        named = sorted(name for name in allowed if name.startswith(prefix))
        if not named:
            continue
        findings.append(
            _finding(
                "PL-METHODS-CONTENT-RELAYED",
                f"the policy relays {', '.join(named)}, which returns upstream content to the "
                "client without a tool rule of its own",
                "methods.allow",
                line,
                help_text=(
                    "Confirm that the upstream may serve this content: a prompt or a resource "
                    "that has been tampered with reaches the client unfiltered."
                ),
            )
        )
    return findings


def _approval_findings(
    document: Mapping[str, Any], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """The findings about the approval rules that cannot be satisfied (G-14).

    ``require_approval: true`` refuses the call and offers no way to approve
    it: there is no approval artefact the proxy checks.  The behaviour is
    safe -- the call does not happen -- but it is not what the word
    "approval" suggests, and an operator who believes a second party can
    release the call is wrong.  The linter says so.
    """
    findings: list[Finding] = []
    tools = document.get("tools")
    if not isinstance(tools, Mapping):
        return findings
    for name, rule in tools.items():
        if not isinstance(rule, Mapping):
            continue
        if rule.get("require_approval") is not True:
            continue
        findings.append(
            _finding(
                "PL-APPROVAL-NO-CHANNEL",
                f"the rule for {name!r} requires an approval, but mcp-guard has no approval "
                "channel: the call is refused and stays refused",
                f"tools.{name}.require_approval",
                _line_for(index, ("tools", name, "require_approval")),
                help_text=(
                    "Treat require_approval as 'always refused'.  If the call has to be "
                    "releasable, allow it and use the rate limit or the session budget."
                ),
            )
        )
    return findings


def _document_findings(
    document: Mapping[str, Any], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """The findings of the document as a whole."""
    findings: list[Finding] = []
    tools = document.get("tools")
    if not isinstance(tools, Mapping) or not tools:
        findings.append(
            _finding(
                "PL-NO-TOOLS",
                "the policy lists no tools, and default_action is always 'deny': every call "
                "will be refused",
                "<document>",
                _line_for(index, ()),
            )
        )

    findings.extend(_methods_findings(document, index))
    findings.extend(_approval_findings(document, index))
    findings.extend(_nfkc_collision_findings(document, index))
    return findings


def _nfkc_collision_findings(
    document: Mapping[str, Any], index: Mapping[tuple[Any, ...], int]
) -> list[Finding]:
    """Flag NFKC-colliding tool names as errors (F-05)."""
    import unicodedata

    findings: list[Finding] = []
    tools = document.get("tools")
    if not isinstance(tools, Mapping):
        return findings
    seen: dict[str, str] = {}
    for name in tools.keys():
        norm = unicodedata.normalize("NFKC", str(name))
        if norm in seen:
            prev = seen[norm]
            findings.append(
                _finding(
                    "PL-CONFUSABLE-TOOL-NAME",
                    f"tool {name!r} collides under Unicode NFKC normalisation with earlier tool {prev!r}: "
                    "confusable tool rule names create policy shadowing ambiguities",
                    f"tools.{name}",
                    _line_for(index, ("tools", name)),
                    help_text="Rename one of the tools to avoid confusable/shadowing rule collision.",
                )
            )
        else:
            seen[norm] = str(name)
    return findings


# -- the entry point -------------------------------------------------------

def lint_text(text: str, *, path: str = "<policy>", base_dir: Path | None = None) -> LintReport:
    """Lint the text of a policy file and return the report."""
    report = LintReport(path=path)
    base = (base_dir or Path.cwd()).resolve()
    index = _line_index(text)

    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        report.findings.append(
            _finding(
                "PL-SCHEMA",
                f"the policy file is not valid YAML: {exc}",
                "<document>",
                None,
                help_text="The policy file has to be a YAML mapping.",
            )
        )
        return report

    if document is None:
        document = {}
    if not isinstance(document, Mapping):
        report.findings.append(
            _finding(
                "PL-SCHEMA",
                f"the policy file must contain a mapping at the top level, got "
                f"{type(document).__name__}",
                "<document>",
                None,
            )
        )
        return report

    report.findings.extend(_schema_findings(document, index))
    arguments = list(_walk_arguments(document))
    report.findings.extend(_regex_findings(arguments, index))
    report.findings.extend(_path_prefix_findings(arguments, index, base))
    report.findings.extend(_list_findings(arguments, index))
    report.findings.extend(_document_findings(document, index))
    return report


def lint_policy(path: str | Path, *, base_dir: Path | None = None) -> LintReport:
    """Lint the policy file at ``path`` and return the report.

    A file that cannot be read raises :class:`OSError`: not being able to read
    the file is a usage error, not a finding about the policy.
    """
    policy_path = Path(path)
    text = policy_path.read_text(encoding="utf-8")
    return lint_text(text, path=str(policy_path), base_dir=base_dir)


# -- the output ------------------------------------------------------------

def to_sarif(report: LintReport) -> dict[str, Any]:
    """The report as a SARIF-lite document.

    SARIF 2.1.0 with the fields a scanner needs: the tool, its rules, and one
    result per finding with a rule id, a level, a message and a location.  It
    is a subset of the format, not the whole of it: the run carries the counts
    and the policy path in ``properties``, which is where a SARIF consumer
    that does not know this tool will look first.
    """
    rules = [
        {
            "id": rule_id,
            "name": meta["name"],
            "shortDescription": {"text": meta["short"]},
            "fullDescription": {"text": meta["full"]},
            "defaultConfiguration": {"level": meta["severity"]},
        }
        for rule_id, meta in RULES.items()
    ]
    # G-17: Ensure artifactLocation URI is a valid URI reference
    raw_path = report.path or "policy.yaml"
    if raw_path.startswith(("file://", "/")) or "://" in raw_path:
        uri = raw_path
    else:
        norm_p = raw_path.replace("\\", "/").lstrip("./")
        uri = f"file:///{norm_p}"

    results = []
    for finding in report.findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": finding.severity,
            "message": {"text": finding.message},
        }
        if finding.help_text:
            result["properties"] = {"help": finding.help_text}
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": uri,
                    "uriBaseId": "%SRCROOT%",
                },
            }
        }
        if finding.line is not None:
            location["physicalLocation"]["region"] = {"startLine": finding.line}
        result["locations"] = [location]
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-guard policy-lint",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": "file:///",
                    }
                },
                "results": results,
                "properties": {
                    "policy": report.path,
                    "counts": report.counts(),
                },
            }
        ],
    }


def render_human(report: LintReport) -> str:
    """The report as the text an operator reads."""
    counts = report.counts()
    lines = [
        f"{report.path}: {counts[ERROR]} error(s), {counts[WARNING]} warning(s), "
        f"{counts[NOTE]} note(s)"
    ]
    if not report.findings:
        lines.append("  no findings: the policy is valid and every rule is satisfied")
        return "\n".join(lines)

    order = {ERROR: 0, WARNING: 1, NOTE: 2}
    for finding in sorted(
        report.findings, key=lambda item: (order[item.severity], item.location, item.rule_id)
    ):
        where = finding.location
        if finding.line is not None:
            where = f"{where}:{finding.line}"
        lines.append(f"  {finding.severity:<7} {finding.rule_id:<26} {where}")
        lines.append(f"          {finding.message}")
        if finding.help_text:
            lines.append(f"          help: {finding.help_text}")
    return "\n".join(lines)
