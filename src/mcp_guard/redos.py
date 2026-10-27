"""The load-time guard against a regular expression denial of service (R-01).

A policy regex with a nested quantifier -- ``(a+)+``, ``(a|aa)+``,
``(.*a){10,}`` -- turns a short client value into minutes of backtracking.
The pattern lives in the **operator's** policy file, but the client is the one
who pays for it: the proxy is stuck in the regex engine while the connection
waits.

Two independent guards run at load time, and a policy has to pass both:

1. **The static analysis** (:func:`describe_risk`) parses the pattern with the
   standard library's own parser and walks the parsed tree.  Nothing is
   executed, so refusing a pattern costs nothing and cannot itself stall.
   The walker is **closed**: it knows every opcode that can hold a sub-pattern
   and refuses a pattern that uses an opcode it does not model, because "no
   opinion" must never mean "accepted" for a construct the analyser has not
   looked at (G-03).
2. **The dynamic probe** (:func:`probe_risk`) *measures* the pattern: it
   matches the compiled pattern against a synthetic adversarial value under a
   wall-clock budget.  A static analyser cannot enumerate the space of
   catastrophic patterns; a timed probe measures it directly, and it catches
   the shapes the static analysis reasons about incorrectly (G-01, G-03).

The dynamic probe is bounded twice over: the synthetic input is at most
:data:`PROBE_LENGTHS`' largest length, and on the main thread the match runs
under an interval timer, so a pattern that tries to hang the probe is
interrupted rather than waited for.

A pattern that is refused can still be used with ``allow_unsafe_regex: true``
on the constraint, which is off by default and is announced on stderr when the
policy is loaded.
"""

from __future__ import annotations

import re
import signal
import threading
import time
from typing import Any, Callable, Iterator

#: The cap on the length of a client value a regex is applied to, unless the
#: constraint says otherwise.  A regex is matched against the whole value, so
#: the value is what the engine backtracks over.
DEFAULT_MAX_REGEX_INPUT = 4096

#: The opcode names of the standard library's regex parser that this module
#: looks at.
_REPEAT_OPS = frozenset({"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"})

#: The opcodes that consume exactly one character and therefore cannot match
#: the empty string.
_ATOM_OPS = frozenset({"LITERAL", "NOT_LITERAL", "ANY", "IN", "RANGE", "CATEGORY"})

#: The opcodes that hold a sub-pattern.
#:
#: This set is the heart of the fail-closed walker: an opcode that is not in
#: it and not in :data:`_LEAF_OPS` is a construct this module cannot see
#: inside, and a pattern that uses one is refused (G-03).  The *shape* of
#: each sub-pattern is handled explicitly in :func:`_walk`, because the
#: opcodes do not agree on where they keep it.
_CONTAINER_OPS = frozenset(
    {
        "MAX_REPEAT",
        "MIN_REPEAT",
        "POSSESSIVE_REPEAT",
        "SUBPATTERN",
        "BRANCH",
        "ASSERT",
        "ASSERT_NOT",
        "ATOMIC_GROUP",
        "GROUPREF_EXISTS",
    }
)

#: The opcodes that cannot hold a sub-pattern.  A pattern built only from
#: these and from :data:`_CONTAINER_OPS` is fully modelled by the walker.
_LEAF_OPS = frozenset(
    {
        "ANY",
        "ANY_ALL",
        "AT",
        "BIGCHARSET",
        "CATEGORY",
        "CHARSET",
        "FAILURE",
        "GROUPREF",
        "GROUPREF_IGNORE",
        "GROUPREF_LOC_IGNORE",
        "GROUPREF_UNI_IGNORE",
        "IN",
        "IN_IGNORE",
        "IN_LOC_IGNORE",
        "IN_UNI_IGNORE",
        "INFO",
        "JUMP",
        "LITERAL",
        "LITERAL_IGNORE",
        "LITERAL_LOC_IGNORE",
        "LITERAL_UNI_IGNORE",
        "MARK",
        "NEGATE",
        "NOT_LITERAL",
        "NOT_LITERAL_IGNORE",
        "NOT_LITERAL_LOC_IGNORE",
        "NOT_LITERAL_UNI_IGNORE",
        "RANGE",
        "RANGE_UNI_IGNORE",
        "SUCCESS",
    }
)

#: The number of iterations above which a *bounded* repetition over an
#: unbounded body is a polynomial denial of service (G-01).
#:
#: ``(a+){k}`` distributes an input of length ``n`` over the ``k`` iterations
#: in ``C(n+k-1, k-1)`` ways -- a polynomial of degree ``k-1`` in ``n``.  With
#: the default cap of 4096 characters on a client value, ``k=2`` is already about
#: eight million steps (tens of milliseconds) and ``k=3`` is about eleven billion
#: (minutes).  A repetition of two or more iterations over a variable-length
#: body is therefore refused (F-02); ``k=1`` is only grouping and stays legal.
#:
#: The same threshold applies to a bounded repetition over an *ambiguous*
#: alternation -- ``(a|aa){2}`` -- which backtracks the same way.
NESTED_REPEAT_MIN_ITERATIONS = 2

#: The wall-clock budget one probe match may take before the pattern is
#: refused.  A pattern that cannot reject a thirty-two-character synthetic
#: value in fifty milliseconds is not a pattern an operator wants in a proxy.
DEFAULT_PROBE_BUDGET_SECONDS = 0.05

#: The lengths of the synthetic values the probe matches against.  They are
#: short on purpose: the probe has to be fast, and a catastrophic pattern
#: already shows at thirty-two characters.
PROBE_LENGTHS = (20, 32)

#: The lengths used when the wall-clock budget cannot be enforced -- that is,
#: off the main thread, where the interval timer does not reach.  The set is
#: short so that the worst case stays bounded even without an interrupt.
PROBE_LENGTHS_REDUCED = (12, 16)

#: The alphabets the probe uses.  A pattern over one alphabet that is not
#: slow is usually not slow at all, but a pattern over digits or whitespace
#: is, so two alphabets are tried.
PROBE_ALPHABETS = ("a", "0")

#: The character appended to the synthetic value.  It is not a letter and not
#: a digit, so a pattern that matches the repeated characters still has to
#: backtrack over every way of splitting them before it can fail.
_PROBE_SUFFIX = "\n"

try:  # Python 3.11 and later
    from re import _parser as _sre  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python 3.10 and earlier
    import sre_parse as _sre  # type: ignore[no-redef]

#: The value the parser uses for "no upper bound".
_MAXREPEAT = getattr(_sre, "MAXREPEAT", object())


class _ProbeTimeout(Exception):
    """Raised inside the probe when the budget is exceeded."""


def parse_pattern(pattern: str) -> Any:
    """The parsed form of ``pattern``, or ``None`` when it cannot be parsed.

    ``None`` means "no opinion": the pattern is accepted and the risk is not
    checked.  That is the safe direction for a *private* parser API that a
    future Python may move.
    """
    try:
        return _sre.parse(pattern, 0)
    except Exception:  # pragma: no cover - the pattern was compiled before
        return None


def _walk(items: Any) -> Iterator[tuple[str, Any]]:
    """Every opcode of the parsed tree, with its argument.

    The descent is driven by :data:`_CONTAINER_OPS`, so it visits every
    sub-pattern the parser can produce -- including the ``yes`` and ``no``
    branches of a conditional group and the body of an atomic group, which
    the earlier allow-list walker skipped (G-03).
    """
    for op, av in items:
        name = op.name
        yield name, av
        if name in _REPEAT_OPS:
            yield from _walk(av[2])
        elif name == "SUBPATTERN":
            yield from _walk(av[3])
        elif name == "BRANCH":
            # ``av[1]`` is a list of branches, each of which is a sequence.
            for branch in av[1]:
                yield from _walk(branch)
        elif name in ("ASSERT", "ASSERT_NOT"):
            yield from _walk(av[1])
        elif name == "ATOMIC_GROUP":
            # The argument of an atomic group *is* the sub-pattern.
            yield from _walk(av)
        elif name == "GROUPREF_EXISTS":
            # A conditional group keeps its ``yes`` branch and its ``no``
            # branch in the second and third place.  The earlier allow-list
            # walker never visited either of them, which hid a nested
            # quantifier from the detector entirely (G-03).
            if len(av) > 1 and av[1]:
                yield from _walk(av[1])
            if len(av) > 2 and av[2]:
                yield from _walk(av[2])


def _unmodelled_opcode(items: Any) -> str | None:
    """The name of the first opcode this module does not model, if any.

    "No opinion" must not mean "accepted": an opcode outside
    :data:`_CONTAINER_OPS` and :data:`_LEAF_OPS` could be hiding a
    repetition, and a repetition is the whole problem (G-03).
    """
    for name, _av in _walk(items):
        if name in _CONTAINER_OPS or name in _LEAF_OPS:
            continue
        return name
    return None


def _sequence_nullable(items: Any) -> bool:
    """Can every element of the sequence match the empty string?"""
    return all(_node_nullable(op, av) for op, av in items)


def _node_nullable(op: Any, av: Any) -> bool:
    """Can this opcode match the empty string?"""
    name = op.name
    if name in _ATOM_OPS:
        return False
    if name in _REPEAT_OPS:
        if av[0] == 0:
            return True
        return _sequence_nullable(av[2])
    if name == "SUBPATTERN":
        return _sequence_nullable(av[3])
    if name == "BRANCH":
        return any(_sequence_nullable(branch) for branch in av[1])
    if name in ("ASSERT", "ASSERT_NOT", "AT"):
        # A zero-width assertion matches the empty string.
        return True
    if name == "ATOMIC_GROUP":
        return _sequence_nullable(av)
    if name == "GROUPREF_EXISTS":
        return (len(av) > 1 and _sequence_nullable(av[1])) or (
            len(av) > 2 and _sequence_nullable(av[2])
        )
    return False


def _literal_text(items: Any) -> str | None:
    """The literal text of a branch, or ``None`` when it is not a plain literal."""
    text: list[str] = []
    for op, av in items:
        if op.name == "LITERAL":
            text.append(chr(av))
        elif op.name == "SUBPATTERN":
            inner = _literal_text(av[3])
            if inner is None:
                return None
            text.append(inner)
        else:
            return None
    return "".join(text)


def _ambiguous_alternatives(alternatives: list[Any]) -> bool:
    """Can two alternatives of an alternation match the same text?

    ``(a|aa)`` can: the text ``aa`` is matched by the first alternative plus
    the second, or by the second alone.  ``(a|b)`` cannot, and ``(ab|ac)``
    cannot either.

    A branch that is not a plain literal -- a character class, a group -- is
    conservatively assumed to overlap with the others, because the module
    cannot prove that it does not (OPUS-08).
    """
    prefixes = [_literal_text(alternative) for alternative in alternatives]
    if any(prefix is None for prefix in prefixes):
        # A non-literal branch may overlap with any other branch.
        return len(alternatives) > 1
    for index, first in enumerate(prefixes):
        for second in prefixes[index + 1 :]:
            if first.startswith(second) or second.startswith(first):
                return True
    return False


def _branches(items: Any) -> list[list[Any]]:
    """Every alternation inside the parsed tree."""
    found: list[list[Any]] = []
    for name, av in _walk(items):
        if name == "BRANCH":
            found.append(av[1])
    return found


def _contains_unbounded_repeat(items: Any) -> bool:
    """Is there a repetition without an upper bound inside the tree?"""
    for name, av in _walk(items):
        if name in _REPEAT_OPS and av[1] == _MAXREPEAT:
            return True
    return False


def describe_risk(pattern: str) -> str | None:
    """Why ``pattern`` is a denial-of-service risk -- or ``None``.

    The shapes that are refused:

    ``nested quantifier``
        a repetition whose body contains another repetition without an upper
        bound -- ``(a+)+``, ``(a*)*``, ``(.*a){10,}``.  A *bounded* outer
        repetition over an unbounded body is refused too when it can run at
        least :data:`NESTED_REPEAT_MIN_ITERATIONS` times, because the work is
        then a polynomial of degree ``k-1`` in the length of the value
        (G-01).
    ``empty group``
        a repetition without an upper bound whose body can match the empty
        string -- ``(a?)+``.
    ``ambiguous alternation``
        a repetition without an upper bound whose body holds an alternation
        whose alternatives can match the same text -- ``(a|aa)+``, ``(a|a)+``.
    ``unmodelled construct``
        the pattern uses an opcode the walker does not understand, so the
        walker cannot see whether it holds a repetition.  The pattern is
        refused rather than accepted on the strength of an opinion the module
        cannot form (G-03).
    """
    tree = parse_pattern(pattern)
    if tree is None:
        return None

    unmodelled = _unmodelled_opcode(tree)
    if unmodelled is not None:
        return f"unmodelled construct ({unmodelled})"

    for name, av in _walk(tree):
        if name not in _REPEAT_OPS:
            continue
        _minimum, maximum, body = av

        if _contains_unbounded_repeat(body):
            if maximum == _MAXREPEAT:
                return "nested quantifier"
            if isinstance(maximum, int) and maximum >= NESTED_REPEAT_MIN_ITERATIONS:
                return "nested quantifier"

        if maximum == _MAXREPEAT:
            if _sequence_nullable(body):
                return "empty group"
            for alternatives in _branches(body):
                if _ambiguous_alternatives(alternatives):
                    return "ambiguous alternation"
            continue

        # A *bounded* repetition still backtracks when its body can match the
        # same text in more than one way: ``(a|aa){2}`` is polynomial in the
        # length of the value just like ``(a|aa)+`` is, only with a smaller
        # degree (F-02).
        if isinstance(maximum, int) and maximum >= NESTED_REPEAT_MIN_ITERATIONS:
            for alternatives in _branches(body):
                if _ambiguous_alternatives(alternatives):
                    return "ambiguous alternation"
    return None


# -- the dynamic probe -----------------------------------------------------

def _run_with_budget(
    function: Callable[[], Any], budget: float
) -> tuple[Any, bool]:
    """Run ``function`` under a wall-clock budget.

    Returns ``(result, timed_out)``.  On the main thread the budget is
    enforced with an interval timer, which interrupts the regular expression
    engine itself -- so a pattern that tries to hang the probe is stopped
    rather than waited for.  Off the main thread the budget cannot be
    enforced (the signal machinery belongs to the main thread); the caller
    then uses a shorter probe input so that the worst case stays bounded.
    """
    if threading.current_thread() is not threading.main_thread():
        return function(), False
    if not hasattr(signal, "setitimer"):  # pragma: no cover - not POSIX
        return function(), False

    def _on_alarm(_signum: int, _frame: Any) -> None:
        raise _ProbeTimeout

    previous = signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, budget)
    try:
        return function(), False
    except _ProbeTimeout:
        return None, True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def probe_risk(
    pattern: str,
    *,
    budget_seconds: float = DEFAULT_PROBE_BUDGET_SECONDS,
    lengths: tuple[int, ...] | None = None,
) -> str | None:
    """Measure ``pattern`` against a synthetic adversarial value.

    The probe matches the compiled pattern against a short value built out of
    one repeated character, with a suffix that forces the matcher to back
    track over every way of splitting the repetition.  A pattern that needs
    more than ``budget_seconds`` for that is refused: whatever the client
    sends, the proxy will be in the regex engine for a long time.

    Returns ``None`` when the pattern is fast enough, and a description of the
    measurement otherwise.
    """
    try:
        compiled = re.compile(pattern)
    except re.error:  # pragma: no cover - the pattern was compiled before
        return None

    deep = threading.current_thread() is threading.main_thread() and hasattr(signal, "setitimer")
    if lengths is None:
        lengths = PROBE_LENGTHS if deep else PROBE_LENGTHS_REDUCED

    for length in lengths:
        for alphabet in PROBE_ALPHABETS:
            candidate = alphabet * length + _PROBE_SUFFIX
            started = time.monotonic()
            _result, timed_out = _run_with_budget(
                lambda: compiled.fullmatch(candidate), budget_seconds
            )
            elapsed = time.monotonic() - started
            if timed_out:
                return (
                    f"the pattern did not finish matching a {length}-character value within "
                    f"{budget_seconds * 1000:.0f} ms"
                )
            if elapsed > budget_seconds:
                return (
                    f"the pattern takes {elapsed * 1000:.0f} ms to reject a {length}-character "
                    f"value, which is over the {budget_seconds * 1000:.0f} ms budget"
                )
    return None


def check_pattern(
    pattern: str,
    *,
    budget_seconds: float = DEFAULT_PROBE_BUDGET_SECONDS,
    probe: bool = True,
) -> str | None:
    """The full load-time check for ``pattern`` -- or ``None`` when it is safe.

    The static analysis runs first, because it costs nothing.  The dynamic
    probe runs only for the patterns the static analysis considers safe, which
    is what makes it affordable: it measures the patterns the analyser reasons
    about incorrectly.
    """
    risk = describe_risk(pattern)
    if risk is not None:
        return risk
    if not probe:
        return None
    return probe_risk(pattern, budget_seconds=budget_seconds)
