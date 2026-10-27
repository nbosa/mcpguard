"""A tiny validation layer that replaces the pydantic models.

``mcp-guard`` ships with no runtime dependencies, so the policy models are
plain dataclasses that are filled by an explicit ``from_dict`` instead of by a
validation framework.  The behaviour the policy loader depends on is kept:

* an unknown key is a hard error that names the key;
* a value of the wrong type is a hard error that names the key and the type;
* a numeric bound (``ge=0``, ``ge=1``) is enforced;
* the errors are collected and reported together, so a policy with three
  mistakes is described in one message instead of three.

The API mirrors the small part of pydantic the rest of the code base uses:
:meth:`Model.from_dict` and :meth:`Model.model_validate`.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

__all__ = ["ValidationError", "Model", "coerce_bool", "coerce_float", "coerce_int", "coerce_str"]


class ValidationError(ValueError):
    """Raised when a document does not match the schema.

    The ``errors()`` method returns one entry per problem, each with a ``loc``
    (the path to the offending value) and a ``msg``.
    """

    def __init__(self, message: str, errors: Iterable[Mapping[str, Any]] | None = None) -> None:
        super().__init__(message)
        self._errors = [dict(error) for error in (errors or [])]

    def errors(self) -> list[dict[str, Any]]:
        """The individual problems, each with a ``loc`` and a ``msg``."""
        return [dict(error) for error in self._errors]

    @classmethod
    def one(cls, loc: tuple[Any, ...], message: str) -> "ValidationError":
        """Build an error that describes a single problem."""
        return cls(message, errors=[{"loc": tuple(loc), "msg": message}])


def _fail(loc: tuple[Any, ...], message: str) -> None:
    raise ValidationError.one(loc, message)


def _join(loc: tuple[Any, ...]) -> str:
    return ".".join(str(item) for item in loc) or "<document>"


# ---------------------------------------------------------------------------
# coercion helpers
# ---------------------------------------------------------------------------

_TRUE_WORDS = {"true", "yes", "on", "1"}
_FALSE_WORDS = {"false", "no", "off", "0"}


def coerce_bool(value: Any, loc: tuple[Any, ...]) -> bool:
    """Accept a boolean, the integers ``0``/``1`` and the usual words."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_WORDS:
            return True
        if lowered in _FALSE_WORDS:
            return False
    _fail(loc, f"expected a boolean, got {type(value).__name__}")
    raise AssertionError  # pragma: no cover - _fail always raises


def coerce_int(value: Any, loc: tuple[Any, ...], *, minimum: int | None = None) -> int:
    """Accept an integer, rejecting a boolean and a fractional number."""
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(loc, f"expected an integer, got {type(value).__name__}")
    if minimum is not None and value < minimum:
        _fail(loc, f"expected an integer >= {minimum}, got {value}")
    return value


def coerce_float(value: Any, loc: tuple[Any, ...]) -> float:
    """Accept an integer or a float, rejecting a boolean."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(loc, f"expected a number, got {type(value).__name__}")
    return float(value)


def coerce_str(value: Any, loc: tuple[Any, ...]) -> str:
    """Accept a string."""
    if not isinstance(value, str):
        _fail(loc, f"expected a string, got {type(value).__name__}")
    return value


# ---------------------------------------------------------------------------
# the model base
# ---------------------------------------------------------------------------


class Model:
    """Base class for the policy models.

    Subclasses implement :meth:`from_dict` and declare ``FIELDS`` -- the
    set of keys the document may contain.
    """

    #: The keys a document may contain.  Anything else is an error.
    FIELDS: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, data: Any, loc: tuple[Any, ...] = ()) -> Any:
        """Build the model from a mapping, refusing anything unexpected."""
        if data is None:
            data = {}
        if not isinstance(data, Mapping):
            raise ValidationError.one(
                loc, f"expected a mapping, got {type(data).__name__}"
            )
        unknown = [key for key in data if key not in cls.FIELDS]
        if unknown:
            errors = [
                {"loc": loc + (key,), "msg": f"extra fields not permitted"}
                for key in sorted(unknown)
            ]
            raise ValidationError(
                f"{_join(loc)}: unknown key(s): {', '.join(sorted(map(repr, unknown)))}",
                errors=errors,
            )
        return cls._build(data, loc)  # type: ignore[attr-defined]

    @classmethod
    def model_validate(cls, data: Any) -> Any:
        """Build the model from a mapping (the pydantic spelling)."""
        return cls.from_dict(data)

    @classmethod
    def _build(cls, data: Mapping[str, Any], loc: tuple[Any, ...]) -> Any:
        raise NotImplementedError
