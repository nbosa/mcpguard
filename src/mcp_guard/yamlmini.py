"""A small, dependency-free YAML reader for the subset ``mcp-guard`` uses.

``mcp-guard`` ships with **no runtime dependencies**, so the policy files it
reads cannot be parsed with PyYAML.  This module implements the block-style
YAML subset that the documented policy schema uses:

* block mappings and block sequences, nested by indentation;
* plain, single-quoted and double-quoted scalars;
* block scalars (``|`` and ``>``) with the usual chomping indicators;
* single-line flow collections (``[a, b]`` and ``{a: 1}``);
* comments, blank lines and the ``---`` / ``...`` document markers.

Everything the subset does *not* cover -- anchors, aliases, tags, complex
keys, multi-document streams -- raises :class:`YAMLError` with a message that
names the line.  A policy that uses an unsupported construct is therefore
refused loudly instead of being silently misread.

Two entry points mirror the small part of the PyYAML API the rest of the code
base uses:

:func:`safe_load`
    parse a document into plain Python objects;
:func:`compose`
    parse a document into a node tree that carries the line a node starts on,
    which is what the linter needs to point at the offending line.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

__all__ = [
    "YAMLError",
    "Mark",
    "Node",
    "ScalarNode",
    "MappingNode",
    "SequenceNode",
    "safe_load",
    "compose",
]


class YAMLError(Exception):
    """Raised when a document cannot be parsed."""


# ---------------------------------------------------------------------------
# node tree
# ---------------------------------------------------------------------------


class Mark:
    """A position in the source document."""

    __slots__ = ("line", "column")

    def __init__(self, line: int, column: int) -> None:
        self.line = line
        self.column = column

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Mark(line={self.line}, column={self.column})"


class Node:
    """Base class of the composed node tree."""

    __slots__ = ("start_mark", "end_mark")

    def __init__(self, start_mark: Mark, end_mark: Mark) -> None:
        self.start_mark = start_mark
        self.end_mark = end_mark


class ScalarNode(Node):
    """A single value."""

    __slots__ = ("value", "tag", "style")

    def __init__(
        self,
        value: Any,
        start_mark: Mark,
        end_mark: Mark,
        tag: str = "tag:yaml.org,2002:str",
        style: str = "",
    ) -> None:
        super().__init__(start_mark, end_mark)
        self.value = value
        self.tag = tag
        self.style = style


class SequenceNode(Node):
    """An ordered list of nodes."""

    __slots__ = ("value", "tag")

    def __init__(self, value: list[Node], start_mark: Mark, end_mark: Mark) -> None:
        super().__init__(start_mark, end_mark)
        self.value = value
        self.tag = "tag:yaml.org,2002:seq"


class MappingNode(Node):
    """An ordered list of key/value node pairs."""

    __slots__ = ("value", "tag")

    def __init__(
        self, value: list[tuple[Node, Node]], start_mark: Mark, end_mark: Mark
    ) -> None:
        super().__init__(start_mark, end_mark)
        self.value = value
        self.tag = "tag:yaml.org,2002:map"


# ---------------------------------------------------------------------------
# scalar resolution
# ---------------------------------------------------------------------------

_NULL_VALUES = {"", "~", "null", "Null", "NULL"}
_TRUE_VALUES = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSE_VALUES = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}

_INT_RE = re.compile(r"^[-+]?[0-9]+$")
_HEX_RE = re.compile(r"^[-+]?0x[0-9a-fA-F_]+$")
_OCT_RE = re.compile(r"^[-+]?0o[0-7_]+$")
_FLOAT_RE = re.compile(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")
_SPECIAL_FLOAT_RE = re.compile(r"^[-+]?\.(inf|Inf|INF)$|^\.(nan|NaN|NAN)$")

_ESCAPES = {
    "0": "\x00",
    "a": "\x07",
    "b": "\x08",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\x0b",
    "f": "\x0c",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}


def _resolve_plain(text: str) -> Any:
    """Resolve a plain (unquoted) scalar the way the YAML core schema does."""
    if text in _NULL_VALUES:
        return None
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    if _INT_RE.match(text):
        return int(text)
    if _HEX_RE.match(text):
        return int(text.replace("_", ""), 16)
    if _OCT_RE.match(text):
        return int(text.replace("_", ""), 8)
    if _SPECIAL_FLOAT_RE.match(text):
        return float(text.replace(".inf", "inf").replace(".Inf", "inf").replace(".INF", "inf"))
    if _FLOAT_RE.match(text):
        return float(text)
    return text


def _strip_comment(text: str) -> str:
    """Remove a trailing ``#`` comment from a plain scalar."""
    for index, char in enumerate(text):
        if char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
    return text.rstrip()


# ---------------------------------------------------------------------------
# the reader
# ---------------------------------------------------------------------------


class _Line:
    """One physical line of the document."""

    __slots__ = ("number", "indent", "content", "raw")

    def __init__(self, number: int, indent: int, content: str, raw: str) -> None:
        self.number = number
        self.indent = indent
        self.content = content
        self.raw = raw

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Line({self.number}, {self.indent}, {self.content!r})"


class _Parser:
    """A recursive-descent parser for the supported YAML subset."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines: list[_Line] = []
        self.position = 0
        for number, raw in enumerate(text.splitlines(), start=0):
            expanded = raw.replace("\t", "    ") if raw.lstrip(" ").startswith("\t") else raw
            stripped = expanded.lstrip(" ")
            indent = len(expanded) - len(stripped)
            self.lines.append(_Line(number, indent, stripped.rstrip(), expanded))
        # A trailing newline produces an empty final element; drop it so the
        # parser does not see a phantom empty line.
        while self.lines and not self.lines[-1].content:
            self.lines.pop()

    # -- line handling ----------------------------------------------------
    def _is_skippable(self, line: _Line) -> bool:
        return not line.content or line.content.startswith("#")

    def peek(self) -> _Line | None:
        """The next line that carries content."""
        while self.position < len(self.lines):
            line = self.lines[self.position]
            if self._is_skippable(line):
                self.position += 1
                continue
            return line
        return None

    def advance(self) -> None:
        self.position += 1

    # -- errors -----------------------------------------------------------
    def _error(self, message: str, line: _Line | None = None) -> YAMLError:
        where = f"line {line.number + 1}: " if line is not None else ""
        return YAMLError(f"{where}{message}")

    # -- document ---------------------------------------------------------
    def parse(self) -> Node | None:
        line = self.peek()
        if line is None:
            return None
        if line.content == "---":
            self.advance()
            line = self.peek()
            if line is None:
                return None
        if line.content in ("...", "---"):
            return None
        node = self._parse_node(line.indent)
        # Nothing but comments may follow.
        trailing = self.peek()
        if trailing is not None and trailing.content not in ("...", "---"):
            raise self._error("unexpected content after the document", trailing)
        return node

    def _parse_node(self, indent: int) -> Node:
        line = self.peek()
        if line is None or line.indent < indent:
            return self._null_node(line)
        if self._is_sequence_entry(line.content):
            return self._parse_sequence(line.indent)
        if line.content.startswith(("{", "[")):
            # A flow collection: the whole document may be one, and JSON is
            # valid YAML, so a policy may be written as JSON.
            return self._parse_flow_node(line)
        if self._try_split_key(line.content) is None:
            # A node that is not a mapping entry is a plain scalar.
            self.advance()
            return self._scalar_node(line.content, line, line.indent)
        return self._parse_mapping(line.indent)

    def _parse_flow_node(self, line: _Line) -> Node:
        """Parse a flow collection, gathering the lines it spans."""
        parts = [line.content]
        while not _flow_balanced(" ".join(parts)):
            self.position += 1
            if self.position >= len(self.lines):
                raise self._error("unterminated flow collection", line)
            parts.append(self.lines[self.position].content.strip())
        self.advance()
        text = " ".join(part for part in parts if part)
        mark = Mark(line.number, line.indent)
        if text.startswith("["):
            return _flow_to_node(self._parse_flow_sequence(text, line), mark)
        return _flow_to_node(dict(self._parse_flow_mapping(text, line)), mark, mapping=True)

    def _null_node(self, line: _Line | None) -> Node:
        mark = Mark(line.number if line else 0, line.indent if line else 0)
        return ScalarNode(None, mark, mark, "tag:yaml.org,2002:null", "")

    # -- sequences --------------------------------------------------------
    @staticmethod
    def _is_sequence_entry(content: str) -> bool:
        return content == "-" or content.startswith("- ") or content.startswith("-\t")

    def _parse_sequence(self, indent: int) -> Node:
        start = self.peek()
        assert start is not None
        items: list[Node] = []
        while True:
            line = self.peek()
            if line is None or line.indent != indent:
                break
            if not self._is_sequence_entry(line.content):
                break
            offset = 1
            while offset < len(line.content) and line.content[offset] == " ":
                offset += 1
            rest = line.content[offset:]
            if not rest:
                # The item's value is a nested block below the dash.
                self.advance()
                nested = self.peek()
                if nested is not None and nested.indent > indent:
                    items.append(self._parse_node(nested.indent))
                else:
                    items.append(self._null_node(line))
                continue
            # Rewrite the dash line as a plain line that starts at the column
            # of the value, so ``- key: value`` behaves like ``key: value``.
            self.lines[self.position] = _Line(
                line.number, indent + offset, rest, line.raw
            )
            items.append(self._parse_node(indent + offset))
        end = self.lines[min(self.position, len(self.lines) - 1)] if self.lines else start
        return SequenceNode(
            items,
            Mark(start.number, start.indent),
            Mark(end.number, end.indent),
        )

    # -- mappings ---------------------------------------------------------
    def _parse_mapping(self, indent: int) -> Node:
        start = self.peek()
        assert start is not None
        entries: list[tuple[Node, Node]] = []
        while True:
            line = self.peek()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise self._error("unexpected indentation", line)
            if self._is_sequence_entry(line.content):
                break
            if line.content in ("...", "---"):
                break
            key_node, value_node = self._parse_mapping_entry(line, indent)
            entries.append((key_node, value_node))
        end = self.lines[min(self.position, len(self.lines) - 1)] if self.lines else start
        return MappingNode(
            entries,
            Mark(start.number, start.indent),
            Mark(end.number, end.indent),
        )

    def _parse_mapping_entry(self, line: _Line, indent: int) -> tuple[Node, Node]:
        content = line.content
        key_text, rest = self._split_key(content, line)
        key_node = self._scalar_node(key_text, line, line.indent)
        rest = rest.strip()
        if rest:
            if rest[0] in "|>":
                self.advance()
                value_node = self._parse_block_scalar(rest, line, indent)
            else:
                text = self._gather_scalar_text(rest, line, indent)
                self.advance()
                value_node = self._scalar_node(text, line, indent + 2)
            return key_node, value_node

        # No inline value: the value is the block below the key, if any.
        self.advance()
        nested = self.peek()
        if nested is None:
            return key_node, self._null_node(line)
        if nested.indent > indent:
            return key_node, self._parse_node(nested.indent)
        if nested.indent == indent and self._is_sequence_entry(nested.content):
            # A block sequence may sit at the same column as its key.
            return key_node, self._parse_sequence(indent)
        return key_node, self._null_node(line)

    # -- multi-line scalars ------------------------------------------------
    def _gather_scalar_text(self, first: str, line: _Line, indent: int) -> str:
        """Collect a scalar that continues on the following lines.

        A plain scalar may be folded over several lines, and a quoted scalar
        may be broken across lines.  Both are folded into a single value with
        the line breaks replaced by spaces, the way YAML folds them.
        """
        quote = first[0]
        if quote in "\"'":
            if self._quoted_complete(first, quote):
                return first
            parts = [first]
            while self.position + 1 < len(self.lines):
                self.position += 1
                nxt = self.lines[self.position]
                parts.append(nxt.content.strip())
                if self._quoted_complete(parts[-1], quote):
                    break
            return " ".join(part for part in parts if part)

        parts = [first]
        while self.position + 1 < len(self.lines):
            nxt = self.lines[self.position + 1]
            if not nxt.content:
                # A blank line ends the scalar.
                break
            if nxt.indent <= indent:
                break
            self.position += 1
            parts.append(_strip_comment(nxt.content.strip()))
        return " ".join(part for part in parts if part)

    @staticmethod
    def _quoted_complete(text: str, quote: str) -> bool:
        """Does ``text`` end with a closing ``quote`` that is not escaped?"""
        if len(text) < 2 or not text.endswith(quote):
            return False
        if quote == '"':
            backslashes = 0
            cursor = len(text) - 2
            while cursor >= 0 and text[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2 == 1:
                return False
        return True

    def _split_key(self, content: str, line: _Line) -> tuple[str, str]:
        """Split ``key: value`` into the key text and the remainder."""
        found = self._try_split_key(content)
        if found is None:
            raise self._error("expected a 'key: value' mapping entry", line)
        return found

    def _try_split_key(self, content: str) -> tuple[str, str] | None:
        """Split ``key: value`` -- or return ``None`` when there is no key."""
        if content.startswith(("'", '"')):
            quote = content[0]
            cursor = 1
            while cursor < len(content):
                char = content[cursor]
                if char == "\\" and quote == '"':
                    cursor += 2
                    continue
                if char == quote:
                    if quote == "'" and content[cursor + 1 : cursor + 2] == "'":
                        cursor += 2
                        continue
                    break
                cursor += 1
            if cursor >= len(content):
                return None
            key_text = content[: cursor + 1]
            remainder = content[cursor + 1 :]
            if not remainder.startswith(":"):
                return None
            return key_text, remainder[1:]
        # A plain key ends at the first ": " or at a trailing ":".
        position = content.find(":")
        while position != -1:
            after = content[position + 1 : position + 2]
            if after in ("", " "):
                return content[:position], content[position + 1 :]
            position = content.find(":", position + 1)
        return None

    # -- block scalars ----------------------------------------------------
    def _parse_block_scalar(self, header: str, line: _Line, indent: int) -> Node:
        style = header[0]
        modifiers = header[1:].strip()
        chomp = "clip"
        explicit_indent = 0
        for modifier in modifiers:
            if modifier == "-":
                chomp = "strip"
            elif modifier == "+":
                chomp = "keep"
            elif modifier.isdigit():
                explicit_indent = int(modifier)
            else:
                raise self._error(f"invalid block scalar header '{header}'", line)
        collected: list[str] = []
        block_indent = indent + explicit_indent if explicit_indent else None
        while self.position < len(self.lines):
            current = self.lines[self.position]
            if not current.content and not current.raw.strip():
                collected.append("")
                self.position += 1
                continue
            if current.indent <= indent:
                break
            if block_indent is None:
                block_indent = current.indent
            if current.indent < block_indent:
                break
            collected.append(current.raw[block_indent:])
            self.position += 1
        while collected and not collected[-1]:
            collected.pop()
        if style == "|":
            text = "\n".join(collected)
        else:
            folded: list[str] = []
            for item in collected:
                if not item:
                    folded.append("\n")
                elif folded and folded[-1] not in ("\n",):
                    folded[-1] = folded[-1] + " " + item
                else:
                    folded.append(item)
            text = "".join(folded)
        if chomp == "strip":
            text = text.rstrip("\n")
        elif chomp == "clip":
            text = text.rstrip("\n") + "\n" if text else text
        else:
            text = text + "\n"
        mark = Mark(line.number, line.indent)
        return ScalarNode(text, mark, mark, "tag:yaml.org,2002:str", style)

    # -- scalars ----------------------------------------------------------
    def _scalar_node(self, text: str, line: _Line, column: int) -> Node:
        text = text.strip()
        mark = Mark(line.number, column)
        if not text:
            return ScalarNode(None, mark, mark, "tag:yaml.org,2002:null", "")
        if text[0] in "&*!":
            raise self._error(
                "anchors, aliases and tags are not supported by this reader", line
            )
        if text[0] == '"':
            value = self._parse_double_quoted(text, line)
            return ScalarNode(value, mark, mark, "tag:yaml.org,2002:str", '"')
        if text[0] == "'":
            value = self._parse_single_quoted(text, line)
            return ScalarNode(value, mark, mark, "tag:yaml.org,2002:str", "'")
        if text[0] == "[":
            values = self._parse_flow_sequence(text, line)
            return _flow_to_node(values, mark)
        if text[0] == "{":
            pairs = self._parse_flow_mapping(text, line)
            return _flow_to_node(dict(pairs), mark, mapping=True)
        value = _resolve_plain(_strip_comment(text))
        return ScalarNode(value, mark, mark, "tag:yaml.org,2002:str", "")

    def _parse_double_quoted(self, text: str, line: _Line) -> str:
        if len(text) < 2 or not text.endswith('"'):
            raise self._error("unterminated double-quoted string", line)
        body = text[1:-1]
        result: list[str] = []
        cursor = 0
        while cursor < len(body):
            char = body[cursor]
            if char != "\\":
                result.append(char)
                cursor += 1
                continue
            cursor += 1
            if cursor >= len(body):
                raise self._error("dangling escape in a double-quoted string", line)
            code = body[cursor]
            if code in _ESCAPES:
                result.append(_ESCAPES[code])
                cursor += 1
                continue
            if code in ("x", "u", "U"):
                width = {"x": 2, "u": 4, "U": 8}[code]
                digits = body[cursor + 1 : cursor + 1 + width]
                if len(digits) != width:
                    raise self._error("truncated escape in a double-quoted string", line)
                try:
                    result.append(chr(int(digits, 16)))
                except ValueError as exc:
                    raise self._error("invalid escape in a double-quoted string", line) from exc
                cursor += 1 + width
                continue
            raise self._error(f"unknown escape '\\{code}' in a double-quoted string", line)
        return "".join(result)

    def _parse_single_quoted(self, text: str, line: _Line) -> str:
        if len(text) < 2 or not text.endswith("'"):
            raise self._error("unterminated single-quoted string", line)
        return text[1:-1].replace("''", "'")

    def _parse_flow_sequence(self, text: str, line: _Line) -> list[Any]:
        if not text.endswith("]"):
            raise self._error("unterminated flow sequence", line)
        return [value for _, value in self._split_flow(text[1:-1], line)]

    def _parse_flow_mapping(self, text: str, line: _Line) -> list[tuple[Any, Any]]:
        if not text.endswith("}"):
            raise self._error("unterminated flow mapping", line)
        pairs: list[tuple[Any, Any]] = []
        for key, value in self._split_flow(text[1:-1], line):
            if not isinstance(key, tuple):
                raise self._error("expected 'key: value' in a flow mapping", line)
            pairs.append((key[1], value))
        return pairs

    def _split_flow(self, body: str, line: _Line) -> list[tuple[Any, Any]]:
        """Split a flow collection body into ``(key, value)`` pairs.

        In a sequence the key is ``None``; in a mapping it is the ``(raw, value)``
        tuple produced by the recursive call.
        """
        items: list[tuple[Any, Any]] = []
        for piece in _split_flow_items(body, line, self._error):
            key_text, value_text = _split_flow_pair(piece)
            if key_text is None:
                items.append((None, self._flow_scalar(value_text, line)))
            else:
                items.append(
                    ((key_text, self._flow_scalar(key_text, line)), self._flow_scalar(value_text, line))
                )
        return items

    def _flow_scalar(self, text: str, line: _Line) -> Any:
        text = text.strip()
        if text.startswith('"'):
            return self._parse_double_quoted(text, line)
        if text.startswith("'"):
            return self._parse_single_quoted(text, line)
        if text.startswith("["):
            return self._parse_flow_sequence(text, line)
        if text.startswith("{"):
            return dict(self._parse_flow_mapping(text, line))
        if not text:
            return None
        return _resolve_plain(_strip_comment(text))


def _flow_balanced(text: str) -> bool:
    """Are the flow brackets of ``text`` balanced?

    Brackets inside a quoted string do not count, so a value such as
    ``"a}b"`` does not unbalance the collection.
    """
    depth = 0
    quote: str | None = None
    for char in text:
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
    return depth <= 0 and quote is None


def _split_flow_items(body: str, line: _Line, error) -> Iterator[str]:
    """Split the body of a flow collection on top-level commas."""
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for char in body:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        if char == "," and depth == 0:
            yield "".join(current)
            current = []
            continue
        current.append(char)
    if quote is not None:
        raise error("unterminated quoted string in a flow collection", line)
    tail = "".join(current).strip()
    if tail:
        yield tail


def _split_flow_pair(piece: str) -> tuple[str | None, str]:
    """Split ``key: value`` inside a flow collection."""
    depth = 0
    quote: str | None = None
    for index, char in enumerate(piece):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == ":" and depth == 0:
            after = piece[index + 1 : index + 2]
            if after in ("", " "):
                return piece[:index], piece[index + 1 :]
    return None, piece


def _flow_to_node(value: Any, mark: Mark, mapping: bool = False) -> Node:
    """Build a node for a parsed flow collection."""
    if mapping:
        pairs = [
            (
                ScalarNode(key, mark, mark),
                ScalarNode(item, mark, mark)
                if not isinstance(item, (list, dict))
                else _flow_to_node(item, mark, mapping=isinstance(item, dict)),
            )
            for key, item in value.items()
        ]
        return MappingNode(pairs, mark, mark)
    items = [
        ScalarNode(item, mark, mark)
        if not isinstance(item, (list, dict))
        else _flow_to_node(item, mark, mapping=isinstance(item, dict))
        for item in value
    ]
    return SequenceNode(items, mark, mark)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def compose(text: str) -> Node | None:
    """Parse ``text`` into a node tree that carries line information."""
    return _Parser(text).parse()


def _to_python(node: Node | None) -> Any:
    if node is None:
        return None
    if isinstance(node, ScalarNode):
        return node.value
    if isinstance(node, SequenceNode):
        return [_to_python(item) for item in node.value]
    if isinstance(node, MappingNode):
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            result[_to_python(key_node)] = _to_python(value_node)
        return result
    raise YAMLError(f"unsupported node {type(node).__name__}")


def safe_load(text: str) -> Any:
    """Parse ``text`` into plain Python objects.

    Raises:
        YAMLError: when the document uses a construct outside the supported
            subset, or is malformed.
    """
    return _to_python(compose(text))
