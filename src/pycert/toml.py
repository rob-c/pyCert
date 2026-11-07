"""A small TOML parser for pyCert's configuration (Python 3.6 compatible).

Python 3.11 added :mod:`tomllib`; pyCert supports Python 3.6, so it needs its own
parser.  This one implements the part of TOML 1.0 that a configuration file
needs, strictly and with line/column error messages:

* bare, quoted and dotted keys, ``[table]`` and ``[[array.of.tables]]`` headers;
* basic and literal strings, including multi-line forms and escapes;
* integers (decimal, hex, octal, binary, underscores), floats and booleans;
* arrays (multi-line, trailing comma) and inline tables;
* comments, CRLF line endings and a UTF-8 BOM.

It deliberately rejects date/time values and non-finite floats: pyCert's
configuration has no use for them, and refusing is safer than silently
misinterpreting them.  Every rendered pyCert configuration round-trips, and the
test suite cross-checks the parser against :mod:`tomllib` on the supported
subset (where available).
"""

import re
from typing import Any, Dict, List, Tuple

__all__ = ["TOMLDecodeError", "loads", "load"]

_EOF = "\x00"
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_INT_DEC = re.compile(r"[+-]?(?:0|[1-9](?:_?[0-9])*)$")
_INT_HEX = re.compile(r"0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*$")
_INT_OCT = re.compile(r"0o[0-7](?:_?[0-7])*$")
_INT_BIN = re.compile(r"0b[01](?:_?[01])*$")
_FLOAT = re.compile(
    r"[+-]?(?:0|[1-9](?:_?[0-9])*)"
    r"(?:\.[0-9](?:_?[0-9])*)?"
    r"(?:[eE][+-]?[0-9](?:_?[0-9])*)?$"
)
_ESCAPES = {
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "f": "\f",
    "r": "\r",
    '"': '"',
    "\\": "\\",
}


class TOMLDecodeError(ValueError):
    def __init__(self, message: str, line: int = 0, column: int = 0):
        self.line = line
        self.column = column
        location = " (line %d, column %d)" % (line, column) if line else ""
        super().__init__(message + location)


def load(fp) -> Dict[str, Any]:
    data = fp.read() if hasattr(fp, "read") else fp
    if isinstance(data, bytes):
        data = data.decode("utf-8-sig")
    return loads(data)


def loads(text) -> Dict[str, Any]:
    if isinstance(text, bytes):
        text = text.decode("utf-8-sig")
    if not isinstance(text, str):
        raise TOMLDecodeError("configuration must be a string")
    return _Parser(text).parse()


class _Parser:
    def __init__(self, text: str):
        if text.startswith("\ufeff"):
            text = text[1:]
        self.text = text
        self.length = len(text)
        self.pos = 0
        self.line = 1
        self.line_start = 0
        self.root = {}  # type: Dict[str, Any]
        self.current = self.root
        # Object-id based bookkeeping keeps array-of-tables elements distinct.
        self.header_tables = set()  # dicts declared with [table]
        self.header_arrays = set()  # lists declared with [[table]]
        self.dotted_tables = set()  # dicts created by dotted keys
        self.inline_tables = set()  # dicts defined by inline-table values (immutable)
        self.value_arrays = set()  # lists assigned as values (not [[table]])

    # -- errors and low-level helpers -------------------------------------
    def _error(self, message: str) -> TOMLDecodeError:
        return TOMLDecodeError(message, self.line, self.pos - self.line_start + 1)

    def _fail(self, message: str) -> None:
        raise self._error(message)

    def _at_end(self) -> bool:
        return self.pos >= self.length

    def _peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.text[index] if index < self.length else _EOF

    def _advance(self, count: int = 1) -> str:
        start = self.pos
        end = min(start + count, self.length)
        for index in range(start, end):
            if self.text[index] == "\n":
                self.line += 1
                self.line_start = index + 1
        self.pos = end
        return self.text[start:end]

    def _skip_spaces(self) -> None:
        while self._peek() in (" ", "\t"):
            self._advance()

    def _skip_comment(self) -> None:
        if self._peek() == "#":
            while not self._at_end() and self._peek() not in ("\r", "\n"):
                self._advance()

    def _skip_blank(self) -> None:
        while not self._at_end():
            char = self._peek()
            if char in (" ", "\t", "\r", "\n"):
                self._advance()
            elif char == "#":
                self._skip_comment()
            else:
                return

    def _end_of_line(self) -> None:
        self._skip_spaces()
        self._skip_comment()
        if self._at_end():
            return
        if self._peek() == "\r":
            self._advance()
        if self._peek() == "\n":
            self._advance()
            return
        self._fail("expected a newline")

    # -- top level ---------------------------------------------------------
    def parse(self) -> Dict[str, Any]:
        while True:
            self._skip_blank()
            if self._at_end():
                return self.root
            if self._peek() == "[":
                self._parse_header()
            else:
                self._parse_key_value(self.current)
            self._end_of_line()

    def _parse_header(self) -> None:
        self._advance()  # [
        array_table = False
        if self._peek() == "[":
            array_table = True
            self._advance()
        self._skip_spaces()
        path = self._parse_key_path()
        self._skip_spaces()
        if self._peek() != "]":
            self._fail("expected ']' to close the table header")
        self._advance()
        if array_table:
            if self._peek() != "]":
                self._fail("expected ']]' to close the array-of-tables header")
            self._advance()
        key = ".".join(path)
        if array_table:
            self.current = self._descend(path, array_table=True)
        else:
            table = self._descend(path)
            if id(table) in self.inline_tables or id(table) in self.dotted_tables:
                self._fail("table %r was already defined by a dotted key or inline table" % key)
            if id(table) in self.header_tables:
                self._fail("table %r is defined more than once" % key)
            self.header_tables.add(id(table))
            self.current = table

    # -- keys --------------------------------------------------------------
    def _parse_key_path(self) -> Tuple[str, ...]:
        parts = [self._parse_key_segment()]
        while True:
            self._skip_spaces()
            if self._peek() != ".":
                return tuple(parts)
            self._advance()
            self._skip_spaces()
            parts.append(self._parse_key_segment())

    def _parse_key_segment(self) -> str:
        char = self._peek()
        if char == '"':
            return self._basic_string(multiline=False)
        if char == "'":
            return self._literal_string(multiline=False)
        match = _BARE_KEY.match(self.text, self.pos)
        if not match:
            self._fail("expected a key")
        self._advance(len(match.group(0)))
        return match.group(0)

    def _parse_key_value(self, target: Dict[str, Any]) -> None:
        path = self._parse_key_path()
        self._skip_spaces()
        if self._peek() != "=":
            self._fail("expected '=' after the key")
        self._advance()
        self._skip_spaces()
        value = self._parse_value()
        container = target
        for part in path[:-1]:
            if part not in container:
                container[part] = {}
                self.dotted_tables.add(id(container[part]))
            container = container[part]
            if not isinstance(container, dict):
                self._fail("key %r is not a table" % part)
            if id(container) in self.inline_tables:
                self._fail("key %r is an inline table and cannot be extended" % part)
        key = path[-1]
        if key in container:
            self._fail("duplicate key %r" % key)
        container[key] = value
        self._seal_value(value)

    # -- table navigation --------------------------------------------------
    def _descend(self, path: Tuple[str, ...], array_table: bool = False) -> Dict[str, Any]:
        container = self.root
        for index, part in enumerate(path):
            last = index == len(path) - 1
            if last and array_table:
                value = container.setdefault(part, [])
                if not isinstance(value, list):
                    self._fail("key %r is a table, not an array of tables" % part)
                if id(value) in self.value_arrays:
                    self._fail("key %r is an array value, not an array of tables" % part)
                if id(value) not in self.header_arrays:
                    self.header_arrays.add(id(value))
                value.append({})
                return value[-1]
            if part not in container:
                container[part] = {}
            value = container[part]
            if isinstance(value, list):
                if id(value) in self.value_arrays or id(value) not in self.header_arrays:
                    self._fail("key %r is an array value, not an array of tables" % part)
                if not value or not isinstance(value[-1], dict):
                    self._fail("key %r is not an array of tables" % part)
                if last:
                    self._fail("key %r is an array of tables; use [[...]]" % part)
                container = value[-1]
            elif isinstance(value, dict):
                if id(value) in self.inline_tables:
                    self._fail("key %r is an inline table and cannot be extended" % part)
                container = value
            else:
                self._fail("key %r is not a table" % part)
        return container

    # -- values ------------------------------------------------------------
    def _parse_value(self) -> Any:
        char = self._peek()
        if char == '"':
            return self._basic_string(multiline=self.text.startswith('"""', self.pos))
        if char == "'":
            return self._literal_string(multiline=self.text.startswith("'''", self.pos))
        if char == "[":
            return self._array()
        if char == "{":
            return self._inline_table()
        if char in ("t", "f"):
            return self._boolean()
        return self._number()

    def _boolean(self) -> bool:
        for literal, value in (("true", True), ("false", False)):
            if self.text.startswith(literal, self.pos):
                following = self._peek(len(literal))
                if following == _EOF or following in " \t\r\n,]}#":
                    self._advance(len(literal))
                    return value
        self._fail("invalid value")
        raise AssertionError("unreachable")

    def _number(self) -> Any:
        match = re.match(r"[^\s,\]\}#]+", self.text[self.pos :])
        if not match:
            self._fail("expected a value")
        token = match.group(0)
        self._advance(len(token))
        if token in ("inf", "+inf", "-inf", "nan", "+nan", "-nan"):
            self._fail("non-finite floats are not supported")
        if _INT_HEX.match(token):
            return int(token[2:].replace("_", ""), 16)
        if _INT_OCT.match(token):
            return int(token[2:].replace("_", ""), 8)
        if _INT_BIN.match(token):
            return int(token[2:].replace("_", ""), 2)
        if _INT_DEC.match(token):
            return int(token.replace("_", ""))
        if _FLOAT.match(token) and any(c in token for c in ".eE"):
            return float(token.replace("_", ""))
        self._fail("invalid value %r" % token)
        raise AssertionError("unreachable")

    def _parse_escape(self) -> str:
        self._advance()  # backslash
        char = self._peek()
        if char in _ESCAPES:
            self._advance()
            return _ESCAPES[char]
        if char in ("u", "U"):
            count = 4 if char == "u" else 8
            self._advance()
            digits = self.text[self.pos : self.pos + count]
            if len(digits) != count or not re.match(r"^[0-9A-Fa-f]+$", digits):
                self._fail("invalid unicode escape")
            self._advance(count)
            value = int(digits, 16)
            if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                self._fail("invalid unicode code point")
            return chr(value)
        self._fail("invalid escape sequence \\%s" % char)
        raise AssertionError("unreachable")

    def _basic_string(self, multiline: bool) -> str:
        if multiline:
            self._advance(3)
            if self._peek() == "\r":
                self._advance()
            if self._peek() == "\n":
                self._advance()
        else:
            self._advance()
        chunks = []  # type: List[str]
        while True:
            if self._at_end():
                self._fail("unterminated string")
            if multiline and self.text.startswith('"""', self.pos):
                run = 3
                while self.text[self.pos + run : self.pos + run + 1] == '"':
                    run += 1
                if run > 5:
                    self._fail("too many quotes at the end of a multi-line string")
                chunks.append('"' * (run - 3))
                self._advance(run)
                return _normalise_newlines("".join(chunks))
            if not multiline:
                char = self._peek()
                if char == '"':
                    self._advance()
                    return "".join(chunks)
                if char in ("\r", "\n"):
                    self._fail("newline in a single-line string")
            char = self._peek()
            if char == "\\":
                if multiline:
                    save = (self.pos, self.line, self.line_start)
                    self._advance()
                    while self._peek() in (" ", "\t"):
                        self._advance()
                    if self._peek() in ("\r", "\n"):
                        if self._peek() == "\r":
                            self._advance()
                        if self._peek() == "\n":
                            self._advance()
                        while self._peek() in (" ", "\t", "\r", "\n"):
                            self._advance()
                        continue
                    self.pos, self.line, self.line_start = save
                chunks.append(self._parse_escape())
                continue
            if ord(char) < 0x20 and char != "\t" and not (multiline and char in ("\r", "\n")):
                self._fail("control character in string")
            chunks.append(char)
            self._advance()

    def _literal_string(self, multiline: bool) -> str:
        if multiline:
            self._advance(3)
            if self._peek() == "\r":
                self._advance()
            if self._peek() == "\n":
                self._advance()
            end = self.text.find("'''", self.pos)
            if end == -1:
                self._fail("unterminated multi-line literal string")
            run = 3
            while self.text[end + run : end + run + 1] == "'":
                run += 1
            if run > 5:
                self._fail("too many quotes at the end of a multi-line literal string")
            value = self.text[self.pos : end] + "'" * (run - 3)
            self._advance(end - self.pos + run)
            return _normalise_newlines(value)
        self._advance()
        end = self.pos
        while end < self.length and self.text[end] != "'":
            if self.text[end] in ("\r", "\n"):
                self._fail("newline in a single-line string")
            end += 1
        if end >= self.length:
            self._fail("unterminated literal string")
        value = self.text[self.pos : end]
        self._advance(end - self.pos + 1)
        return value

    def _array(self) -> List[Any]:
        self._advance()  # [
        items = []  # type: List[Any]
        while True:
            self._skip_array_blank()
            if self._at_end():
                self._fail("unterminated array")
            if self._peek() == "]":
                self._advance()
                return items
            items.append(self._parse_value())
            self._skip_array_blank()
            if self._peek() == ",":
                self._advance()
                continue
            if self._peek() == "]":
                self._advance()
                return items
            self._fail("expected ',' or ']' in array")

    def _skip_array_blank(self) -> None:
        while not self._at_end():
            char = self._peek()
            if char in (" ", "\t", "\r", "\n"):
                self._advance()
            elif char == "#":
                self._skip_comment()
            else:
                return

    def _seal_value(self, value) -> None:
        """Remember tables/arrays that came from a value rather than a header."""
        if isinstance(value, dict):
            self.inline_tables.add(id(value))
            for nested in value.values():
                self._seal_value(nested)
        elif isinstance(value, list):
            self.value_arrays.add(id(value))
            for nested in value:
                self._seal_value(nested)

    def _inline_table(self) -> Dict[str, Any]:
        self._advance()  # {
        table = {}  # type: Dict[str, Any]
        self.inline_tables.add(id(table))
        self._skip_spaces()
        if self._peek() == "}":
            self._advance()
            return table
        while True:
            self._skip_spaces()
            path = self._parse_key_path()
            self._skip_spaces()
            if self._peek() != "=":
                self._fail("expected '=' in inline table")
            self._advance()
            self._skip_spaces()
            value = self._parse_value()
            container = table
            for part in path[:-1]:
                if part not in container:
                    container[part] = {}
                    self.inline_tables.add(id(container[part]))
                container = container[part]
                if not isinstance(container, dict):
                    self._fail("inline table key conflict")
            if path[-1] in container:
                self._fail("duplicate key in inline table")
            container[path[-1]] = value
            self._skip_spaces()
            if self._peek() == ",":
                self._advance()
                continue
            if self._peek() == "}":
                self._advance()
                return table
            self._fail("expected ',' or '}' in inline table")


def _normalise_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")
