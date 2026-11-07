"""TOML parser tests, including differential checks against tomllib."""

import random
import tomllib

import pytest

from pycert.toml import TOMLDecodeError, loads

VALID = [
    ("", {}),
    ("# only a comment\n", {}),
    ("a = 1\n", {"a": 1}),
    ("a = 0\nb = -1\nc = +42\n", {"a": 0, "b": -1, "c": 42}),
    ("a = 1_000\n", {"a": 1000}),
    ("a = 0xDEAD_BEEF\n", {"a": 0xDEADBEEF}),
    ("a = 0o755\n", {"a": 0o755}),
    ("a = 0b1010_1010\n", {"a": 0b10101010}),
    ("a = 1.5\nb = -0.25\nc = 1e3\nd = 1.5e-2\n", {"a": 1.5, "b": -0.25, "c": 1000.0, "d": 0.015}),
    ("a = true\nb = false\n", {"a": True, "b": False}),
    ('a = "hello"\n', {"a": "hello"}),
    ('a = ""\n', {"a": ""}),
    ('a = "tab\\there"\n', {"a": "tab\there"}),
    ('a = "quote: \\" backslash: \\\\"\n', {"a": 'quote: " backslash: \\'}),
    ('a = "snowman \\u2603"\n', {"a": "snowman \u2603"}),
    ('a = "emoji \\U0001F600"\n', {"a": "emoji \U0001f600"}),
    ("a = 'literal \\n stays'\n", {"a": "literal \\n stays"}),
    ('a = """multi\nline"""\n', {"a": "multi\nline"}),
    ('a = """trimmed \\\n   line"""\n', {"a": "trimmed line"}),
    ("a = '''raw\nline'''\n", {"a": "raw\nline"}),
    ('a = """ quotes "" inside """\n', {"a": ' quotes "" inside '}),
    ("a = '''it's fine'''\n", {"a": "it's fine"}),
    ("a = []\n", {"a": []}),
    ("a = [1, 2, 3]\n", {"a": [1, 2, 3]}),
    ("a = [1, 2, 3,]\n", {"a": [1, 2, 3]}),
    ("a = [\n  1,\n  2, # comment\n]\n", {"a": [1, 2]}),
    ("a = [[1, 2], [3]]\n", {"a": [[1, 2], [3]]}),
    ('a = ["x", 1, true]\n', {"a": ["x", 1, True]}),
    ("a = { x = 1, y = 'z' }\n", {"a": {"x": 1, "y": "z"}}),
    ("a = { nested = { b = 2 } }\n", {"a": {"nested": {"b": 2}}}),
    ("a.b.c = 1\n", {"a": {"b": {"c": 1}}}),
    ("[t]\na = 1\n", {"t": {"a": 1}}),
    ("[t.u]\na = 1\n", {"t": {"u": {"a": 1}}}),
    ("[a.b]\nx = 1\n[a]\ny = 2\n", {"a": {"b": {"x": 1}, "y": 2}}),
    ("[[items]]\na = 1\n[[items]]\na = 2\n", {"items": [{"a": 1}, {"a": 2}]}),
    (
        "[[items]]\n[items.sub]\nx = 1\n[[items]]\n[items.sub]\nx = 2\n",
        {"items": [{"sub": {"x": 1}}, {"sub": {"x": 2}}]},
    ),
    ('"quoted key" = 1\n', {"quoted key": 1}),
    ("'literal key' = 1\n", {"literal key": 1}),
    ("a-b_c = 1\n", {"a-b_c": 1}),
    ("a = 1\r\nb = 2\r\n", {"a": 1, "b": 2}),
    ("a = 1 # trailing\n[t] # table\nb = 2\n", {"a": 1, "t": {"b": 2}}),
    ("a = 1\n\n\n# blank lines\n\nb = 2\n", {"a": 1, "b": 2}),
    ("[a]\n[a.b]\n[a.b.c]\nx = 1\n", {"a": {"b": {"c": {"x": 1}}}}),
    ("a = 1\n[[b]]\nx = 2\n", {"a": 1, "b": [{"x": 2}]}),
    ('key = "value with = and [brackets]"\n', {"key": "value with = and [brackets]"}),
    ("a = 1_2_3\n", {"a": 123}),
    ("a = 1.0\n", {"a": 1.0}),
    ('a = "\\u00e9"\n', {"a": "é"}),
    ("a = '''\nline1\r\nline2'''\n", {"a": "line1\nline2"}),
    ('a = """a\\\n\n   b"""\n', {"a": "ab"}),
]


@pytest.mark.parametrize("doc,expected", VALID)
def test_valid_documents(doc, expected):
    assert loads(doc) == expected
    assert tomllib.loads(doc) == expected


INVALID = [
    ("a = ", "value"),
    ("a = \n", "value"),
    ("a\n", "="),
    ("a = 1 b = 2\n", "newline"),
    ("a = 'unterminated\n", "newline"),
    ('a = "unterminated\n', "newline"),
    ('a = """unterminated\n', "unterminated"),
    ("a = '''unterminated\n", "unterminated"),
    ("a = [1, 2\n", "array"),
    ("a = [1 2]\n", "','"),
    ("[a\n", "']'"),
    ("[[a]\n", "']]'"),
    ("[a]]\n", "newline"),
    ("a = 1\na = 2\n", "duplicate"),
    ("[a]\n[a]\n", "more than once"),
    ("a.b = 1\n[a]\n", "dotted"),
    ("[a]\nb.c = 1\n[a.b]\n", "dotted"),
    ("a = { b = 1 }\n[a]\n", "inline"),
    ("a = { b = 1 }\na.c = 2\n", "inline"),
    ("a = []\n[[a]]\n", "array"),
    ("a = [{b=1}]\n[[a]]\n", "array"),
    ("a = 01\n", "value"),
    ("a = 1__0\n", "value"),
    ("a = 1.", "value") if False else ("a = 1.\n", "value"),
    ("a = .5\n", "value"),
    ("a = tru\n", "value"),
    ("a = TRUE\n", "value"),
    ("a = inf\n", "non-finite"),
    ("a = nan\n", "non-finite"),
    ("a = +inf\n", "non-finite"),
    ("a = 1979-05-27\n", "value"),
    ('a = "bad \\q escape"\n', "escape"),
    ('a = "bad \\u12"\n', "unicode"),
    ('a = "control \x01"\n', "control"),
    ('a = "newline\ninside"\n', "newline"),
    ("a = 1\n[b]\nc = \n", "value"),
    ("= 1\n", "key"),
    ("[a.]\n", "key"),
    ("[.a]\n", "key"),
    ("a..b = 1\n", "key"),
    ("a = { b = 1, }\n", "key"),
    ("a = { b = 1\n}\n", "expected ',' or '}'"),
    ("a = [1,,2]\n", "value"),
    ("a = 1\na.b = 2\n", "table"),
    ("a = 1\n[a.b]\n", "table"),
    ("[[a]]\n[a]\n", "array of tables"),
]


@pytest.mark.parametrize("doc,match", INVALID)
def test_invalid_documents(doc, match):
    with pytest.raises(TOMLDecodeError) as exc:
        loads(doc)
    assert match.lower() in str(exc.value).lower()


def test_error_reports_line_and_column():
    with pytest.raises(TOMLDecodeError) as exc:
        loads("a = 1\nb = @\n")
    assert exc.value.line == 2
    assert exc.value.column >= 5


def test_bytes_and_bom():
    assert loads(b"\xef\xbb\xbfa = 1\n") == {"a": 1}
    assert loads(b"a = 1\n") == {"a": 1}
    assert loads("\ufeffa = 1\n") == {"a": 1}


# ---------------------------------------------------------------------------
# Differential generation against tomllib
# ---------------------------------------------------------------------------


def _escape(value):
    out = []
    for char in value:
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 0x20:
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    return "".join(out)


def _render_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return '"%s"' % _escape(value)
    if isinstance(value, list):
        return "[" + ", ".join(_render_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join("%s = %s" % (k, _render_value(v)) for k, v in value.items()) + " }"
    raise TypeError(type(value))


def _generate(seed):
    rng = random.Random(seed)
    data = {}
    key = "k%d" % seed
    data[key] = rng.choice([0, 1, -1, 42, 1000])
    data["flag"] = rng.choice([True, False])
    data["ratio"] = rng.choice([0.0, 1.5, -2.25, 1e-3])
    data["text"] = rng.choice(["hello", "", "café", "a=b # c", "line\nbreak", 'quote"inside'])
    data["list"] = [rng.choice([1, 2, 3, "x", True]) for _ in range(rng.randint(0, 4))]
    data["table"] = {"a": rng.randint(0, 10), "b": rng.choice(["x", "y"])}
    data["nested"] = {"inner": {"value": rng.randint(0, 100)}}
    data["inline"] = {"one": 1, "two": "2"}
    items = [{"id": i, "name": "item-%d" % i} for i in range(rng.randint(1, 3))]
    data["items"] = items
    doc = []
    for key, value in data.items():
        if key in ("table", "nested", "items"):
            continue
        doc.append("%s = %s" % (key, _render_value(value)))
    doc.append("[table]")
    for key, value in data["table"].items():
        doc.append("%s = %s" % (key, _render_value(value)))
    doc.append("[nested.inner]")
    doc.append("value = %s" % _render_value(data["nested"]["inner"]["value"]))
    for item in data["items"]:
        doc.append("[[items]]")
        doc.append("id = %d" % item["id"])
        doc.append("name = %s" % _render_value(item["name"]))
    return "\n".join(doc) + "\n", data


@pytest.mark.parametrize("seed", range(80))
def test_generated_documents_match_tomllib(seed):
    doc, expected = _generate(seed)
    assert loads(doc) == expected
    assert tomllib.loads(doc) == expected


@pytest.mark.parametrize("seed", range(20))
def test_random_mutations_never_crash(seed):
    rng = random.Random(seed + 5000)
    doc, _expected = _generate(seed)
    chars = list(doc)
    for _ in range(rng.randint(1, 5)):
        if not chars:
            break
        index = rng.randrange(len(chars))
        operation = rng.choice(["delete", "insert", "replace"])
        if operation == "delete":
            del chars[index]
        elif operation == "insert":
            chars.insert(index, rng.choice("[]{}=,#\"'\n abc0123."))
        else:
            chars[index] = rng.choice("[]{}=,#\"'\n abc0123.")
    mutated = "".join(chars)
    try:
        ours = loads(mutated)
    except TOMLDecodeError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail("parser raised %s instead of TOMLDecodeError: %r" % (type(exc).__name__, mutated))
    # If we accept it, tomllib should accept it with the same result for this
    # supported subset (mutations may introduce dates/inf, which we reject).
    try:
        reference = tomllib.loads(mutated)
    except tomllib.TOMLDecodeError:
        pytest.fail("parser accepted what tomllib rejects: %r -> %r" % (mutated, ours))
    assert ours == reference
