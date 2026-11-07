"""Second-round TOML tests: generated corpora, limits, numerics and errors."""

import tomllib

import pytest
from test_toml import _generate

from pycert.toml import MAX_DEPTH, MAX_DOCUMENT_BYTES, TOMLDecodeError, loads

# ---------------------------------------------------------------------------
# Differential generation (fresh seeds)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(1000, 1100))
def test_generated_documents_still_match_tomllib(seed):
    doc, expected = _generate(seed)
    assert loads(doc) == expected
    assert tomllib.loads(doc) == expected


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


def test_document_size_limit():
    payload = "a = '" + "x" * (MAX_DOCUMENT_BYTES + 1) + "'\n"
    with pytest.raises(TOMLDecodeError, match="larger"):
        loads(payload)


def test_document_size_limit_bytes():
    payload = b"a = 1\n" + b"#" * (MAX_DOCUMENT_BYTES + 1)
    with pytest.raises(TOMLDecodeError, match="larger"):
        loads(payload)


def test_array_depth_limit():
    payload = "a = " + "[" * (MAX_DEPTH + 1) + "1" + "]" * (MAX_DEPTH + 1) + "\n"
    with pytest.raises(TOMLDecodeError, match="deeply"):
        loads(payload)


def test_inline_table_depth_limit():
    payload = "a = " + "{ b = " * (MAX_DEPTH + 1) + "1" + " }" * (MAX_DEPTH + 1) + "\n"
    with pytest.raises(TOMLDecodeError, match="deeply"):
        loads(payload)


def test_depth_just_below_limit_is_accepted():
    depth = MAX_DEPTH - 1
    payload = "a = " + "[" * depth + "1" + "]" * depth + "\n"
    assert loads(payload)["a"]


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------

NUMBERS = [
    ("0", 0),
    ("+0", 0),
    ("-0", 0),
    ("1", 1),
    ("-1", -1),
    ("+1", 1),
    ("1_000", 1000),
    ("1_2_3", 123),
    ("0x0", 0),
    ("0xff", 255),
    ("0xFF", 255),
    ("0o0", 0),
    ("0o755", 493),
    ("0b0", 0),
    ("0b1010", 10),
    ("0.0", 0.0),
    ("+0.0", 0.0),
    ("-0.0", 0.0),
    ("1.5", 1.5),
    ("1e3", 1000.0),
    ("1E3", 1000.0),
    ("1.5e-2", 0.015),
    ("1_000.5", 1000.5),
    ("5e+22", 5e22),
    ("6.626e-34", 6.626e-34),
]


@pytest.mark.parametrize("literal,expected", NUMBERS)
def test_number_literals(literal, expected):
    assert loads("v = %s\n" % literal)["v"] == expected
    assert tomllib.loads("v = %s\n" % literal)["v"] == expected


BAD_NUMBERS = [
    "01",
    "00",
    "+01",
    "-01",
    "1__0",
    "_1",
    "1_",
    "0x",
    "0x_1",
    "0xGG",
    "0o8",
    "0b2",
    "1.",
    ".5",
    "1e",
    "1e+",
    "+",
    "-",
    "inf",
    "+inf",
    "-inf",
    "nan",
    "+nan",
    "-nan",
    "1.2.3",
    "0b1_",
]


@pytest.mark.parametrize("literal", BAD_NUMBERS)
def test_bad_number_literals(literal):
    with pytest.raises(TOMLDecodeError):
        loads("v = %s\n" % literal)


# ---------------------------------------------------------------------------
# Strings and escapes
# ---------------------------------------------------------------------------

STRINGS = [
    ('"a"', "a"),
    ('""', ""),
    ('"a b"', "a b"),
    ('"\\b\\t\\n\\f\\r"', "\b\t\n\f\r"),
    ('"\\\\"', "\\"),
    ('"\\""', '"'),
    ('"\\u00e9"', "é"),
    ('"\\U0001F600"', "😀"),
    ("'a'", "a"),
    ("''", ""),
    ("'a\\nb'", "a\\nb"),
    ("'a\"b'", 'a"b'),
    ('"""a"""', "a"),
    ('"""a\nb"""', "a\nb"),
    ('"""a\\\n   b"""', "ab"),
    ('"""a""b"""', 'a""b'),
    ('"""a\\"b"""', 'a"b'),
    ("'''a'''", "a"),
    ("'''a\nb'''", "a\nb"),
    ("'''a''b'''", "a''b"),
    ("'''a'b'''", "a'b"),
]


@pytest.mark.parametrize("literal,expected", STRINGS)
def test_string_literals(literal, expected):
    assert loads("v = %s\n" % literal)["v"] == expected
    assert tomllib.loads("v = %s\n" % literal)["v"] == expected


BAD_STRINGS = [
    '"unterminated',
    "'unterminated",
    '"""unterminated',
    "'''unterminated",
    '"bad \\q escape"',
    '"bad \\u12"',
    '"bad \\uD800"',
    '"bad \\U00110000"',
    '"line\nbreak"',
    "'line\nbreak'",
    '"\x01control"',
    '"trailing\\"',
]


@pytest.mark.parametrize("literal", BAD_STRINGS)
def test_bad_string_literals(literal):
    with pytest.raises(TOMLDecodeError):
        loads("v = %s\n" % literal)


# ---------------------------------------------------------------------------
# Tables, keys and arrays
# ---------------------------------------------------------------------------

TABLE_CASES = [
    ("a.b = 1\n", {"a": {"b": 1}}),
    ("[a]\nb.c = 1\n", {"a": {"b": {"c": 1}}}),
    ("[[a]]\nx = 1\n", {"a": [{"x": 1}]}),
    ("[[a]]\n[[a]]\n", {"a": [{}, {}]}),
    ("[[a.b]]\nx = 1\n", {"a": {"b": [{"x": 1}]}}),
    ("[a.b]\nx = 1\n[a]\ny = 2\n", {"a": {"b": {"x": 1}, "y": 2}}),
    ('"a b" = 1\n', {"a b": 1}),
    ("'a b' = 1\n", {"a b": 1}),
    ("a-b_c = 1\n", {"a-b_c": 1}),
    ("a = []\n", {"a": []}),
    ("a = [1,]\n", {"a": [1]}),
    ("a = [\n1,\n2,\n]\n", {"a": [1, 2]}),
    ("a = [[1], [2, 3]]\n", {"a": [[1], [2, 3]]}),
    ("a = {b = 1}\n", {"a": {"b": 1}}),
    ("a = {b = {c = 1}}\n", {"a": {"b": {"c": 1}}}),
]


@pytest.mark.parametrize("doc,expected", TABLE_CASES)
def test_table_cases(doc, expected):
    assert loads(doc) == expected
    assert tomllib.loads(doc) == expected


BAD_TABLES = [
    "[a\n",
    "[[a]\n",
    "[a]]\n",
    "[a.]\n",
    "[.a]\n",
    "a..b = 1\n",
    "= 1\n",
    "a = 1\n[a]\n",
    "a.b = 1\n[a]\n",
    "a = []\n[[a]]\n",
    "a = {b = 1}\n[a]\n",
    "a = {b = 1}\na.c = 2\n",
    "[a]\n[a]\n",
    "[[a]]\n[a]\n",
    "a = 1\na = 2\n",
    "a = [1 2]\n",
    "a = [1,,2]\n",
    "a = {b = 1,}\n",
    "a = {b = 1\n}\n",
]


@pytest.mark.parametrize("doc", BAD_TABLES)
def test_bad_table_cases(doc):
    with pytest.raises(TOMLDecodeError):
        loads(doc)


# ---------------------------------------------------------------------------
# Mutation fuzzing (second corpus)
# ---------------------------------------------------------------------------


def _mutate(seed, doc):
    import random

    rng = random.Random(seed)
    chars = list(doc)
    for _ in range(rng.randint(1, 8)):
        if not chars:
            break
        index = rng.randrange(len(chars))
        operation = rng.choice(["delete", "insert", "replace", "duplicate"])
        if operation == "delete":
            del chars[index]
        elif operation == "insert":
            chars.insert(index, rng.choice("[]{}=" + "#\"'\n abc0123."))
        elif operation == "duplicate":
            chars.insert(index, chars[index])
        else:
            chars[index] = rng.choice("[]{}=" + "#\"'\n abc0123.")
    return "".join(chars)


@pytest.mark.parametrize("seed", range(2000, 2100))
def test_mutations_never_raise_unexpected_exceptions(seed):
    doc, _expected = _generate(seed - 2000)
    mutated = _mutate(seed, doc)
    try:
        ours = loads(mutated)
    except TOMLDecodeError:
        return
    try:
        reference = tomllib.loads(mutated)
    except tomllib.TOMLDecodeError:
        pytest.fail("parser accepted what tomllib rejects: %r" % mutated)
    assert ours == reference


# ---------------------------------------------------------------------------
# Error locations and edge input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "doc,line",
    [
        ("a = 1\nb = @\n", 2),
        ("[a\n", 1),
        ("a = [1,\n2\n", 3),
        ("a = '''unterminated\n", 1),
        ("a = 1\nb = 2\nc\n", 3),
    ],
)
def test_error_line_numbers(doc, line):
    with pytest.raises(TOMLDecodeError) as exc:
        loads(doc)
    assert exc.value.line == line


@pytest.mark.parametrize(
    "doc,expected",
    [
        ("", {}),
        ("\n\n\n", {}),
        ("# comment only\n", {}),
        ("a = 1 # comment\n", {"a": 1}),
        ("a = 1\r\nb = 2\r\n", {"a": 1, "b": 2}),
        ('a = "é"\n', {"a": "é"}),
        ("a = 1\n\n# x\n\n[t]\nb = 2\n", {"a": 1, "t": {"b": 2}}),
    ],
)
def test_edge_inputs(doc, expected):
    assert loads(doc) == expected
