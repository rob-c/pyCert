import os
import stat

import pytest

from pycert.errors import PyCertError
from pycert.util import (
    atomic_write,
    check_private_permissions,
    clamp_text,
    format_fingerprint,
    human_duration,
    normalize_fingerprint,
    parse_duration,
    slugify,
)


def test_slugify_handles_unicode_and_punctuation():
    assert slugify("Jane Doe") == "jane-doe"
    assert slugify("servér/host.example.ac.uk") == "server-host.example.ac.uk"
    assert slugify("../../etc/passwd") == "etc-passwd"
    assert slugify("") == "cert"


@pytest.mark.parametrize(
    "seconds,expected",
    [(0, "0s"), (59, "59s"), (60, "1m00s"), (3660, "1h01m"), (90000, "1d01h"), (-30, "-30s")],
)
def test_human_duration(seconds, expected):
    assert human_duration(seconds) == expected


@pytest.mark.parametrize(
    "text,expected",
    [("30", 30), ("45s", 45), ("10m", 600), ("2h", 7200), ("7d", 604800), ("1.5h", 5400)],
)
def test_parse_duration(text, expected):
    assert parse_duration(text) == expected


def test_parse_duration_rejects_junk():
    with pytest.raises(PyCertError):
        parse_duration("soon")


def test_atomic_write_sets_permissions(tmp_path):
    path = tmp_path / "nested" / "secret.txt"
    atomic_write(path, b"value", mode=0o600)
    assert path.read_bytes() == b"value"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert check_private_permissions(path) == []
    os.chmod(path, 0o644)
    assert check_private_permissions(path)


def test_atomic_write_leaves_no_temp_files(tmp_path):
    atomic_write(tmp_path / "a", "x")
    assert [p.name for p in tmp_path.iterdir()] == ["a"]


def test_fingerprint_helpers():
    raw = bytes.fromhex("00ff10")
    assert format_fingerprint(raw) == "00:FF:10"
    assert normalize_fingerprint("00:ff:10") == "00ff10"
    assert normalize_fingerprint("00 FF 10") == "00ff10"


def test_clamp_text():
    assert clamp_text("a  b\nc") == "a b c"
    assert clamp_text("x" * 20, limit=10).endswith("\u2026")
