"""Additional focused hardening checks."""

import os

import pytest

from pycert.config import SecretConfig
from pycert.errors import PyCertError
from pycert.transport import (
    TransportError,
    _parse_retry_after,
    _same_host_redirect,
    _validate_headers,
    _validate_url,
)
from pycert.util import atomic_write, ensure_dir


def test_header_control_characters_round3():
    for value in ("\x00", "\x01", "\x7f"):
        with pytest.raises(ValueError):
            _validate_headers({"X": value})


def test_header_tab_is_allowed():
    _validate_headers({"X": "a\tb"})


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org:0/",
        "http://example.org:65536/",
        "http://[::1",
        "http://exa mple.org/",
    ],
)
def test_url_invalid_round3(url):
    with pytest.raises(TransportError):
        _validate_url(url, True)


def test_redirect_default_port_equivalence():
    assert (
        _same_host_redirect("https://example.org:443/a", "https://example.org/b", False)
        == "https://example.org/b"
    )


@pytest.mark.parametrize("value,expected", [("0", 0.0), ("5", 5.0), ("bad", None), ("-1", 0.0)])
def test_retry_after_round3(value, expected):
    result = _parse_retry_after(value)
    if expected is None:
        assert result is None
    else:
        assert result == pytest.approx(expected, abs=1.0)


def test_ensure_dir_refuses_file_at_path(tmp_path):
    path = tmp_path / "file"
    path.write_text("x")
    with pytest.raises((FileExistsError, NotADirectoryError, OSError)):
        ensure_dir(path / "child")


def test_atomic_write_fsync_failure_is_tolerated(tmp_path, monkeypatch):
    def bad_fsync(fd):
        raise OSError("fsync not supported")

    monkeypatch.setattr(os, "fsync", bad_fsync)
    path = tmp_path / "file"
    atomic_write(path, b"x")
    assert path.read_bytes() == b"x"


def test_command_timeout_config_validation():
    import tempfile
    from pathlib import Path

    from pycert.config import init_config, validate_config

    config = init_config(Path(tempfile.mkdtemp()) / "conf", copy_chain=False)
    config.secrets.command_timeout = 0
    with pytest.raises(PyCertError):
        validate_config(config)


def test_secret_command_missing():
    store = SecretConfig(backend="command", command="")
    assert store.command == ""


def test_weak_key_warning_round3():
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    from pycert import certs

    assert certs.key_strength_warning(rsa.generate_private_key(65537, 1024).public_key())
    assert certs.key_strength_warning(ec.generate_private_key(ec.SECP256R1()).public_key()) is None
