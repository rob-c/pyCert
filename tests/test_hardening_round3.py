"""Unit-level hardening tests added in the third round."""

import datetime as dt
import os
import stat
import sys
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import certs
from pycert import p12 as p12_module
from pycert.ca import _safe_xml
from pycert.config import MAX_CONFIG_BYTES, SecretConfig, load_config
from pycert.errors import ConfigError, CryptoError, ProtocolError, PyCertError, SecretError
from pycert.secrets_store import SecretStore
from pycert.store import MAX_STATE_BYTES, Store
from pycert.transport import TransportError, _validate_headers, _validate_url
from pycert.util import atomic_write, ensure_dir, read_private_file


# -- ensure_dir / atomic writes ----------------------------------------------
@pytest.mark.parametrize("seed", range(10))
def test_ensure_dir_concurrent_creation(tmp_path, seed):
    root = tmp_path / ("nested-%d" % seed)
    errors = []

    def worker(index):
        try:
            ensure_dir(root / "a" / "b" / ("c%d" % index))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not errors
    assert (root / "a" / "b").is_dir()


def test_atomic_write_fsyncs_file_and_directory(tmp_path, monkeypatch):
    calls = []
    real_fsync = os.fsync

    def recording_fsync(fd):
        calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    atomic_write(tmp_path / "nested" / "file", b"x")
    assert len(calls) >= 2


def test_atomic_write_modes(tmp_path):
    for mode in (0o600, 0o400, 0o644):
        path = tmp_path / ("mode-%o" % mode)
        atomic_write(path, b"x", mode=mode)
        assert stat.S_IMODE(path.stat().st_mode) == mode


def test_atomic_write_replaces_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("old")
    link = tmp_path / "link"
    link.symlink_to(target)
    atomic_write(link, b"new")
    assert target.read_text() == "old"
    assert link.read_bytes() == b"new" and not link.is_symlink()


def test_read_private_file_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(PyCertError, match="symlink"):
        read_private_file(link)


# -- parser and format limits -------------------------------------------------
def test_config_size_limit(tmp_path):
    path = tmp_path / "pycert.toml"
    path.write_text("a = '" + "x" * (MAX_CONFIG_BYTES + 1) + "'\n")
    with pytest.raises(ConfigError, match="larger"):
        load_config(path)


@pytest.mark.parametrize("depth", [1000, 5000])
def test_config_nesting_is_rejected_cleanly(tmp_path, depth):
    path = tmp_path / "pycert.toml"
    path.write_text("a = " + "[" * depth + "1" + "]" * depth + "\n")
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize("depth", [1000])
def test_config_inline_table_nesting_is_rejected_cleanly(tmp_path, depth):
    path = tmp_path / "pycert.toml"
    path.write_text("a = " + "{ b = " * depth + "1" + " }" * depth + "\n")
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize(
    "payload",
    [
        b"<r><!DOCTYPE x></r>",
        b"<r><!ENTITY a 'b'></r>",
        b"<r>" + b"<a>" * 110 + b"</a>" * 110 + b"</r>",
        b"<r>" + b"<a/>" * 100001 + b"</r>",
        b"x" * (4 * 1024 * 1024 + 1),
    ],
)
def test_xml_limits(payload):
    with pytest.raises(ProtocolError):
        _safe_xml(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"x" * (certs.MAX_CERTIFICATE_BYTES + 1),
        b"x" * (certs.MAX_BUNDLE_BYTES + 1),
    ],
)
def test_certificate_size_limits(payload):
    with pytest.raises(CryptoError):
        certs.load_certificates(payload)


def test_store_state_size_limit(tmp_path):
    store = Store(tmp_path / "data")
    state = store.new_state(alias="big", type="user", cn="big", email="x@y.z")
    with open(store.file(state, "state.json"), "wb") as handle:
        handle.write(b"{" + b" " * (MAX_STATE_BYTES + 1) + b"}")
    with pytest.raises(PyCertError, match="larger"):
        store.get(state.alias)


def test_p12_size_limit(tmp_path, monkeypatch):
    path = tmp_path / "x.p12"
    path.write_bytes(b"x" * 1000)
    monkeypatch.setattr(p12_module, "MAX_P12_BYTES", 100)
    with pytest.raises(PyCertError, match="larger"):
        p12_module.read_pkcs12(path, "pw")


def test_p12_chain_limit(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(PyCertError, match="more than"):
        p12_module.write_pkcs12(
            tmp_path / "x.p12",
            key=key,
            certificate=certificate,
            chain=[certificate] * 21,
            password="pw",
            iterations=1000,
            mac_iterations=100,
        )


# -- secret store hardening ---------------------------------------------------
def test_secret_symlink(tmp_path):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "t")
    target = tmp_path / "target"
    target.write_text("{}")
    store.path.symlink_to(target)
    with pytest.raises(SecretError, match="symlink"):
        store.set("x")


def test_secret_lock_symlink(tmp_path):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "t")
    target = tmp_path / "target"
    target.write_text("")
    store.path.with_name(store.path.name + ".lock").symlink_to(target)
    with pytest.raises(SecretError, match="lock"):
        store.set("x")


def test_secret_command_timeout(tmp_path):
    store = SecretStore(
        SecretConfig(
            backend="command",
            command="%s -c 'import time; time.sleep(2)'" % sys.executable,
            command_timeout=0.1,
        ),
        tmp_path,
        "t",
    )
    with pytest.raises(SecretError, match="timed out"):
        store.get()


def test_secret_file_permissions(tmp_path):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "t")
    store.set("secret")
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


# -- transport framing helpers ------------------------------------------------
def test_url_control_characters():
    for value in ("http://x/\x00", "http://x/\r", "http://x/\n"):
        with pytest.raises(TransportError):
            _validate_url(value, True)


def test_header_control_characters():
    for value in ("\x00", "\r", "\n"):
        with pytest.raises(ValueError):
            _validate_headers({"X": value})


def test_weak_key_helper():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    strong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert certs.key_strength_warning(weak.public_key())
    assert certs.key_strength_warning(strong.public_key()) is None
