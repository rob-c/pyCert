"""Coverage-oriented tests for small modules and defensive branches."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert import _dataclasses, asn1, bundled, csr, p12, store, util
from pycert.compat import field
from pycert.errors import ConfigError, CryptoError, NotFound, PyCertError


def test_asn1_error_paths():
    with pytest.raises(ValueError):
        asn1.encode_length(-1)
    with pytest.raises(ValueError):
        asn1.encode_length(1 << 40)
    with pytest.raises(TypeError):
        asn1.integer("not-an-int")


def test_dataclasses_fallback_error_paths():
    assert repr(_dataclasses._Missing()) == "<missing>"
    with pytest.raises(ValueError):
        field(default=1, default_factory=list)
    with pytest.raises(ValueError):
        _dataclasses.Field(default=[])
    with pytest.raises(ValueError):
        _dataclasses.Field(default_factory=1)

    @_dataclasses.dataclass
    class Base:
        x: int = 1

    @_dataclasses.dataclass
    class Child(Base):
        x: int = 2

    assert Child().x == 2
    assert [name for name, _ in _dataclasses._collect_fields(Child)] == ["x"]

    @_dataclasses.dataclass(frozen=True)
    class Frozen:
        x: int

    value = Frozen(1)
    with pytest.raises(_dataclasses.FrozenInstanceError):
        value.x = 2
    with pytest.raises(_dataclasses.FrozenInstanceError):
        del value.x


def test_bundled_error_paths(tmp_path, monkeypatch):
    bundled.certificates.cache_clear()
    monkeypatch.setattr(bundled, "PINNED", {"missing.pem": "00"})
    monkeypatch.setattr(bundled, "path_for", lambda name: tmp_path / name)
    with pytest.raises(ConfigError):
        bundled.certificates()
    (tmp_path / "missing.pem").write_bytes(b"not a certificate")
    with pytest.raises(ConfigError):
        bundled.certificates()
    # A real certificate with the wrong pin.
    source = Path("src/pycert/data/ca/escience-root.pem")
    monkeypatch.setattr(bundled, "path_for", lambda name: source)
    with pytest.raises(ConfigError):
        bundled.certificates()
    bundled.certificates.cache_clear()


def test_util_edge_paths(tmp_path, monkeypatch):
    assert util.format_fingerprint("aa:bb") == "AA:BB"
    with pytest.raises(PyCertError):
        util.format_fingerprint("abc")
    file_path = tmp_path / "file"
    file_path.write_text("x")
    with pytest.raises(OSError):
        util.ensure_dir(file_path / "child")
    target = tmp_path / "atomic"
    real_replace = os.replace

    def fail_replace(*args, **kwargs):
        raise RuntimeError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(RuntimeError):
        util.atomic_write(target, "x")
    monkeypatch.setattr(os, "replace", real_replace)
    assert not list(tmp_path.glob(".atomic.*"))
    private = tmp_path / "private"
    private.write_text("secret")
    private.chmod(0o644)
    assert util.read_private_file(private) == b"secret"
    assert util.check_private_permissions(tmp_path / "missing") == []
    symlink = tmp_path / "link"
    symlink.symlink_to(private)
    assert any("symlink" in item for item in util.check_private_permissions(symlink))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
    util.safe_chmod(private, 0o600)


def test_pkcs12_writer_unknown_hash():
    from pycert import pkcs12_writer

    with pytest.raises(ValueError):
        pkcs12_writer._hash_algorithm("md5")


def test_p12_error_paths(tmp_path, ctx, issued, monkeypatch):
    state = issued("p12 coverage")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    certificate = ctx.store.load_certificate(state)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(PyCertError):
        p12.write_pkcs12(tmp_path / "a.p12", key=key, certificate=certificate, password="")
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "b.p12", key=other_key, certificate=certificate, password="x")
    with pytest.raises(PyCertError):
        p12.write_pkcs12(
            tmp_path / "c.p12", key=key, certificate=certificate, chain=[certificate] * 21, password="x"
        )
    with pytest.raises(PyCertError):
        p12.read_pkcs12(tmp_path / "missing.p12", "x")
    big = tmp_path / "big.p12"
    big.write_bytes(b"x" * (p12.MAX_P12_BYTES + 1))
    with pytest.raises(PyCertError):
        p12.read_pkcs12(big, "x")
    with pytest.raises(PyCertError):
        p12.read_pkcs12_bytes(b"x" * (p12.MAX_P12_BYTES + 1), "x")
    with pytest.raises(CryptoError):
        p12.read_pkcs12_bytes(b"not p12", "x")
    # PKCS#12 with a key but no certificate.
    from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_lib

    no_cert = pkcs12_lib.serialize_key_and_certificates(
        b"name", key, None, None, serialization.BestAvailableEncryption(b"x")
    )
    with pytest.raises(CryptoError):
        p12.read_pkcs12_bytes(no_cert, "x")
    # A chain that does not lead to an issuer is simply dropped.
    assert p12._ordered_chain(certificate, [ctx.store.load_certificate(issued("p12 other"))]) == []


def test_store_edge_paths(ctx, issued, tmp_path, monkeypatch):
    state = ctx.store.new_state(alias="store-dup-a", type="user", cn="same common", email="")
    ctx.store.save(state)
    second = ctx.store.new_state(alias="store-dup-b", type="user", cn="same common", email="")
    ctx.store.save(second)
    with pytest.raises(PyCertError):
        ctx.store.get("same common")
    with pytest.raises(PyCertError):
        ctx.store.load_pending_key(state, "")
    with pytest.raises(OSError):
        ctx.store.load_pending_csr(state)
    assert store.parse_alias_set([" a ", "", " b "]) == ["a", "b"]
    old = ctx.store.requests_dir
    monkeypatch.setattr(ctx.store, "requests_dir", tmp_path / "missing")
    assert ctx.store.corrupt_files() == []
    monkeypatch.setattr(ctx.store, "requests_dir", old)
    bad = ctx.store.path(state) / "state.json"
    bad.write_text("{")
    assert ctx.store.corrupt_files()


def test_csr_edge_paths():
    from cryptography.hazmat.primitives.asymmetric import ec

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr.example.org")])
    ec_key = ec.generate_private_key(ec.SECP256R1())
    request = csr.build_csr(
        ec_key,
        name,
        cert_type="user",
        extensions=["key_usage", "extended_key_usage", "basic_constraints"],
    )
    assert csr.signature_valid(request)
    summary = csr.summarize(request)
    assert summary.sans == []
    assert csr.split_ec_and_rsa(ec_key) == "ec"
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert csr.split_ec_and_rsa(rsa_key) == "rsa"
    with pytest.raises(CryptoError):
        csr.split_ec_and_rsa(object())
    with pytest.raises(CryptoError):
        csr.build_csr(rsa_key, name, hash_name="not-a-hash")


def test_p12_mac_fallback_and_inconsistent_bundles(tmp_path, ctx, issued, monkeypatch):
    from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_lib

    from pycert import p12 as p12_module

    state = issued("p12 fallback")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    certificate = ctx.store.load_certificate(state)
    target = tmp_path / "fallback.p12"
    original = p12_module.read_pkcs12_bytes
    calls = []

    def fallback(blob, password):
        calls.append(1)
        if len(calls) == 1:
            raise CryptoError("old reader")
        return original(blob, password)

    monkeypatch.setattr(p12_module, "read_pkcs12_bytes", fallback)
    p12_module.write_pkcs12(target, key=key, certificate=certificate, password="x")
    monkeypatch.setattr(p12_module, "read_pkcs12_bytes", original)

    # Key without matching cert, and cert without key.
    no_cert = pkcs12_lib.serialize_key_and_certificates(
        b"name", key, None, None, serialization.BestAvailableEncryption(b"x")
    )
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12_bytes(no_cert, "x")
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_cert = _other_cert(other_key)
    monkeypatch.setattr(p12_module.pkcs12, "load_key_and_certificates", lambda *a, **k: (key, wrong_cert, []))
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12_bytes(b"x", "x")


def _other_cert(key):
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, __import__("cryptography").hazmat.primitives.hashes.SHA256())
    )


def test_dataclasses_multiple_inheritance_and_frozen_mutation():
    @_dataclasses.dataclass
    class A:
        x: int = 1

    @_dataclasses.dataclass
    class B:
        x: int = 2

    @_dataclasses.dataclass
    class C(A, B):
        pass

    assert C().x in (1, 2)

    @_dataclasses.dataclass(frozen=True)
    class F:
        x: int = 1

    value = F()
    object.__setattr__(value, "_pycert_frozen", False)
    value.x = 3
    del value.x


def test_ensure_dir_file_exists_error(tmp_path):
    path = tmp_path / "file"
    path.write_text("x")
    with pytest.raises(OSError):
        util.ensure_dir(path / "child")


def test_entrypoint_module():
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-m", "pycert", "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "pyCert" in result.stdout


def test_p12_verification_failure_paths(tmp_path, ctx, issued, monkeypatch):
    state = issued("p12 verify failures")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    cert = ctx.store.load_certificate(state)
    original = p12.read_pkcs12_bytes

    def wrong_cert(blob, password):
        bundle = original(blob, password)
        return SimpleNamespace(key=bundle.key, cert=_other_cert(rsa.generate_private_key(public_exponent=65537, key_size=2048)), chain=[])

    monkeypatch.setattr(p12, "read_pkcs12_bytes", wrong_cert)
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "wrong.p12", key=key, certificate=cert, password="x")
    monkeypatch.setattr(p12, "read_pkcs12_bytes", original)

    assert p12._ordered_chain(cert, [cert]) == []


def test_p12_missing_key_and_cert_branches(tmp_path, ctx, issued, monkeypatch):
    from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_lib

    state = issued("p12 branches")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    cert = ctx.store.load_certificate(state)
    # Key absent, certificate present.
    no_key = pkcs12_lib.serialize_key_and_certificates(
        b"name", None, cert, None, serialization.BestAvailableEncryption(b"x")
    )
    with pytest.raises(CryptoError):
        p12.read_pkcs12_bytes(no_key, "x")
    # Key present, certificate absent, extra certificate does not match.
    other = _other_cert(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    no_cert = pkcs12_lib.serialize_key_and_certificates(
        b"name", key, None, [other], serialization.BestAvailableEncryption(b"x")
    )
    with pytest.raises(CryptoError):
        p12.read_pkcs12_bytes(no_cert, "x")
    # A bundle where the certificate matches but its key does not.
    original = p12.read_pkcs12_bytes
    monkeypatch.setattr(
        p12,
        "read_pkcs12_bytes",
        lambda blob, password: SimpleNamespace(key=rsa.generate_private_key(public_exponent=65537, key_size=2048), cert=cert, chain=[]),
    )
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "mismatch.p12", key=key, certificate=cert, password="x")
    monkeypatch.setattr(p12, "read_pkcs12_bytes", original)


def test_p12_ordered_chain_invalid_issuer(tmp_path, ctx, issued):
    state = issued("p12 chain invalid")
    leaf = ctx.store.load_certificate(state)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    fake_issuer = (
        x509.CertificateBuilder()
        .subject_name(leaf.issuer)
        .issuer_name(leaf.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + __import__("datetime").timedelta(days=1))
        .sign(key, __import__("cryptography").hazmat.primitives.hashes.SHA256())
    )
    assert p12._ordered_chain(leaf, [fake_issuer]) == []


def test_store_ambiguous_aliases_and_lock_error(ctx):
    first = ctx.store.new_state(alias="CaseAlias", type="user", cn="Case One", email="")
    ctx.store.save(first)
    second = ctx.store.new_state(alias="casealias", type="user", cn="Case Two", email="")
    ctx.store.save(second)
    with pytest.raises(NotFound):
        ctx.store.get("CASEALIAS")
    if store.fcntl is not None:
        real = store.fcntl.flock
        store.fcntl.flock = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lock"))
        try:
            with pytest.raises(RuntimeError), ctx.store.lock(first):
                pass
        finally:
            store.fcntl.flock = real


def test_p12_verification_error_lines(tmp_path, ctx, issued, monkeypatch):
    from pycert.p12 import P12Bundle

    state = issued("p12 verify lines")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    cert = ctx.store.load_certificate(state)
    other = _other_cert(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    # certificate mismatch
    monkeypatch.setattr(p12, "read_pkcs12_bytes", lambda *a: P12Bundle(key, other, []))
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "cert-mismatch.p12", key=key, certificate=cert, password="x")
    # key mismatch (certificate matches)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(p12, "read_pkcs12_bytes", lambda *a: P12Bundle(other_key, cert, []))
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "key-mismatch.p12", key=key, certificate=cert, password="x")


def test_csr_signature_failure_branch():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed")])
    with pytest.raises(CryptoError):
        csr.build_csr(key, name, cert_type="user")


def test_pkcs12_empty_repeat():
    from pycert import pkcs12_writer

    assert pkcs12_writer._repeat_to_block(b"", 64) == b""


def test_entrypoint_runpy(monkeypatch):
    import runpy

    monkeypatch.setattr(__import__("sys"), "argv", ["pycert", "--version"])
    with pytest.raises(SystemExit):
        runpy.run_module("pycert", run_name="__main__")


def test_p12_cert_from_extras_and_encode_failure(ctx, issued, tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_lib

    state = issued("p12 extras")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    cert = ctx.store.load_certificate(state)
    blob = pkcs12_lib.serialize_key_and_certificates(
        b"name", key, None, [cert], serialization.BestAvailableEncryption(b"x")
    )
    bundle = p12.read_pkcs12_bytes(blob, "x")
    assert bundle.cert == cert
    monkeypatch.setattr(p12, "encode_pkcs12", lambda *a, **k: (_ for _ in ()).throw(ValueError("encode")))
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "encode.p12", key=key, certificate=cert, password="x")


def test_p12_written_bundle_private_key_mismatch(ctx, issued, tmp_path, monkeypatch):
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.asymmetric import rsa

    state = issued("p12 key mismatch")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    cert = ctx.store.load_certificate(state)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(p12, "read_pkcs12_bytes", lambda *a, **k: SimpleNamespace(cert=cert, key=other))
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "mismatch.p12", key=key, certificate=cert, password="x")


def test_chain_key_ids_allow_missing_authority_key_id():
    from types import SimpleNamespace

    from cryptography import x509

    from pycert.chain import ChainBuilder

    class Extensions:
        def get_extension_for_class(self, cls):
            if cls is x509.AuthorityKeyIdentifier:
                return SimpleNamespace(value=SimpleNamespace(key_identifier=None))
            if cls is x509.SubjectKeyIdentifier:
                return SimpleNamespace(value=SimpleNamespace(digest=b"x"))
            raise x509.ExtensionNotFound("missing", cls.oid)

    child = SimpleNamespace(extensions=Extensions())
    issuer = SimpleNamespace(extensions=Extensions())
    assert ChainBuilder._key_ids_consistent(child, issuer)


def test_toml_crlf_and_table_conflicts():
    from pycert import toml

    with pytest.raises(toml.TOMLDecodeError):
        toml.loads("a = [1]\n[[a]]\n")
    with pytest.raises(toml.TOMLDecodeError):
        toml.loads("a = [1]\n[a.b]\n")
    with pytest.raises(toml.TOMLDecodeError):
        toml.loads("a = { b = 1, b.c = 2 }\n")
    assert toml.loads('a = """x\r\ny"""\n')["a"] == "x\ny"
    assert toml.loads('a = """\r\nx"""\n')["a"] == "x"
    assert toml.loads('a = """x \\\t\n y"""\n')["a"] == "x y"
    assert toml.loads('a = """x \\\r\n y"""\n')["a"] == "x y"
    assert toml.loads("a = '''x\r\ny'''\n")["a"] == "x\ny"
    assert toml.loads("a = '''\r\nx'''\n")["a"] == "x"


def test_signature_description_falls_back_on_unsupported_hash():
    from types import SimpleNamespace

    from pycert import certs

    class BadCert:
        signature_algorithm_oid = SimpleNamespace(_name="weird", dotted_string="1.2.3")

        @property
        def signature_hash_algorithm(self):
            raise ValueError("unsupported")

    assert "weird" in certs.signature_description(BadCert())


def test_p12_written_cert_key_mismatch(ctx, issued, tmp_path, monkeypatch):
    from types import SimpleNamespace

    state = issued("p12 cert key mismatch")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    cert = ctx.store.load_certificate(state)
    other_state = issued("p12 other cert")
    other_cert = ctx.store.load_certificate(other_state)
    monkeypatch.setattr(p12.certs, "fingerprint", lambda c: "same")
    monkeypatch.setattr(
        p12, "read_pkcs12_bytes", lambda *a, **k: SimpleNamespace(cert=other_cert, key=key)
    )
    with pytest.raises(CryptoError):
        p12.write_pkcs12(tmp_path / "certkey.p12", key=key, certificate=cert, password="x")
