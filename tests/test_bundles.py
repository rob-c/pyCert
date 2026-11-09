"""Decoding legacy Java and PEM certificate bundles for inspection."""

import hashlib
import shutil
import struct
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from pycert import bundles, certs, p12
from pycert.errors import CryptoError, PyCertError


def _jks(certificates, *, password="passwd", key_chain=None, magic=bundles.JKS_MAGIC):
    body = struct.pack(">III", magic, 2, len(certificates) + (1 if key_chain else 0))

    def utf(value):
        raw = value.encode("utf-8")
        return struct.pack(">H", len(raw)) + raw

    def der(cert):
        raw = cert.public_bytes(serialization.Encoding.DER)
        return struct.pack(">I", len(raw)) + raw

    if key_chain:
        body += struct.pack(">I", 1) + utf("client") + struct.pack(">Q", 0)
        body += struct.pack(">I", 4) + b"fake"  # private key bytes are not decoded
        body += struct.pack(">I", len(key_chain))
        for cert in key_chain:
            body += utf("X.509") + der(cert)
    for index, cert in enumerate(certificates):
        body += struct.pack(">I", 2) + utf("trusted-%d" % index) + struct.pack(">Q", 0)
        body += utf("X.509") + der(cert)
    digest = hashlib.sha1(
        password.encode("utf-16-be") + b"Mighty Aphrodite" + body
    ).digest()
    return body + digest


def test_inspect_pkcs12_with_private_key_and_chain(ctx, issued, tmp_path):
    state = issued("bundle leaf")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    leaf = ctx.store.load_certificate(state)
    chain = ctx.store.load_chain(state)
    path = tmp_path / "cakeystore.pkcs12"
    p12.write_pkcs12(path, key=key, certificate=leaf, chain=chain, password="secret")

    result = bundles.load_bundle(path, "secret")
    assert result.format == "pkcs12"
    assert result.has_private_key is True
    assert result.key_description.startswith("RSA")
    assert result.certificates[0].role == "leaf"
    assert result.certificates[0].certificate == leaf
    assert len(result) >= 2
    fingerprints = [certs.fingerprint(item.certificate) for item in result.certificates]
    assert len(fingerprints) == len(set(fingerprints))
    assert result.as_dict()["certificates"][0]["role"] == "leaf"


def test_inspect_certificate_only_pkcs12_and_password_errors(ctx, issued, tmp_path):
    state = issued("cert only bundle")
    leaf = ctx.store.load_certificate(state)
    path = tmp_path / "cert-only.p12"
    blob = pkcs12.serialize_key_and_certificates(
        b"name",
        None,
        None,
        [leaf],
        serialization.BestAvailableEncryption(b"secret"),
    )
    path.write_bytes(blob)
    result = bundles.load_bundle(path, "secret")
    assert result.has_private_key is False
    assert result.certificates[0].role == "trusted"
    assert "no private key" in result.warnings[0]
    with pytest.raises(CryptoError):
        bundles.load_bundle(path, "wrong")
    with pytest.raises(CryptoError):
        bundles.load_bundle(path, "")


def test_inspect_pem_and_der_bundles(ctx, issued, tmp_path):
    state = issued("pem bundle")
    leaf = ctx.store.load_certificate(state)
    chain = ctx.store.load_chain(state)
    pem = tmp_path / "bundle.pem"
    pem.write_text("".join(certs.cert_pem(c) for c in [leaf, *chain]))
    result = bundles.load_bundle(pem)
    assert result.format == "pem"
    assert len(result) == len(chain) + 1
    assert all(item.role == "certificate" for item in result.certificates)

    der = tmp_path / "cert.der"
    der.write_bytes(certs.cert_der(leaf))
    result = bundles.load_bundle(der)
    assert result.format == "der"
    assert result.certificates[0].certificate == leaf


def test_inspect_jks_truststore_and_private_key_chain(ctx, issued, tmp_path):
    state = issued("jks leaf")
    leaf = ctx.store.load_certificate(state)
    chain = ctx.store.load_chain(state)
    path = tmp_path / "truststore.jks"
    path.write_bytes(_jks([leaf, *chain]))
    result = bundles.load_bundle(path, "passwd")
    assert result.format == "jks"
    assert result.integrity_checked is True
    assert result.has_private_key is False
    assert [item.role for item in result.certificates] == ["trusted"] * (len(chain) + 1)
    assert result.certificates[1].alias == "trusted-1"

    key_store = tmp_path / "cakeystore.jks"
    key_store.write_bytes(_jks([], key_chain=[leaf, *chain]))
    result = bundles.load_bundle(key_store, "passwd")
    assert result.has_private_key is True
    assert [item.role for item in result.certificates[:2]] == ["leaf", "chain"]
    assert any("not decoded" in warning for warning in result.warnings)


def test_inspect_jks_without_password_and_bad_password(ctx, issued, tmp_path):
    state = issued("jks no password")
    leaf = ctx.store.load_certificate(state)
    path = tmp_path / "truststore.jks"
    path.write_bytes(_jks([leaf]))
    result = bundles.load_bundle(path)
    assert result.integrity_checked is False
    assert any("not verified" in warning for warning in result.warnings)
    with pytest.raises(CryptoError, match="integrity"):
        bundles.load_bundle(path, "wrong")


def test_inspect_jceks(ctx, issued, tmp_path):
    state = issued("jceks user")
    leaf = ctx.store.load_certificate(state)
    path = tmp_path / "truststore.jceks"
    path.write_bytes(_jks([leaf], magic=bundles.JCEKS_MAGIC))
    assert bundles.load_bundle(path, "passwd").format == "jceks"


def test_bundle_errors_and_limits(ctx, issued, tmp_path, monkeypatch):
    with pytest.raises(PyCertError):
        bundles.load_bundle(tmp_path / "missing.p12")
    empty = tmp_path / "empty.p12"
    empty.write_bytes(b"")
    with pytest.raises(CryptoError):
        bundles.load_bundle(empty)
    large = tmp_path / "large.p12"
    large.write_bytes(b"x" * (bundles.MAX_BUNDLE_BYTES + 1))
    with pytest.raises(CryptoError):
        bundles.load_bundle(large)
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(b"not a bundle")
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(struct.pack(">III", bundles.JKS_MAGIC, 2, 1))
    state = issued("bundle limit")
    leaf = ctx.store.load_certificate(state)
    other_state = issued("bundle limit 2")
    other_cert = ctx.store.load_certificate(other_state)
    monkeypatch.setattr(bundles, "MAX_BUNDLE_CERTIFICATES", 1)
    with pytest.raises(CryptoError, match="more than"):
        bundles.load_bundle_bytes(certs.cert_pem(leaf) + certs.cert_pem(other_cert))


def test_bundle_dataclass_and_pkcs12_defensive_paths(ctx, issued, tmp_path, monkeypatch):
    state = issued("bundle defensive")
    leaf = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    other = issued("bundle other")
    other_cert = ctx.store.load_certificate(other)
    bundle = bundles.CertificateBundle(path="x", format="pem", certificates=[])
    assert bundle.warnings == []

    monkeypatch.setattr(bundles, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(b"xx")
    monkeypatch.undo()

    with_key = certs.cert_pem(leaf) + "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
    assert bundles.load_bundle_bytes(with_key).has_private_key is True

    monkeypatch.setattr(bundles.pkcs12, "load_key_and_certificates", lambda *a, **k: (key, None, [leaf]))
    assert bundles.load_bundle_bytes(b"p12").certificates[0].role == "leaf"
    monkeypatch.setattr(bundles.pkcs12, "load_key_and_certificates", lambda *a, **k: (key, None, []))
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(b"p12")
    monkeypatch.setattr(bundles.pkcs12, "load_key_and_certificates", lambda *a, **k: (key, other_cert, []))
    assert "does not match" in bundles.load_bundle_bytes(b"p12").warnings[-1]
    monkeypatch.setattr(bundles.pkcs12, "load_key_and_certificates", lambda *a, **k: (None, None, []))
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(b"p12")
    monkeypatch.undo()

    with pytest.raises(CryptoError):
        bundles._bundle_from_certificates([], "pem", "x")


def test_jks_defensive_paths(ctx, issued):
    state = issued("jks defensive")
    leaf = ctx.store.load_certificate(state)
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(b"\xfe\xed\xfe\xed")
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(struct.pack(">III", bundles.JKS_MAGIC, 3, 0) + b"x" * 20)
    # No digest.
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(struct.pack(">III", bundles.JKS_MAGIC, 2, 0))
    # Empty but valid keystore.
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(struct.pack(">III", bundles.JKS_MAGIC, 2, 0) + b"x" * 20)
    # Duplicate certificate.
    duplicate = _jks([leaf, leaf])
    assert len(bundles.load_bundle_bytes(duplicate).certificates) == 1
    # Invalid certificate DER.
    der = b"\x01\x02"
    body = struct.pack(">III", bundles.JKS_MAGIC, 2, 1)
    body += struct.pack(">I", 2) + struct.pack(">H", 1) + b"a" + struct.pack(">Q", 0)
    body += struct.pack(">H", 5) + b"X.509" + struct.pack(">I", len(der)) + der
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(body + b"x" * 20)
    # Truncated timestamp, UTF length, UTF payload, cert length, private key.
    header = struct.pack(">III", bundles.JKS_MAGIC, 2, 1) + struct.pack(">I", 2)
    for suffix in (
        struct.pack(">H", 1) + b"a" + b"",
        struct.pack(">H", 1) + b"a" + b"",
        b"",
        struct.pack(">H", 1) + b"a" + b"",
    ):
        with pytest.raises(CryptoError):
            bundles.load_bundle_bytes(header + suffix)
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(
            struct.pack(">III", bundles.JKS_MAGIC, 2, 1)
            + struct.pack(">I", 1)
            + struct.pack(">H", 1)
            + b"a"
            + struct.pack(">Q", 0)
            + struct.pack(">I", 100)
        )
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(
            struct.pack(">III", bundles.JKS_MAGIC, 2, 1)
            + struct.pack(">I", 2)
            + struct.pack(">H", 1)
            + b"a"
            + struct.pack(">Q", 0)
            + struct.pack(">H", 5)
            + b"X.509"
            + struct.pack(">I", 100)
        )
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(
            struct.pack(">III", bundles.JKS_MAGIC, 2, 1)
            + struct.pack(">I", 2)
            + struct.pack(">H", 100)
            + b"a"
        )


def test_write_java_bundle_with_key_and_all_certificates(ctx, issued, tmp_path):
    state = issued("bundle write leaf")
    key = ctx.store.load_key(state, ctx.key_passphrase())
    leaf = ctx.store.load_certificate(state)
    chain = ctx.store.load_chain(state)
    other_state = issued("bundle write other")
    other = ctx.store.load_certificate(other_state)
    source = tmp_path / "source.p12"
    p12.write_pkcs12(
        source,
        key=key,
        certificate=leaf,
        chain=[*chain, other],
        password="source",
        preserve_chain=True,
    )
    loaded = bundles.load_bundle(source, "source")
    target = tmp_path / "java-compatible.p12"
    assert bundles.write_java_bundle(target, loaded, "target") == str(target)
    assert bytes.fromhex("2a864886f70d010c0103") in target.read_bytes()
    written = bundles.load_bundle(target, "target")
    assert written.has_private_key is True
    assert {certs.fingerprint(item.certificate) for item in written.certificates} == {
        certs.fingerprint(item.certificate) for item in loaded.certificates
    }


def test_write_certificate_only_java_bundle_from_jks(ctx, issued, tmp_path):
    state = issued("bundle write jks")
    leaf = ctx.store.load_certificate(state)
    source = tmp_path / "truststore.jks"
    source.write_bytes(_jks([leaf]))
    loaded = bundles.load_bundle(source, "passwd")
    target = tmp_path / "truststore-output.p12"
    bundles.write_java_bundle(target, loaded, "target")
    from cryptography.hazmat.primitives.serialization import pkcs12

    key_value, cert_value, extras = pkcs12.load_key_and_certificates(target.read_bytes(), b"target")
    assert key_value is None
    assert cert_value is None
    assert [certs.fingerprint(c) for c in extras] == [certs.fingerprint(leaf)]


def test_write_java_bundle_requires_password_and_certificates(tmp_path):
    empty = bundles.CertificateBundle(path="x", format="pkcs12", certificates=[])
    with pytest.raises(CryptoError):
        bundles.write_java_bundle(tmp_path / "x.p12", empty, "pw")
    with pytest.raises(CryptoError):
        bundles.write_java_bundle(tmp_path / "x.p12", empty, "")


def test_write_java_bundle_refuses_undecoded_jks_key(ctx, issued, tmp_path):
    state = issued("bundle jks key")
    leaf = ctx.store.load_certificate(state)
    source = tmp_path / "cakeystore.jks"
    source.write_bytes(_jks([], key_chain=[leaf]))
    loaded = bundles.load_bundle(source, "passwd")
    assert loaded.has_private_key is True
    with pytest.raises(CryptoError, match="cannot decode"):
        bundles.write_java_bundle(tmp_path / "out.p12", loaded, "target")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
def test_inspect_openssl_legacy_rc2_bundle_and_rewrite(tmp_path):
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    source = tmp_path / "legacy-rc2.p12"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=legacy rc2",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "pkcs12", "-export", "-legacy", "-in", str(cert), "-inkey", str(key),
            "-out", str(source), "-passout", "pass:legacy-pw",
        ],
        check=True,
        capture_output=True,
    )
    loaded = bundles.load_bundle(source, "legacy-pw")
    assert len(loaded) == 1
    assert loaded.key_count == 1
    assert loaded.raw_key_bags and loaded.raw_cert_bags
    assert loaded.certificates[0].role == "leaf"
    target = tmp_path / "rewritten.p12"
    bundles.write_java_bundle(target, loaded, "legacy-pw")
    from cryptography.hazmat.primitives.serialization import pkcs12

    key_value, cert_value, _extras = pkcs12.load_key_and_certificates(
        target.read_bytes(), b"legacy-pw"
    )
    assert key_value is not None
    assert cert_value is not None
    assert certs.common_name(cert_value.subject) == "legacy rc2"



def test_raw_bundle_certificate_only_and_multiple_keys(ctx, issued):
    from pycert.pkcs12_writer import _certificate_bag, _key_bag, encode_raw_pkcs12

    state = issued("raw cert only")
    leaf = ctx.store.load_certificate(state)
    cert_bag = _certificate_bag(leaf, "leaf", None, False)
    loaded = bundles.load_bundle_bytes(
        encode_raw_pkcs12([], [cert_bag], "pw"), password="pw"
    )
    assert loaded.key_count == 0
    assert loaded.certificates[0].role == "trusted"

    key = ctx.store.load_key(state, ctx.key_passphrase())
    key_bag = _key_bag(key, "pw", 1000, "leaf", b"id")
    loaded = bundles.load_bundle_bytes(
        encode_raw_pkcs12([key_bag, key_bag], [cert_bag], "pw"), password="pw"
    )
    assert loaded.key_count == 2
    assert loaded.certificates[0].role == "certificate"
    assert any("2 key entries" in warning for warning in loaded.warnings)


def test_openssl_rc2_failure_is_clear(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        bundles.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout=b"", stderr=b"no rc2"),
    )
    with pytest.raises(CryptoError, match="legacy RC2"):
        bundles._openssl_rc2_40_decrypt(b"data", b"12345", b"12345678")
