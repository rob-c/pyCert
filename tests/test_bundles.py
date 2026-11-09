"""Decoding legacy Java and PEM certificate bundles for inspection."""

import hashlib
import struct

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
