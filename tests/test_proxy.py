"""RFC 3820 proxy bundles and user/host certificate definitions."""

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from pycert import asn1, certs
from pycert.errors import CryptoError, NotFound, PyCertError
from pycert.proxy import (
    PROXY_CERT_INFO_OID,
    PROXY_POLICY_INHERIT_ALL_OID,
    PROXY_POLICY_LIMITED_OID,
    create_proxy_bundle,
    load_proxy_bundle,
    remove_proxy_bundle,
)
from pycert.workflow import renew

PIN = "1234567890AB"


def test_proxy_bundle_is_signed_verified_and_removable(tmp_path, ctx, issued):
    state = issued("proxy user")
    target = tmp_path / "proxy.pem"
    result = create_proxy_bundle(ctx, state.alias, target, hours=2, remove=False)
    assert Path(result.path).is_file()
    assert (Path(result.path).stat().st_mode & 0o777) == 0o600
    assert result.removed is False
    proxy, issuer = load_proxy_bundle(target)
    assert proxy.issuer == issuer.subject
    assert proxy.subject != issuer.subject
    assert proxy.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[-1].value == "proxy"
    info = proxy.extensions.get_extension_for_oid(ObjectIdentifier(PROXY_CERT_INFO_OID))
    assert info.critical is True
    assert info.value.value  # DER ProxyCertInfo
    assert asn1.oid(PROXY_POLICY_INHERIT_ALL_OID) in info.value.value
    assert certs.public_keys_equal(proxy, proxy.public_key())


def test_proxy_runtime_signs_bundle_then_removes_it(tmp_path, ctx, issued):
    state = issued("runtime proxy")
    target = tmp_path / "runtime-proxy.pem"
    result = create_proxy_bundle(ctx, state.alias, target, hours=1, remove=True)
    assert result.removed is True
    assert not target.exists()
    with pytest.raises(NotFound):
        load_proxy_bundle(target)


def test_proxy_limited_and_path_length_extensions(tmp_path, ctx, issued):
    state = issued("limited proxy")
    target = tmp_path / "limited.pem"
    create_proxy_bundle(ctx, state.alias, target, hours=1, path_length=0, limited=True)
    proxy, _ = load_proxy_bundle(target)
    info = proxy.extensions.get_extension_for_oid(ObjectIdentifier(PROXY_CERT_INFO_OID))
    assert asn1.oid(PROXY_POLICY_LIMITED_OID) in info.value.value
    assert proxy.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[-1].value == "limited proxy"


def test_proxy_key_and_certificate_are_in_bundle(tmp_path, ctx, issued):
    state = issued("bundle key")
    target = tmp_path / "keyed.pem"
    create_proxy_bundle(ctx, state.alias, target, hours=1)
    data = target.read_bytes()
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in data and b"BEGIN PRIVATE KEY" not in data
    proxy, issuer = load_proxy_bundle(target)
    private = serialization.load_pem_private_key(data, password=ctx.p12_passphrase().encode())
    assert certs.certificate_matches_key(proxy, private)
    assert certs.certificate_matches_key(issuer, ctx.store.load_key(state, ctx.key_passphrase()))


def test_proxy_remove_is_idempotent(tmp_path):
    target = tmp_path / "missing.pem"
    assert remove_proxy_bundle(target) is False
    target.write_text("x")
    assert remove_proxy_bundle(target) is True
    assert remove_proxy_bundle(target) is False


def test_user_certificate_definition(ctx, issued):
    state = issued("user definition", email="user@example.org")
    assert state.type == "user"
    certificate = ctx.store.load_certificate(state)
    assert certificate is not None
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "user@example.org" in sans.get_values_for_type(x509.RFC822Name)
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION in eku


def test_host_certificate_definition(ctx, issued):
    user = issued("host auth", email="host-auth@example.org")
    host = issued("host.example.org", type="host", auth_alias=user.alias, email="host@example.org")
    assert host.type == "host"
    certificate = ctx.store.load_certificate(host)
    assert certificate is not None
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "host.example.org" in sans.get_values_for_type(x509.DNSName)
    assert not sans.get_values_for_type(x509.RFC822Name)
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_host_renewal_can_change_sans_without_changing_type(ctx, issued):
    user = issued("host renew auth", email="host-renew-auth@example.org")
    host = issued("old.example.org", type="host", auth_alias=user.alias, email="host@example.org")
    renewed = renew(
        ctx,
        host.alias,
        san_dns=["new.example.org"],
        email="host@example.org",
        pin=PIN,
        wait=True,
        timeout=30,
        interval=0.1,
    )
    assert renewed.type == "host"
    certificate = ctx.store.load_certificate(renewed)
    assert certificate is not None
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["new.example.org"]


def test_user_renewal_can_change_sans_and_contact(ctx, issued):
    user = issued("user renew", email="old@example.org")
    renewed = renew(
        ctx,
        user.alias,
        san_dns=["extra.example.org"],
        san_email=["new@example.org"],
        email="new@example.org",
        pin=PIN,
        wait=True,
        timeout=30,
        interval=0.1,
    )
    assert renewed.type == "user"
    certificate = ctx.store.load_certificate(renewed)
    assert certificate is not None
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "extra.example.org" in sans.get_values_for_type(x509.DNSName)
    assert "new@example.org" in sans.get_values_for_type(x509.RFC822Name)


def test_cli_proxy_creates_and_removes_bundle(e2e, tmp_path):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    state = e2e.request_user("cli proxy", wait=True).json
    alias = state["alias"]
    target = tmp_path / "cli-proxy.pem"
    result = e2e.run_json("proxy", alias, "--out", str(target), "--remove")
    assert result.code == 0, result.err
    assert result.json["removed"] is True
    assert not target.exists()


def test_proxy_rejects_invalid_parameters(tmp_path, ctx, issued):
    state = issued("proxy invalid params")
    with pytest.raises(NotFound):
        create_proxy_bundle(ctx, "missing alias", tmp_path / "x.pem")
    with pytest.raises(PyCertError):
        create_proxy_bundle(ctx, state.alias, tmp_path / "x.pem", hours=0)
    with pytest.raises(PyCertError):
        create_proxy_bundle(ctx, state.alias, tmp_path / "x.pem", hours=24 * 31)
    with pytest.raises(PyCertError):
        create_proxy_bundle(ctx, state.alias, tmp_path / "x.pem", rsa_bits=1024)
    from pycert.proxy import encode_proxy_cert_info

    with pytest.raises(PyCertError):
        encode_proxy_cert_info(path_length=-1)


def test_proxy_password_protected_bundle(tmp_path, ctx, issued):
    state = issued("proxy password")
    target = tmp_path / "encrypted.pem"
    create_proxy_bundle(ctx, state.alias, target, hours=1, password="secret")
    proxy, _ = load_proxy_bundle(target)
    data = target.read_bytes()
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(data, password=None)
    private = serialization.load_pem_private_key(data, password=b"secret")
    assert certs.certificate_matches_key(proxy, private)


def test_proxy_load_rejects_non_proxy_and_short_bundles(tmp_path, ctx, issued):
    from pycert.proxy import load_proxy_bundle

    state = issued("proxy bad bundle")
    cert = ctx.store.load_certificate(state)
    (tmp_path / "one.pem").write_text(certs.cert_pem(cert))
    with pytest.raises(CryptoError):
        load_proxy_bundle(tmp_path / "one.pem")
    (tmp_path / "plain.pem").write_text(certs.cert_pem(cert) + certs.cert_pem(cert))
    with pytest.raises(CryptoError):
        load_proxy_bundle(tmp_path / "plain.pem")


def _self_signed(key, cn="issuer", *, eku=True, days=30, invalid=False):
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID

    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days if not invalid else -1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


def test_proxy_issuer_without_eku_and_ed25519(tmp_path, ctx, issued, monkeypatch):
    from pycert import certs
    from pycert.proxy import build_proxy_certificate

    user = issued("proxy issuer")
    key = ctx.store.load_key(user, ctx.key_passphrase())
    proxy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_cert = _self_signed(ed_key, eku=False)
    ed_proxy = build_proxy_certificate(ed_cert, ed_key, proxy_key)
    assert certs.certificate_matches_key(ed_proxy, proxy_key)
    no_eku = _self_signed(key, eku=False)
    proxy = build_proxy_certificate(no_eku, key, proxy_key)
    assert proxy.issuer == no_eku.subject
    with pytest.raises(PyCertError):
        build_proxy_certificate(no_eku, rsa.generate_private_key(public_exponent=65537, key_size=2048), proxy_key)
    with pytest.raises(PyCertError):
        build_proxy_certificate(_self_signed(key, invalid=True), key, proxy_key)


def test_proxy_post_write_verification_failures(tmp_path, ctx, issued, monkeypatch):
    from pycert import proxy as proxy_module

    state = issued("proxy verify")
    target = tmp_path / "verify.pem"
    real = proxy_module.load_proxy_bundle

    def wrong_proxy(path):
        proxy, issuer = real(path)
        return _self_signed(ed25519.Ed25519PrivateKey.generate()), issuer

    monkeypatch.setattr(proxy_module, "load_proxy_bundle", wrong_proxy)
    with pytest.raises(CryptoError):
        create_proxy_bundle(ctx, state.alias, target)

    def wrong_issuer(path):
        proxy, issuer = real(path)
        return proxy, _self_signed(ed25519.Ed25519PrivateKey.generate())

    monkeypatch.setattr(proxy_module, "load_proxy_bundle", wrong_issuer)
    with pytest.raises(CryptoError):
        create_proxy_bundle(ctx, state.alias, target)


def test_proxy_create_rejects_bad_stored_key(tmp_path, ctx, issued, monkeypatch):
    state = issued("proxy bad key")
    real = ctx.store.load_key
    monkeypatch.setattr(ctx.store, "load_key", lambda *a, **k: rsa.generate_private_key(public_exponent=65537, key_size=2048))
    with pytest.raises(PyCertError):
        create_proxy_bundle(ctx, state.alias, tmp_path / "bad.pem")
    monkeypatch.setattr(ctx.store, "load_key", real)


def test_proxy_load_valid_certificate_without_proxy_extension(tmp_path, ctx, issued):
    state = issued("proxy no ext")
    certificate = ctx.store.load_certificate(state)
    chain = ctx.store.load_chain(state)
    target = tmp_path / "no-extension.pem"
    from pycert import certs

    target.write_text(certs.cert_pem(certificate) + certs.certs_pem(chain))
    with pytest.raises(CryptoError):
        load_proxy_bundle(target)


def test_proxy_generated_certificate_mismatch_is_rejected(tmp_path, ctx, issued, monkeypatch):
    from pycert import proxy as proxy_module

    state = issued("proxy mismatch")
    calls = []
    real = proxy_module.certs.certificate_matches_key
    def side_effect(*args, **kwargs):
        calls.append(1)
        return len(calls) < 3
    monkeypatch.setattr(proxy_module.certs, "certificate_matches_key", side_effect)
    with pytest.raises(CryptoError):
        create_proxy_bundle(ctx, state.alias, tmp_path / "mismatch.pem")
    monkeypatch.setattr(proxy_module.certs, "certificate_matches_key", real)


def test_load_proxy_bundle_missing_file(tmp_path):
    with pytest.raises(NotFound):
        load_proxy_bundle(tmp_path / "missing-proxy.pem")
