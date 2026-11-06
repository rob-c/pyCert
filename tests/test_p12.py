import shutil
import stat
import subprocess

import pytest

from pycert import certs
from pycert import p12 as p12_module
from pycert.errors import CryptoError, PyCertError

OPENSSL = shutil.which("openssl")


def test_write_read_roundtrip(ctx, issued):
    state = issued()
    path = p12_module.Path(state.p12_path)
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    password = ctx.p12_passphrase()
    bundle = p12_module.read_pkcs12(path, password)
    assert certs.common_name(bundle.cert.subject) == state.cn
    assert certs.key_description(bundle.key.public_key()) == state.key_algorithm
    assert len(bundle.chain) == 2  # intermediate + root
    assert certs.fingerprint(bundle.chain[-1]) == certs.fingerprint(ctx.config.bundle.certificates[0])
    assert p12_module.describe_file(path)["private_permissions"] is True


def test_friendly_name_defaults_to_common_name(ctx, issued, tmp_path):
    state = issued()
    path = tmp_path / "no-name.p12"
    p12_module.write_pkcs12(
        path,
        key=ctx.store.load_key(state, ctx.key_passphrase()),
        certificate=ctx.store.load_certificate(state),
        chain=ctx.store.load_chain(state),
        password="another-secret",
        friendly_name="",
    )
    assert p12_module.read_pkcs12(path, "another-secret")


def test_wrong_password_fails_cleanly(ctx, issued):
    state = issued()
    with pytest.raises(CryptoError, match="could not open"):
        p12_module.read_pkcs12(state.p12_path, "definitely-not-the-password")


def test_write_refuses_foreign_key(ctx, issued):
    state = issued()
    from cryptography.hazmat.primitives.asymmetric import rsa

    certificate = ctx.store.load_certificate(state)
    with pytest.raises(CryptoError, match="does not match"):
        p12_module.write_pkcs12(
            ctx.store.path(state) / "bad.p12",
            key=rsa.generate_private_key(65537, 2048),
            certificate=certificate,
            chain=[],
            password="x" * 16,
        )


def test_write_requires_password(ctx, issued):
    state = issued()
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    with pytest.raises(PyCertError):
        p12_module.write_pkcs12(
            ctx.store.path(state) / "nopw.p12", key=key, certificate=certificate, chain=[], password=""
        )


def test_chain_is_ordered_leaf_to_root(ctx, issued):
    state = issued()
    bundle = p12_module.read_pkcs12(state.p12_path, ctx.p12_passphrase())
    subjects = [c.subject for c in bundle.chain]
    leaf = bundle.cert.subject
    assert leaf not in subjects
    for child, issuer in zip([bundle.cert, *bundle.chain], bundle.chain, strict=False):
        assert child.issuer == issuer.subject


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
def test_openssl_reads_and_verifies_our_p12(ctx, issued, tmp_path):
    state = issued()
    password = ctx.p12_passphrase()
    result = subprocess.run(
        [OPENSSL, "pkcs12", "-in", state.p12_path, "-passin", f"pass:{password}", "-info", "-nodes"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "friendlyName" in result.stdout
    assert "BEGIN CERTIFICATE" in result.stdout
    assert "BEGIN PRIVATE KEY" in result.stdout

    extract = tmp_path / "certs.pem"
    subprocess.run(
        [
            OPENSSL,
            "pkcs12",
            "-in",
            state.p12_path,
            "-passin",
            f"pass:{password}",
            "-nokeys",
            "-out",
            str(extract),
        ],
        check=True,
        capture_output=True,
    )
    root = ctx.config.bundle.certificates[0]
    intermediate = ctx.config.bundle.certificates[1]
    (tmp_path / "root.pem").write_text(certs.cert_pem(root))
    (tmp_path / "intermediate.pem").write_text(certs.cert_pem(intermediate))
    verify = subprocess.run(
        [
            OPENSSL,
            "verify",
            "-CAfile",
            str(tmp_path / "root.pem"),
            "-untrusted",
            str(tmp_path / "intermediate.pem"),
            str(ctx.store.cert_path(state)),
        ],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stderr
    assert "OK" in verify.stdout


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
def test_legacy_pkcs12_can_be_imported(tmp_path):
    """CertWizard/Java 8 produced PBE-SHA1-3DES (or RC2) files."""
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    legacy = tmp_path / "legacy.p12"
    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=legacy test",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            OPENSSL,
            "pkcs12",
            "-export",
            "-legacy",
            "-in",
            str(cert),
            "-inkey",
            str(key),
            "-out",
            str(legacy),
            "-passout",
            "pass:legacy-pw",
        ],
        check=True,
        capture_output=True,
    )
    bundle = p12_module.read_pkcs12(legacy, "legacy-pw")
    assert certs.common_name(bundle.cert.subject) == "legacy test"
    assert certs.key_description(bundle.key.public_key()) == "RSA 2048"
