"""Export formats, encryption types and the new-passphrase rule."""

import io
import json
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from pycert import bundles, certs, cli, exporter
from pycert.errors import CryptoError, PyCertError
from pycert.p12 import read_pkcs12
from pycert.workflow import export_certificate

NEW = "export passphrase 1"


def _certificates(data: bytes) -> "list[x509.Certificate]":
    return x509.load_pem_x509_certificates(data)


@pytest.fixture
def user(issued):
    return issued("export person")


def test_format_catalogue():
    assert exporter.DEFAULT_FORMAT == "p12" and list(exporter.FORMATS)[0] == "p12"
    p12 = exporter.get_format("p12")
    assert p12.bundle and p12.has_key and p12.default_encryption == "aes256" and not p12.is_directory
    assert exporter.get_format("pem-files").is_directory
    assert exporter.get_format("cert").default_encryption == ""
    with pytest.raises(PyCertError, match="unknown export format"):
        exporter.get_format("jks")
    assert exporter.file_base(" a b/c\\d ") == "a_b-c-d"
    assert exporter.file_base("  ") == "certificate"
    assert exporter.default_destination("x y", "p12", "/tmp").name == "x_y.p12"
    assert exporter.default_destination("x", exporter.get_format("pem-files"), "/tmp") == exporter.Path("/tmp")


def test_passphrase_rules(ctx):
    p12, key, cert = (exporter.get_format(n) for n in ("p12", "key", "cert"))
    exporter.check_passphrase(ctx, cert, None, False)  # public: nothing to protect
    with pytest.raises(PyCertError, match="always protected"):
        exporter.check_passphrase(ctx, p12, None, True)
    with pytest.raises(PyCertError, match="not both"):
        exporter.check_passphrase(ctx, key, NEW, True)
    exporter.check_passphrase(ctx, key, None, True)
    with pytest.raises(PyCertError, match="needs a new passphrase"):
        exporter.check_passphrase(ctx, p12, "", False)
    with pytest.raises(PyCertError, match="at least 8"):
        exporter.check_passphrase(ctx, p12, "1234567", False)
    with pytest.raises(PyCertError, match="saved secret"):
        exporter.check_passphrase(ctx, p12, ctx.p12_passphrase(), False)
    exporter.check_passphrase(ctx, p12, NEW, False)


def test_passphrase_rules_without_a_saved_secret(ctx, monkeypatch):
    monkeypatch.setattr(ctx.secrets, "get", lambda *a, **k: None)
    exporter.check_passphrase(ctx, exporter.get_format("p12"), NEW, False)


@pytest.mark.parametrize("encryption, expected", [("aes256", "pbes2"), ("3des", "")])
def test_p12_encryptions(ctx, user, tmp_path, encryption, expected):
    result = export_certificate(ctx, user.alias, tmp_path, password=NEW, encryption=encryption)
    path = result.files["p12"]
    assert path.name == "export_person.p12" and (path.stat().st_mode & 0o777) == 0o600
    bundle = read_pkcs12(path, NEW)
    assert certs.fingerprint(bundle.cert) == user.cert.sha256 and bundle.chain
    assert bundles.load_bundle_bytes(path.read_bytes(), NEW, prefer_raw=True).encryption == expected
    # both loaders report that the PKCS#12 MAC was verified
    assert bundles.load_bundle_bytes(path.read_bytes(), NEW, prefer_raw=True).integrity_checked
    assert bundles.load_bundle(path, NEW).integrity_checked
    assert result.as_dict()["encryption"] == encryption and result.as_dict()["files"]["p12"] == str(path)


def test_p12_without_chain_and_overwrite(ctx, user, tmp_path):
    target = tmp_path / "leaf.p12"
    export_certificate(ctx, user.alias, target, password=NEW, include_chain=False)
    assert read_pkcs12(target, NEW).chain == []
    with pytest.raises(PyCertError, match="already exists"):
        export_certificate(ctx, user.alias, target, password=NEW)
    export_certificate(ctx, user.alias, target, password=NEW, overwrite=True)
    link = tmp_path / "link.p12"
    os.symlink(tmp_path / "elsewhere.p12", link)
    with pytest.raises(PyCertError, match="symbolic link"):
        export_certificate(ctx, user.alias, link, password=NEW, overwrite=True)


@pytest.mark.parametrize("encryption, header", [("pkcs8", "ENCRYPTED PRIVATE KEY"), ("traditional", "Proc-Type: 4,ENCRYPTED")])
def test_pem_bundle_and_key_encryptions(ctx, user, tmp_path, encryption, header):
    bundle = export_certificate(ctx, user.alias, tmp_path / "b.pem", format="pem-bundle", password=NEW, encryption=encryption)
    text = bundle.files["bundle"].read_bytes()
    assert header.encode() in text and len(_certificates(text)) >= 2
    assert serialization.load_pem_private_key(text, NEW.encode())
    key = export_certificate(ctx, user.alias, tmp_path / "k.key", format="key", password=NEW, encryption=encryption)
    assert header.encode() in key.files["key"].read_bytes()
    assert (key.files["key"].stat().st_mode & 0o777) == 0o400


def test_unprotected_single_key_only_in_pkcs8(ctx, user, tmp_path):
    messages = []
    result = export_certificate(ctx, user.alias, tmp_path / "plain.key", format="key", no_passphrase=True, progress=messages.append)
    assert result.unprotected_key and b"BEGIN PRIVATE KEY" in result.files["key"].read_bytes()
    assert any("NO passphrase" in m for m in messages)
    with pytest.raises(PyCertError, match="PKCS#8"):
        export_certificate(ctx, user.alias, tmp_path / "t.key", format="key", no_passphrase=True, encryption="traditional")
    with pytest.raises(PyCertError, match="cannot use encryption"):
        export_certificate(ctx, user.alias, tmp_path / "x.p12", password=NEW, encryption="pkcs8")
    with pytest.raises(CryptoError, match="without passphrase"):
        exporter.key_bytes(ctx.store.load_key(user, ctx.key_passphrase()), "pkcs8", None)


def test_pem_files(ctx, user, tmp_path):
    result = export_certificate(ctx, user.alias, tmp_path / "dir", format="pem-files", password=NEW)
    assert sorted(result.files) == ["cert", "key"]
    assert (result.files["cert"].stat().st_mode & 0o777) == 0o644
    assert certs.load_private_key(result.files["key"].read_bytes(), NEW)


@pytest.mark.parametrize("name", ["cert", "fullchain", "der", "p7b"])
def test_public_formats_need_no_passphrase(ctx, user, tmp_path, name):
    result = export_certificate(ctx, user.alias, tmp_path, format=name, password="ignored")
    (path,) = result.files.values()
    data = path.read_bytes()
    if name == "cert":
        assert len(_certificates(data)) == 1
    elif name == "fullchain":
        assert len(_certificates(data)) >= 2
    elif name == "der":
        assert certs.fingerprint(x509.load_der_x509_certificate(data)) == user.cert.sha256
    else:
        assert len(pkcs7.load_der_pkcs7_certificates(data)) >= 2
    assert result.encryption == "" and not result.unprotected_key


def test_material_checks(ctx, user, issued, tmp_path):
    certificate = ctx.store.load_certificate(user)
    other_key = ctx.store.load_key(issued("someone else"), ctx.key_passphrase())
    common = {"alias": "x", "certificate": certificate, "chain": [], "ctx": ctx, "password": NEW}
    with pytest.raises(PyCertError, match="not available"):
        exporter.export_material(load_key=None, fmt="p12", destination=tmp_path / "a.p12", **common)
    with pytest.raises(CryptoError, match="does not match"):
        exporter.export_material(load_key=lambda: other_key, fmt="p12", destination=tmp_path / "b.p12", **common)
    messages = []
    exporter.export_material(
        load_key=lambda: ctx.store.load_key(user, ctx.key_passphrase()),
        fmt=exporter.get_format("p12"),
        destination=tmp_path / "c.p12",
        progress=messages.append,
        **{**common, "password": "pässwörd-long"},
    )
    assert any("non-ASCII" in m for m in messages)


def _cli(args, capsys, stdin="", tty=False, typed=None, monkeypatch=None):
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    if tty:
        sys.stdin.isatty = lambda: True
    try:
        if typed is not None:
            answers = iter(typed)
            monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))
        code = cli.main(args)
    finally:
        sys.stdin = old
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_export_formats(config, ctx, user, tmp_path, capsys, monkeypatch):
    base = ["--config", str(config.path)]
    code, out, err = _cli([*base, "--json", "export", user.alias, "--format", "cert", "--out", str(tmp_path)], capsys)
    assert code == 0, err
    assert json.loads(out)["files"]["cert"].endswith(".crt")
    code, out, err = _cli([*base, "export", user.alias, "--format", "cert", "--out", str(tmp_path)], capsys)
    assert code == 1 and "already exists" in err
    code, out, err = _cli([*base, "export", user.alias, "--format", "cert", "--out", str(tmp_path), "--force"], capsys)
    assert code == 0 and out.startswith("cert: ")
    code, _, err = _cli([*base, "export", user.alias, "--format", "der", "--no-key-passphrase", "--out", str(tmp_path)], capsys)
    assert code == 1 and "holds no private key" in err
    code, _, err = _cli([*base, "export", user.alias, "--stored", "--format", "p12"], capsys)
    assert code == 1 and "takes no format options" in err
    code, out, err = _cli(
        [*base, "--json", "export", user.alias, "--encryption", "3des", "--no-chain", "--out", str(tmp_path / "j.p12"), "--password-stdin"],
        capsys,
        NEW + "\n",
    )
    assert code == 0, err
    assert json.loads(out)["encryption"] == "3des" and read_pkcs12(tmp_path / "j.p12", NEW).chain == []
    code, out, err = _cli(
        [*base, "export", user.alias, "--format", "pem-bundle", "--out", str(tmp_path / "b.pem")],
        capsys,
        tty=True,
        typed=[NEW, NEW],
        monkeypatch=monkeypatch,
    )
    assert code == 0, err
    code, out, err = _cli([*base, "--json", "export", user.alias, "--stored"], capsys)
    assert code == 0 and json.loads(out)["p12"].endswith(".p12")
    code, out, err = _cli([*base, "export", user.alias, "--stored"], capsys)
    assert code == 0 and out.strip().endswith(".p12")
