"""Tests for pycert doctor and pycert selftest."""

import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert import certs
from pycert.cli import main
from pycert.config import ChainEntry, write_config
from pycert.diagnostics import FAIL, OK, WARN, run_doctor, run_selftest


def test_selftest_all_ok():
    results = run_selftest()
    assert results
    assert all(result.status == OK for result in results), [(r.name, r.detail) for r in results]


def test_doctor_offline(ctx):
    results = run_doctor(ctx, offline=True)
    assert results
    assert not any(result.status == FAIL for result in results)
    assert any("offline" in result.detail for result in results)


def test_doctor_online(ctx):
    results = run_doctor(ctx)
    statuses = {result.name: result.status for result in results}
    assert statuses["CA connectivity"] == OK
    assert statuses["CA info"] == OK
    assert statuses["TLS peer"] == OK
    assert statuses["TLS chain"] == OK
    assert statuses["DNS"] == OK
    assert not any(result.status == FAIL for result in results)


def test_doctor_detects_disabled_tls(config, ctx):
    config.ca.tls_verify = False
    results = run_doctor(ctx, offline=True)
    assert any(result.name == "TLS verification" and result.status == FAIL for result in results)


def test_doctor_detects_loose_permissions(ctx):
    state = ctx.store.new_state(alias="loose", type="user", cn="loose", email="x@y.z")
    ctx.store.file(state, "state.json").chmod(0o644)
    results = run_doctor(ctx, offline=True)
    assert any(result.name == "file permissions" and result.status == FAIL for result in results)


def test_doctor_warns_missing_secret(ctx):
    results = run_doctor(ctx, offline=True)
    assert any(result.name == "saved secret" and result.status == WARN for result in results)


def test_doctor_detects_expired_ca(tmp_path, config, ctx):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=400))
        .not_valid_after(now - dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = config.directory / "expired.pem"
    path.write_text(certs.cert_pem(cert))
    config.chain.append(ChainEntry(file="expired.pem", sha256=certs.fingerprint(cert)))
    config.invalidate_chain_cache()
    write_config(config.path, config)
    results = run_doctor(ctx, offline=True)
    assert any(result.name == "CA certificate validity" and result.status == FAIL for result in results)


def test_doctor_detects_bad_pin(config, ctx):
    config.ca.tls_pin_sha256 = ["00" * 32]
    results = run_doctor(ctx)
    assert any(result.name == "CA connectivity" and result.status == FAIL for result in results)


def test_cli_doctor_json(config, capsys):
    code = main(["--config", str(config.path), "doctor", "--offline", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert any(item["check"] == "CA chain" for item in payload)
    assert code in (0, 1)


def test_cli_doctor_human(config, capsys):
    code = main(["--config", str(config.path), "doctor", "--offline"])
    captured = capsys.readouterr()
    assert "[OK" in captured.out
    assert code in (0, 1)


def test_cli_selftest_json(capsys):
    code = main(["selftest", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert all(item["status"] == "ok" for item in payload)
    assert code == 0


def test_cli_selftest_human(capsys):
    code = main(["selftest"])
    captured = capsys.readouterr()
    assert "TOML parser" in captured.out
    assert code == 0
