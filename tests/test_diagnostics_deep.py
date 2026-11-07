"""Second-round doctor checks."""

import datetime as dt
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert.cli import main
from pycert.diagnostics import FAIL, WARN, run_doctor


def result_map(results):
    return {result.name: result.status for result in results}


def test_doctor_detects_world_writable_config(config, ctx):
    config.path.chmod(0o666)
    statuses = result_map(run_doctor(ctx, offline=True))
    assert statuses["configuration file"] == FAIL


def test_doctor_warns_group_writable_config(config, ctx):
    config.path.chmod(0o664)
    statuses = result_map(run_doctor(ctx, offline=True))
    assert statuses["configuration file"] == WARN


def test_doctor_warns_symlinked_config(config, ctx, tmp_path):
    link = tmp_path / "linked.toml"
    link.symlink_to(config.path)
    config.path = link
    ctx.config.path = link
    statuses = result_map(run_doctor(ctx, offline=True))
    assert statuses["configuration file"] == WARN


def test_doctor_detects_corrupt_state(config, ctx):
    state = ctx.store.new_state(alias="bad", type="user", cn="bad", email="x@y.z")
    ctx.store.file(state, "state.json").write_text("{not json")
    statuses = result_map(run_doctor(ctx, offline=True))
    assert statuses["stored state"] == FAIL


def test_doctor_warns_weak_certificate(config, ctx):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    state = ctx.store.new_state(alias="weak", type="user", cn="weak", email="x@y.z")
    ctx.store.save_certificate(state, certificate, [])
    statuses = result_map(run_doctor(ctx, offline=True))
    assert statuses["key strength"] == WARN


def test_doctor_detects_symlinked_secret_file(config, ctx, tmp_path):
    ctx.secrets.set("value", config.secrets.account)
    target = tmp_path / "real-secret.json"
    os.replace(ctx.secrets.path, target)
    ctx.secrets.path.symlink_to(target)
    statuses = result_map(run_doctor(ctx, offline=True))
    assert statuses["secret file"] == FAIL


def test_doctor_json_cli(config, capsys):
    main(["--config", str(config.path), "doctor", "--offline", "--json"])
    captured = capsys.readouterr()
    import json

    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert any(item["check"] == "configuration file" for item in payload)
