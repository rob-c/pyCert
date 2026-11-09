"""Coverage-oriented tests for doctor/selftest branches."""

import builtins
from pathlib import Path
from types import SimpleNamespace

from pycert import diagnostics
from pycert.diagnostics import Check


def _names(results):
    return {item.name: item.status for item in results}


def test_check_and_doctor_offline_warnings(ctx, config, monkeypatch, capsys):
    check = Check("x", diagnostics.FAIL, "detail")
    assert check.failed and check.as_dict()["status"] == diagnostics.FAIL
    config.warnings = ["warning"]
    config.ca.tls_verify = False
    config.ca.allow_plaintext = True
    config.csr.pin_hash = "sha256"
    config.chain[0].sha256 = None
    monkeypatch.setattr(diagnostics.stat, "S_IMODE", lambda _mode: 0o755)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy")
    results = diagnostics.run_doctor(ctx, offline=True)
    names = _names(results)
    assert names["plaintext HTTP"] == diagnostics.FAIL
    assert names["TLS verification"] == diagnostics.FAIL
    assert names["PIN hash"] == diagnostics.WARN
    assert names["chain pins"] == diagnostics.WARN
    assert names["data directory"] == diagnostics.FAIL
    assert names["network"] == diagnostics.WARN


def test_doctor_chain_and_filesystem_failures(ctx, config, monkeypatch):
    def broken_bundle():
        raise RuntimeError("broken bundle")

    monkeypatch.setattr(type(config), "bundle", property(lambda self: broken_bundle()))
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["CA chain"] == diagnostics.FAIL
    # Missing config file and non-existent data directory.
    config.path = Path("/definitely/missing/pycert.toml")
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["configuration file"] == diagnostics.FAIL


def test_doctor_cryptography_import_failure(ctx, monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "cryptography":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["cryptography"] == diagnostics.FAIL


def test_doctor_secret_and_audit_failures(ctx, config, monkeypatch):
    monkeypatch.setattr(ctx.secrets, "exists", lambda _account: (_ for _ in ()).throw(RuntimeError("secret")))
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["saved secret"] == diagnostics.FAIL
    monkeypatch.setattr(ctx.store, "audit", lambda: ["bad file"])
    monkeypatch.setattr(ctx.store, "corrupt_files", lambda: [("state", "bad")])
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["file permissions"] == diagnostics.FAIL
    assert _names(results)["stored state"] == diagnostics.FAIL


def test_doctor_network_failures(ctx, config, monkeypatch):
    client = SimpleNamespace(last_error="offline", ping=lambda: False)
    monkeypatch.setattr(ctx, "client", lambda: client)
    results = diagnostics.run_doctor(ctx, offline=False)
    assert _names(results)["CA connectivity"] == diagnostics.FAIL
    client = SimpleNamespace(
        last_error="",
        ping=lambda: True,
        info=lambda: (_ for _ in ()).throw(RuntimeError("info")),
        last_tls=None,
        transport=SimpleNamespace(clock_offset=0, _default_resolve=lambda *a: []),
    )
    monkeypatch.setattr(ctx, "client", lambda: client)
    results = diagnostics.run_doctor(ctx, offline=False)
    assert _names(results)["CA info"] == diagnostics.FAIL
    client = SimpleNamespace(
        last_error="",
        ping=lambda: True,
        info=lambda: SimpleNamespace(ras=[]),
        last_tls=SimpleNamespace(not_after=SimpleNamespace(date=lambda: "x"), subject="s"),
        transport=SimpleNamespace(
            clock_offset=500,
            last_peer_certificate=b"bad",
            _default_resolve=lambda *a: (_ for _ in ()).throw(RuntimeError("dns")),
        ),
    )
    monkeypatch.setattr(ctx, "client", lambda: client)
    results = diagnostics.run_doctor(ctx, offline=False)
    assert _names(results)["TLS chain"] == diagnostics.FAIL
    assert _names(results)["clock skew"] == diagnostics.WARN
    assert _names(results)["DNS"] == diagnostics.FAIL


def test_selftest_failure_paths(monkeypatch):
    monkeypatch.setattr("pycert.toml.loads", lambda _doc: (_ for _ in ()).throw(RuntimeError("toml")))
    monkeypatch.setattr("pycert.csr.build_csr", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("csr")))
    monkeypatch.setattr("pycert.p12.write_pkcs12", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("p12")))
    monkeypatch.setattr("pycert.bundled.certificates", lambda: (_ for _ in ()).throw(RuntimeError("bundle")))
    results = diagnostics.run_selftest()
    names = _names(results)
    assert names["TOML parser"] == diagnostics.FAIL
    assert names["key generation and CSR"] == diagnostics.FAIL
    assert names["PKCS#12"] == diagnostics.FAIL
    assert names["bundled CA chain"] == diagnostics.FAIL


def test_doctor_py36_no_anchors_data_dir_and_secret_symlink(ctx, config, monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostics.sys, "version_info", (3, 6, 0, "final", 0))
    config._bundle = SimpleNamespace(certificates=[], anchors=[], sources=[])
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["Python 3.6 support"] == diagnostics.WARN
    assert _names(results)["trust anchors"] == diagnostics.FAIL
    # Data directory stat failure.
    monkeypatch.setattr(type(config), "data_dir", property(lambda self: tmp_path / "missing"))
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["data directory"] == diagnostics.FAIL
    # Secret file symlink.
    link = tmp_path / "secrets.json"
    link.symlink_to(tmp_path / "target")
    ctx.config.secrets.file = str(link)
    results = diagnostics.run_doctor(ctx, offline=True)
    assert _names(results)["secret file"] == diagnostics.FAIL


def test_selftest_bundled_chain_failure(monkeypatch):
    from pycert import chain

    monkeypatch.setattr(chain, "build_chain", lambda *a, **k: SimpleNamespace(trusted=False, problems=["bad"], chain=[]))
    results = diagnostics.run_selftest()
    assert _names(results)["bundled CA chain"] == diagnostics.FAIL


def test_doctor_tls_chain_failure(ctx, monkeypatch):
    client = SimpleNamespace(
        last_error="",
        ping=lambda: True,
        info=lambda: SimpleNamespace(ras=[]),
        last_tls=SimpleNamespace(not_after=SimpleNamespace(date=lambda: "x"), subject="s"),
        transport=SimpleNamespace(clock_offset=0, last_peer_certificate=b"bad", _default_resolve=lambda *a: []),
    )
    monkeypatch.setattr(ctx, "client", lambda: client)
    results = diagnostics.run_doctor(ctx, offline=False)
    assert _names(results)["TLS chain"] == diagnostics.FAIL


def test_doctor_saved_secret_and_untrusted_tls(ctx, monkeypatch):
    monkeypatch.setattr(ctx.secrets, "exists", lambda _account: True)
    monkeypatch.setattr(
        ctx, "build_chain", lambda cert: SimpleNamespace(trusted=False, problems=["bad"], chain=[])
    )
    client = SimpleNamespace(
        last_error="", ping=lambda: True, info=lambda: SimpleNamespace(ras=[]),
        last_tls=SimpleNamespace(not_after=SimpleNamespace(date=lambda: "x"), subject="s"),
        transport=SimpleNamespace(clock_offset=0, last_peer_certificate=b"der", _default_resolve=lambda *a: []),
    )
    monkeypatch.setattr(ctx, "client", lambda: client)
    # A real DER certificate is needed for the TLS-chain branch.
    from cryptography import x509

    from pycert import certs
    cert = x509.load_pem_x509_certificate(Path("src/pycert/data/ca/escience-root.pem").read_bytes())
    client.transport.last_peer_certificate = certs.cert_der(cert)
    results = diagnostics.run_doctor(ctx, offline=False)
    assert _names(results)["TLS chain"] == diagnostics.FAIL
