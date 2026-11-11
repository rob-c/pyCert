"""Branch coverage for the CLI's text output (the paths with less to say)."""

import shutil
import socket

import pytest

from pycert import cli
from pycert.config import load_config, new_acme_profile, validate_config, write_config
from pycert.workflow import AppContext
from sandbox_ca.acme import ACMEServer


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# init / ping
# ---------------------------------------------------------------------------


def test_init_without_a_backend_keeps_the_automatic_choice(isolated_home, monkeypatch, capsys):
    # With no keychain tool on the PATH, "auto" resolves to the private file backend:
    # the real login keychain is never touched.
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    target = isolated_home / "conf"
    args = cli.build_parser().parse_args(["init", str(target), "--email", "e@example.org", "--ra", "CLRC DL"])
    assert cli.cmd_init(args) == 0
    assert "Configuration written" in capsys.readouterr().out
    config = load_config(target / "pycert.toml")
    assert config.secrets.backend == "auto"
    secrets = AppContext.from_config(config).secrets
    assert secrets.backend == "file" and secrets.path.is_relative_to(isolated_home)
    assert secrets.exists(config.secrets.account)


def test_ping_over_plain_http_prints_no_tls_details(e2e, config, ca):
    config.ca.base_url = ca.plain_url
    config.ca.allow_plaintext = True
    write_config(config.path, config)
    result = e2e.run("ping")
    assert result.code == 0, result.err
    assert f"pong from {ca.plain_url}" in result.out
    assert "TLS peer" not in result.out


# ---------------------------------------------------------------------------
# request / wait / download without a PIN or a PKCS#12
# ---------------------------------------------------------------------------


@pytest.fixture
def acme_server(ca, config):
    server = ACMEServer(ca, port=0, challenge_mode="auto").start()
    profile = new_acme_profile(
        "sandbox-acme", server.directory_url(), contact=["ops@example.org"], terms_agreed=True, tls_trust="chain"
    )
    profile.chain = list(config.chain)
    profile.ca.retries = 0
    profile.acme.poll_interval = 0.1
    profile.acme.validation_timeout = 20
    profile.acme.http_mode = "standalone"
    profile.acme.http_bind = "127.0.0.1"
    profile.acme.http_port = _free_port()
    config.add_ca(profile)
    validate_config(config)
    write_config(config.path, config)
    yield server
    server.stop()


def test_acme_request_output_has_no_pin_line(e2e, acme_server):
    result = e2e.run(
        "request", "pinless.example.org", "--type", "host", "--ca", "sandbox-acme", "--key-algorithm", "ec", "--no-export"
    )
    assert result.code == 0, result.err
    assert "Request 'pinless.example.org' is" in result.out
    assert "PIN for the RA" not in result.out + result.err
    assert "(not exported yet)" in result.out


def test_wait_and_download_without_export_print_no_pkcs12(e2e):
    created = e2e.request_user("no export person", extra=["--no-export"])
    assert created.code == 0, created.err
    alias = created.json["alias"]
    waited = e2e.run("wait", alias, "--no-export", "--interval", "0.1", "--timeout", "20")
    assert waited.code == 0, waited.err
    assert f"Certificate for '{alias}' is ready" in waited.out and "PKCS#12" not in waited.out
    downloaded = e2e.run("download", alias, "--no-export")
    assert downloaded.code == 0, downloaded.err
    assert "Certificate stored:" in downloaded.out and "PKCS#12" not in downloaded.out


# ---------------------------------------------------------------------------
# show (sparse records) / check --verbose
# ---------------------------------------------------------------------------


def test_show_prints_only_what_a_sparse_record_has(ctx, capsys):
    state = ctx.store.new_state(alias="sparse", type="user", cn="sparse person", email="x@example.org")
    state.deploy = [{"name": "web", "cert": "/srv/tls/cert.pem"}]
    cli._print_state(cli.Console(), ctx, state)
    out = capsys.readouterr().out
    for absent in ("Submitted", "Server ", "Certificate ", "PKCS#12", "hook", "last deployed", "last error", "History"):
        assert absent not in out
    assert "Deploy 'web'  /srv/tls/cert.pem" in out

    state.server.csr_id = "1001"
    state.history = [{"at": "2026-01-01T00:00:00+00:00", "status": "NEW"}]
    cli._print_state(cli.Console(), ctx, state)
    out = capsys.readouterr().out
    assert "Server          CSR 1001 / status -" in out and "certificate id" not in out
    assert "  2026-01-01T00:00:00+00:00  NEW\n" in out


def test_check_verbose_lists_only_problems(e2e, issued):
    issued("healthy person")
    result = e2e.run("check", "--verbose")
    assert result.code == 0, result.out
    assert result.out.startswith("PYCERT OK - 1 certificate(s) valid")
    assert "[OK]" not in result.out and "  [" not in result.out
