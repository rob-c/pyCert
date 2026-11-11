"""CLI: CA profiles, bulk host requests, deployment, monitoring, reports and editing."""

import base64
import csv
import getpass
import grp
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

from pycert import cli, diagnostics
from pycert.config import load_config, new_acme_profile, new_ukca_profile, validate_config, write_config
from pycert.errors import PyCertError
from pycert.util import iso, parse_iso
from sandbox_ca.acme import ACMEServer

EAB_KEY = base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode()


def _save(config):
    validate_config(config)
    write_config(config.path, config)


@pytest.fixture
def user(e2e):
    return e2e.setup_issued("cli person")


def _host(e2e, name, auth, *extra):
    return e2e.run_json("request", name, "--type", "host", "--auth", auth, "--pin", e2e.PIN, "--key-algorithm", "ec", *extra)


# ---------------------------------------------------------------------------
# pycert ca
# ---------------------------------------------------------------------------


def test_ca_list_show_add_default_remove(e2e, config, tmp_path, monkeypatch):
    listing = e2e.run_json("ca", "list")
    assert listing.code == 0 and listing.json[0]["primary"] and listing.json[0]["default"]
    assert "(default)" in e2e.run("ca", "list").out
    assert e2e.run_json("ca", "show").json["name"] == config.ca.name
    assert "kind" in e2e.run("ca", "show").out

    assert "give a name" in e2e.run("ca", "add-acme").err
    assert "--directory" in e2e.run("ca", "add-acme", "le").err
    added = e2e.run("ca", "add-acme", "le", "--directory", "https://acme.example.org/directory", "--eab-kid", "kid-9")
    assert added.code == 0, added.err
    assert "terms_agreed=true" in added.out and "pycert ca eab le --kid kid-9" in added.out
    profile = load_config(config.path).profile_for("le")
    assert profile.kind == "acme" and profile.acme.contact == [config.identity.email]
    assert profile.acme.eab_kid == "kid-9" and not profile.acme.terms_agreed

    shown = e2e.run_json(
        "ca", "add-acme", "le2", "--directory", "https://acme2.example.org/directory", "--agree-tos",
        "--challenge", "dns-01", "--dns-hook", "/usr/local/bin/hook", "--contact", "ops@example.org", "--make-default",
    )
    assert shown.code == 0 and shown.json["acme"]["challenge"] == "dns-01"
    assert load_config(config.path).default_ca == "le2"

    assert "--url" in e2e.run("ca", "add-ukca", "second").err
    assert "chain file not found" in e2e.run("ca", "add-ukca", "second", "--url", "https://x.example.org", "--chain", str(tmp_path / "nope.pem")).err
    chain_file = config.path.parent / config.chain[0].file
    ukca = e2e.run("ca", "add-ukca", "second", "--url", "https://second.example.org", "--chain", str(chain_file), "--display-name", "Second")
    assert ukca.code == 0, ukca.err
    second = load_config(config.path).profile_for("second")
    assert second.display_name == "Second" and second.chain[0].sha256 and second.bundle.anchors

    assert "give the name" in e2e.run("ca", "default").err
    assert e2e.run("ca", "default", "second").code == 0
    assert load_config(config.path).default_ca == "second"

    assert "give the name" in e2e.run("ca", "remove").err
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert "without --yes" in e2e.run("ca", "remove", "le").err
    assert e2e.run("ca", "remove", "le", "--yes").code == 0
    assert "le" not in load_config(config.path).cas


def test_ca_remove_refuses_while_certificates_use_it(e2e, config, ctx):
    config.add_ca(new_ukca_profile("second", "https://second.example.org"))
    _save(config)
    state = ctx.store.new_state(alias="bound", type="user", cn="bound person", email="x@example.org")
    state.ca = "second"
    ctx.store.save(state)
    refused = e2e.run("ca", "remove", "second", "--yes")
    assert refused.code == 1 and "1 stored certificate(s) belong to 'second' (bound)" in refused.err
    assert e2e.run("ca", "remove", "second", "--yes", "--force").code == 0


def test_ca_eab_stores_the_key(e2e, config, ctx, monkeypatch):
    config.add_ca(new_acme_profile("le", "https://acme.example.org/directory"))
    _save(config)
    assert "give the name" in e2e.run("ca", "eab").err
    assert "not an ACME CA" in e2e.run("ca", "eab", config.ca.name).err
    assert "--kid is required" in e2e.run("ca", "eab", "le").err
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    assert "no EAB HMAC key" in e2e.run("ca", "eab", "le", "--kid", "kid-1").err
    monkeypatch.setattr(sys, "stdin", io.StringIO("c2hvcnQ\n"))
    assert "too short" in e2e.run("ca", "eab", "le", "--kid", "kid-1").err
    monkeypatch.setattr(sys, "stdin", io.StringIO(EAB_KEY + "\n"))
    stored = e2e.run("ca", "eab", "le", "--kid", "kid-1")
    assert stored.code == 0, stored.err
    assert ctx.secrets.get("acme-eab:le") == EAB_KEY
    assert load_config(config.path).profile_for("le").acme.eab_kid == "kid-1"
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(getpass, "getpass", lambda _prompt: EAB_KEY)
    assert e2e.run("ca", "eab", "le").code == 0  # kid already configured; key from the prompt


# ---------------------------------------------------------------------------
# ping / ras / info across CAs
# ---------------------------------------------------------------------------


@pytest.fixture
def acme_profile(ca, config):
    server = ACMEServer(ca, port=0, challenge_mode="auto").start()
    profile = new_acme_profile("sandbox-acme", server.directory_url(), contact=["ops@example.org"], tls_trust="chain")
    profile.chain = list(config.chain)
    profile.ca.retries = 0
    config.add_ca(profile)
    _save(config)
    yield profile
    server.stop()


def test_ping_all_and_per_ca(e2e, config, acme_profile):
    config.add_ca(new_acme_profile("dead", "https://127.0.0.1:1/directory"))
    config.profile_for("dead").ca.retries = 0
    config.profile_for("dead").ca.connect_timeout = 2.0
    _save(config)
    everything = e2e.run_json("ping", "--all")
    assert everything.code == 1
    by_name = {row["ca"]: row for row in everything.json}
    assert by_name[config.ca.name]["ok"] and by_name["sandbox-acme"]["ok"] and not by_name["dead"]["ok"]
    text = e2e.run("ping", "--all")
    assert "pong from" in text.out and "no response from https://127.0.0.1:1/directory" in text.err
    single = e2e.run_json("ping", "--ca", "sandbox-acme")
    assert single.code == 0 and single.json["kind"] == "acme" and single.json["tls"]["subject"]


def test_ras_and_info_by_ca(e2e, config, acme_profile):
    refused = e2e.run("ras", "--ca", "sandbox-acme")
    assert refused.code == 1 and "needs a CertWizard-protocol CA" in refused.err
    info = e2e.run_json("info", "--ca", "sandbox-acme")
    assert info.code == 0 and info.json["ca"] == "sandbox-acme" and info.json["account_status"] == "not registered"
    text = e2e.run("info", "--ca", "sandbox-acme")
    assert "(acme) at https://" in text.out and "terms_of_service" in text.out
    second = new_ukca_profile("second", e2e.ca.url, chain=list(config.chain))
    config.add_ca(second)
    _save(config)
    ras = e2e.run_json("ras", "--ca", "second")
    assert ras.code == 0 and ras.json["ras"]
    assert e2e.run_json("info", "--ca", "second").json["ras"]


# ---------------------------------------------------------------------------
# Bulk host requests
# ---------------------------------------------------------------------------


def test_bulk_host_requests_and_deploy_presets(e2e, user, tmp_path):
    names = tmp_path / "hosts.txt"
    names.write_text("# grid front-ends\nweb2.example.org\n\nweb3.example.org  # spare\n")
    result = e2e.run_json(
        "request", "web1.example.org", "--from-file", str(names), "--type", "host", "--auth", user,
        "--pin", e2e.PIN, "--key-algorithm", "ec", "--description", "front end",
        "--deploy-preset", "grid-host", "--deploy-dir", str(tmp_path / "grid"), "--deploy-hook", "true",
    )
    assert result.code == 0, result.err
    assert [row["common_name"] for row in result.json] == ["web1.example.org", "web2.example.org", "web3.example.org"]
    state = e2e.state("web2.example.org")
    assert state.description == "front end" and state.ca == e2e.config.ca.name
    target = state.deploy[0]
    assert target["cert"] == f"{tmp_path}/grid/web2.example.org/hostcert.pem" and target["hook"] == "true"


@pytest.mark.parametrize(
    "args, message",
    [
        ([], "give at least one common name"),
        (["a.example.org", "a.example.org", "--type", "host"], "duplicate names: a.example.org"),
        (["a.example.org", "b.example.org", "--type", "host", "--alias", "x"], "--alias can only be used"),
        (["Jane Doe", "John Doe"], "only supported for host certificates"),
        (["--from-file", "/nonexistent/hosts.txt", "--type", "host"], "cannot read /nonexistent/hosts.txt"),
    ],
)
def test_bulk_request_argument_errors(e2e, args, message):
    result = e2e.run("request", *args, "--pin", e2e.PIN)
    assert result.code == 1 and message in result.err


def test_bulk_request_partial_failure(e2e, user):
    e2e.ca.fail_next("/CSRs", status=500)
    result = e2e.run_json("request", "bad.example.org", "good.example.org", "--type", "host", "--auth", user, "--pin", e2e.PIN, "--key-algorithm", "ec")
    assert result.code == 1
    assert result.json[0]["common_name"] == "bad.example.org" and "error" in result.json[0]
    assert result.json[1]["status"] == "SUBMITTED"
    e2e.ca.fail_next("/CSRs", status=500)
    text = e2e.run("request", "bad2.example.org", "good2.example.org", "--type", "host", "--auth", user, "--pin", e2e.PIN, "--key-algorithm", "ec")
    assert text.code == 1 and "Request 'bad2.example.org' FAILED" in text.out and "PIN for the RA" in text.out
    existing = e2e.run("request", "good.example.org", "new.example.org", "--type", "host", "--auth", user, "--pin", e2e.PIN)
    assert existing.code == 1 and "already exists" in existing.err


def test_single_request_with_wait_deploys(e2e, user, tmp_path):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    result = e2e.run(
        "request", "deployed.example.org", "--type", "host", "--auth", user, "--pin", e2e.PIN,
        "--deploy-preset", "nginx", "--deploy-dir", str(tmp_path / "nginx"), "--wait", "--interval", "0.2", "--timeout", "30",
    )
    assert result.code == 0, result.err
    assert "valid until" in result.out
    assert (tmp_path / "nginx" / "deployed.example.org.fullchain.pem").is_file()
    assert (os.stat(tmp_path / "nginx" / "deployed.example.org.key").st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# list / show / edit
# ---------------------------------------------------------------------------


def test_list_filters_show_and_edit(e2e, config, ctx, user, tmp_path):
    assert _host(e2e, "listed.example.org", user).code == 0
    config.add_ca(new_ukca_profile("second", "https://second.example.org"))
    _save(config)
    hosts = e2e.run_json("list", "--type", "host").json
    assert [row["alias"] for row in hosts] == ["listed.example.org"]
    assert e2e.run_json("list", "--ca", "second").json == []
    assert e2e.run("edit", user, "--description", "  grid UI user  ").code == 0
    table = e2e.run("list", "-v", "--no-audit")
    assert "CA" in table.out.splitlines()[0] and "grid UI user" in table.out

    assert "nothing to change" in e2e.run("edit", user).err
    edited = e2e.run_json("edit", user, "--no-auto-renew")
    assert edited.json == {"alias": user, "description": "grid UI user", "auto_renew": False}
    assert e2e.run_json("edit", user, "--auto-renew").json["auto_renew"] is True

    state = ctx.store.get(user)
    state.deploy = [{"name": "globus", "cert": "/tmp/u.pem", "hook": "true", "last_deployed": iso(), "last_error": "boom"}]
    state.ca = "gone"
    ctx.store.save(state)
    shown = e2e.run("show", user)
    for fragment in ("profile not configured", "Description     grid UI user", "Auto-renew      yes", "Deploy 'globus'", "hook          true", "last deployed", "last error    boom"):
        assert fragment in shown.out


def test_renew_due_respects_auto_renew_and_ca(e2e, ctx, user):
    def due(*extra):
        result = e2e.run_json("renew", "--due", "400", "--dry-run", *extra)
        assert result.code == 0, result.err
        return [row["alias"] for row in result.json["renewed"]]

    assert due() == [user]
    assert due("--ca", "elsewhere") == []
    assert due("--ca", ctx.config.ca.name) == [user]
    e2e.run("edit", user, "--no-auto-renew")
    assert due() == []
    assert due("--include-manual") == [user]


# ---------------------------------------------------------------------------
# report and check
# ---------------------------------------------------------------------------


def test_report_formats(e2e, ctx, user):
    empty_ca = e2e.run("report", "--ca", "elsewhere")
    assert empty_ca.out.strip() == "No certificates."
    table = e2e.run("report")
    assert table.out.startswith("ALIAS") and user in table.out and "OK" in table.out
    rows = list(csv.DictReader(io.StringIO(e2e.run("report", "--format", "csv").out)))
    assert rows[0]["alias"] == user and rows[0]["health"] == "OK"
    assert e2e.run("report", "--format", "json").json[0]["alias"] == user
    assert e2e.run_json("report", "--type", "host").json == []
    assert e2e.run("report", "--format", "csv", "--ca", "elsewhere").out.strip() == "alias"


def test_check_exit_codes(e2e, ctx, user, tmp_path):
    ok = e2e.run("check")
    assert ok.code == 0 and ok.out.startswith("PYCERT OK - 1 certificate(s) valid")
    warning = e2e.run("check", "--warn", "400")
    assert warning.code == 1 and warning.out.startswith("PYCERT WARNING")
    critical = e2e.run("check", "--warn", "400", "--crit", "400", "-v")
    assert critical.code == 2 and f"[CRITICAL] {user}: expires in" in critical.out
    unknown = e2e.run("check", "no-such-cert")
    assert unknown.code == 3 and "no matching certificates" in unknown.out
    bad = e2e.run("check", "--warn", "5", "--crit", "10")
    assert bad.code == 3 and bad.out.startswith("PYCERT UNKNOWN - the critical threshold")
    as_json = e2e.run_json("check", "--type", "user")
    assert as_json.code == 0 and as_json.json["counts"]["valid"] == 1
    state = ctx.store.get(user)
    state.deploy = [{"name": "globus", "cert": str(tmp_path / "missing.pem")}]
    ctx.store.save(state)
    assert e2e.run("check").code == 1
    assert e2e.run("check", "--no-deploy-check").code == 0
    assert e2e.run("check", "--ca", ctx.config.ca.name).code == 1


def test_check_reports_unknown_when_the_configuration_is_broken(capsys, tmp_path):
    assert cli.main(["--config", str(tmp_path / "missing.toml"), "check"]) == 3
    assert capsys.readouterr().out.startswith("PYCERT UNKNOWN - configuration file not found")


# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------


def test_deploy_commands(e2e, ctx, user, tmp_path):
    presets = e2e.run("deploy", "presets")
    assert "grid-host" in presets.out and "haproxy" not in presets.out  # HAProxy cannot read encrypted keys
    assert "grid-host" in e2e.run_json("deploy", "presets").json
    assert "give the alias" in e2e.run("deploy", "list").err
    assert "has no deployment targets" in e2e.run("deploy", "list", user).out
    me, group = getpass.getuser(), grp.getgrgid(os.getgid()).gr_name
    added = e2e.run(
        "deploy", "add", user, "--preset", "globus-user", "--dir", str(tmp_path / "globus"),
        "--owner", me, "--group", group, "--now",
    )
    assert added.code == 0, added.err
    assert "Deployed." in added.out and (tmp_path / "globus" / "userkey.pem").is_file()
    custom = e2e.run(
        "deploy", "add", user, "--name", "files", "--cert", str(tmp_path / "c.pem"), "--key", str(tmp_path / "k.pem"),
        "--key-mode", "0400", "--cert-mode", "0640", "--hook", f"{sys.executable} -c pass",
    )
    assert custom.code == 0, custom.err
    listing = e2e.run("deploy", "list", user)
    assert "[globus-user]" in listing.out and "[files]" in listing.out and "encrypt_key" not in listing.out
    assert len(e2e.run_json("deploy", "list", user).json) == 2
    ran = e2e.run_json("deploy", "run", user, "--name", "files")
    assert ran.code == 0 and ran.json[0]["hook"].endswith("-c pass")
    assert "ENCRYPTED PRIVATE KEY" in (tmp_path / "k.pem").read_text()
    assert (os.stat(tmp_path / "c.pem").st_mode & 0o777) == 0o640
    quiet = e2e.run("deploy", "run", user, "--no-hook")
    assert quiet.code == 0 and "files: wrote 2 file(s)" in quiet.out and "ran" not in quiet.out
    assert "--name is required" in e2e.run("deploy", "remove", user).err
    assert e2e.run("deploy", "remove", user, "--name", "files").code == 0
    assert [t["name"] for t in ctx.store.get(user).deploy] == ["globus-user"]


# ---------------------------------------------------------------------------
# Interactive confirmation, diagnostics and small helpers
# ---------------------------------------------------------------------------


def test_terminal_confirm_and_context(config, monkeypatch, capsys):
    import argparse

    answers = iter(["", "no"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert cli._terminal_confirm("Publish TXT", "_acme-challenge.example.org TXT abc") is True
    assert cli._terminal_confirm("Publish TXT", "again") is False
    assert "_acme-challenge.example.org" in capsys.readouterr().err
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    ctx = cli._context(argparse.Namespace(config=str(config.path), json=False))
    assert ctx.confirm is cli._terminal_confirm
    assert cli._context(argparse.Namespace(config=str(config.path), json=True)).confirm is None


def test_doctor_checks_deployments_and_every_ca(config, ctx, issued, tmp_path, monkeypatch):
    state = ctx.store.get(issued("doctor person").alias)
    state.deploy = [{"name": "globus", "cert": str(tmp_path / "usercert.pem")}]
    ctx.store.save(state)
    config.add_ca(new_ukca_profile("second", ctx.config.ca.base_url, chain=list(config.chain)))
    dead = new_acme_profile("dead", "https://127.0.0.1:1/directory")
    dead.ca.retries = 0
    config.add_ca(dead)
    config.add_ca(new_acme_profile("broken", "https://broken.example.org/directory"))
    validate_config(config)
    original = ctx.provider

    def provider(name=""):
        if name == "broken":
            raise PyCertError("plugin exploded")
        return original(name)

    monkeypatch.setattr(ctx, "provider", provider)
    results = {item.name: item for item in diagnostics.run_doctor(ctx)}
    assert results["deployments"].status == diagnostics.WARN and "missing" in results["deployments"].detail
    assert results["CA 'second'"].status == diagnostics.OK
    assert results["CA 'dead'"].status == diagnostics.FAIL
    assert results["CA 'broken'"].status == diagnostics.FAIL and "plugin exploded" in results["CA 'broken'"].detail

    from pycert.deploy import deploy_state

    deploy_state(ctx, ctx.store.get(state.alias))
    offline = {item.name: item for item in diagnostics.run_doctor(ctx, offline=True)}
    assert offline["deployments"].status == diagnostics.OK and "up to date" in offline["deployments"].detail


def test_doctor_checks_other_cas_when_the_primary_is_down(config, ctx, monkeypatch):
    from pycert.ca import CAClient

    config.add_ca(new_acme_profile("dead", "https://127.0.0.1:1/directory"))
    config.profile_for("dead").ca.retries = 0
    monkeypatch.setattr(CAClient, "ping", lambda self: False)
    results = {item.name: item for item in diagnostics.run_doctor(ctx)}
    assert results["CA connectivity"].status == diagnostics.FAIL
    assert results["CA 'dead'"].status == diagnostics.FAIL


def test_parse_iso_rejects_non_strings():
    with pytest.raises(ValueError, match="must be a string"):
        parse_iso(None)
    assert parse_iso("2026-01-02T03:04:05Z") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert parse_iso("2026-01-02") == datetime(2026, 1, 2, tzinfo=timezone.utc)
    assert parse_iso(iso()) - datetime.now(timezone.utc) < timedelta(seconds=5)


def test_bulk_json_single_name_keeps_the_classic_shape(e2e, user):
    result = _host(e2e, "classic.example.org", user)
    assert result.code == 0 and isinstance(result.json, dict) and result.json["alias"] == "classic.example.org"
    assert json.loads(result.out)["ca"] == e2e.config.ca.name
