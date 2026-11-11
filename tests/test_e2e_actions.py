"""Every CLI action driven end-to-end against the mock CA listener."""

from pathlib import Path


def test_ping_against_listener(e2e):
    result = e2e.run_json("ping")
    assert result.code == 0
    assert result.json["ok"] is True
    assert result.json["tls"]["subject"]
    assert e2e.captured("/pingservice", "GET")


def test_ras_and_info_against_listener(e2e):
    ras = e2e.run_json("ras")
    assert ras.code == 0
    assert [item["ou"] for item in ras.json["ras"]] == ["CLRC", "CLRC"]
    info = e2e.run_json("info")
    assert info.code == 0
    assert "mock CA says hello" in info.json["motd"]
    assert e2e.captured("/CA", "GET")
    assert e2e.captured("/CA/motd/text", "GET")


def test_config_actions(e2e, capsys):
    assert e2e.run_json("config", "show").code == 0
    assert e2e.run("config", "check").code == 0
    assert e2e.run("config", "path").out.strip() == str(e2e.config.path)
    assert e2e.run("config", "set", "ca.timeout=5").code == 0


def test_request_wait_download_export_verify(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    result = e2e.request_user("e2e user", wait=True)
    assert result.code == 0, result.err
    alias = result.json["alias"]
    state = e2e.state(alias)
    assert state.status == "DOWNLOADED"
    assert Path(state.p12_path).is_file()
    assert e2e.captured("/CSR", "POST")
    # lookup by key, then download inline
    assert e2e.captured("/resources/resource/publickey/pk", "POST")

    listed = e2e.run_json("list")
    assert listed.code == 0
    assert listed.json[0]["alias"] == alias
    shown = e2e.run_json("show", alias)
    assert shown.code == 0
    assert shown.json["status"] == "DOWNLOADED"
    status = e2e.run_json("status", alias)
    assert status.code == 0
    verified = e2e.run_json("verify", alias)
    assert verified.code == 0
    assert verified.json["ok"] is True
    exported = e2e.run_json("export", alias, "--stored")  # pyCertWiz's own copy (saved secret)
    assert exported.code == 0
    assert Path(exported.json["p12"]).is_file()


def test_request_manual_approve_sign_download(e2e):
    e2e.ca.auto_approve = False
    result = e2e.request_user("manual user", wait=False)
    assert result.code == 0
    alias = result.json["alias"]
    state = e2e.state(alias)
    assert e2e.state(alias).status == "SUBMITTED"
    status = e2e.run_json("status", alias, "--refresh")
    assert status.code == 0
    e2e.approve(state)
    e2e.sign(state)
    downloaded = e2e.run_json("download", alias)
    assert downloaded.code == 0, downloaded.err
    assert e2e.state(alias).status == "DOWNLOADED"
    assert e2e.captured("/certificate/", "GET") or e2e.captured("/resources/resource/publickey/pk", "POST")


def test_wait_until_signed(e2e):
    e2e.ca.auto_approve = False
    result = e2e.request_user("wait user")
    alias = result.json["alias"]
    state = e2e.state(alias)
    e2e.approve(state)
    e2e.sign(state)
    waited = e2e.run_json("wait", alias, "--interval", "0.2", "--timeout", "30")
    assert waited.code == 0, waited.err
    assert waited.json["status"] in ("DOWNLOADED", "SIGNED")


def test_export_and_install(e2e, tmp_path):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("install user", wait=True).json["alias"]
    target = tmp_path / "e2e.p12"
    (tmp_path / "pw").write_text("a new passphrase\n")
    exported = e2e.run_json("export", alias, "--out", str(target), "--password-file", str(tmp_path / "pw"))
    assert exported.code == 0 and target.is_file()
    assert exported.json["files"]["p12"] == str(target)
    install = e2e.run_json("install", alias, "--dir", str(tmp_path / "globus"), "--password-file", str(tmp_path / "pw"))
    assert install.code == 0
    assert Path(install.json["cert"]).is_file()
    assert Path(install.json["key"]).is_file()


def test_delete_action(e2e, tmp_path):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("delete user", wait=True).json["alias"]
    directory = e2e.ctx.store.path(e2e.state(alias))
    assert e2e.run("delete", alias, "--yes").code == 0
    assert not directory.exists()


def test_import_action(e2e, tmp_path):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("import user", wait=True).json["alias"]
    state = e2e.state(alias)
    target = tmp_path / "import.p12"
    target.write_bytes(Path(state.p12_path).read_bytes())
    password_file = tmp_path / "pw"
    password_file.write_text(e2e.ctx.p12_passphrase() + "\n")
    imported = e2e.run_json(
        "import",
        str(target),
        "--alias",
        "imported e2e",
        "--password-file",
        str(password_file),
        "--allow-unverified-chain",
    )
    assert imported.code == 0, imported.err
    assert imported.json["alias"] == "imported e2e"


def test_doctor_online_and_selftest(e2e):
    doctor = e2e.run_json("doctor")
    assert doctor.code == 0, doctor.err
    checks = {item["check"]: item["status"] for item in doctor.json}
    assert checks["CA connectivity"] == "ok"
    assert checks["TLS chain"] == "ok"
    selftest = e2e.run_json("selftest")
    assert selftest.code == 0
    assert all(item["status"] == "ok" for item in selftest.json)


def test_watch_once(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    e2e.request_user("watch user", wait=False)
    watched = e2e.run_json("watch", "--once")
    assert watched.code == 0, watched.err
    assert watched.json["downloaded"] == 1


def test_renew_and_revoke(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("renew user", wait=True).json["alias"]
    renewed = e2e.run_json(
        "renew", alias, "--yes", "--wait", "--pin", e2e.PIN, "--interval", "0.2", "--timeout", "30"
    )
    assert renewed.code == 0, renewed.err
    revoked = e2e.run_json("revoke", alias, "--yes", "--reason", "superseded")
    assert revoked.code == 0, revoked.err
    assert e2e.state(alias).status == "REVOKED"


def test_renew_due_actions(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("due user", wait=True).json["alias"]
    e2e.set_expiry(alias, 5)
    preview = e2e.run_json("renew", "--due", "30", "--dry-run")
    assert preview.code == 0
    assert preview.json["renewed"][0]["alias"] == alias
    actual = e2e.run_json("renew", "--due", "30", "--yes", "--wait", "--interval", "0.2", "--timeout", "30")
    assert actual.code == 0, actual.err
    assert actual.json["renewed"][0]["error"] is None


def test_host_request_flow(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    user_alias = e2e.request_user("host auth user", wait=True).json["alias"]
    host = e2e.request_host(auth=user_alias, wait=True)
    assert host.code == 0, host.err
    state = e2e.state(host.json["alias"])
    assert state.status == "DOWNLOADED"
    assert "DNS:host.example.org" in e2e.state(host.json["alias"]).cert.sans


def test_secret_actions(e2e, capsys):
    set_result = e2e.run("secret", "set", "--generate", "--account", "e2e-secret")
    assert set_result.code == 0
    got = e2e.run("secret", "get", "--show", "--account", "e2e-secret")
    assert got.code == 0 and got.out.strip()
    listed = e2e.run("secret", "list")
    assert listed.code == 0 and "e2e-secret" in listed.out
    assert e2e.run("secret", "test", "--account", "e2e-secret").code == 0
    assert e2e.run("secret", "rm", "--account", "e2e-secret").code == 0
