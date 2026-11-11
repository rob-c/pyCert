"""Branch coverage for configuration, the request store, the secret store and monitoring."""

import os

from pycert import monitor
from pycert import store as store_module
from pycert.config import (
    KeystoreLink,
    default_config_paths,
    load_config,
    new_ukca_profile,
    render_config,
    write_config,
)
from pycert.store import STATUS_FAILED, STATUS_SUBMITTED

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_profile_identity_override_is_created_once_then_edited(config):
    config.add_ca(new_ukca_profile("second", "https://second.example.org"))
    config.set("cas.second.identity.ou", "PPD")
    first_override = config.profile_for("second")._identity
    config.set("cas.second.identity.l", "RAL")
    second = config.profile_for("second")
    assert second._identity is first_override  # edited in place, not rebuilt from the global identity
    assert (second.own_identity.ou, second.own_identity.l) == ("PPD", "RAL")
    assert (config.identity.ou, config.identity.l) == ("CLRC", "DL")


def test_default_config_paths_are_not_repeated(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("PYCERT_CONFIG", str(tmp_path / ".config" / "pycert" / "pycert.toml"))
    assert default_config_paths() == [
        tmp_path / ".config" / "pycert" / "pycert.toml",
        tmp_path / ".pycert" / "config.toml",
    ]


def test_keystore_link_without_a_ca_round_trips(config):
    config.keystores.append(KeystoreLink(name="hosts", path="/srv/keystores/hosts.p12"))
    rendered = render_config(config)
    section = rendered.split("[[keystores]]", 1)[1].split("\n\n", 1)[0]
    assert 'name = "hosts"' in section and "\nca = " not in section
    write_config(config.path, config)
    link = load_config(config.path).keystores[0]
    assert (link.name, link.ca, link.auto_import, link.write_back) == ("hosts", "", True, True)


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------


def test_state_lock_without_fcntl(ctx, monkeypatch):
    """Windows has no fcntl: the per-process thread lock still serialises access."""
    state = ctx.store.new_state(alias="no fcntl", type="user", cn="no fcntl", email="x@example.org")
    monkeypatch.setattr(store_module, "fcntl", None)
    with ctx.store.lock(state), ctx.store.lock(state):
        state.notes.append("nested")
        ctx.store.save(state)
    assert ctx.store._lock_handles == {} and ctx.store._lock_counts[str(ctx.store.path(state))] == 0
    assert ctx.store.get("no fcntl").notes == ["nested"]


def test_state_lock_without_o_nofollow(ctx, monkeypatch):
    state = ctx.store.new_state(alias="no nofollow", type="user", cn="no nofollow", email="x@example.org")
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with ctx.store.lock(state):
        assert (ctx.store.path(state) / ".lock").is_file()
    assert ctx.store._lock_handles == {}


def test_archive_ignores_a_p12_that_is_already_gone(ctx, tmp_path):
    state = ctx.store.new_state(alias="archived", type="user", cn="archived", email="x@example.org")
    ctx.store.file(state, "cert.pem").write_text("placeholder")
    state.p12_path = str(tmp_path / "moved-away.p12")
    target = ctx.store.archive_current(state)
    assert sorted(path.name for path in target.iterdir()) == ["cert.pem"]


# ---------------------------------------------------------------------------
# secrets_store
# ---------------------------------------------------------------------------


def test_file_secret_lock_without_o_nofollow(ctx, monkeypatch):
    assert ctx.secrets.backend == "file"
    monkeypatch.delattr(os, "O_NOFOLLOW")
    ctx.secrets.set("a saved secret value", "cov-account")
    assert ctx.secrets.get("cov-account") == "a saved secret value"
    assert ctx.secrets.path.with_name(ctx.secrets.path.name + ".lock").is_file()


# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------


def test_failed_request_reports_the_last_recorded_detail(ctx):
    state = ctx.store.new_state(alias="failed person", type="user", cn="failed person", email="x@example.org")
    state.set_status(STATUS_SUBMITTED, "sent to the CA")
    state.set_status(STATUS_FAILED, "the RA rejected the request")
    state.add_history(STATUS_FAILED)  # a later entry without detail is skipped
    category, findings = monitor.evaluate(ctx, state)
    assert category == "failed"
    assert findings[0].message == "request failed (the RA rejected the request)"
    state.history = [{"status": STATUS_FAILED}]
    _category, findings = monitor.evaluate(ctx, state)
    assert findings[0].message == "request failed (see pycert show)"
