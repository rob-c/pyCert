"""Second-round GUI logic tests (mostly headless)."""

import datetime as dt

import pytest

tkinter = pytest.importorskip("tkinter")

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

from pycert.gui import PyCertApp  # noqa: E402
from pycert.store import RequestState  # noqa: E402


def state(status="DOWNLOADED", days=None, p12=True):
    item = RequestState(alias="x", slug="x", type="user", cn="x", status=status)
    if days is not None:
        item.cert.not_after = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()
    if p12:
        item.p12_path = "/tmp/x.p12"
    return item


@pytest.mark.parametrize(
    "status,days,expected",
    [
        ("REVOKED", 365, "revoked"),
        ("FAILED", 365, "failed"),
        ("SUBMITTED", None, "pending"),
        ("APPROVED", None, "pending"),
        ("SIGNED", None, "pending"),
        ("DOWNLOADED", -1, "expired"),
        ("DOWNLOADED", 1, "expiring"),
        ("DOWNLOADED", 30, "expiring"),
        ("DOWNLOADED", 60, "valid"),
        ("IMPORTED", 365, "valid"),
    ],
)
def test_tag_matrix(status, days, expected):
    assert PyCertApp._tag(state(status, days)) == expected


@pytest.mark.parametrize("column", ["alias", "type", "status", "expires", "days"])
def test_sort_keys_are_stable(column):
    app = object.__new__(PyCertApp)
    app._sort_column = column
    first = state("DOWNLOADED", 10)
    first.alias = "a"
    second = state("SUBMITTED", None)
    second.alias = "b"
    keys = sorted([app._sort_key(first), app._sort_key(second)], key=repr)
    assert len(keys) == 2


def _app(config):
    try:
        return PyCertApp(str(config.path), startup_ping=False)
    except tkinter.TclError as exc:  # pragma: no cover
        pytest.skip("no display: %s" % exc)


def test_render_pending_and_issued_states(config, ctx, issued):
    pending = ctx.store.new_state(alias="pending", type="user", cn="pending", email="x@y.z")
    pending.set_status("SUBMITTED")
    ctx.store.save(pending)
    issued_state = issued()
    app = _app(config)
    try:
        app.update()
        app.tree.selection_set(pending.slug)
        app.update()
        assert app.overview_labels["status"].cget("text") == "SUBMITTED"
        app.tree.selection_set(issued_state.slug)
        app.update()
        assert "BEGIN CERTIFICATE" not in app.cert_text.get("1.0", "end")
        assert "Chain (leaf first)" in app.cert_text.get("1.0", "end")
        assert app.overview_labels["verified"].cget("text") == "yes"
    finally:
        app.destroy()


def test_buttons_disable_without_selection(config):
    app = _app(config)
    try:
        app.update()
        app.tree.selection_remove(app.tree.selection())
        app._on_select()
        assert str(app.buttons["export"].cget("state")) == "disabled"
        assert str(app.buttons["verify"].cget("state")) == "disabled"
    finally:
        app.destroy()


def test_settings_and_new_request_dialogs_build(config):
    app = _app(config)
    try:
        from pycert.gui import NewRequestDialog, SettingsDialog

        settings = SettingsDialog(app)
        app.update()
        assert len(settings.chain_tree.get_children()) == len(config.bundle.certificates)
        settings.destroy()
        dialog = NewRequestDialog(app)
        app.update()
        assert dialog.algorithm_var.get() in ("rsa", "ec")
        dialog.destroy()
    finally:
        app.destroy()


def test_log_is_bounded(config):
    app = _app(config)
    try:
        for index in range(600):
            app.log("line %d" % index)
        app.update()
        text = app.log_text.get("1.0", "end-1c")
        assert "line 599" in text
        assert len(text.splitlines()) <= 420
    finally:
        app.destroy()
