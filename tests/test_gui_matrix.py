"""GUI logic tests that do not need a display, plus display-gated smoke tests."""

import datetime as dt

import pytest

tkinter = pytest.importorskip("tkinter")

from pycert.gui import PyCertApp, _set_text  # noqa: E402
from pycert.store import RequestState  # noqa: E402


def state_with(status="DOWNLOADED", days=None, p12=True):
    state = RequestState(alias="x", slug="x", type="user", cn="x", status=status)
    if days is not None:
        expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
        state.cert.not_after = expiry.isoformat()
    if p12:
        state.p12_path = "/tmp/x.p12"
    return state


@pytest.mark.parametrize(
    "status,days,expected",
    [
        ("REVOKED", 365, "revoked"),
        ("FAILED", 365, "failed"),
        ("SUBMITTED", None, "pending"),
        ("DOWNLOADED", -1, "expired"),
        ("DOWNLOADED", 10, "expiring"),
        ("DOWNLOADED", 365, "valid"),
    ],
)
def test_status_tag_matrix(status, days, expected):
    assert PyCertApp._tag(state_with(status, days)) == expected


@pytest.mark.parametrize(
    "column,value,expected",
    [
        ("alias", "abc", "abc"),
        ("type", "user", "user"),
        ("status", "VALID", "VALID"),
        ("expires", None, "9999"),
        ("days", None, 10**6),
    ],
)
def test_sort_key_matrix(column, value, expected):
    app = object.__new__(PyCertApp)
    app._sort_column = column
    state = RequestState(alias="a", slug="a", type="user", cn="a", status="X")
    if column == "expires":
        state.cert.not_after = value
    elif column == "days":
        state.cert.not_after = None
    else:
        setattr(state, column, value)
    assert app._sort_key(state) == expected


def test_set_text_helper():
    app = tkinter.Tk()
    try:
        app.withdraw()
        text = tkinter.Text(app)
        _set_text(text, "hello")
        assert text.get("1.0", "end-1c") == "hello"
        assert str(text.cget("state")) == "disabled"
    finally:
        app.destroy()


def _app(config):
    try:
        return PyCertApp(str(config.path), startup_ping=False)
    except tkinter.TclError as exc:  # pragma: no cover
        pytest.skip("no display: %s" % exc)


def test_dashboard_renders_issued_certificate(config, issued):
    state = issued()
    app = _app(config)
    try:
        app.update()
        app.tree.selection_set(state.slug)
        app.update()
        assert app.overview_labels["cn"].cget("text") == state.cn
        assert app.overview_labels["verified"].cget("text") == "yes"
        assert app.overview_labels["p12"].cget("text") == state.p12_path
        assert "Chain (leaf first)" in app.cert_text.get("1.0", "end")
        assert app._tag(state) == "valid"
        app._sort_by("days")
        app._sort_by("days")
        assert app._sort_reverse is True
    finally:
        app.destroy()


def test_dashboard_buttons_for_pending_state(config, ctx):
    state = ctx.store.new_state(alias="pending", type="user", cn="pending", email="x@y.z")
    state.set_status("SUBMITTED")
    ctx.store.save(state)
    app = _app(config)
    try:
        app.update()
        app.tree.selection_set(state.slug)
        app.update()
        assert str(app.buttons["wait"].cget("state")) == "normal"
        assert str(app.buttons["export"].cget("state")) == "disabled"
        assert str(app.buttons["revoke"].cget("state")) == "disabled"
    finally:
        app.destroy()


def test_dashboard_empty_state(config):
    app = _app(config)
    try:
        app.update()
        assert "No certificate requests" in app.overview_labels["status"].cget("text")
    finally:
        app.destroy()


def test_new_request_dialog_defaults(config):
    app = _app(config)
    try:
        from pycert.gui import NewRequestDialog

        dialog = NewRequestDialog(app)
        app.update()
        assert dialog.cn_label.cget("text") == "Full name"
        dialog.type_var.set("host")
        dialog._on_type_change()
        assert dialog.cn_label.cget("text") == "Host name"
        dialog.algorithm_var.set("ec")
        app.update()
        assert "P-256" in dialog.size_combo.cget("values")
        dialog.destroy()
    finally:
        app.destroy()


def test_settings_dialog_chain_rows(config):
    app = _app(config)
    try:
        from pycert.gui import SettingsDialog

        dialog = SettingsDialog(app)
        app.update()
        assert len(dialog.chain_tree.get_children()) == len(config.bundle.certificates)
        dialog.destroy()
    finally:
        app.destroy()


def test_log_is_bounded(config):
    app = _app(config)
    try:
        for index in range(500):
            app.log("line %d" % index)
        app.update()
        text = app.log_text.get("1.0", "end-1c")
        assert "line 499" in text
        assert len(text.splitlines()) <= 420
    finally:
        app.destroy()


pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
