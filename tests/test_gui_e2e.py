"""GUI actions driven against the mock CA listener."""

import time

import pytest

tkinter = pytest.importorskip("tkinter")

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


def _app(config):
    from pycert.gui import PyCertApp

    try:
        return PyCertApp(str(config.path), startup_ping=False)
    except tkinter.TclError as exc:  # pragma: no cover
        pytest.skip("no display: %s" % exc)


def _pump(app, condition, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.update()
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_gui_refresh_and_render_issued(config, issued):
    state = issued()
    app = _app(config)
    try:
        app.refresh_list()
        app.update()
        app.tree.selection_set(state.slug)
        app.update()
        assert app._selected_alias == state.alias
        assert app.overview_labels["status"].cget("text") == "DOWNLOADED"
        assert app.overview_labels["verified"].cget("text") == "yes"
    finally:
        app.destroy()


def test_gui_verify_action(config, issued, monkeypatch):
    from pycert import gui as gui_module

    messages = []
    monkeypatch.setattr(gui_module.messagebox, "showinfo", lambda *a, **k: messages.append(a))
    monkeypatch.setattr(gui_module.messagebox, "showwarning", lambda *a, **k: messages.append(a))
    state = issued()
    app = _app(config)
    try:
        app.tree.selection_set(state.slug)
        app.update()
        app.verify_selected()
        assert _pump(app, lambda: bool(messages))
        assert "All checks passed" in messages[0][1]
    finally:
        app.destroy()


def test_gui_export_action(config, issued, monkeypatch):
    from pycert import gui as gui_module

    messages = []
    monkeypatch.setattr(gui_module.messagebox, "showinfo", lambda *a, **k: messages.append(a))
    state = issued()
    app = _app(config)
    try:
        app.tree.selection_set(state.slug)
        app.update()
        app.export_selected()
        assert _pump(app, lambda: bool(messages))
    finally:
        app.destroy()


def test_gui_diagnostics_action(config, monkeypatch):
    from pycert import gui as gui_module

    messages = []
    monkeypatch.setattr(gui_module.messagebox, "showinfo", lambda *a, **k: messages.append(a))
    monkeypatch.setattr(gui_module.messagebox, "showerror", lambda *a, **k: messages.append(a))
    app = _app(config)
    try:
        app.run_diagnostics()
        assert _pump(app, lambda: bool(messages), timeout=20)
        assert "Diagnostics" in messages[0][0]
    finally:
        app.destroy()


def test_gui_ping_action(config, monkeypatch):
    app = _app(config)
    try:
        app.ping_server()
        assert _pump(app, lambda: "online" in app.online_label.cget("text").lower(), timeout=20)
    finally:
        app.destroy()


def test_gui_new_request_dialog_submit(config, ca, monkeypatch):
    from pycert import gui as gui_module
    from pycert.gui import NewRequestDialog

    messages = []
    monkeypatch.setattr(gui_module.messagebox, "showinfo", lambda *a, **k: messages.append(a))
    monkeypatch.setattr(gui_module.messagebox, "showerror", lambda *a, **k: None)
    ca.auto_approve = True
    ca.sign_after_polls = 0
    app = _app(config)
    try:
        dialog = NewRequestDialog(app)
        dialog.cn_entry.delete(0, "end")
        dialog.cn_entry.insert(0, "gui user")
        dialog.email_var.set("gui@example.org")
        dialog.ra_var.set("CLRC DL")
        dialog.wait_var.set(False)
        # Supply a PIN so the modal one-time PIN dialog does not block the test.
        dialog.generate_pin_var.set(False)
        dialog.pin_var.set("1234567890AB")
        dialog._submit()
        assert _pump(app, lambda: any(state.cn == "gui user" for state in app.ctx.store.list()), timeout=20)
        assert any(state.cn == "gui user" for state in app.ctx.store.list())
    finally:
        app.destroy()


def test_gui_revoke_dialog_builds(config, issued):
    from pycert.gui import RevokeDialog

    state = issued()
    app = _app(config)
    try:
        dialog = RevokeDialog(app, state)
        app.update()
        assert "Revoke" in dialog.title()
        dialog.destroy()
    finally:
        app.destroy()


def test_gui_settings_chain_rows(config):
    from pycert.gui import SettingsDialog

    app = _app(config)
    try:
        dialog = SettingsDialog(app)
        app.update()
        assert len(dialog.chain_tree.get_children()) == len(config.bundle.certificates)
        dialog.destroy()
    finally:
        app.destroy()
