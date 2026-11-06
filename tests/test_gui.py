"""GUI smoke tests. Skipped when tkinter or a display is unavailable."""

import pytest

tkinter = pytest.importorskip("tkinter")


def _app(config):
    from pycert.gui import PyCertApp

    try:
        return PyCertApp(str(config.path))
    except tkinter.TclError as exc:  # pragma: no cover - headless CI
        pytest.skip(f"no display available: {exc}")


def test_gui_lists_and_renders(config, issued):
    state = issued()
    app = _app(config)
    try:
        app.update()
        rows = app.tree.get_children()
        assert state.slug in rows
        app.tree.selection_set(state.slug)
        app.update()
        assert app._selected_alias == state.alias
        assert app.overview_labels["status"].cget("text") == "DOWNLOADED"
        assert app.overview_labels["cn"].cget("text") == state.cn
        assert "BEGIN CERT" not in app.cert_text.get("1.0", "end")  # never show PEM bodies
        assert "Subject" in app.cert_text.get("1.0", "end")
        assert app._tag(state) == "valid"
        app.notebook.select(2)
        app.update()
        assert app.notebook.tab(app.notebook.select(), "text") == "History"
        assert "DOWNLOADED" in app.history_text.get("1.0", "end")
    finally:
        app.destroy()


def test_gui_button_state_follows_selection(config, issued):
    state = issued()
    app = _app(config)
    try:
        app.update()
        app.tree.selection_remove(app.tree.selection())
        app._on_select()
        assert str(app.buttons["export"].cget("state")) == "disabled"
        app.tree.selection_set(state.slug)
        app.update()
        assert str(app.buttons["export"].cget("state")) == "normal"
        assert str(app.buttons["revoke"].cget("state")) == "normal"
    finally:
        app.destroy()


def test_gui_new_request_dialog_builds(config):
    app = _app(config)
    try:
        from pycert.gui import NewRequestDialog

        dialog = NewRequestDialog(app)
        app.update()
        assert dialog.type_var.get() == "user"
        assert dialog.ra_var.get() == "CLRC DL"
        assert dialog.algorithm_var.get() == "rsa"
        dialog.type_var.set("host")
        dialog._on_type_change()
        assert dialog.cn_label.cget("text") == "Host name"
        dialog.destroy()
        app.update()
    finally:
        app.destroy()


def test_gui_sorting_and_empty_state(config):
    app = _app(config)
    try:
        app.update()
        assert app.tree.get_children() == ()
        app._sort_by("days")
        assert app._sort_reverse is False
        app._sort_by("days")
        assert app._sort_reverse is True
        app._sort_by("status")
        assert app._sort_reverse is False
        assert "No certificate requests" in app.overview_labels["status"].cget("text")
    finally:
        app.destroy()


def test_gui_dialogs_build(config, issued):
    state = issued()
    app = _app(config)
    try:
        from pycert.gui import RevokeDialog, SettingsDialog

        settings = SettingsDialog(app)
        app.update()
        settings.destroy()
        revoke = RevokeDialog(app, state)
        app.update()
        assert str(revoke.revoke_button.cget("state")) == "disabled"
        revoke.confirm.set(True)
        app.update()
        assert str(revoke.revoke_button.cget("state")) == "normal"
        revoke.destroy()
    finally:
        app.destroy()
