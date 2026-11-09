"""GUI smoke tests. Skipped when tkinter or a display is unavailable."""

import pytest

tkinter = pytest.importorskip("tkinter")


def _app(config):
    from pycert.gui import PyCertApp

    try:
        return PyCertApp(str(config.path), startup_ping=False)
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


pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


def test_gui_inspects_java_certificate_bundle(config, issued, tmp_path):
    from pycert import p12

    state = issued("bundle gui")
    app = _app(config)
    try:
        key = app.ctx.store.load_key(state, app.ctx.key_passphrase())
        leaf = app.ctx.store.load_certificate(state)
        chain = app.ctx.store.load_chain(state)
        path = tmp_path / "java-bundle.p12"
        p12.write_pkcs12(path, key=key, certificate=leaf, chain=chain, password="secret")

        from pycert.gui import BundleDialog

        dialog = BundleDialog(app, path)
        app.update()
        dialog.password_var.set("secret")
        dialog.load()
        app.update()
        rows = dialog.tree.get_children()
        assert len(rows) == len(chain) + 1
        assert dialog.tree.item("0", "values")[1] == "leaf"
        dialog.tree.selection_set("0")
        dialog._show_details()
        details = dialog.details.get("1.0", "end")
        assert "BEGIN CERTIFICATE" in details
        assert "Subject" in details
        assert "private key" in dialog.summary_label.cget("text")
        dialog.destroy()
    finally:
        app.destroy()


def test_gui_dark_mode_updates_text_and_pin_dialog(config, monkeypatch):
    import tkinter as tk

    from pycert import gui

    monkeypatch.setenv("PYCERT_THEME", "dark")
    app = _app(config)
    try:
        assert app._dark is True
        assert app.style.theme_use() == "clam"
        for widget in (app.log_text, app.cert_text, app.history_text):
            assert widget.cget("background") == gui.DARK_COLORS["text_bg"]
            assert widget.cget("foreground") == gui.DARK_COLORS["text_fg"]
        assert app.tree.tag_configure("valid")["foreground"] == gui.DARK_COLORS["tag_valid"]

        app.set_appearance("light")
        assert app.log_text.cget("background") == gui.LIGHT_COLORS["text_bg"]
        assert app.tree.tag_configure("valid")["foreground"] == gui.LIGHT_COLORS["tag_valid"]
        app.set_appearance("dark")
        assert app.log_text.cget("background") == gui.DARK_COLORS["text_bg"]

        monkeypatch.setattr(tk.Toplevel, "wait_window", lambda *args, **kwargs: None)
        dialog = gui.PinDialog(app, "1234567890AB", "Jane Doe")
        app.update()

        def find_entry(widget):
            for child in widget.winfo_children():
                if isinstance(child, tk.Entry):
                    return child
                found = find_entry(child)
                if found is not None:
                    return found
            return None

        pin_entry = find_entry(dialog)
        assert pin_entry is not None
        assert pin_entry.cget("readonlybackground") == gui.DARK_COLORS["field"]
        assert dialog.cget("background") == gui.DARK_COLORS["bg"]
        dialog.destroy()
    finally:
        app.destroy()


def test_system_dark_mode_override(monkeypatch):
    from pycert import gui

    monkeypatch.setenv("PYCERT_THEME", "dark")
    assert gui._detect_system_dark() is True
    monkeypatch.setenv("PYCERT_THEME", "light")
    assert gui._detect_system_dark() is False
    monkeypatch.setenv("PYCERT_THEME", "system")
    assert gui._initial_appearance_mode() == "system"
