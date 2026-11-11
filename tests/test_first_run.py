"""First run: no configuration yet. 'pycert init' and the GUI set pyCertWiz up the same way."""

import sys

import pytest

from pycert import secrets_store
from pycert.config import find_config, load_config
from pycert.errors import ConfigError, ConfigNotFound, PyCertError
from pycert.workflow import create_configuration, default_config_dir


@pytest.fixture
def fresh_home(tmp_path, monkeypatch):
    """A home directory where pyCertWiz has never been set up."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def test_no_configuration_is_a_first_run(fresh_home, tmp_path):
    with pytest.raises(ConfigNotFound, match="no configuration file found"):
        find_config()
    # a named file that is missing is an error, not a first run
    with pytest.raises(ConfigError) as raised:
        find_config(tmp_path / "missing.toml")
    assert not isinstance(raised.value, ConfigNotFound)


def test_default_config_dir(fresh_home, monkeypatch, tmp_path):
    assert default_config_dir() == fresh_home / ".config" / "pycert"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert default_config_dir() == tmp_path / "xdg" / "pycert"


def test_create_configuration(fresh_home, tmp_path):
    ctx = create_configuration(email=" jane@example.ac.uk ", ra="CLRC,DL", backend="file")
    path = fresh_home / ".config" / "pycert" / "pycert.toml"
    assert ctx.config.path == path and find_config() == path
    config = load_config(None)
    assert config.identity.email == "jane@example.ac.uk" and config.identity.ra == "CLRC DL"
    assert config.secrets.backend == "file" and ctx.secrets.get(allow_missing=True)
    with pytest.raises(PyCertError, match="already exists"):
        create_configuration()
    assert create_configuration(force=True, backend="file").config.identity.email == ""
    # a .toml path names its folder; a base URL is kept
    other = create_configuration(tmp_path / "other" / "pycert.toml", base_url="https://ca.example.org:8443", backend="file")
    assert other.config.path == tmp_path / "other" / "pycert.toml"
    assert other.config.ca.base_url == "https://ca.example.org:8443"


@pytest.mark.parametrize(
    "choices, message",
    [
        ({"email": "not an address"}, "not a valid e-mail"),
        ({"ra": "CLRC"}, "invalid RA"),
        ({"backend": "carrier-pigeon"}, "unknown secret backend"),
    ],
)
def test_create_configuration_checks_before_writing(fresh_home, choices, message):
    with pytest.raises(PyCertError, match=message):
        create_configuration(**choices)
    assert not (fresh_home / ".config").exists()


def test_auto_backend(monkeypatch):
    monkeypatch.setattr(secrets_store.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(secrets_store.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert secrets_store.auto_backend() == "keychain"
    monkeypatch.setattr(secrets_store.platform, "system", lambda: "Linux")
    assert secrets_store.auto_backend() == "secret-service"
    monkeypatch.setattr(secrets_store.shutil, "which", lambda name: None)
    assert secrets_store.auto_backend() == "file"


# -- the GUI ----------------------------------------------------------------


@pytest.fixture
def setup_module(gui_env):
    from pycert.gui import setup

    return setup


def test_backend_choices(setup_module, monkeypatch):
    for module in (setup_module, secrets_store):
        monkeypatch.setattr(module.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(module.shutil, "which", lambda name: f"/usr/bin/{name}")
    choices = setup_module.backend_choices()
    assert [value for value, _ in choices] == ["auto", "keychain", "secret-service", "file"]
    assert "macOS login keychain" in choices[0][1]
    for module in (setup_module, secrets_store):
        monkeypatch.setattr(module.platform, "system", lambda: "Linux")
        monkeypatch.setattr(module.shutil, "which", lambda name: None)
    choices = setup_module.backend_choices()
    assert [value for value, _ in choices] == ["auto", "file"]
    assert "private file" in choices[0][1]


def test_setup_dialog(setup_module, qtbot, fresh_home, tmp_path):
    dialog = setup_module.SetupDialog()
    qtbot.addWidget(dialog)
    assert "~/.config/pycert/pycert.toml" in dialog.findChildren(setup_module.QLabel)[1].text()
    assert dialog.config_path is None
    dialog.email.setText("nobody")
    dialog._accept()
    assert "not a valid e-mail address." in dialog.error.text() and dialog.result() == 0
    assert not (fresh_home / ".config").exists()
    dialog.email.setText("jane@example.ac.uk")
    dialog.ra.setText("CLRC DL")
    dialog.backend.setCurrentIndex(dialog.backend.findData("file"))
    dialog._accept()
    assert dialog.result() == setup_module.QDialog.DialogCode.Accepted
    assert dialog.config_path == fresh_home / ".config" / "pycert" / "pycert.toml"
    assert load_config(None).identity.email == "jane@example.ac.uk"
    # outside the home directory the full path is shown; errors end with a full stop once
    elsewhere = setup_module.SetupDialog(directory=tmp_path / "elsewhere")
    qtbot.addWidget(elsewhere)
    assert str(tmp_path / "elsewhere" / "pycert.toml") in elsewhere.findChildren(setup_module.QLabel)[1].text()
    elsewhere.ra.setText("one two three")
    elsewhere._accept()
    assert elsewhere.error.text().startswith("Invalid RA") and not elsewhere.error.text().endswith("..")


def test_first_run_opens_the_setup_then_the_window(setup_module, qtbot, fresh_home, monkeypatch, capsys):
    from pycert.gui import app as app_module

    app_module.create_application(["test"])
    # quitting the setup: no window, nothing written
    monkeypatch.setattr(app_module, "_show_modal", lambda dialog: setup_module.QDialog.DialogCode.Rejected)
    assert app_module.open_main_window(start_background=False) is None
    assert not (fresh_home / ".config").exists()

    def complete(dialog):
        dialog.email.setText("jane@example.ac.uk")
        dialog.backend.setCurrentIndex(dialog.backend.findData("file"))
        dialog._accept()
        return dialog.result()

    monkeypatch.setattr(app_module, "_show_modal", complete)
    window = app_module.open_main_window(start_background=False)
    qtbot.addWidget(window)
    try:
        assert window.cfg.identity.email == "jane@example.ac.uk"
    finally:
        window.runner.shutdown()
        window.runner.wait(5000)
    # once set up, the window opens directly
    monkeypatch.setattr(app_module, "_show_modal", lambda dialog: pytest.fail("no setup expected"))
    again = app_module.open_main_window(start_background=False)
    qtbot.addWidget(again)
    again.runner.shutdown()
    again.runner.wait(5000)


def test_gui_check_before_setup(setup_module, fresh_home, capsys, monkeypatch):
    from PySide6.QtGui import QPixmap

    from pycert.gui import main as gui_main

    assert gui_main(["--check"]) == 0
    assert "first-run setup" in capsys.readouterr().out
    assert not (fresh_home / ".config").exists()
    monkeypatch.setattr(setup_module.SetupDialog, "grab", lambda self: QPixmap())
    assert gui_main(["--check"]) == 1
    assert "the first-run setup did not render" in capsys.readouterr().err


# -- PySide6 and None on Python 3.10/3.11 ---------------------------------------


def test_raise_refcount():
    from pycert.gui import _raise_refcount

    target = object()
    before = sys.getrefcount(target)
    assert _raise_refcount(target, 5)
    assert sys.getrefcount(target) == before + 5
    assert _raise_refcount(target, -5)
    assert sys.getrefcount(target) == before


def test_raise_refcount_refuses_an_unknown_layout(monkeypatch):
    import pycert.gui as gui

    monkeypatch.setattr(gui.sys, "getrefcount", lambda obj: -42)
    assert gui._raise_refcount(object(), 5) is False


def test_protect_none(monkeypatch):
    import types

    import pycert.gui as gui

    calls = []
    monkeypatch.setattr(gui, "_raise_refcount", lambda obj, amount: calls.append((obj, amount)) or True)
    monkeypatch.setattr(gui, "_none_protected", False)
    # Python 3.12+ (None is immortal) and other implementations: nothing to do
    monkeypatch.setattr(gui, "sys", types.SimpleNamespace(version_info=(3, 12), implementation=types.SimpleNamespace(name="cpython")))
    assert gui.protect_none() is False
    monkeypatch.setattr(gui, "sys", types.SimpleNamespace(version_info=(3, 11), implementation=types.SimpleNamespace(name="pypy")))
    assert gui.protect_none() is False
    assert calls == []
    # CPython 3.10/3.11: once
    monkeypatch.setattr(gui, "sys", types.SimpleNamespace(version_info=(3, 11), implementation=types.SimpleNamespace(name="cpython")))
    assert gui.protect_none() is True
    assert gui.protect_none() is False
    assert calls == [(None, 1 << 40)]
