"""Shared fixtures: a mock CA, a temporary configuration, an app context."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pycert.config import ChainEntry, init_config, load_config, write_config  # noqa: E402
from pycert.workflow import AppContext  # noqa: E402
from sandbox_ca.mock_ca import MockCA  # noqa: E402


@pytest.fixture(scope="session")
def mock_ca():
    ca = MockCA()
    try:
        yield ca
    finally:
        ca.stop()


@pytest.fixture
def ca(mock_ca):
    mock_ca.reset()
    return mock_ca


@pytest.fixture
def config(tmp_path, ca):
    confdir = tmp_path / "conf"
    confdir.mkdir()
    config = init_config(confdir, copy_chain=False)
    pins = ca.chain_files(confdir / "chain")
    config.chain = [ChainEntry(label=name, file=f"chain/{name}", sha256=pin) for name, pin in pins.items()]
    config.ca.base_url = ca.url
    config.ca.retries = 0
    config.ca.timeout = 60.0
    config.identity.email = "test@example.org"
    config.identity.ra = "CLRC DL"
    config.paths.data_dir = str(tmp_path / "data")
    config.secrets.backend = "file"
    config.keys.rsa_bits = 2048
    write_config(config.path, config)
    return load_config(config.path)


@pytest.fixture
def ctx(config):
    return AppContext.from_config(config)


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Keep the real ~/.local/share/pycert and keychain out of the tests."""
    monkeypatch.setenv("PYCERT_DATA_DIR", str(tmp_path / "home-data"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def issued(ctx, config, ca):
    """Create a fully issued certificate and return its state."""
    from pycert.workflow import RequestSpec, create_request

    def _make(cn: str = "jane doe", *, type: str = "user", **kwargs):
        ca.auto_approve = True
        ca.sign_after_polls = 0
        spec = RequestSpec.build(config, cn, type=type, pin="1234567890AB", **kwargs)
        return create_request(
            ctx,
            spec,
            wait=True,
            timeout=30,
            interval=0.2,
            progress=lambda _m: None,
        )

    return _make


@pytest.fixture
def e2e(config, ctx, ca, capsys):
    from e2e import E2E

    return E2E(config, ctx, ca, capsys)


@pytest.fixture
def two_hosts(ctx, issued):
    """A user certificate and two host certificates it authenticated."""
    user = issued("jane doe")
    host_a = issued("a.example.org", type="host", auth_alias=user.alias)
    host_b = issued("b.example.org", type="host", auth_alias=user.alias)
    return user, host_a, host_b


@pytest.fixture
def certwizard_store(tmp_path, ctx, two_hosts):
    """A keystore holding two host certificates that pyCertWiz does not manage yet."""
    from test_keystore import _entry_parts, build_keystore

    _user, host_a, host_b = two_hosts
    path = tmp_path / "cakeystore.pkcs12"
    build_keystore(
        path,
        [("a.example.org", *_entry_parts(ctx, host_a)), ("b.example.org", *_entry_parts(ctx, host_b))],
    )
    for state in (host_a, host_b):
        ctx.store.delete(ctx.store.get(state.alias))
    return path


# ---------------------------------------------------------------------------
# Qt GUI fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gui_env(tmp_path, monkeypatch, qapp):
    """Keep GUI preferences in a temp file and never block on a modal dialog.

    GUI test modules use it with ``pytestmark = pytest.mark.usefixtures("gui_env")``.
    """
    pytest.importorskip("PySide6")
    pytest.importorskip("pytestqt")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QDialog, QMessageBox

    monkeypatch.setenv("PYCERT_GUI_SETTINGS", str(tmp_path / "gui.ini"))
    monkeypatch.setattr(QMessageBox, "exec", lambda self: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    # Any dialog a test does not script is cancelled at once instead of blocking the run.
    from PySide6.QtWidgets import QFileDialog, QInputDialog

    monkeypatch.setattr(QDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False)))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: ("", "")))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: ("", "")))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: ""))
    from pycert.gui import settings as settings_module
    from pycert.gui import tray

    settings_module.preferences().setValue("tray", False)
    monkeypatch.setattr(tray.QSystemTrayIcon, "isSystemTrayAvailable", staticmethod(lambda: False))
    # As pycert.gui.app.run() does: a cycle holding Qt objects must never be
    # collected on a worker thread (that frees widgets off the GUI thread).
    from pycert.gui.workers import MainThreadCollector

    collector = MainThreadCollector(interval_ms=200)
    yield
    collector.stop()


@pytest.fixture
def window(qtbot, config, gui_env):
    from pycert.gui.app import MainWindow, create_application

    create_application(["test"])
    main = MainWindow(str(config.path), start_background=False)
    qtbot.addWidget(main)
    main.resize(1300, 820)
    main.show()
    yield main
    main.runner.shutdown()
    main.runner.wait(5000)


@pytest.fixture
def java_keystore(tmp_path, ctx, issued):
    from test_keystore import PASSWORD, _entry_parts, build_keystore

    user = issued("jane doe")
    hosts = [issued(f"h{i}.example.org", type="host", auth_alias=user.alias) for i in (1, 2)]
    path = build_keystore(tmp_path / "cakeystore.pkcs12", [(s.alias, *_entry_parts(ctx, s)) for s in hosts])
    for state in hosts:
        ctx.store.delete(ctx.store.get(state.alias))
    return path, PASSWORD
