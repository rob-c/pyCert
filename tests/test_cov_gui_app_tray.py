"""GUI coverage: the entry points, the task runner, the background monitor and the tray icon.

The tray tests pretend a system tray exists (the offscreen platform has none),
so the real QSystemTrayIcon, its menu and its notifications are exercised.
"""

import gc
import os
import threading
import types

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from gui_support import wait_idle  # noqa: E402

from pycert.errors import PyCertError  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")


# ---------------------------------------------------------------------------
# Entry points (pycert.gui)
# ---------------------------------------------------------------------------


def test_gui_available_explains_a_missing_pyside(monkeypatch):
    import sys

    import pycert.gui as gui

    monkeypatch.setitem(sys.modules, "PySide6", None)  # what an install without the extra looks like
    problem = gui.gui_available()
    assert "needs PySide6" in problem and "pip install" in problem
    # a packaged pyCertWiz bundles Qt: what is missing are system libraries
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    problem = gui.gui_available()
    assert "cannot load Qt" in problem and "libegl1" in problem and "pip install" not in problem


def test_gui_available_needs_a_display_on_linux(monkeypatch):
    import pycert.gui as gui

    monkeypatch.setattr(gui, "sys", types.SimpleNamespace(platform="linux"))
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "QT_QPA_PLATFORM"):
        monkeypatch.delenv(name, raising=False)
    assert "no display" in gui.gui_available()
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    assert gui.gui_available() is None


def test_run_gui_and_main_start_the_application(monkeypatch):
    import pycert.gui as gui
    from pycert.gui import app as app_module

    calls = []
    monkeypatch.setattr(app_module, "run", lambda path, argv=None: calls.append(("run", path, argv)) or 3)
    assert gui.run_gui("/etc/pycert.toml", argv=["pycert-gui"]) == 3
    assert calls == [("run", "/etc/pycert.toml", ["pycert-gui"])]

    monkeypatch.setattr(gui, "run_gui", lambda path, argv=None: calls.append(("run_gui", path, argv)) or 0)
    assert gui.main(["--config", "/tmp/c.toml", "-reverse"]) == 0
    name, path, argv = calls[-1]
    assert (name, path) == ("run_gui", "/tmp/c.toml") and argv[1:] == ["-reverse"]  # Qt's own options pass through


# ---------------------------------------------------------------------------
# Task runner and garbage collection on the UI thread
# ---------------------------------------------------------------------------


def test_a_task_outliving_its_runner_is_released_without_callbacks(qtbot):
    import shiboken6

    from pycert.gui.workers import TaskRunner

    runner = TaskRunner()
    release = threading.Event()
    seen = []

    def work(progress, _stop):
        release.wait(10)
        progress("progress for a runner that has gone")
        return "late result"

    task = runner.start(work, seen.append, seen.append, seen.append, name="orphan")
    shiboken6.delete(runner)  # the window (and its runner) closed while the work was running
    release.set()
    qtbot.waitUntil(lambda: task.done and task.work is None, timeout=10000)
    assert seen == []
    assert task.runner is None and task.on_done is None and task.result is None


def test_progress_and_results_after_shutdown_are_dropped(qtbot):
    from pycert.gui.workers import TaskRunner

    runner = TaskRunner()
    progress_seen, done_seen, busy = [], [], []
    runner.progress.connect(progress_seen.append)
    runner.busy_changed.connect(busy.append)

    def work(progress, stop):
        stop.wait(10)  # until shutdown cancels it
        progress("still working after shutdown")
        return "result nobody wants"

    runner.start(work, done_seen.append, on_progress=progress_seen.append)
    runner.shutdown()
    assert runner.wait(5000)
    qtbot.waitUntil(lambda: not runner.busy, timeout=5000)
    assert progress_seen == [] and done_seen == []
    assert busy == [True]  # a closed runner no longer reports


def test_finishing_a_task_twice_calls_back_once(qtbot):
    from pycert.gui.workers import TaskRunner

    runner = TaskRunner()
    results, busy = [], []
    runner.busy_changed.connect(busy.append)
    task = runner.start(lambda _p, _s: 42, results.append)
    qtbot.waitUntil(lambda: not runner.busy, timeout=5000)
    runner._finish(task)  # a stray second delivery of the same task
    assert results == [42]
    assert not runner.busy and busy[:2] == [True, False]


def test_collector_does_nothing_when_automatic_collection_was_off():
    from pycert.gui.workers import MainThreadCollector

    threshold, enabled = gc.get_threshold(), gc.isenabled()
    gc.set_threshold(0, *threshold[1:])
    try:
        collector = MainThreadCollector(interval_ms=60000)
        assert collector.check() == 0
        collector.stop()
    finally:
        gc.set_threshold(*threshold)
        if enabled:
            gc.enable()


def test_nested_collectors_restore_automatic_collection_once():
    from pycert.gui.workers import MainThreadCollector

    gc.enable()
    outer = MainThreadCollector(interval_ms=60000)
    inner = MainThreadCollector(interval_ms=60000)  # gc is already off: it must not switch it back on
    inner.stop()
    assert not gc.isenabled()
    outer.stop()
    assert gc.isenabled()


# ---------------------------------------------------------------------------
# Background monitor
# ---------------------------------------------------------------------------


def _run_check(qtbot, window):
    results, failures = [], []
    window.monitor.checked.connect(lambda report, collected: results.append((report, collected)))
    window.monitor.failed.connect(failures.append)
    window.monitor.run_now()
    window.monitor.run_now()  # already running: ignored
    qtbot.waitUntil(lambda: bool(results or failures), timeout=30000)
    wait_idle(qtbot, window)
    return results, failures


def _pending(ca, config, ctx, cn):
    from pycert.workflow import RequestSpec, create_request

    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    return create_request(ctx, RequestSpec.build(config, cn, pin="1234567890AB"), progress=lambda _m: None)


def test_monitor_with_nothing_pending_syncs_linked_keystores(qtbot, ctx, java_keystore, window):
    from pycert import keystore as ks

    path, password = java_keystore
    ks.link_keystore(window.ctx, path, password, name="site")
    window.reload_config()
    wait_idle(qtbot, window)
    assert not window.ctx.store.pending()
    results, failures = _run_check(qtbot, window)
    assert failures == []
    _report, collected = results[0]
    assert collected == []
    assert {"h1.example.org", "h2.example.org"} <= {s.alias for s in window.ctx.store.list()}  # imported by the sync


def test_monitor_without_auto_collect_only_polls(qtbot, ca, config, ctx, window):
    from pycert.gui.settings import preferences

    state = _pending(ca, config, ctx, "polled person")
    preferences().setValue("auto_collect", False)
    results, _failures = _run_check(qtbot, window)
    report, collected = results[0]
    assert collected == [] and report.counts["pending"] == 1  # still waiting at the CA
    assert not ctx.store.get(state.alias).cert.sha256


def test_monitor_skips_a_request_deleted_during_the_check(qtbot, monkeypatch, ca, config, ctx, window):
    from pycert.gui import tray as tray_module

    state = _pending(ca, config, ctx, "short lived")

    def deleted_meanwhile(ctx, **_kwargs):  # e.g. "Delete local copy" while the check runs
        ctx.store.delete(ctx.store.get(state.alias))

    monkeypatch.setattr(tray_module, "watch", deleted_meanwhile)
    results, failures = _run_check(qtbot, window)
    assert failures == [] and results[0][1] == []
    assert not ctx.store.exists(state.alias)


def test_monitor_failure_is_reported_and_logged(qtbot, monkeypatch, window):
    from pycert import monitor

    def broken(*_args, **_kwargs):
        raise PyCertError("the store is unreadable")

    monkeypatch.setattr(monitor, "check", broken)
    results, failures = _run_check(qtbot, window)
    assert results == [] and failures == ["the store is unreadable"]
    assert "Background check failed: the store is unreadable" in window.activity.text.toPlainText()
    assert window.monitor.running is False  # the next cycle can run


# ---------------------------------------------------------------------------
# Tray icon
# ---------------------------------------------------------------------------


@pytest.fixture
def tray_on(monkeypatch, gui_env):
    """Pretend the desktop has a system tray and the preference is on."""
    from pycert.gui import tray as tray_module
    from pycert.gui.settings import preferences

    monkeypatch.setattr(tray_module.QSystemTrayIcon, "isSystemTrayAvailable", staticmethod(lambda: True))
    preferences().setValue("tray", True)


def test_tray_icon_menu_actions(qtbot, monkeypatch, tray_on, window):
    from PySide6.QtWidgets import QSystemTrayIcon

    from pycert.gui import app as app_module

    controller = window.tray
    assert controller.supported() and controller.tray is not None and controller.tray.isVisible()
    assert controller.tray.contextMenu() is controller.menu
    calls = []
    monkeypatch.setattr(app_module.MainWindow, "new_request", lambda self, *a: calls.append("new"))
    show, check, new, _separator, quit_action = controller.menu.actions()
    window.hide()
    show.trigger()
    assert window.isVisible()
    check.trigger()
    wait_idle(qtbot, window)
    new.trigger()
    assert calls == ["new"]
    window.hide()
    controller._activated(QSystemTrayIcon.ActivationReason.Context)  # right-click opens the menu, nothing else
    assert not window.isVisible()
    controller._activated(QSystemTrayIcon.ActivationReason.DoubleClick)
    assert window.isVisible()
    quit_action.trigger()
    assert not window.isVisible() and not controller.tray.isVisible()


def test_tray_preference_switches_the_icon_off(tray_on, window):
    from pycert.gui.settings import preferences

    assert window.tray.tray is not None
    window.tray.apply_preferences()  # unchanged: the icon is kept
    preferences().setValue("tray", False)
    window.tray.apply_preferences()
    assert window.tray.tray is None


def test_tray_notifies_expiry_once_a_day(qtbot, monkeypatch, tmp_path, ca, ctx, issued, tray_on, window):
    from pycert import monitor
    from pycert.deploy import add_target
    from pycert.gui.settings import preferences

    issued("long lived")
    ca.valid_days = 10
    expiring = issued("expiring soon")
    add_target(ctx, ctx.store.get(expiring.alias), {"name": "web", "cert": str(tmp_path / "missing" / "cert.pem")})
    report = monitor.check(ctx, warn_days=30, crit_days=7)
    messages = [f.message for f in report.findings]
    assert any(m.startswith("valid for") for m in messages) and any("deployment" in m for m in messages)
    shown = []
    monkeypatch.setattr(window.tray.tray, "showMessage", lambda *args: shown.append(args[:2]))
    notes = window.tray.update(report, ["collected person"])
    assert notes[0][0] == "Certificate issued" and len(notes) == 2
    assert notes[1][0].startswith("expiring soon expires in ")  # not the valid one, not the deployment warning
    assert shown == notes and "1 expiring" in window.tray.tray.toolTip()
    # the same expiry is not announced again today
    assert window.tray.update(report, []) == []
    # notifications can be switched off; the tooltip is still kept up to date
    preferences().setValue("notify", False)
    assert window.tray.update(report, ["another"]) == []


def test_closing_the_window_keeps_monitoring_from_the_tray(monkeypatch, tray_on, window):
    from pycert.gui import app as app_module

    monkeypatch.setattr(app_module, "sys", types.SimpleNamespace(platform="linux", argv=["pycert-gui"]))
    messages = []
    monkeypatch.setattr(window.tray.tray, "showMessage", lambda title, *_rest: messages.append(title))
    window.close()
    assert not window.isVisible() and messages == ["pyCertWiz is still running"]
    assert window.monitor.timer.isActive() and not window.runner._closed  # still monitoring
    window.quit_application()  # Quit from the tray menu
    assert window.runner._closed and not window.monitor.timer.isActive() and not window.tray.tray.isVisible()


def test_quitting_without_an_application_object(monkeypatch, window):
    from pycert.gui import app as app_module

    monkeypatch.setattr(app_module, "QApplication", types.SimpleNamespace(instance=lambda: None))
    window.quit_application()
    assert window.runner._closed and not window.isVisible()
