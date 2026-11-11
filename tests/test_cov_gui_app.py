"""GUI coverage: the main window's actions, edge cases and error paths.

Same conventions as test_gui_qt.py: a real MainWindow against the mock CA,
modal dialogs scripted through their ``exec`` and nothing left blocking.
"""

import os
import socket

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from gui_support import wait_idle  # noqa: E402
from PySide6.QtCore import QModelIndex, QPoint  # noqa: E402
from PySide6.QtGui import QDesktopServices  # noqa: E402
from PySide6.QtWidgets import QDialog, QInputDialog, QMenu, QMessageBox  # noqa: E402

from pycert.errors import PyCertError  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")

NOOP = lambda _m: None  # noqa: E731


def _log(window) -> str:
    return window.activity.text.toPlainText()


def _capture(monkeypatch, name: str, answer=QMessageBox.StandardButton.Ok) -> list:
    """Replace a QMessageBox static (information, warning, question...) and record its text."""
    seen = []
    monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: seen.append(a[2]) or answer))
    return seen


def _capture_errors(monkeypatch, window) -> list:
    errors = []
    monkeypatch.setattr(window, "show_error", lambda title, exc: errors.append((title, str(exc))))
    return errors


def _record_pins(monkeypatch) -> list:
    """Record what the PIN dialog shows (name, PIN) instead of blocking on it."""
    from pycert.gui import app as app_module
    from pycert.gui.dialogs import PinDialog

    shown = []

    class RecordingPinDialog(PinDialog):
        def exec(self):
            return QDialog.DialogCode.Accepted

        def __init__(self, parent, pins):
            super().__init__(parent, pins)
            shown.append(list(pins))

    monkeypatch.setattr(app_module, "PinDialog", RecordingPinDialog)
    return shown


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# Start-up, the prompter and the system colour scheme
# ---------------------------------------------------------------------------


def test_prompter_asks_on_the_ui_thread_for_a_worker(qtbot, monkeypatch, window):
    answers = []
    window.runner.start(lambda _p, _s: window.prompter("Publish TXT", "Add the record"), answers.append)
    wait_idle(qtbot, window)
    monkeypatch.setattr(QMessageBox, "exec", lambda self: QMessageBox.StandardButton.Cancel)
    window.runner.start(lambda _p, _s: window.prompter("Publish TXT", "Add the record"), answers.append)
    wait_idle(qtbot, window)
    assert answers == [True, False]


def test_startup_runs_the_background_checks(qtbot, monkeypatch, config, ca):
    from pycert.gui import theme
    from pycert.gui.app import MainWindow, create_application
    from pycert.gui.settings import preferences

    create_application(["test"])
    main = MainWindow(str(config.path))  # start_background=True: ping, unlock, monitor
    qtbot.addWidget(main)
    checked = []
    main.monitor.checked.connect(lambda report, _collected: checked.append(report))
    try:
        qtbot.waitUntil(lambda: bool(checked) and "online" in main.status_ca.text(), timeout=30000)
        wait_idle(qtbot, main)
        applied = []
        monkeypatch.setattr(theme, "apply", applied.append)
        main._system_scheme_changed()  # following the system: the new scheme is applied
        preferences().setValue("appearance", "dark")
        main._system_scheme_changed()  # an explicit choice is kept
        assert applied == ["system"]
    finally:
        main.runner.shutdown()
        main.runner.wait(5000)


def test_window_starts_without_colour_scheme_notifications(qtbot, monkeypatch, config):
    from PySide6.QtGui import QGuiApplication

    from pycert.gui.app import MainWindow, create_application

    create_application(["test"])
    monkeypatch.setattr(QGuiApplication, "styleHints", staticmethod(lambda: object()))  # Qt before 6.5
    main = MainWindow(str(config.path), start_background=False)
    qtbot.addWidget(main)
    assert main.stack.currentIndex() == 0


# ---------------------------------------------------------------------------
# Table, selection, navigation and the banner
# ---------------------------------------------------------------------------


def test_columns_selection_and_navigation_edge_cases(qtbot, monkeypatch, issued, window):
    from pycert.gui.models import COL_EXPIRES, COL_TYPE

    issued("jane doe")
    window.refresh()
    assert window.table.isColumnHidden(COL_EXPIRES) and not window.table.isColumnHidden(COL_TYPE)
    window._toggle_column(COL_EXPIRES, True)
    window._toggle_column(COL_TYPE, False)
    assert not window.table.isColumnHidden(COL_EXPIRES) and window.table.isColumnHidden(COL_TYPE)
    assert window._hidden_columns() == {COL_TYPE}  # remembered in the preferences
    # a selection that no longer exists falls back to the first row
    window.refresh(select="no such certificate")
    assert window.detail.title.text() == "jane doe"
    window._show_index(QModelIndex())  # nothing to show
    assert window.detail.title.text() == "jane doe"
    window._nav_changed(None, None)
    window._nav_clicked(window._nav_items["personal"])  # a view, not a tool: nothing opens
    window._select_view("no such view")
    window.perform("no such action")
    below_the_rows = QPoint(5, window.table.viewport().height() - 2)
    assert not window.table.indexAt(below_the_rows).isValid()
    window._context_menu(below_the_rows)  # no row there: no menu
    window.hide()
    window.bring_to_front()
    assert window.isVisible()


def test_banner_offers_renewals_and_goes_away(qtbot, monkeypatch, ca, issued, window):
    from pycert.gui.settings import preferences

    ca.valid_days = 10
    issued("expiring person")
    window.refresh()
    assert window.banner.isVisible() and "1 certificate needs renewing" in window.banner.text.text()
    calls = []
    monkeypatch.setattr(window, "renew_due", lambda: calls.append("renew"))
    monkeypatch.setattr(window, "run_doctor", lambda: calls.append("doctor"))
    window.banner.button.click()
    assert calls == ["renew"]
    preferences().setValue("warn_days", 5)  # no longer inside the warning window
    preferences().setValue("crit_days", 2)
    window.refresh()
    assert not window.banner.isVisible() and window._banner_kind == ""
    window._banner_action()  # nothing to act on
    window._banner_kind = "unreachable"
    window._banner_action()
    assert calls == ["renew", "doctor"]


# ---------------------------------------------------------------------------
# Selection-dependent actions
# ---------------------------------------------------------------------------


ACTIONS = (
    "wait", "download", "export", "deploy", "deploy_add", "verify", "renew", "revoke", "delete", "folder",
    "copy_fingerprint", "copy_pem", "install_globus", "save_pem", "proxy", "edit", "rename", "view",
    "deploy_remove:web",
)


def test_every_action_asks_for_a_selection_first(qtbot, monkeypatch, ctx, issued, window):
    infos = _capture(monkeypatch, "information")
    window._selected_alias = None
    for action in ACTIONS:
        window.perform(action)
    window._set_auto_renew(True)
    window.sync_keystores()  # no keystores are linked: nothing to synchronise
    assert infos == ["Select a certificate first."] * (len(ACTIONS) + 1)
    assert not window.runner.busy
    # a certificate deleted behind the window's back: the list is refreshed instead
    user = issued("deleted elsewhere")
    window.refresh(select=user.alias)
    assert window.stack.currentIndex() == 1
    ctx.store.delete(ctx.store.get(user.alias))
    window.check_selected()
    assert window.stack.currentIndex() == 0 and not window.runner.busy


def test_error_dialog_details_and_cancelled_tasks(qtbot, monkeypatch, window):
    from pycert.gui.dialogs import ProgressDialog

    details = []
    monkeypatch.setattr(QMessageBox, "exec", lambda self: details.append(self.detailedText()) or 0)
    window.show_error("Unexpected", RuntimeError("boom"))
    from_worker = ValueError("from a worker")
    from_worker.__pycert_traceback__ = "Traceback (on the worker)\nValueError: from a worker"
    window.show_error("Unexpected", from_worker)
    window.show_error("Expected", PyCertError("refused by the CA"))
    assert "RuntimeError: boom" in details[0]
    assert details[1].startswith("Traceback (on the worker)")
    assert details[2] == ""  # pyCertWiz's own errors are explained, not dumped
    # Cancel in the progress dialog: logged, not reported as a failure
    errors, finished = _capture_errors(monkeypatch, window), []

    def work(progress, stop_event):
        progress("waiting for the CA")
        stop_event.wait(10)
        raise PyCertError("cancelled")

    window.run_task("Slow step", work, finished.append)
    dialog = next(d for d in window.findChildren(ProgressDialog) if d.isVisible())
    qtbot.waitUntil(lambda: "waiting for the CA" in dialog.log.toPlainText(), timeout=5000)
    dialog.reject()  # the Cancel button / Escape
    wait_idle(qtbot, window)
    assert errors == [] and finished == []
    assert "Slow step: cancelled" in _log(window)


def test_check_now_runs_the_background_check(qtbot, window):
    results = []
    window.monitor.checked.connect(lambda report, _collected: results.append(report))
    window.check_now()
    qtbot.waitUntil(lambda: bool(results), timeout=30000)
    wait_idle(qtbot, window)
    assert "Checking the CA for pending requests" in _log(window)


# ---------------------------------------------------------------------------
# New requests (UK CA: manual approval, RA PINs)
# ---------------------------------------------------------------------------


def _script_wizard(monkeypatch, *, ca="", hosts=(), name="", own_pin="", preset="", directory="", wait=True):
    from pycert.gui import wizard as wizard_module
    from pycert.gui.wizard import PAGE_PIN

    def fake_exec(self):
        self.show()
        if ca:
            self.type_page.ca.setCurrentIndex(self.type_page.ca.findData(ca))
        if hosts:
            self.type_page.host.setChecked(True)
        self.next()
        if hosts:
            self.details_page.hosts.setPlainText("\n".join(hosts))
        else:
            self.details_page.name.setText(name)
        self.next()
        if preset:
            self.key_page.preset.setCurrentIndex(self.key_page.preset.findData(preset))
            self.key_page.directory.setText(directory)
        self.next()
        if self.currentId() == PAGE_PIN:
            if own_pin:
                self.pin_page.own.setChecked(True)
                self.pin_page.pin.setText(own_pin)
                self.pin_page.confirm.setText(own_pin)
            self.next()
        self.review_page.wait.setChecked(wait)
        assert self.review_page.validatePage(), self.review_page.error.text()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(wizard_module.NewRequestWizard, "exec", fake_exec)


def test_new_hosts_one_refused_by_the_ra(qtbot, monkeypatch, tmp_path, ca, ctx, issued, window):
    issued("jane doe")  # authenticates the host requests
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    ca.fail_next("/CSRs", status=202, body=ca._error_xml("refused by the RA"))
    window.refresh()
    _script_wizard(monkeypatch, hosts=("a.example.org", "b.example.org"), preset="grid-host", directory=str(tmp_path / "grid"))
    pins = _record_pins(monkeypatch)
    warnings = _capture(monkeypatch, "warning")
    window.new_request()
    wait_idle(qtbot, window)
    assert warnings and "a.example.org: " in warnings[0] and "refused by the RA" in warnings[0]
    assert ctx.store.get("a.example.org").status == "FAILED"
    submitted = ctx.store.get("b.example.org")
    assert submitted.status == "SUBMITTED" and submitted.deploy[0]["name"] == "grid-host"
    assert "b.example.org" in submitted.deploy[0]["cert"]  # several hosts: one directory each
    assert [name for name, _pin in pins[0]][-1] == "b.example.org"
    assert "pyCertWiz checks the CA in the background" in _log(window)
    assert window.detail.title.text() == "b.example.org"


def test_a_single_refused_request_is_reported(qtbot, monkeypatch, ca, ctx, window):
    ca.fail_next("/CSR", status=202, body=ca._error_xml("refused by the RA"))
    _script_wizard(monkeypatch, name="Refused Person", own_pin="ABCDEFGHJK23")
    errors = _capture_errors(monkeypatch, window)
    window.new_request()
    wait_idle(qtbot, window)
    assert errors and errors[0][0] == "The request could not be submitted" and "refused by the RA" in errors[0][1]


def test_new_hosts_all_refused_with_own_pin(qtbot, monkeypatch, ca, ctx, issued, window):
    issued("jane doe")
    for _ in range(2):
        ca.fail_next("/CSRs", status=202, body=ca._error_xml("refused by the RA"))
    window.refresh()
    _script_wizard(monkeypatch, hosts=("a.example.org", "b.example.org"), own_pin="ABCDEFGHJK23")
    pins = _record_pins(monkeypatch)
    warnings = _capture(monkeypatch, "warning")
    window.new_request()
    wait_idle(qtbot, window)
    assert pins == []  # the user chose the PIN: nothing to show
    assert warnings and warnings[0].count("refused by the RA") == 2
    assert {ctx.store.get(name).status for name in ("a.example.org", "b.example.org")} == {"FAILED"}


def test_cancelling_a_multi_host_request_stops_before_the_next_host(qtbot, monkeypatch, ca, ctx, issued, window):
    from pycert.gui.dialogs import ProgressDialog

    issued("jane doe")
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    ca.fail_next("/CSRs", status=503, delay=2.0)  # the CA is slow to answer the first request
    window.refresh()
    _script_wizard(monkeypatch, hosts=("a.example.org", "b.example.org"), own_pin="ABCDEFGHJK23")
    warnings = _capture(monkeypatch, "warning")
    window.new_request()
    dialog = next(d for d in window.findChildren(ProgressDialog) if d.isVisible())
    qtbot.waitUntil(lambda: "— a.example.org —" in dialog.log.toPlainText(), timeout=10000)
    dialog.reject()  # Cancel while the first host is being submitted
    wait_idle(qtbot, window)
    assert not ctx.store.exists("b.example.org")  # never requested
    assert warnings and "a.example.org" in warnings[0] and "b.example.org" not in warnings[0]


# ---------------------------------------------------------------------------
# New requests and renewals with an ACME CA (no RA approval, no PINs)
# ---------------------------------------------------------------------------

ACME = "sandbox-acme"


@pytest.fixture
def acme_window(qtbot, ca, config, window):
    """The window with a second CA: the sandbox ACME server (http-01 validated automatically)."""
    from pycert.config import new_acme_profile, validate_config, write_config
    from sandbox_ca.acme import ACMEServer

    server = ACMEServer(ca, port=0, challenge_mode="auto").start()
    try:
        profile = new_acme_profile(
            ACME, server.directory_url(), display_name="Sandbox ACME", contact=["ops@example.org"],
            terms_agreed=True, tls_trust="chain",
        )
        profile.chain = list(config.chain)
        profile.ca.retries = 0
        profile.acme.poll_interval = 0.1
        profile.acme.validation_timeout = 20
        profile.acme.http_bind = "127.0.0.1"  # never port 80
        profile.acme.http_port = _closed_port()
        config.add_ca(profile)
        validate_config(config)
        write_config(config.path, config)
        window.reload_config()
        wait_idle(qtbot, window)
        yield window
        wait_idle(qtbot, window, timeout=60000)
    finally:
        server.stop()


def test_acme_request_waits_and_collects(qtbot, monkeypatch, acme_window):
    window = acme_window
    _script_wizard(monkeypatch, ca=ACME, hosts=("acme.example.org",), wait=True)
    pins = _record_pins(monkeypatch)
    window.new_request()
    wait_idle(qtbot, window, timeout=60000)
    state = window.ctx.store.get("acme.example.org")
    assert state.ca == ACME and state.cert.sha256 and state.p12_path
    assert pins == [] and "Issued: acme.example.org" in _log(window)


def test_acme_request_without_waiting(qtbot, monkeypatch, acme_window):
    window = acme_window
    _script_wizard(monkeypatch, ca=ACME, hosts=("later.example.org",), wait=False)
    window.new_request()
    wait_idle(qtbot, window, timeout=60000)
    state = window.ctx.store.get("later.example.org")
    assert state.ca == ACME and not state.cert.sha256
    # no RA is involved, so there is no "pyCertWiz checks the CA in the background" note
    assert "Issued:" not in _log(window) and "checks the CA in the background" not in _log(window)


def test_acme_renewal_waits_for_the_new_certificate(qtbot, monkeypatch, config, ctx, acme_window):
    from pycert.gui import app as app_module
    from pycert.workflow import RequestSpec, create_request

    window = acme_window
    spec = RequestSpec.build(config, "renew.example.org", type="host", ca=ACME, key_algorithm="ec")
    original = create_request(ctx, spec, wait=True, interval=0.1, timeout=30, progress=NOOP)
    window.refresh(select=original.alias)
    monkeypatch.setattr(app_module.RenewDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    pins = _record_pins(monkeypatch)
    window.perform("renew")
    wait_idle(qtbot, window, timeout=60000)
    renewed = ctx.store.get(original.alias)
    assert not renewed.renewal and renewed.cert.serial != original.cert.serial
    assert pins == [] and f"Renewal for {original.alias}: " in _log(window)


# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------


def test_deployment_targets_added_without_deploying_and_errors(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from pycert.gui import app as app_module

    user = issued("deploy person")
    window.refresh(select=user.alias)
    cert_file = tmp_path / "web" / "cert.pem"

    def add(self):
        self.target = {"name": "web", "cert": str(cert_file)}
        self.deploy_now.setChecked(False)
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(app_module.DeployTargetDialog, "exec", add)
    errors = _capture_errors(monkeypatch, window)
    window.perform("deploy_add")
    assert [t["name"] for t in ctx.store.get(user.alias).deploy] == ["web"]
    assert not cert_file.exists() and not window.runner.busy  # added, not deployed
    window.perform("deploy_add")  # the same name again
    assert errors == [("Could not add the target", f"'{user.alias}' already has a deployment target called 'web'")]
    _capture(monkeypatch, "question", QMessageBox.StandardButton.No)
    window.perform("deploy_remove:web")  # not confirmed
    assert [t["name"] for t in ctx.store.get(user.alias).deploy] == ["web"]
    _capture(monkeypatch, "question", QMessageBox.StandardButton.Yes)
    window.perform("deploy_remove:elsewhere")
    assert errors[-1] == ("Could not remove the target", f"'{user.alias}' has no deployment target called 'elsewhere'")


# ---------------------------------------------------------------------------
# Renewals
# ---------------------------------------------------------------------------


def test_renew_refused_while_a_renewal_is_in_flight(qtbot, monkeypatch, ca, ctx, issued, window):
    from pycert.workflow import renew

    user = issued("renewing person")
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    renew(ctx, user.alias, progress=NOOP)
    window.refresh(select=user.alias)
    infos = _capture(monkeypatch, "information")
    window.perform("renew")
    assert infos == ["A renewal is already in progress for this certificate."] and not window.runner.busy


def test_renew_due_reports_a_store_error(monkeypatch, window):
    from pycert import workflow

    def broken(*_args, **_kwargs):
        raise PyCertError("the store is locked")

    monkeypatch.setattr(workflow, "renew_due", broken)
    errors = _capture_errors(monkeypatch, window)
    window.renew_due()
    assert errors == [("Could not list renewals", "the store is locked")]


def test_renew_due_can_be_declined(qtbot, monkeypatch, ca, ctx, issued, window):
    ca.valid_days = 10
    user = issued("jane doe")
    questions = _capture(monkeypatch, "question", QMessageBox.StandardButton.No)
    window.renew_due()
    assert questions and "jane doe" in questions[0]
    assert not window.runner.busy and not ctx.store.get(user.alias).renewal


def test_renew_due_labels_each_pin_with_its_certificate(qtbot, monkeypatch, ca, ctx, issued, window):
    ca.valid_days = 10
    first, second = issued("jane doe"), issued("john q smith")
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    pins = _record_pins(monkeypatch)
    warnings = _capture(monkeypatch, "warning")
    window.renew_due()
    wait_idle(qtbot, window)
    assert ctx.store.get(first.alias).renewal and ctx.store.get(second.alias).renewal
    assert warnings == []
    assert len(pins) == 1 and sorted(name for name, _pin in pins[0]) == ["jane doe", "john q smith"]


def test_renew_due_reports_failures(qtbot, monkeypatch, ca, ctx, issued, window):
    ca.valid_days = 10
    user = issued("forgotten person")
    ca.reset()  # the CA no longer has a record of it
    pins = _record_pins(monkeypatch)
    warnings = _capture(monkeypatch, "warning")
    window.renew_due()
    wait_idle(qtbot, window)
    assert pins == []
    assert warnings and warnings[0].startswith(f"{user.alias}: cannot renew")
    assert not ctx.store.get(user.alias).renewal


# ---------------------------------------------------------------------------
# Delete, notifications, about, configuration reload
# ---------------------------------------------------------------------------


def test_delete_reports_a_file_system_error(monkeypatch, ctx, issued, window):
    user = issued("locked files")
    window.refresh(select=user.alias)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: (user.alias, True)))

    def read_only(_state):
        raise PermissionError("read-only folder")

    monkeypatch.setattr(window.ctx.store, "delete", read_only)
    errors = _capture_errors(monkeypatch, window)
    window.perform("delete")
    assert errors == [("Could not delete", "read-only folder")]
    assert ctx.store.exists(user.alias)


def test_notification_can_show_the_folder(monkeypatch, tmp_path, window):
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toLocalFile()) or True))

    def click_show_in_folder(self):
        for candidate in self.buttons():
            if self.buttonRole(candidate) == QMessageBox.ButtonRole.ActionRole:
                candidate.click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", click_show_in_folder)
    window.notify_done("Exported", "one file", str(tmp_path / "out" / "cert.p12"))
    assert opened == [str(tmp_path / "out")]


def test_about_box(monkeypatch, config, window):
    shown = []
    monkeypatch.setattr(QMessageBox, "about", staticmethod(lambda parent, title, text: shown.append((title, text))))
    window.show_about()
    assert shown[0][0] == "About pyCertWiz" and str(config.path) in shown[0][1]


def test_reload_reports_a_broken_configuration(monkeypatch, config, window):
    errors = _capture_errors(monkeypatch, window)
    original = config.path.read_text()
    config.path.write_text("[ca\nbase_url = ")
    try:
        window.reload_config()
    finally:
        config.path.write_text(original)
    assert errors and errors[0][0] == "The configuration could not be loaded"
    assert window.cfg.path == config.path  # the previous configuration stays in use


# ---------------------------------------------------------------------------
# CA reachability
# ---------------------------------------------------------------------------


def test_unreachable_cas_are_flagged_and_cleared(qtbot, monkeypatch, issued, window):
    from pycert.config import CAProfile
    from pycert.gui.models import COL_CA

    issued("jane doe")
    window.cfg.add_ca(CAProfile(window.cfg, "plugin-ca", kind="not-installed", display_name="Plugin CA"))
    window.refresh()
    assert not window.table.isColumnHidden(COL_CA)  # several CAs: the CA column is useful
    window.ping_cas()
    wait_idle(qtbot, window)
    assert window._banner_kind == "unreachable" and "Cannot reach Plugin CA" in window.banner.text.text()
    assert "online" in window.status_ca.text()
    assert "CA 'plugin-ca' is unreachable: unknown CA kind 'not-installed'" in _log(window)
    window.refresh()
    assert window._banner_kind == "unreachable" and window.banner.isVisible()  # kept until the CA is back
    # the primary CA goes down as well
    window.cfg.remove_ca("plugin-ca")
    url = window.cfg.ca.base_url
    window.cfg.ca.base_url = f"https://127.0.0.1:{_closed_port()}"
    before = len(_log(window))
    window.ping_cas()
    wait_idle(qtbot, window)
    assert "unreachable" in window.status_ca.text() and "Reachable:" not in _log(window)[before:]
    # back online: the warning goes away
    window.cfg.ca.base_url = url
    window.ping_cas()
    wait_idle(qtbot, window)
    assert "online" in window.status_ca.text()
    assert window._banner_kind == "" and not window.banner.isVisible()


# ---------------------------------------------------------------------------
# Linked Java keystores
# ---------------------------------------------------------------------------


class _RecordingMenu(QMenu):
    """Records the menu instead of showing it; optionally 'clicks' one entry."""

    shown: "list[list[str]]" = []
    choose = ""

    def exec(self, *_args):
        texts = [action.text() for action in self.actions() if not action.isSeparator()]
        _RecordingMenu.shown.append(texts)
        for action in self.actions():
            if action.text() == _RecordingMenu.choose:
                action.trigger()
                return action
        return None


def test_keystore_menu_sync_reports_and_unlink(qtbot, monkeypatch, tmp_path, java_keystore, window):
    from test_keystore import _entry_parts, build_keystore

    from pycert import keystore as ks
    from pycert.gui import app as app_module

    path, password = java_keystore
    linked, _keystore = ks.link_keystore(window.ctx, path, password, name="site")
    ks.sync(window.ctx, linked)
    window.reload_config()
    wait_idle(qtbot, window)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: pytest.fail("already unlocked")))
    window.unlock_keystores_at_startup()  # unlocked this session: nothing to ask
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toLocalFile()) or True))
    monkeypatch.setattr(app_module, "QMenu", _RecordingMenu)
    _RecordingMenu.shown = []

    def right_click(key, choose=""):
        _RecordingMenu.choose = choose
        window._nav_menu(window.nav.visualItemRect(window._nav_items[key]).center())

    right_click("keystore:site", "Show the keystore file")
    assert opened == [str(path.parent)]
    right_click("all")  # not a keystore: no menu
    window._nav_menu(QPoint(5, window.nav.viewport().height() - 2))  # below the items: no menu
    assert _RecordingMenu.shown == [["Synchronise now", "Show the keystore file", "Unlink…"]]
    # nothing changed: a sync is skipped quietly
    before = _log(window)
    right_click("keystore:site", "Synchronise now")
    wait_idle(qtbot, window)
    window.sync_keystores()
    wait_idle(qtbot, window)
    assert "not synchronised" not in _log(window)[len(before):]
    # a duplicated entry is reported as a problem with the file
    h1 = window.ctx.store.get("h1.example.org")
    parts = _entry_parts(window.ctx, h1)
    build_keystore(path, [("h1.example.org", *parts), ("h1.example.org", *parts)], password=password)
    window.sync_keystores()
    wait_idle(qtbot, window)
    assert "Keystore 'site': entry 'h1.example.org' appears more than once" in _log(window)
    # its passphrase was changed elsewhere (keytool -storepasswd): reported, not raised
    build_keystore(path, [("h1.example.org", *parts)], password="changed elsewhere")
    window.sync_keystores()
    wait_idle(qtbot, window)
    assert "Keystore 'site' not synchronised" in _log(window)
    # Java tools replace the file: while it is missing only its folder is watched
    path.unlink()
    window._watch_keystores()
    window._sync_timer.stop()  # the deletion's change notification is not part of this test
    assert window.watcher.directories() == [str(path.parent)]
    # locked: the menu offers to unlock it
    ks.lock(window.ctx, "site")
    window._populate_nav()
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False)))
    right_click("keystore:site", "Unlock…")
    assert _RecordingMenu.shown[-1][0] == "Unlock…" and not ks.is_unlocked(window.ctx, "site")
    # unlinking needs a confirmation
    _capture(monkeypatch, "question", QMessageBox.StandardButton.No)
    right_click("keystore:site", "Unlink…")
    assert [link.name for link in window.cfg.keystores] == ["site"]
    _capture(monkeypatch, "question", QMessageBox.StandardButton.Yes)
    errors = _capture_errors(monkeypatch, window)
    window.unlink_keystore("elsewhere")
    assert errors and errors[0][0] == "Could not unlink the keystore"
