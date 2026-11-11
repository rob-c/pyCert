"""Qt GUI tests (pytest-qt, offscreen platform; no display needed).

They drive the real main window, dialogs and wizard against the mock CA, with
modal ``exec()`` calls replaced so nothing blocks.
"""

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from gui_support import close_popup_soon as _close_popup_soon  # noqa: E402
from gui_support import wait_idle as _wait_idle  # noqa: E402
from gui_support import walk_menu as _walk_menu  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QDialog, QMessageBox  # noqa: E402

from pycert import certs  # noqa: E402
from pycert.errors import PyCertError  # noqa: E402
from pycert.store import STATUS_SUBMITTED  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")


def _visible_aliases(main):
    proxy = main.proxy
    from pycert.gui.models import StateRole

    return [proxy.index(row, 0).data(StateRole).alias for row in range(proxy.rowCount())]


# ---------------------------------------------------------------------------
# Availability and entry points
# ---------------------------------------------------------------------------


def test_gui_available_and_main_without_pyside(monkeypatch, capsys):
    import pycert.gui as gui

    assert gui.gui_available() is None
    monkeypatch.setattr(gui, "gui_available", lambda: "the graphical interface needs PySide6")
    assert gui.main(["--config", "/nonexistent"]) == 1
    assert "PySide6" in capsys.readouterr().err


def test_cli_gui_reports_missing_dependency(monkeypatch, config):
    import argparse

    import pycert.gui as gui
    from pycert import cli
    from pycert.errors import PyCertError

    monkeypatch.setattr(gui, "gui_available", lambda: "no display")
    with pytest.raises(PyCertError, match="no display"):
        cli.cmd_gui(argparse.Namespace(config=str(config.path)))


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


def test_empty_store_shows_empty_state(window):
    assert window.stack.currentIndex() == 0
    assert window.cards["valid"].value.text() == "0"


def test_lists_certificates_and_renders_details(qtbot, config, ctx, issued, window):
    user = issued("jane doe", description="Grid user")
    window.refresh()
    assert window.stack.currentIndex() == 1
    assert _visible_aliases(window) == [user.alias]
    assert window.cards["valid"].value.text() == "1"
    detail = window.detail
    assert detail.title.text() == "jane doe"
    assert "User certificate" in detail.subtitle.text()
    assert "Valid" in detail.pill.text()
    assert detail.fields["description"].text() == "Grid user"
    assert detail.fields["fingerprint"].text().replace(" ", "") == user.cert.sha256
    assert "BEGIN" not in detail.fields["subject"].text()  # never PEM bodies or keys
    assert detail.primary.property("action") == "renew"
    # chain tab shows leaf + issuers
    assert detail.chain_tree.topLevelItemCount() == 1
    assert detail.history.count() >= 1


def test_filters_views_and_search(qtbot, ctx, issued, window):
    user = issued("jane doe")
    host = issued("web1.example.org", type="host", auth_alias=user.alias)
    window.refresh()
    assert set(_visible_aliases(window)) == {user.alias, host.alias}
    window._select_view("hosts")
    assert _visible_aliases(window) == [host.alias]
    window._select_view("personal")
    assert _visible_aliases(window) == [user.alias]
    window._select_view("pending")
    assert _visible_aliases(window) == []
    window._select_view("all")
    window.search.setText("web1")
    assert _visible_aliases(window) == [host.alias]
    window.search.setText("")
    window._apply_view("ca:" + ctx.config.primary_profile.name, "UK")
    assert len(_visible_aliases(window)) == 2
    window._select_view("all", categories={"valid"})
    assert len(_visible_aliases(window)) == 2


def test_pending_request_is_collected_by_check(qtbot, ca, config, ctx, window):
    from pycert.workflow import RequestSpec, create_request

    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    spec = RequestSpec.build(config, "pending person", pin="1234567890AB")
    state = create_request(ctx, spec, progress=lambda _m: None)
    window.refresh(select=state.alias)
    assert window.cards["pending"].value.text() == "1"
    assert window.detail.primary.property("action") == "wait"
    window.check_selected()
    _wait_idle(qtbot, window)
    assert ctx.store.get(state.alias).status == STATUS_SUBMITTED
    # now the CA signs it: a check collects, verifies and exports
    ca.approve_all()
    ca.sign_all()
    window.check_selected()
    _wait_idle(qtbot, window)
    collected = ctx.store.get(state.alias)
    assert collected.cert.sha256 and collected.p12_path
    assert window.cards["valid"].value.text() == "1"


def test_background_monitor_collects_and_notifies(qtbot, ca, config, ctx, window):
    from pycert.gui.tray import TrayController
    from pycert.workflow import RequestSpec, create_request

    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(config, "monitored person", pin="1234567890AB")
    state = create_request(ctx, spec, progress=lambda _m: None)
    results = []
    window.monitor.checked.connect(lambda report, collected: results.append((report, collected)))
    window.monitor.run_now()
    qtbot.waitUntil(lambda: bool(results), timeout=30000)
    report, collected = results[0]
    assert collected == [state.alias]
    assert report.level == "OK"
    notes = TrayController.update(window.tray, report, collected)
    assert notes and "issued" in notes[0][0].lower()


def test_actions_copy_edit_auto_renew_export_verify(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QInputDialog

    from pycert.gui import app as app_module

    user = issued("jane doe")
    window.refresh(select=user.alias)
    window.perform("copy_fingerprint")
    assert QGuiApplication.clipboard().text() == user.cert.sha256
    window.perform("copy_pem")
    assert "BEGIN CERTIFICATE" in QGuiApplication.clipboard().text()
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("Lab laptop", True)))
    window.perform("edit")
    assert ctx.store.get(user.alias).description == "Lab laptop"
    window.detail.auto_renew.setChecked(False)
    assert ctx.store.get(user.alias).auto_renew is False
    reports = []
    monkeypatch.setattr(app_module.ReportDialog, "exec", lambda self: reports.append(self.table.rowCount()) or 1)
    window.perform("verify")
    _wait_idle(qtbot, window)
    assert reports and reports[-1] >= 4
    exported = tmp_path / "exported.p12"

    def fill_export(self):
        self.destination.setText(str(exported))
        self.password.setText("a new export passphrase")
        self.confirm.setText("a new export passphrase")
        self._accept()
        return self.result()

    monkeypatch.setattr(app_module.ExportDialog, "exec", fill_export)
    window.perform("export")
    _wait_idle(qtbot, window)
    from pycert.p12 import read_pkcs12

    assert read_pkcs12(exported, "a new export passphrase").cert is not None


def test_renew_flow_shows_pin_and_collects(qtbot, monkeypatch, ca, ctx, issued, window):
    from pycert.gui import app as app_module

    user = issued("renew me")
    window.refresh(select=user.alias)
    pins = []
    monkeypatch.setattr(app_module.RenewDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    monkeypatch.setattr(app_module.PinDialog, "exec", lambda self: pins.append(self) or 1)
    window.perform("renew")
    _wait_idle(qtbot, window)
    renewed = ctx.store.get(user.alias)
    assert renewed.renewal is True
    assert pins, "the RA PIN must be shown once"
    window.perform("wait")
    _wait_idle(qtbot, window)
    assert ctx.store.get(user.alias).renewal is False


def test_revoke_dialog_requires_typed_alias_and_revokes(qtbot, monkeypatch, ctx, issued, window):
    from pycert.gui import app as app_module
    from pycert.gui.dialogs import RevokeDialog

    user = issued("revoke me")
    dialog = RevokeDialog(window, ctx.store.get(user.alias), ("unspecified", "keyCompromise"))
    assert not dialog.ok.isEnabled()
    dialog.confirm.setText(user.alias)
    assert dialog.ok.isEnabled()
    assert dialog.reason_code() == "unspecified"
    window.refresh(select=user.alias)
    monkeypatch.setattr(app_module.RevokeDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    window.perform("revoke")
    _wait_idle(qtbot, window)
    assert ctx.store.get(user.alias).status == "REVOKED"


def test_delete_requires_exact_name(monkeypatch, ctx, issued, window):
    from PySide6.QtWidgets import QInputDialog

    user = issued("delete me")
    window.refresh(select=user.alias)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("wrong", True)))
    window.perform("delete")
    assert ctx.store.exists(user.alias)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: (user.alias, True)))
    window.perform("delete")
    assert not ctx.store.exists(user.alias)
    assert window.stack.currentIndex() == 0


def test_deploy_target_dialog_and_deploy(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from pycert.gui import app as app_module
    from pycert.gui.dialogs import DeployTargetDialog

    user = issued("jane doe")
    state = ctx.store.get(user.alias)
    dialog = DeployTargetDialog(window, state)
    dialog.preset.setCurrentIndex(dialog.preset.findData("globus-user"))
    dialog.directory.setText(str(tmp_path / "globus"))
    dialog.key_mode.setText("0666")
    dialog._accept()
    assert dialog.target is None and "other users" in dialog.error.text()
    dialog.key_mode.setText("0400")
    dialog.deploy_now.setChecked(True)
    dialog._accept()
    assert dialog.target["cert"].endswith("usercert.pem")

    created = dialog.target

    def fake_exec(self):
        self.target = created
        self.deploy_now.setChecked(True)
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(app_module.DeployTargetDialog, "exec", fake_exec)
    monkeypatch.setattr(app_module.ReportDialog, "exec", lambda self: 1)
    window.refresh(select=user.alias)
    window.perform("deploy_add")
    _wait_idle(qtbot, window)
    cert_file = tmp_path / "globus" / "usercert.pem"
    key_file = tmp_path / "globus" / "userkey.pem"
    assert cert_file.is_file() and key_file.is_file()
    assert (key_file.stat().st_mode & 0o777) == 0o400
    assert certs.fingerprint(certs.load_certificate(cert_file.read_bytes())) == user.cert.sha256
    assert window.detail.deploy_table.rowCount() == 1
    assert not window.table.isColumnHidden(6)
    window.perform("deploy_remove:globus-user")
    assert ctx.store.get(user.alias).deploy == []


def test_settings_dialog_saves_identity_and_ca_profiles(qtbot, monkeypatch, config, window):
    from PySide6.QtWidgets import QInputDialog

    from pycert.config import load_config
    from pycert.gui.settings import SettingsDialog, pref

    dialog = SettingsDialog(window, str(config.path))
    qtbot.addWidget(dialog)
    dialog.email.setText("new@example.org")
    answers = iter([("letsencrypt-staging", True), ("https://acme.example.org/directory", True)])
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: next(answers)))
    dialog._add_acme()
    assert "letsencrypt-staging" in dialog.config.cas
    dialog.acme_tos.setChecked(True)
    dialog.acme_mode.setCurrentText("webroot")
    dialog.acme_webroot.setText("/var/www/html")
    dialog.appearance.setCurrentIndex(dialog.appearance.findData("dark"))
    dialog.warn_days.setValue(45)
    dialog._save()
    assert dialog.saved, dialog.error.text()
    reloaded = load_config(config.path)
    assert reloaded.identity.email == "new@example.org"
    profile = reloaded.profile_for("letsencrypt-staging")
    assert profile.kind == "acme" and profile.acme.terms_agreed and profile.acme.webroot == "/var/www/html"
    assert pref("appearance", "system") == "dark"
    assert pref("warn_days", 30) == 45
    # an invalid threshold combination is refused
    dialog2 = SettingsDialog(window, str(config.path))
    dialog2.crit_days.setValue(90)
    dialog2.warn_days.setValue(10)
    dialog2._save()
    assert not dialog2.saved and "critical" in dialog2.error.text()


def test_settings_reload_updates_window(monkeypatch, config, window):
    from pycert.gui import app as app_module

    def fake_exec(self):
        self.saved = True
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(app_module.SettingsDialog, "exec", fake_exec)
    window.open_settings()
    assert window.cfg.path == config.path


# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------


def test_wizard_builds_validated_specs(qtbot, ctx, issued, window):
    from pycert.errors import PyCertError
    from pycert.gui.wizard import PAGE_DETAILS, NewRequestWizard

    wizard = NewRequestWizard(window, ctx, window.runner)
    qtbot.addWidget(wizard)
    wizard.show()
    assert wizard.type_page.user.isChecked()
    wizard.next()
    assert wizard.currentId() == PAGE_DETAILS
    details = wizard.details_page
    with pytest.raises(PyCertError):
        details.build_specs()
    details.name.setText("Jane")
    assert not details.validatePage() and details.error.text()
    details.name.setText("Jane Doe")
    specs = details.build_specs(pin="ABCDEFGHJK23", key={"key_algorithm": "rsa", "rsa_bits": 2048, "ec_curve": ""})
    assert specs[0].cn == "jane doe" and specs[0].rsa_bits == 2048

    user = issued("auth person")
    host_wizard = NewRequestWizard(window, ctx, window.runner, cert_type="host")
    qtbot.addWidget(host_wizard)
    host_wizard.show()
    assert host_wizard.type_page.host.isChecked()
    host_wizard.next()
    host_details = host_wizard.details_page
    assert host_details.auth.count() == 1
    host_details.hosts.setPlainText("a.example.org\nb.example.org\n")
    specs = host_details.build_specs()
    assert [s.cn for s in specs] == ["a.example.org", "b.example.org"]
    assert all(s.auth_alias == user.alias for s in specs)
    host_details.extra_dns.setText("c.example.org")
    with pytest.raises(PyCertError, match="single host"):
        host_details.build_specs()
    host_details.hosts.setPlainText("a.example.org\na.example.org")
    host_details.extra_dns.clear()
    with pytest.raises(PyCertError, match="twice"):
        host_details.build_specs()


def test_wizard_pin_and_review_pages(qtbot, ctx, window):
    from pycert.gui.wizard import PAGE_PIN, PAGE_REVIEW, NewRequestWizard

    wizard = NewRequestWizard(window, ctx, window.runner)
    qtbot.addWidget(wizard)
    wizard.show()
    wizard.next()
    wizard.details_page.name.setText("Jane Doe")
    wizard.next()
    assert wizard.key_page.nextId() == PAGE_PIN
    wizard.next()
    pin_page = wizard.pin_page
    pin_page.own.setChecked(True)
    pin_page.pin.setText("short")
    assert not pin_page.validatePage()
    pin_page.pin.setText("ABCDEFGHJK23")
    pin_page.confirm.setText("ABCDEFGHJK2X")
    assert not pin_page.validatePage()
    pin_page.confirm.setText("ABCDEFGHJK23")
    assert pin_page.validatePage()
    wizard.next()
    assert wizard.currentId() == PAGE_REVIEW
    assert "jane doe" in wizard.review_page.summary.text().lower() or "Jane Doe" in wizard.review_page.summary.text()
    assert wizard.review_page.validatePage()
    assert wizard.specs[0].pin == "ABCDEFGHJK23"


def test_new_request_end_to_end_with_pin_dialog(qtbot, monkeypatch, ca, ctx, window):
    from pycert.gui import app as app_module
    from pycert.gui import wizard as wizard_module

    ca.auto_approve = True
    ca.sign_after_polls = 0

    def fake_exec(self):
        self.show()
        self.next()
        self.details_page.name.setText("Wizard Person")
        self.next()
        self.next()
        self.next()
        assert self.review_page.validatePage()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(wizard_module.NewRequestWizard, "exec", fake_exec)
    shown = []
    monkeypatch.setattr(app_module.PinDialog, "exec", lambda self: shown.append(self) or 1)
    window.new_request()
    _wait_idle(qtbot, window)
    state = ctx.store.get("wizard person")
    assert state.status == STATUS_SUBMITTED
    assert shown and shown[0].copy_buttons


# ---------------------------------------------------------------------------
# Bundle inspector, import and dialogs
# ---------------------------------------------------------------------------


def test_bundle_inspector_round_trip(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from pycert.gui.bundle import BundleInspector

    user = issued("bundle person")
    p12 = Path(ctx.store.get(user.alias).p12_path)
    inspector = BundleInspector(window)
    qtbot.addWidget(inspector)
    inspector.path.setText(str(p12))
    inspector.password.setText("wrong")
    assert not inspector.load(auto=True)
    inspector.password.setText(ctx.p12_passphrase())
    assert inspector.load(auto=True)
    assert inspector.table.rowCount() >= 2
    assert "BEGIN CERTIFICATE" in inspector.details.toPlainText()
    assert "PRIVATE KEY" not in inspector.details.toPlainText()
    pem = inspector.save_pem(str(tmp_path / "all.pem"))
    assert pem and Path(pem).read_text().count("BEGIN CERTIFICATE") == inspector.table.rowCount()
    java = inspector.save_java(str(tmp_path / "java.p12"), password="java-password")
    assert java and Path(java).is_file()
    assert inspector.update_in_place(confirm=False, password=ctx.p12_passphrase())
    assert (p12.parent / (p12.name + ".bak")).is_file()


def test_import_flow(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from pycert.gui import app as app_module

    user = issued("import source")
    p12 = Path(ctx.store.get(user.alias).p12_path)
    copy = tmp_path / "copy.p12"
    copy.write_bytes(p12.read_bytes())

    def fake_exec(self):
        self.path.setText(str(copy))
        self.password.setText(ctx.p12_passphrase())
        self.alias.setText("imported copy")
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(app_module.ImportDialog, "exec", fake_exec)
    window.import_p12()
    _wait_idle(qtbot, window)
    assert ctx.store.get("imported copy").status == "IMPORTED"


def test_pin_progress_and_report_dialogs(qtbot, window):
    from pycert.gui.dialogs import PinDialog, ProgressDialog, ReportDialog

    pin = PinDialog(window, [("a.example.org", "AAAA-BBBB-CCCC"), ("b.example.org", "DDDD-EEEE-FFFF")])
    qtbot.addWidget(pin)
    pin.copy_buttons[0].click()
    from PySide6.QtGui import QGuiApplication

    assert QGuiApplication.clipboard().text() == "AAAA-BBBB-CCCC"
    report = ReportDialog(window, "t", "summary", [("ok", "a", "b"), ("fail", "c", "d")], ok=False)
    qtbot.addWidget(report)
    assert report.table.rowCount() == 2
    results = []

    def slow(progress, stop_event):
        progress("step one")
        while not stop_event.is_set():
            stop_event.wait(0.05)
        raise RuntimeError("cancelled")

    dialog = ProgressDialog(window, "Slow", window.runner, slow, results.append, results.append)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: "step one" in dialog.log.toPlainText(), timeout=5000)
    dialog.reject()  # cancels instead of closing while running
    _wait_idle(qtbot, window)
    assert results and "cancelled" in str(results[0])


def test_prompter_on_ui_thread(monkeypatch, window):
    assert window.prompter("Publish TXT", "Add _acme-challenge") is True


def test_theme_switch_and_icons(qtbot, window):
    from PySide6.QtCore import QCoreApplication, QEvent

    from pycert.gui import icons, theme

    # Re-styling the whole application must not race widgets still being deleted.
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    window.set_appearance("dark")
    assert theme.tokens().dark
    window.set_appearance("light")
    assert not theme.tokens().dark
    for name in icons.ICON_NAMES:
        assert not icons.icon(name).isNull()
    assert not icons.app_icon().isNull()
    assert theme.status_color("expired") == theme.tokens().expired


def test_ping_cas_updates_status(qtbot, window, ca):
    window.ping_cas()
    _wait_idle(qtbot, window)
    assert "online" in window.status_ca.text()


def test_close_cancels_background_work(qtbot, window):
    window.quit_application()
    assert not window.isVisible()


def test_context_menu_and_nav_tools(qtbot, monkeypatch, issued, window):
    from pycert.gui import app as app_module

    issued("menu person")
    window.refresh()
    opened = []
    monkeypatch.setattr(app_module.MainWindow, "run_doctor", lambda self: opened.append("doctor"))
    window._nav_clicked(window.nav.findItems("Diagnostics", Qt.MatchFlag.MatchExactly)[0])
    assert opened == ["doctor"]


# ---------------------------------------------------------------------------
# Java keystores as a store
# ---------------------------------------------------------------------------


def test_link_keystore_from_the_gui(qtbot, monkeypatch, ctx, java_keystore, window):
    from pycert.gui import dialogs

    path, password = java_keystore

    def fake_exec(self):
        assert self.path.text() == str(path)
        self.name.setText("site")
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(dialogs.LinkKeystoreDialog, "exec", fake_exec)
    window.link_keystore(str(path), password)
    _wait_idle(qtbot, window)
    assert [link.name for link in window.cfg.keystores] == ["site"]
    assert "keystore:site" in window._nav_items
    assert sorted(_visible_aliases(window)) == ["h1.example.org", "h2.example.org"]
    window.refresh(select="h1.example.org")
    assert window.detail.fields["keystore"].text().startswith("site · alias")
    # an external change to the file is picked up by a sync
    from pycert import keystore as ks

    with ks.open_keystore(path, password) as keystore:
        keystore.remove("h2.example.org")
    window.sync_keystores("site")
    _wait_idle(qtbot, window)
    assert window.ctx.store.get("h2.example.org").keystore == {}
    window._keystore_file_changed(str(path))
    assert window._sync_timer.isActive()
    window.unlink_keystore("site")
    assert window.cfg.keystores == []


def test_link_dialog_validation(window, java_keystore):
    from pycert.gui.dialogs import LinkKeystoreDialog

    dialog = LinkKeystoreDialog(window, window.cfg)
    dialog._accept()
    assert "keystore file" in dialog.error.text()
    dialog.path.setText(str(java_keystore[0]))
    dialog._accept()
    assert "passphrase" in dialog.error.text()


def test_bundle_inspector_import_all(qtbot, ctx, java_keystore, window):
    from pycert.gui.bundle import BundleInspector

    path, password = java_keystore
    inspector = BundleInspector(window, path)
    qtbot.addWidget(inspector)
    inspector.password.setText(password)
    assert inspector.load()
    assert inspector.import_button.isEnabled() and inspector.link_button.isEnabled()
    requests = []
    inspector.link_requested.connect(lambda p, pw: requests.append((p, pw)))
    inspector.link_button.click()
    assert requests == [(str(path), password)]
    window.import_keystore_entries(str(path), password)
    _wait_idle(qtbot, window)
    assert ctx.store.exists("h1.example.org") and ctx.store.exists("h2.example.org")


def test_wizard_offers_linked_keystores(qtbot, ctx, issued, java_keystore, window):
    from pycert import keystore as ks
    from pycert.gui.wizard import NewRequestWizard

    ks.link_keystore(ctx, java_keystore[0], java_keystore[1], name="site")
    issued("auth person")
    wizard = NewRequestWizard(window, ctx, window.runner, cert_type="host")
    qtbot.addWidget(wizard)
    wizard.show()
    wizard.next()
    wizard.details_page.hosts.setPlainText("new.example.org")
    wizard.next()
    page = wizard.key_page
    assert page.keystore_row.isVisibleTo(wizard)
    page.keystore.setCurrentIndex(page.keystore.findData("site"))
    specs = wizard.details_page.build_specs(key=page.key_options())
    assert specs[0].keystore == "site"


# ---------------------------------------------------------------------------
# Key protection and keystore unlocking
# ---------------------------------------------------------------------------


def test_key_protection_dialog_choices(qtbot, monkeypatch, window):
    from PySide6.QtWidgets import QInputDialog

    from pycert.gui.dialogs import KeyProtectionDialog

    dialog = KeyProtectionDialog(window, "Save", "the key", directory="/tmp")
    qtbot.addWidget(dialog)
    assert dialog.own.isChecked()  # a new passphrase is the default; there is no "saved secret" choice
    dialog._accept()
    assert "Enter a new passphrase" in dialog.error.text()
    dialog.password.setText("short")
    dialog.confirm.setText("short")
    dialog._accept()
    assert "at least 8" in dialog.error.text()
    dialog.password.setText("long enough a")
    dialog.confirm.setText("long enough b")
    dialog._accept()
    assert "do not match" in dialog.error.text()
    dialog.confirm.setText("long enough a")
    dialog._accept()
    assert dialog.chosen_password == "long enough a"
    dialog.none.setChecked(True)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("yes", True)))
    dialog._accept()
    assert dialog.no_passphrase is False and "Not confirmed" in dialog.error.text()
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("unencrypted", True)))
    dialog._accept()
    assert dialog.no_passphrase is True and dialog.chosen_password is None


def test_save_pem_and_install_use_the_protection_choice(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from pycert.gui import app as app_module

    user = issued("jane doe")
    window.refresh(select=user.alias)

    def fake_export(self):
        assert self.selected_format().name == "pem-files"
        self.destination.setText(str(tmp_path / "out"))
        self.password.setText("chosen passphrase")
        self.confirm.setText("chosen passphrase")
        self._accept()
        return self.result()

    def fake_protect(self):
        self.directory.setText(str(tmp_path / "out"))
        self.chosen_password = "chosen passphrase"
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(app_module.ExportDialog, "exec", fake_export)
    monkeypatch.setattr(app_module.KeyProtectionDialog, "exec", fake_protect)
    window.perform("save_pem")
    _wait_idle(qtbot, window)
    key = tmp_path / "out" / "jane_doe.key"
    assert certs.load_private_key(key.read_bytes(), "chosen passphrase")
    window.perform("install_globus")
    assert certs.load_private_key((tmp_path / "out" / "userkey.pem").read_bytes(), "chosen passphrase")


def test_deploy_dialog_unencrypted_needs_confirmation(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from PySide6.QtWidgets import QInputDialog

    from pycert.gui.dialogs import DeployTargetDialog

    state = issued("jane doe")
    dialog = DeployTargetDialog(window, ctx.store.get(state.alias))
    qtbot.addWidget(dialog)
    dialog.preset.setCurrentIndex(dialog.preset.findData(""))
    dialog.paths["key"].setText(str(tmp_path / "k.pem"))
    dialog.unencrypted.setChecked(True)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False)))
    dialog._accept()
    assert dialog.target is None and "not confirmed" in dialog.error.text()
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("unencrypted", True)))
    dialog._accept()
    assert dialog.target["unencrypted_key"] is True and dialog.target["unencrypted_key_confirmed"]
    dialog.paths["bundle"].setText(str(tmp_path / "b.pem"))
    dialog.target = None
    dialog._accept()
    assert dialog.target is None and "bundles are always encrypted" in dialog.error.text()


def test_keystores_are_locked_until_unlocked_each_session(qtbot, monkeypatch, ctx, java_keystore, window):
    from PySide6.QtWidgets import QInputDialog

    from pycert import keystore as ks

    path, password = java_keystore
    ks.link_keystore(window.ctx, path, password, name="site")
    window.reload_config()
    assert ks.is_unlocked(window.ctx, "site")  # the session passphrase survives a settings reload
    ks.lock(window.ctx, "site")
    window._populate_nav()
    assert "(locked)" in window._nav_items["keystore:site"].text()
    answers = iter([("wrong", True), (password, True)])
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: next(answers)))
    assert window.unlock_keystore("site") is True
    _wait_idle(qtbot, window)
    assert ks.is_unlocked(window.ctx, "site") and "(locked)" not in window._nav_items["keystore:site"].text()
    assert sorted(_visible_aliases(window)) == ["h1.example.org", "h2.example.org", "jane doe"]
    # cancelling leaves it locked; startup asks for every locked keystore
    ks.lock(window.ctx, "site")
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False)))
    window.unlock_keystores_at_startup()
    assert not ks.is_unlocked(window.ctx, "site")
    window.sync_keystores()
    _wait_idle(qtbot, window)  # a locked keystore is skipped quietly


def test_bundle_inspector_actions_run_after_it_has_closed(monkeypatch, ctx, java_keystore, window):
    """Linking from the inspector must not open a modal dialog inside the inspector's modal loop."""
    from pycert.gui import app as app_module
    from pycert.gui import bundle, dialogs

    path, password = java_keystore
    inside = {"inspector": False}
    seen = []

    def inspector_exec(self):
        inside["inspector"] = True
        self.password.setText(password)
        assert self.load()
        (self.link_button if not seen else self.import_button).click()
        inside["inspector"] = False
        return QDialog.DialogCode.Accepted

    def link_exec(self):
        seen.append(("link", inside["inspector"], self.password.text() == password))
        return QDialog.DialogCode.Rejected

    monkeypatch.setattr(bundle.BundleInspector, "exec", inspector_exec)
    monkeypatch.setattr(dialogs.LinkKeystoreDialog, "exec", link_exec)
    monkeypatch.setattr(app_module.MainWindow, "import_keystore_entries", lambda self, p, pw: seen.append(("import", inside["inspector"], pw == password)))
    window.open_bundle(str(path))
    window.open_bundle(str(path))
    assert seen == [("link", False, True), ("import", False, True)]


# ---------------------------------------------------------------------------
# Background tasks: nothing is freed on a worker thread
# ---------------------------------------------------------------------------


class _Tracked:
    """Records which thread frees it."""

    freed_on: "list[str]" = []

    def __init__(self, label):
        self.label = label

    def __del__(self):
        import threading

        _Tracked.freed_on.append(f"{self.label}:{'ui' if threading.current_thread() is threading.main_thread() else 'worker'}")


@pytest.fixture
def ui_collector():
    """Garbage collection on the UI thread only, as in the application."""
    import gc

    from pycert.gui.workers import MainThreadCollector

    before = gc.isenabled()  # gui_env already moves collection to the UI thread
    collector = MainThreadCollector(interval_ms=60000)
    yield collector
    collector.stop()
    assert gc.isenabled() == before  # restored to what it was


def test_task_results_closures_and_callbacks_are_released_on_the_ui_thread(qtbot, ui_collector):
    import gc
    import weakref

    from pycert.gui.workers import TaskRunner

    runner = TaskRunner()
    _Tracked.freed_on = []
    delivered = []

    def launch(fail):
        captured = _Tracked("closure")
        callback_state = _Tracked("callback")

        def work(progress, _stop):
            progress(captured.label)
            if fail:
                error = RuntimeError("boom")
                error.payload = _Tracked("error")
                raise error
            return _Tracked("result")

        def done(value):
            delivered.append((callback_state.label, type(value).__name__))

        return weakref.ref(runner.start(work, done, done, name="t"))

    tasks = [launch(False), launch(True)]
    qtbot.waitUntil(lambda: not runner.busy, timeout=10000)
    gc.collect()  # on the UI thread: an error's traceback is a reference cycle
    assert sorted(delivered) == [("callback", "RuntimeError"), ("callback", "_Tracked")]
    assert all(ref() is None for ref in tasks), "finished tasks must not leak"
    assert sorted(_Tracked.freed_on) == sorted(
        ["closure:ui", "callback:ui", "result:ui", "closure:ui", "callback:ui", "error:ui"]
    )
    # a runner that has gone drops late results without calling back
    late = []
    runner2 = TaskRunner()
    runner2.start(lambda progress, stop: stop.wait(0.2) or "late", late.append)
    runner2.shutdown()
    runner2.wait(5000)
    qtbot.wait(50)
    assert late == [] and not runner2.busy


def test_garbage_is_collected_on_the_ui_thread_only(qtbot, ui_collector):
    import gc

    from pycert.gui.workers import TaskRunner

    assert not gc.isenabled()
    _Tracked.freed_on = []
    cycle = _Tracked("cycle")
    cycle.self = cycle
    del cycle
    runner = TaskRunner()

    def allocate(_progress, _stop):
        junk = []
        for _ in range(50000):  # enough to trigger several automatic collections
            node = []
            node.append(node)
            junk.append(node)
        return len(junk)

    runner.start(allocate)
    qtbot.waitUntil(lambda: not runner.busy, timeout=10000)
    assert _Tracked.freed_on == []  # the worker thread did not collect it
    assert ui_collector.check() > 0  # the UI thread's timer does
    assert _Tracked.freed_on == ["cycle:ui"]
    # A collection promotes survivors, which can push an older generation over
    # its threshold; repeated checks settle within a few rounds.
    assert any(ui_collector.check() == 0 for _ in range(5))


# ---------------------------------------------------------------------------
# Renewal starts from the CA's record
# ---------------------------------------------------------------------------


def test_renew_dialog_starts_from_the_cas_contact(qtbot, monkeypatch, ca, ctx, issued, window):
    from pycert.gui import app as app_module

    user = issued("record contact")
    state = ctx.store.get(user.alias)
    state.email = "stale@example.org"
    ctx.store.save(state)
    window.refresh(select=user.alias)
    seen = {}

    def fake_exec(self):
        seen["email"] = self.email.text()
        seen["same"] = self.email_note.text()
        self.email.setText("someone.else@example.org")
        seen["changed"] = self.email_note.text()
        return QDialog.DialogCode.Rejected

    monkeypatch.setattr(app_module.RenewDialog, "exec", fake_exec)
    window.perform("renew")
    _wait_idle(qtbot, window)
    assert seen["email"] == "test@example.org"
    assert "holds for this certificate" in seen["same"]
    assert "replaces it" in seen["changed"]
    assert ctx.store.get(user.alias).renewal is False  # cancelled


def test_renew_is_refused_when_the_ca_has_no_record(qtbot, monkeypatch, ca, ctx, issued, window):

    from pycert.gui import app as app_module

    user = issued("forgotten person")
    ca.reset()
    window.refresh(select=user.alias)
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warnings.append(a[2])))
    monkeypatch.setattr(app_module.RenewDialog, "exec", lambda self: pytest.fail("the dialog must not open"))
    window.perform("renew")
    _wait_idle(qtbot, window)
    assert warnings and "no record of this certificate" in warnings[0]


def test_check_selected_refreshes_an_issued_certificates_record(qtbot, ctx, issued, window):
    user = issued("checked record")
    state = ctx.store.get(user.alias)
    state.server.last_checked = state.server.email = ""
    ctx.store.save(state)
    window.refresh(select=user.alias)
    window.check_selected()
    _wait_idle(qtbot, window)
    assert ctx.store.get(user.alias).server.email == "test@example.org"
    assert "CA status VALID" in window.activity.text.toPlainText()
    assert "contact test@example.org" in window.detail.fields["server"].text()


# ---------------------------------------------------------------------------
# Export dialog, rename, viewer and the user/host type
# ---------------------------------------------------------------------------


def test_type_is_shown_in_the_list_and_details(qtbot, ctx, two_hosts, window):
    from pycert.gui.models import COL_TYPE

    window.refresh()
    assert not window.table.isColumnHidden(COL_TYPE)
    types = {window.model.rows[r].state.alias: window.model.index(r, COL_TYPE).data() for r in range(window.model.rowCount())}
    assert types["jane doe"] == "User" and types["a.example.org"] == "Host"
    window.refresh(select="a.example.org")
    assert window.detail.fields["type"].text().startswith("Host certificate")
    window.refresh(select="jane doe")
    assert window.detail.fields["type"].text().startswith("User certificate")


def test_export_dialog_formats_and_validation(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from PySide6.QtWidgets import QFileDialog, QInputDialog

    from pycert.gui.dialogs import ExportDialog

    state = ctx.store.get(issued("export dialog person").alias)
    dialog = ExportDialog(window, ctx, state, directory=str(tmp_path))
    qtbot.addWidget(dialog)
    assert dialog.selected_format().name == "p12" and dialog.destination.text().endswith("export_dialog_person.p12")
    assert not dialog.no_passphrase.isVisibleTo(dialog) and dialog.encryption.count() == 2
    dialog.encryption.setCurrentIndex(1)
    assert "older software" in dialog.encryption_note.text()
    # the suggested name follows the format; a typed name is kept
    dialog.format.setCurrentIndex(dialog.format.findData("cert"))
    assert dialog.destination.text().endswith(".crt") and not dialog.key_box.isVisibleTo(dialog)
    assert not dialog.encryption.isVisibleTo(dialog)
    dialog.destination.setText(str(tmp_path / "mine.pem"))
    dialog.format.setCurrentIndex(dialog.format.findData("fullchain"))
    assert dialog.destination.text().endswith("mine.pem")
    dialog._accept()
    assert dialog.request["format"] == "fullchain" and dialog.request["password"] is None
    # keys: passphrase rules, then the explicit "no passphrase" override for a single key
    dialog.request = None
    dialog.format.setCurrentIndex(dialog.format.findData("key"))
    dialog._accept()
    assert dialog.request is None and "Enter a new passphrase" in dialog.error.text()
    dialog.password.setText(ctx.p12_passphrase())
    dialog.confirm.setText(ctx.p12_passphrase())
    dialog._accept()
    assert "saved secret" in dialog.error.text()
    dialog.no_passphrase.setChecked(True)
    assert not dialog.password.isEnabled()
    dialog._accept()
    assert "Not confirmed" in dialog.error.text()
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("unencrypted", True)))
    dialog._accept()
    assert dialog.request["no_passphrase"] is True
    # a bundle never offers it
    dialog.request = None
    dialog.format.setCurrentIndex(dialog.format.findData("pem-bundle"))
    assert not dialog.no_passphrase.isChecked()
    dialog.password.setText("bundle passphrase")
    dialog.confirm.setText("bundle passphrase")
    dialog.destination.setText("")
    dialog._accept()
    assert "Choose where" in dialog.error.text()
    # existing files: replace only if the user agrees
    existing = tmp_path / "exists.pem"
    existing.write_text("x")
    dialog.destination.setText(str(existing))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.No))
    dialog._accept()
    assert dialog.request is None
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    dialog._accept()
    assert dialog.request["overwrite"] is True and dialog.request["password"] == "bundle passphrase"
    # a directory format checks the files it would write; browse uses the right picker
    dialog.request = None
    dialog.format.setCurrentIndex(dialog.format.findData("pem-files"))
    (tmp_path / "export_dialog_person.key").write_text("x")
    dialog.destination.setText(str(tmp_path))
    dialog._accept()
    assert dialog.request["overwrite"] is True
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(tmp_path / "picked")))
    dialog._browse()
    assert dialog.destination.text().endswith("picked")
    dialog.format.setCurrentIndex(dialog.format.findData("der"))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "c.cer"), "")))
    dialog._browse()
    assert dialog.destination.text().endswith("c.cer")
    dialog.destination.setText(str(tmp_path))  # a folder for a file format: the default name inside it
    dialog._accept()
    assert dialog.request["destination"] == tmp_path


def test_export_action_writes_the_chosen_format(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from pycert.gui import app as app_module

    user = issued("export action person")
    window.refresh(select=user.alias)

    def unprotected_key(self):
        from PySide6.QtWidgets import QInputDialog

        self.format.setCurrentIndex(self.format.findData("key"))
        self.destination.setText(str(tmp_path / "k.key"))
        self.no_passphrase.setChecked(True)
        monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("unencrypted", True)))
        self._accept()
        return self.result()

    monkeypatch.setattr(app_module.ExportDialog, "exec", unprotected_key)
    done = []
    monkeypatch.setattr(window, "notify_done", lambda title, detail, path=None: done.append(detail))
    window.perform("export")
    _wait_idle(qtbot, window)
    assert (tmp_path / "k.key").read_text().startswith("-----BEGIN PRIVATE KEY") and "NO passphrase" in done[-1]
    monkeypatch.setattr(app_module.ExportDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    window.perform("export")  # cancelled: nothing happens


def test_rename_dialog_and_action(qtbot, monkeypatch, ctx, java_keystore, window):
    from pycert import keystore as ks
    from pycert.gui import app as app_module
    from pycert.gui.dialogs import RenameDialog

    path, password = java_keystore
    linked, _keystore = ks.link_keystore(window.ctx, path, password, name="site")
    ks.sync(window.ctx, linked)
    window.reload_config()
    window.refresh(select="h1.example.org")
    state = window.ctx.store.get("h1.example.org")
    dialog = RenameDialog(window, window.ctx, state)
    qtbot.addWidget(dialog)
    assert dialog.keystore_entry.isChecked() and "site" in dialog.keystore_entry.text()
    dialog.name.setText("  ")
    dialog._accept()
    assert "Empty" in dialog.error.text() or "empty" in dialog.error.text()
    dialog.name.setText("H2.EXAMPLE.ORG")
    dialog._accept()
    assert "already called" in dialog.error.text()
    plain = RenameDialog(window, window.ctx, window.ctx.store.get("jane doe"))
    qtbot.addWidget(plain)
    assert not plain.keystore_entry.isVisibleTo(plain)

    def rename_to(self):
        self.name.setText("h1 renewed 2026")
        self._accept()
        return self.result()

    monkeypatch.setattr(app_module.RenameDialog, "exec", rename_to)
    ks.lock(window.ctx, "site")
    window.perform("rename")  # locked, and the unlock prompt is cancelled: nothing renamed
    _wait_idle(qtbot, window)
    assert window.ctx.store.get("h1.example.org").alias == "h1.example.org"
    ks.unlock(window.ctx, window.cfg.keystore("site"), password)
    window.perform("rename")
    _wait_idle(qtbot, window)
    assert window.ctx.store.get("h1 renewed 2026").keystore["alias"] == "h1 renewed 2026"
    assert ks.Keystore.load(path, password).entry("h1 renewed 2026") is not None
    window.cfg.keystores[0].write_back = False
    read_only = RenameDialog(window, window.ctx, window.ctx.store.get("h1 renewed 2026"))
    qtbot.addWidget(read_only)
    assert not read_only.keystore_entry.isEnabled() and not read_only.keystore_entry.isChecked()
    window.cfg.keystores.clear()
    stale = RenameDialog(window, window.ctx, window.ctx.store.get("h1 renewed 2026"))
    qtbot.addWidget(stale)
    assert stale.link is None
    monkeypatch.setattr(app_module.RenameDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    window.perform("rename")


def test_certificate_viewer(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog

    from pycert.errors import PyCertError
    from pycert.gui.viewer import CertificateViewer

    user = issued("viewer person")
    state = ctx.store.get(user.alias)
    viewer = CertificateViewer(window, ctx, state)
    qtbot.addWidget(viewer)
    assert viewer.tabs.count() == 3 and viewer.chain_list.count() >= 2
    assert "Role:          Certificate" in viewer.chain_text.toPlainText()
    viewer.chain_list.setCurrentRow(viewer.chain_list.count() - 1)
    assert "Role:          Root" in viewer.chain_text.toPlainText()
    viewer._show_chain_entry(99)  # out of range: ignored
    viewer.copy_selected()
    assert QApplication.clipboard().text().startswith("-----BEGIN CERTIFICATE")
    viewer.copy_full_chain()
    assert QApplication.clipboard().text().count("BEGIN CERTIFICATE") >= 2
    viewer.copy_public_key()
    assert QApplication.clipboard().text().startswith("-----BEGIN PUBLIC KEY")
    assert "SPKI SHA-256" in viewer.public_text.toPlainText() and "Modulus" in viewer.public_text.toPlainText()
    assert viewer.save_full_chain() is None  # cancelled
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "chain.pem"), "")))
    assert viewer.save_full_chain().read_text().count("BEGIN CERTIFICATE") >= 2
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path), "")))
    (tmp_path / "viewer_person.fullchain.pem").mkdir()
    assert viewer.save_full_chain() is None  # cannot write: reported
    # the private key: only after typing the confirmation, and cleared on hide/close
    assert viewer.reveal_private_key() is False and viewer.private_text.toPlainText() == ""
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("SHOW", True)))
    assert viewer.reveal_private_key() is True
    assert "BEGIN PRIVATE KEY" in viewer.private_text.toPlainText() and "matches the certificate" in viewer.private_text.toPlainText()
    viewer.hide_private_key()
    assert viewer.private_text.toPlainText() == "" and not viewer.hide_button.isEnabled()
    viewer.reveal_private_key()
    viewer.done(0)
    assert viewer.private_text.toPlainText() == ""
    monkeypatch.setattr(ctx.store, "load_key", lambda *a, **k: (_ for _ in ()).throw(PyCertError("no key")))
    assert viewer.reveal_private_key() is False
    # opened from the window; a missing certificate is reported, not raised
    window.refresh(select=user.alias)
    window.perform("view")
    monkeypatch.setattr(CertificateViewer, "__init__", lambda *a, **k: (_ for _ in ()).throw(PyCertError("gone")))
    errors = []
    monkeypatch.setattr(window, "show_error", lambda title, exc: errors.append(str(exc)))
    window.perform("view")
    assert errors == ["gone"]


# ---------------------------------------------------------------------------
# Resilience: every action, in every certificate state, never crashes the GUI
# ---------------------------------------------------------------------------


def _every_state(ctx, ca, config, issued, java_keystore, tmp_path):
    """One certificate in each state the GUI has to cope with."""
    from pycert import keystore as ks
    from pycert.deploy import add_target
    from pycert.workflow import RequestSpec, create_request, renew, revoke

    user = issued("grid user")
    host = issued("web.example.org", type="host", auth_alias=user.alias)
    add_target(ctx, host, {"name": "web", "cert": str(tmp_path / "deploy" / "cert.pem"), "key": str(tmp_path / "deploy" / "key.pem")})
    revoke(ctx, issued("revoked person").alias, "keyCompromise")
    renewing = issued("renewing person")
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    renew(ctx, renewing.alias, progress=lambda _m: None)
    create_request(ctx, RequestSpec.build(config, "pending person", pin="1234567890AB"), progress=lambda _m: None)
    ca.fail_next("/CSR", status=202, body=ca._error_xml("refused by the RA"))
    with pytest.raises(PyCertError):
        create_request(ctx, RequestSpec.build(config, "failed person", pin="1234567890AB"), progress=lambda _m: None)
    path, password = java_keystore  # two imported hosts in a linked keystore, locked afterwards
    linked, _keystore = ks.link_keystore(ctx, path, password, name="site")
    ks.sync(ctx, linked)
    ks.lock(ctx, "site")
    ca.auto_approve = True  # later checks collect at once instead of waiting
    ca.sign_after_polls = 0


@pytest.mark.parametrize("answer", ["cancel", "accept"])
def test_every_action_in_every_state_survives(qtbot, monkeypatch, tmp_path, ca, config, ctx, issued, java_keystore, answer):
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtGui import QDesktopServices
    from PySide6.QtWidgets import QFileDialog, QInputDialog

    from pycert.gui.app import MainWindow, create_application

    _every_state(ctx, ca, config, issued, java_keystore, tmp_path)
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda *a, **k: True))
    if answer == "accept":
        # Every dialog says OK with whatever it holds by default; prompts get an answer.
        monkeypatch.setattr(QDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
        monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("an answer", True)))
        monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(tmp_path / "missing.p12"), "")))
        monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "saved.pem"), "")))
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(tmp_path / "picked")))
    create_application(["test"])
    window = MainWindow(str(config.path), start_background=False)
    qtbot.addWidget(window)
    window.show()
    try:
        triggered = 0
        for row in range(window.nav.count()):  # every sidebar view
            window.nav.setCurrentRow(row)
        window.nav.setCurrentRow(0)
        aliases = [state.alias for state in window.ctx.store.list()]
        assert len(aliases) >= 8
        for action in _walk_menu(window.menuBar(), []):  # application-wide actions, nothing selected
            if action.isEnabled() and action.text() not in ("About pyCertWiz",):
                action.trigger()
                _wait_idle(qtbot, window)
                triggered += 1
        for alias in aliases:
            try:
                window.ctx.store.get(alias)
            except PyCertError:
                continue  # deleted by an earlier "accept" pass
            window.refresh(select=alias)
            QCoreApplication.processEvents()
            # The details menu is rebuilt on every refresh: look each entry up afresh.
            for index in range(len(_walk_menu(window.detail.more_menu, []))):
                window.refresh(select=alias)
                entries = _walk_menu(window.detail.more_menu, [])
                if index < len(entries) and entries[index].isEnabled():
                    entries[index].trigger()
                    _wait_idle(qtbot, window)
                    triggered += 1
            for action in window.cert_actions.values():
                window.refresh(select=alias)
                if action.isEnabled():
                    action.trigger()
                    _wait_idle(qtbot, window)
                    triggered += 1
            _close_popup_soon()
            window._context_menu(window.table.visualRect(window.table.currentIndex()).center())
        _close_popup_soon()
        window._header_menu(window.table.horizontalHeader().rect().center())
        window.search.setText("example")
        window.search.setText("")
        assert triggered > 50
    finally:
        window.runner.shutdown()
        window.runner.wait(5000)


def test_bundle_inspector_save_as_needs_a_new_passphrase(qtbot, monkeypatch, tmp_path, ctx, issued, window):
    """Saving keys to a new file follows the export rule; a trust store or raw keystore copy does not."""
    from PySide6.QtWidgets import QInputDialog

    from pycert.gui.bundle import BundleInspector, _remaining

    state = issued("inspector export person")
    source = tmp_path / "mine.p12"
    from pycert.workflow import export_certificate

    export_certificate(ctx, state.alias, source, password="original passphrase")
    inspector = BundleInspector(window, str(source))
    qtbot.addWidget(inspector)
    inspector.password.setText("original passphrase")
    inspector.load()
    assert inspector.bundle.has_private_key and not inspector.bundle.raw_key_bags
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warnings.append(a[2])))
    assert inspector.save_java(str(tmp_path / "a.p12"), password="short") is None
    assert "at least 8" in warnings[-1]
    assert inspector.save_java(str(tmp_path / "b.p12"), password=ctx.p12_passphrase()) is None
    assert "saved passphrase" in warnings[-1]
    answers = iter([("first passphrase", True), ("second passphrase", True)])
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: next(answers)))
    assert inspector.save_java(str(tmp_path / "c.p12")) is None and "do not match" in warnings[-1]
    answers = iter([("first passphrase", True), ("", False)])
    assert inspector.save_java(str(tmp_path / "d.p12")) is None
    answers = iter([("a fine passphrase", True), ("a fine passphrase", True)])
    assert inspector.save_java(str(tmp_path / "e.p12")) == str(tmp_path / "e.p12")
    assert _remaining(certs.not_valid_after(ctx.store.load_certificate(state))).endswith("days left")
    import datetime as dt

    assert _remaining(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)) == "expired 3 days ago"


def test_colour_scheme_signal_reaches_live_windows_only(qtbot, config, window, monkeypatch):
    import shiboken6
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtGui import QGuiApplication

    from pycert.gui.app import MainWindow

    calls = []
    monkeypatch.setattr(MainWindow, "_system_scheme_changed", lambda self: calls.append(self))
    doomed = MainWindow(str(config.path), start_background=False)
    doomed.runner.shutdown()
    doomed.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not shiboken6.isValid(doomed)
    QGuiApplication.styleHints().colorSchemeChanged.emit(Qt.ColorScheme.Dark)
    assert window in calls and all(shiboken6.isValid(w) for w in calls)


def test_gui_check_mode(qtbot, config, capsys, monkeypatch, tmp_path):
    """`pycertwiz gui --check` proves Qt and the main window load (used by package tests)."""
    from pycert import cli
    from pycert.gui import main as gui_main

    assert cli.main(["--config", str(config.path), "gui", "--check"]) == 0
    assert "GUI check OK: offscreen platform" in capsys.readouterr().out
    assert gui_main(["--config", str(config.path), "--check"]) == 0
    assert "GUI check OK" in capsys.readouterr().out
    # a configuration that cannot be loaded, and a window that does not render
    assert gui_main(["--config", str(tmp_path / "missing.toml"), "--check"]) == 1
    assert "GUI check failed" in capsys.readouterr().err
    from PySide6.QtGui import QPixmap

    from pycert.gui.app import MainWindow

    monkeypatch.setattr(MainWindow, "grab", lambda self: QPixmap())
    assert gui_main(["--config", str(config.path), "--check"]) == 1
    assert "did not render" in capsys.readouterr().err
