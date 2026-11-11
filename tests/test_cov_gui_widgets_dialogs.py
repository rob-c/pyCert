"""Qt GUI coverage: dialogs, the certificate bundle inspector and the certificate viewer.

Run with ``QT_QPA_PLATFORM=offscreen`` like the other GUI tests.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QDialog, QFileDialog, QInputDialog, QMessageBox, QPushButton, QWidget  # noqa: E402

from pycert import certs  # noqa: E402
from pycert.errors import PyCertError  # noqa: E402
from pycert.store import CertInfo, RequestState  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")


@pytest.fixture
def parent(qtbot):
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


@pytest.fixture
def runner(qtbot):
    from pycert.gui.workers import TaskRunner

    task_runner = TaskRunner()
    yield task_runner
    task_runner.shutdown()
    task_runner.wait(5000)


def _dialog(qtbot, cls, *args, **kwargs):
    dialog = cls(*args, **kwargs)
    qtbot.addWidget(dialog)
    return dialog


def _answer_files(monkeypatch, *, open_file="", save_file="", directory=""):
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (open_file, "")))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (save_file, "")))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: directory))


def _certificate(cn, *, days=(-1, 30), extensions=(), key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Coverage")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days[0]))
        .not_valid_after(now + timedelta(days=days[1]))
    )
    for extension in extensions:
        builder = builder.add_extension(extension, critical=False)
    return builder.sign(key, hashes.SHA256())


CRL_URL = "http://crl.example.org/coverage.crl"
AIA_URL = "http://ca.example.org/issuer.crt"
POLICY = "1.3.6.1.4.1.11439.1.1.1.1.2.1"


def _crl_points():
    return x509.CRLDistributionPoints(
        [x509.DistributionPoint([x509.UniformResourceIdentifier(CRL_URL)], None, None, None)]
    )


def _aia():
    return x509.AuthorityInformationAccess(
        [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(AIA_URL))]
    )


def _policies():
    return x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(POLICY), None)])


def _state(alias="dialog person", **changes):
    cert = changes.pop("cert", CertInfo(sha256="ef" * 32))
    return RequestState(alias=alias, slug=alias.replace(" ", "_"), type=changes.pop("type", "user"), cn=alias, cert=cert, **changes)


# ---------------------------------------------------------------------------
# Progress, renewal
# ---------------------------------------------------------------------------


def test_progress_dialog_closes_normally_once_the_task_has_finished(qtbot, parent, runner):
    import shiboken6
    from PySide6.QtCore import QCoreApplication, QEvent

    from pycert.gui.dialogs import ProgressDialog

    results = []
    # Not registered with qtbot: a finished progress dialog deletes itself.
    dialog = ProgressDialog(parent, "Quick", runner, lambda progress, stop: "finished", results.append, results.append)
    dialog.accepted.connect(lambda: results.append("accepted"))
    qtbot.waitUntil(lambda: "finished" in results, timeout=10000)
    assert results == ["accepted", "finished"]
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not shiboken6.isValid(dialog)  # it does not linger as a hidden child


def test_progress_dialog_close_after_the_task_is_an_ordinary_close(qtbot, parent, runner, monkeypatch):
    from pycert.gui.dialogs import ProgressDialog

    delivered = []
    # Hold back the completion callback, as when Escape arrives just as the task ends.
    monkeypatch.setattr(ProgressDialog, "_done", lambda self, result: delivered.append(result))
    dialog = _dialog(qtbot, ProgressDialog, parent, "Quick", runner, lambda progress, stop: "finished", print, print)
    qtbot.waitUntil(lambda: delivered == ["finished"], timeout=10000)
    dialog.reject()  # nothing left to cancel: an ordinary close
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.cancel_button.isEnabled() and dialog.status.text() != "Cancelling…"


def test_renew_dialog_for_an_ec_host_without_a_ca_record(qtbot, parent, config):
    from pycert.gui.dialogs import RenewDialog

    state = _state("ec.example.org", type="host", key_algorithm="EC P-384")
    state.cert.sans = ["DNS:ec.example.org", "DNS:alt.example.org", "IP:192.0.2.1"]
    dialog = _dialog(qtbot, RenewDialog, parent, state, None, config)  # capabilities unknown
    assert [dialog.algorithm.itemData(i) for i in range(dialog.algorithm.count())] == ["rsa", "ec"]
    assert dialog.algorithm.currentData() == "ec"
    assert [dialog.size.itemData(i) for i in range(dialog.size.count())] == ["P-256", "P-384", "P-521"]
    assert dialog.size.currentData() == config.keys.ec_curve
    assert dialog.email.text() == config.identity.email and dialog.email_note.text() == ""
    assert "requested for the same names" in " ".join(label.text() for label in dialog.findChildren(type(dialog.email_note)))
    options = dialog.options()
    assert options == {
        "key_algorithm": "ec",
        "rsa_bits": 0,
        "ec_curve": config.keys.ec_curve,
        "email": config.identity.email,
        "san_dns": ["ec.example.org", "alt.example.org"],
    }
    dialog.algorithm.setCurrentIndex(dialog.algorithm.findData("rsa"))
    assert dialog.options()["rsa_bits"] == config.keys.rsa_bits and dialog.options()["ec_curve"] == ""


def test_renew_dialog_offers_ec_for_a_ca_without_host_authentication(qtbot, parent, config):
    from pycert.gui.dialogs import RenewDialog
    from pycert.providers import capabilities_for

    acme = capabilities_for("acme")
    dialog = _dialog(qtbot, RenewDialog, parent, _state("rsa person", key_algorithm="RSA 2048"), acme, config, "ra@example.org")
    assert dialog.algorithm.currentData() == "rsa" and dialog.algorithm.findData("ec") >= 0
    dialog.algorithm.setCurrentIndex(dialog.algorithm.findData("ec"))
    assert dialog.size.currentData() == config.keys.ec_curve
    assert "holds for this certificate" in dialog.email_note.text()
    assert "san_dns" not in dialog.options()  # a user certificate has no DNS names to change


# ---------------------------------------------------------------------------
# Deployment targets, import, linking
# ---------------------------------------------------------------------------


def test_deploy_dialog_browse_buttons(qtbot, monkeypatch, parent, tmp_path):
    from pycert.gui.dialogs import DeployTargetDialog

    dialog = _dialog(qtbot, DeployTargetDialog, parent, _state())
    directory_browse = dialog.directory.parentWidget().findChild(QPushButton)
    key_browse = dialog.paths["key"].parentWidget().findChild(QPushButton)
    preset_directory = dialog.directory.text()
    directory_browse.click()  # cancelled: unchanged
    key_browse.click()
    assert dialog.directory.text() == preset_directory and dialog.paths["key"].text() == ""
    _answer_files(monkeypatch, save_file=str(tmp_path / "key.pem"), directory=str(tmp_path / "globus"))
    directory_browse.click()
    key_browse.click()
    assert dialog.directory.text() == str(tmp_path / "globus")
    assert dialog.paths["key"].text() == str(tmp_path / "key.pem")


def test_deploy_dialog_keeps_a_preset_reload_hook(qtbot, parent, tmp_path):
    from pycert.gui.dialogs import DeployTargetDialog

    dialog = _dialog(qtbot, DeployTargetDialog, parent, _state("web.example.org", type="host"))
    dialog.preset.setCurrentIndex(dialog.preset.findData("nginx"))
    assert dialog.hook.text() == "systemctl reload nginx"
    dialog.directory.setText(str(tmp_path / "nginx"))
    dialog._accept()
    assert dialog.error.text() == ""
    assert dialog.target["hook"] == "systemctl reload nginx"
    assert dialog.target["key"] == str(tmp_path / "nginx" / "web.example.org.key")


def test_import_dialog_browse_suggests_a_name_once(qtbot, monkeypatch, parent, config, tmp_path):
    from pycert.gui.dialogs import ImportDialog

    dialog = _dialog(qtbot, ImportDialog, parent, config)
    dialog._browse()  # cancelled
    assert dialog.path.text() == "" and dialog.alias.text() == ""
    _answer_files(monkeypatch, open_file=str(tmp_path / "laptop cert.p12"))
    dialog._browse()
    assert dialog.path.text() == str(tmp_path / "laptop cert.p12") and dialog.alias.text() == "laptop cert"
    _answer_files(monkeypatch, open_file=str(tmp_path / "other.p12"))
    dialog._browse()  # a name already chosen is kept
    assert dialog.path.text() == str(tmp_path / "other.p12") and dialog.alias.text() == "laptop cert"
    assert dialog.ca.count() == len(config.cas)


def test_link_keystore_dialog_browse_and_accept(qtbot, monkeypatch, parent, config, tmp_path):
    from pycert.gui.dialogs import LinkKeystoreDialog

    dialog = _dialog(qtbot, LinkKeystoreDialog, parent, config)
    dialog._browse()  # cancelled
    assert dialog.path.text() == ""
    keystore = tmp_path / "cakeystore.pkcs12"
    _answer_files(monkeypatch, open_file=str(keystore))
    dialog._browse()
    assert dialog.path.text() == str(keystore)
    dialog.password.setText("session only")
    dialog._accept()
    assert dialog.error.text() == "" and dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.auto_import.isChecked() and dialog.write_back.isChecked()


def test_flash_restores_the_original_text(qtbot):
    from pycert.gui.dialogs import flash

    copy = QPushButton("Copy")
    qtbot.addWidget(copy)
    flash(copy, "Copied", ms=10)
    assert copy.text() == "Copied"
    qtbot.waitUntil(lambda: copy.text() == "Copy", timeout=5000)


# ---------------------------------------------------------------------------
# Key protection and export
# ---------------------------------------------------------------------------


def test_key_protection_dialog_without_a_folder_and_with_browse(qtbot, monkeypatch, parent, tmp_path):
    from pycert.gui.dialogs import KeyProtectionDialog

    plain = _dialog(qtbot, KeyProtectionDialog, parent, "Save key", "the key")
    assert plain.directory.parent() is None  # no folder row at all
    with_folder = _dialog(qtbot, KeyProtectionDialog, parent, "Install", "userkey.pem", directory=str(tmp_path))
    with_folder._browse()  # cancelled
    assert with_folder.directory.text() == str(tmp_path)
    _answer_files(monkeypatch, directory=str(tmp_path / "globus"))
    with_folder._browse()
    assert with_folder.directory.text() == str(tmp_path / "globus")


def test_key_protection_without_any_choice_gives_no_passphrase_and_no_override(qtbot, parent, ctx):
    """Neither option selected (not possible by clicking): nothing that could write a key."""
    from pycert.exporter import FORMATS, check_passphrase
    from pycert.gui.dialogs import KeyProtectionDialog

    dialog = _dialog(qtbot, KeyProtectionDialog, parent, "Save key", "the key")
    dialog.own.group().setExclusive(False)
    dialog.own.setChecked(False)
    assert not dialog.own.isChecked() and not dialog.none.isChecked()
    dialog.password.setText("ignored passphrase")
    dialog._accept()
    assert dialog.chosen_password is None and dialog.no_passphrase is False
    with pytest.raises(PyCertError, match="needs a new passphrase"):
        check_passphrase(ctx, FORMATS["key"], dialog.chosen_password, dialog.no_passphrase)


def test_export_dialog_browse_cancelled_keeps_the_destination(qtbot, parent, ctx, tmp_path):
    from pycert.gui.dialogs import ExportDialog

    dialog = _dialog(qtbot, ExportDialog, parent, ctx, _state("export person"), format="cert", directory=str(tmp_path))
    before = dialog.destination.text()
    dialog._browse()
    assert dialog.destination.text() == before


# ---------------------------------------------------------------------------
# Bundle inspector
# ---------------------------------------------------------------------------


@pytest.fixture
def pem_bundle(tmp_path):
    """An expired certificate with a CRL (no AIA) followed by a valid one with AIA."""
    expired = _certificate("expired leaf", days=(-60, -2), extensions=[_crl_points()])
    current = _certificate("current issuer", extensions=[_aia()])
    path = tmp_path / "bundle.pem"
    path.write_text(certs.cert_pem(expired) + certs.cert_pem(current))
    return path, expired, current


def test_bundle_inspector_with_nothing_loaded(qtbot, monkeypatch, parent, pem_bundle):
    from pycert.gui.bundle import BundleInspector

    inspector = _dialog(qtbot, BundleInspector, parent)
    assert inspector._selected() is None
    inspector._copy_selected()  # nothing to copy
    assert inspector.summary.text() == "Choose a file and decode it."
    assert inspector.save_pem() is None and inspector.save_java() is None
    assert inspector.update_in_place() is False
    assert inspector.load() is False and inspector.summary.text() == "Choose a bundle file first."
    inspector._browse()  # cancelled
    assert inspector.bundle is None
    path, _expired, _current = pem_bundle
    _answer_files(monkeypatch, open_file=str(path))
    inspector._browse()
    assert inspector.path.text() == str(path) and inspector.table.rowCount() == 2


def test_bundle_inspector_reports_a_bad_file(qtbot, monkeypatch, parent, tmp_path):
    from pycert.gui.bundle import BundleInspector

    bad = tmp_path / "garbage.p12"
    bad.write_bytes(b"\x00\x01 not a bundle")
    inspector = _dialog(qtbot, BundleInspector, parent)
    inspector.path.setText(str(bad))
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warnings.append(a[1:])))
    assert inspector.load() is False  # a deliberate Decode reports the problem
    assert warnings and warnings[0][0] == "Could not decode the bundle" and inspector.summary.text() == warnings[0][1]


def test_bundle_inspector_pem_details_copy_and_save(qtbot, monkeypatch, parent, pem_bundle, tmp_path):
    from pycert.gui import bundle as bundle_module
    from pycert.gui.bundle import BundleInspector

    path, expired, current = pem_bundle
    inspector = _dialog(qtbot, BundleInspector, parent, path)
    assert inspector.summary.text().startswith("PEM · 2 certificates · no private key")
    assert inspector.table.item(0, 4).foreground().color().name() == "#ff0000"  # expired: shown in red
    assert inspector.table.item(1, 4).foreground().style() == Qt.BrushStyle.NoBrush  # still valid: default colour
    details = inspector.details.toPlainText()
    assert f"CRL          {CRL_URL}" in details and "AIA " not in details
    inspector.table.selectRow(1)
    details = inspector.details.toPlainText()
    assert f"AIA          {AIA_URL}" in details and "CRL " not in details
    assert not inspector.update_button.isEnabled() and not inspector.import_button.isEnabled()

    inspector._copy_selected()
    assert QGuiApplication.clipboard().text() == certs.cert_pem(current)
    assert inspector.summary.text() == "Selected certificate copied to the clipboard."
    inspector._copy_all()
    assert QGuiApplication.clipboard().text() == certs.cert_pem(expired) + certs.cert_pem(current)

    # save as PEM: the file dialog suggests a name next to the bundle
    suggested = []
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: suggested.append(a[2]) or ("", "")))
    assert inspector.save_pem() is None
    assert suggested == [str(path.with_suffix(".pem"))]
    _answer_files(monkeypatch, save_file=str(tmp_path / "copy.pem"))
    assert inspector.save_pem() == str(tmp_path / "copy.pem")
    assert (tmp_path / "copy.pem").read_text().count("BEGIN CERTIFICATE") == 2

    # save as Java PKCS#12: cancelled, the open file itself, no passphrase, a failure, then success
    _answer_files(monkeypatch)
    assert inspector.save_java() is None
    infos = []
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: infos.append(a[1])))
    _answer_files(monkeypatch, save_file=str(path))
    assert inspector.save_java() is None and infos == ["Use Update"]
    _answer_files(monkeypatch, save_file=str(tmp_path / "trust.p12"))
    assert inspector.save_java() is None  # passphrase prompt cancelled
    assert not (tmp_path / "trust.p12").exists()
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warnings.append(a[1])))
    occupied = tmp_path / "occupied.p12"
    occupied.mkdir()
    assert inspector.save_java(str(occupied), password="truststore pass") is None
    assert warnings == ["Could not save the bundle"]
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("truststore pass", True)))
    assert inspector.save_java() == str(tmp_path / "trust.p12")
    reread = bundle_module.bundles.load_bundle(tmp_path / "trust.p12", "truststore pass")
    assert len(reread) == 2 and not reread.has_private_key
    assert inspector.update_in_place(confirm=False, password="x") is False  # only PKCS#12 bundles are updated


def test_bundle_inspector_empty_bundle(qtbot, parent):
    from pycert.bundles import CertificateBundle
    from pycert.gui.bundle import BundleInspector

    inspector = _dialog(qtbot, BundleInspector, parent)
    inspector.bundle = CertificateBundle(path="", format="pem", certificates=[])
    inspector._populate()
    assert inspector.summary.text() == "PEM · 0 certificates · no private key"
    assert inspector.table.rowCount() == 0 and inspector._selected() is None and inspector._all_pem() == ""


def test_bundle_inspector_java_keystore_integrity(qtbot, parent, tmp_path, pem_bundle):
    from test_bundles import _jks

    from pycert.gui.bundle import BundleInspector

    _path, expired, current = pem_bundle
    jks = tmp_path / "truststore.jks"
    jks.write_bytes(_jks([expired, current], password="changeit"))
    inspector = _dialog(qtbot, BundleInspector, parent)
    inspector.path.setText(str(jks))
    inspector.password.setText("changeit")
    assert inspector.load()
    assert "JKS · 2 certificates" in inspector.summary.text() and "integrity verified" in inspector.summary.text()
    assert inspector.table.item(0, 6).text() == "trusted-0"
    assert "alias trusted-0" in inspector.details.toPlainText()


def test_bundle_inspector_java_keystore_keeps_its_passphrase(qtbot, monkeypatch, parent, java_keystore, tmp_path):
    from pycert import bundles
    from pycert.gui.bundle import BundleInspector

    path, password = java_keystore
    inspector = _dialog(qtbot, BundleInspector, parent, path)
    inspector.password.setText(password)
    assert inspector.load()
    assert inspector.bundle.raw_key_bags and "2 key entries" in inspector.summary.text()
    # Raw Java key bags stay encrypted with the passphrase that opened them: no prompt.
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: pytest.fail("no prompt expected")))
    copy = tmp_path / "copy.p12"
    assert inspector.save_java(str(copy)) == str(copy)
    assert bundles.load_bundle(copy, password).key_count == 2
    # updating in place asks first
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.No))
    original = path.read_bytes()
    assert inspector.update_in_place() is False and path.read_bytes() == original
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    assert inspector.update_in_place() is True
    assert (path.parent / (path.name + ".bak")).read_bytes() == original
    assert bundles.load_bundle(path, password).key_count == 2
    # the file went away meanwhile: reported, nothing written
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warnings.append(a[1])))
    path.unlink()
    assert inspector.update_in_place() is False
    assert warnings == ["Could not update the bundle"] and not path.exists()


def test_bundle_inspector_update_needs_a_new_passphrase_for_a_decoded_key(qtbot, parent, ctx, issued):
    from pycert.gui.bundle import BundleInspector

    p12 = Path(ctx.store.get(issued("inspector person").alias).p12_path)
    original = p12.read_bytes()
    inspector = _dialog(qtbot, BundleInspector, parent, p12)
    inspector.password.setText(ctx.p12_passphrase())
    assert inspector.load()
    assert not inspector.bundle.raw_key_bags and inspector.bundle.private_key is not None
    assert inspector.update_in_place(confirm=False) is False  # the passphrase prompt was cancelled
    assert p12.read_bytes() == original and not (p12.parent / (p12.name + ".bak")).exists()


# ---------------------------------------------------------------------------
# Certificate viewer text
# ---------------------------------------------------------------------------


def test_certificate_text_lists_policies_and_crl_points():
    from pycert.gui.viewer import certificate_text

    certificate = _certificate("policy person", extensions=[_policies(), _crl_points(), _aia()])
    text = certificate_text(certificate, "Certificate")
    assert text.startswith("Role:          Certificate")
    assert f"  certificatePolicies: {POLICY}" in text
    assert f"  cRLDistributionPoints: {CRL_URL}" in text
    assert "  authorityInfoAccess\n" in text  # listed without detail
    assert text.rstrip().endswith("-----END CERTIFICATE-----")


def test_public_key_text_for_an_ec_key():
    from pycert.gui.viewer import public_key_text

    key = ec.generate_private_key(ec.SECP384R1())
    text = public_key_text(key.public_key())
    assert "Curve:         secp384r1" in text and "\nPoint:\n  04 " in text
    assert "Modulus" not in text and "SPKI SHA-256:  " + certs.key_fingerprint(key.public_key()) in text
    assert text.rstrip().endswith("-----END PUBLIC KEY-----")
