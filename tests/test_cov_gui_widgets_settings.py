"""Qt GUI coverage: the settings dialog's CA profiles, EAB keys and secret-store test.

Run with ``QT_QPA_PLATFORM=offscreen`` like the other GUI tests.
"""

import base64
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtWidgets import QInputDialog, QMessageBox, QWidget  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")


@pytest.fixture
def parent(qtbot):
    widget = QWidget()
    qtbot.addWidget(widget)  # pytest-qt keeps a weak reference only: the fixture value keeps it alive
    return widget


@pytest.fixture
def dialog(qtbot, parent, config):
    from pycert.gui.settings import SettingsDialog

    settings = SettingsDialog(parent, str(config.path))
    qtbot.addWidget(settings)
    return settings


def _answers(monkeypatch, *replies):
    queue = list(replies)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: queue.pop(0)))
    return queue


def _names(dialog):
    return list(dialog.config.cas)


def test_add_acme_ca_cancelled_invalid_and_duplicate(monkeypatch, dialog):
    primary = _names(dialog)[0]
    pending = _answers(
        monkeypatch,
        ("", False),  # name prompt cancelled
        ("letsencrypt", True),
        ("", False),  # directory URL cancelled
        ("letsencrypt", True),
        ("   ", True),  # an empty URL is the same as cancelling
        (primary, True),
        ("https://acme.example.org/directory", True),  # the name is taken
    )
    for _ in range(4):
        dialog._add_acme()
    assert pending == [] and _names(dialog) == [primary]
    assert "already exists" in dialog.error.text()


def test_add_ukca_ca_every_outcome(monkeypatch, dialog):
    primary = _names(dialog)[0]
    pending = _answers(
        monkeypatch,
        ("", False),  # name prompt cancelled
        ("ukca-test", True),
        ("", False),  # base URL cancelled
        (primary, True),
        ("https://localhost:8443", True),  # the name is taken
        ("Not A Valid Name", True),
        ("https://localhost:8443", True),  # names are lower case
        ("ukca-test", True),
        ("https://ca.example.org:8443", True),
    )
    dialog._add_ukca()
    dialog._add_ukca()
    assert _names(dialog) == [primary]
    dialog._add_ukca()
    assert "already exists" in dialog.error.text()
    dialog._add_ukca()
    assert "invalid CA profile name" in dialog.error.text()
    dialog._add_ukca()
    assert pending == [] and _names(dialog) == [primary, "ukca-test"]
    assert dialog._current_ca == "ukca-test" and dialog.ca_url.text() == "https://ca.example.org:8443"
    assert dialog.ca_list.currentItem().text().endswith("ukca-test · ukca")
    assert dialog.config.cas["ukca-test"].ca.tls_trust == "system"
    assert not dialog.acme_contact.isVisibleTo(dialog.ca_form_host)  # ACME settings hidden for this kind
    assert dialog.ca_form.labelForField(dialog.ca_url).text() == "Server URL"


def test_remove_ca_guards_and_confirmation(monkeypatch, dialog):
    _answers(monkeypatch, ("ukca-test", True), ("https://ca.example.org:8443", True))
    dialog._add_ukca()
    primary = _names(dialog)[0]
    # nothing selected
    dialog._current_ca = ""
    dialog._remove_ca()
    assert _names(dialog) == [primary, "ukca-test"] and dialog.error.text() == ""
    # the primary CA stays
    dialog._reload_ca_list(primary)
    dialog._remove_ca()
    assert "primary CA cannot be removed" in dialog.error.text() and primary in _names(dialog)
    # the user can say no
    dialog._reload_ca_list("ukca-test")
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.No))
    dialog._remove_ca()
    assert "ukca-test" in _names(dialog)
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    dialog._remove_ca()
    assert _names(dialog) == [primary] and dialog._current_ca == primary


def test_show_ca_ignores_a_row_that_does_not_exist(dialog):
    current = dialog._current_ca
    dialog._show_ca(99)
    assert dialog._current_ca == current


def test_set_eab_key(monkeypatch, dialog, config):
    from pycert.providers.acme import EAB_SECRET_PREFIX
    from pycert.workflow import AppContext

    primary = _names(dialog)[0]
    key = base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode("ascii")
    _answers(monkeypatch, ("", False), (key, True))
    dialog._set_eab()  # cancelled
    assert dialog.error.text() == ""
    dialog._set_eab()  # the primary CA is not an ACME CA
    assert "not an ACME CA" in dialog.error.text()

    _answers(monkeypatch, ("le-test", True), ("https://acme.example.org/directory", True), ("not base64 !!", True), (key, True))
    dialog._add_acme()
    assert dialog._current_ca == "le-test" and dialog.acme_contact.isVisibleTo(dialog.ca_form_host)
    assert dialog.acme_contact.text() == config.identity.email  # the identity e-mail is the default contact
    dialog.error.clear()
    dialog._set_eab()
    assert "base64url" in dialog.error.text()
    stored = []
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: stored.append(a[1])))
    dialog.error.clear()
    dialog._set_eab()
    assert stored == ["EAB key stored"] and dialog.error.text() == ""
    assert AppContext.from_config(dialog.config).secrets.get(EAB_SECRET_PREFIX + "le-test") == key
    assert primary in _names(dialog)


def test_secret_store_test_button(dialog):
    dialog._test_secret()
    assert dialog.secret_status.text().startswith("file (") and "secret " in dialog.secret_status.text()
    dialog.config.secrets.backend = "command"
    dialog.config.secrets.command = ""
    dialog._test_secret()
    assert dialog.secret_status.text() == "Problem: secrets.command is empty"
