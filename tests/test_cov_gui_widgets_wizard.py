"""Qt GUI coverage: the 'New certificate' wizard for every kind of CA.

Run with ``QT_QPA_PLATFORM=offscreen`` like the other GUI tests.
"""

import os
import threading

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

import shiboken6  # noqa: E402
from PySide6.QtWidgets import QLineEdit, QWidget  # noqa: E402

from pycert.errors import PyCertError  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")


@pytest.fixture
def parent(qtbot):
    widget = QWidget()
    qtbot.addWidget(widget)  # pytest-qt keeps a weak reference only: the fixture value keeps it alive
    return widget


@pytest.fixture
def runner(qtbot):
    from pycert.gui.workers import TaskRunner

    task_runner = TaskRunner()
    yield task_runner
    task_runner.shutdown()
    task_runner.wait(5000)


@pytest.fixture
def user_only_kind():
    """A CA protocol that issues personal certificates only (no built-in one does)."""
    from pycert import providers
    from pycert.providers.base import Capabilities

    class UserOnlyProvider:
        capabilities = Capabilities(user_certificates=True, host_certificates=False)

    providers.register("useronly", UserOnlyProvider)
    yield "useronly"
    providers.unregister("useronly")


def _wizard(qtbot, parent, ctx, runner, **kwargs):
    from pycert.gui.wizard import NewRequestWizard

    wizard = NewRequestWizard(parent, ctx, runner, **kwargs)
    qtbot.addWidget(wizard)
    return wizard


def _add_acme(ctx, name="acme-test"):
    from pycert.config import new_acme_profile

    ctx.config.add_ca(new_acme_profile(name, "https://acme.example.org/directory", display_name="ACME test"))
    return name


def test_acme_ca_turns_a_personal_request_into_a_host_request(qtbot, parent, ctx, runner, tmp_path):
    from pycert.gui.wizard import PAGE_DETAILS, PAGE_KEY, PAGE_REVIEW

    acme = _add_acme(ctx)
    wizard = _wizard(qtbot, parent, ctx, runner, cert_type="user")
    page = wizard.type_page
    assert page.user.isChecked() and "Registration Authority approves" in page.note.text()
    page.ca.setCurrentIndex(page.ca.findData(acme))
    assert page.host.isChecked() and not page.user.isEnabled() and wizard.cert_type == "host"
    assert page.note.text() == "This CA checks that you control each host name (ACME http-01 or dns-01 validation)."
    assert page.isComplete()

    wizard.show()
    wizard.next()
    assert wizard.currentId() == PAGE_DETAILS
    details = wizard.details_page
    assert not details.ra_row.isVisibleTo(details) and not details.auth.isVisibleTo(details)
    assert details.form.labelForField(details.email).text() == "Administrator e-mail"
    details.hosts.setPlainText("www.example.org\n")
    details.extra_dns.setText("example.org, static.example.org")
    specs = details.build_specs()
    assert specs[0].ca == acme and specs[0].ra == ""
    assert specs[0].san_dns == ["www.example.org", "example.org", "static.example.org"]

    wizard.next()
    assert wizard.currentId() == PAGE_KEY
    key = wizard.key_page
    assert key.preset.currentData() == ""  # no default deployment for an ACME host
    key.algorithm.setCurrentIndex(key.algorithm.findData("ec"))
    assert key.key_note.text() == "EC keys are small and fast and are widely supported."
    key.preset.setCurrentIndex(key.preset.findData("nginx"))
    assert key.hook.text() == "systemctl reload nginx"
    key.directory.setText(str(tmp_path / "ssl"))
    assert key.validatePage() and key.nextId() == PAGE_REVIEW  # no RA PIN with ACME

    wizard.next()
    assert wizard.currentId() == PAGE_REVIEW
    review = wizard.review_page
    summary = review.summary.text()
    assert "ACME test" in summary and "EC P-256" in summary and f"nginx in {tmp_path / 'ssl'}" in summary
    assert ">RA<" not in summary and ">PIN<" not in summary and "Authenticated by" not in summary
    assert review.wait.text() == "Wait for the certificate now (usually a few seconds)"
    assert review.validatePage()
    assert [spec.key_algorithm for spec in wizard.specs] == ["ec"]
    target = wizard.deploy_target(wizard.specs[0].alias or wizard.specs[0].cn)
    assert target["fullchain"].startswith(str(tmp_path / "ssl") + "/") and target["hook"] == "systemctl reload nginx"


def test_user_only_ca_turns_a_host_request_into_a_personal_request(qtbot, parent, ctx, runner, user_only_kind):
    from pycert.config import CAProfile

    ctx.config.add_ca(CAProfile(ctx.config, "people", kind=user_only_kind, display_name="People CA"))
    wizard = _wizard(qtbot, parent, ctx, runner, cert_type="host")
    page = wizard.type_page
    assert page.host.isChecked()
    page.ca.setCurrentIndex(page.ca.findData("people"))
    assert page.user.isChecked() and not page.host.isEnabled() and wizard.cert_type == "user"
    assert page.note.text() == ""  # neither domain validation nor manual approval


def test_default_ca_without_host_certificates_ignores_a_host_request(qtbot, parent, ctx, runner, user_only_kind):
    from pycert.config import CAProfile

    ctx.config.add_ca(CAProfile(ctx.config, "people", kind=user_only_kind, display_name="People CA"))
    ctx.config.default_ca = "people"
    wizard = _wizard(qtbot, parent, ctx, runner, cert_type="host")
    assert wizard.type_page.ca.currentData() == "people" and wizard.cert_type == "user"
    assert "(default)" in wizard.type_page.ca.currentText()


def test_personal_request_with_organisation_ec_key_keystore_and_pin(qtbot, parent, ctx, runner, tmp_path):
    from pycert.config import KeystoreLink
    from pycert.gui.wizard import PAGE_PIN, PAGE_REVIEW

    ctx.config.identity.ra = ""  # no default RA: the list starts empty
    ctx.config.keystores.append(KeystoreLink(name="site", path=str(tmp_path / "cakeystore.pkcs12")))
    wizard = _wizard(qtbot, parent, ctx, runner, cert_type="user")
    assert wizard.type_page.user.isChecked()
    wizard.show()
    wizard.next()
    details = wizard.details_page
    assert details.ra.count() == 0 and details.ra.currentText() == ""
    details.ra.addItem("CLRC DL")
    details.initializePage()  # the same CA again: the RA list is kept
    assert details.ra.count() == 1 and details.ra.currentText() == "CLRC DL"
    details.name.setText("Jane Doe")
    details.org_toggle.setChecked(True)
    details.o.setText("Example Org")
    details.c.setText("gb")
    spec = details.build_specs()[0]
    assert (spec.o, spec.c, spec.ra) == ("Example Org", "GB", "CLRC DL")

    wizard.next()
    key = wizard.key_page
    key.algorithm.setCurrentIndex(key.algorithm.findData("ec"))
    assert "cannot be renewed in place" in key.key_note.text()
    assert key.keystore_row.isVisibleTo(wizard)
    key.keystore.setCurrentIndex(key.keystore.findData("site"))
    key.preset.setCurrentIndex(key.preset.findData("globus-user"))
    key.directory.setText("relative/globus")
    assert not key.validatePage() and "must be absolute" in key.key_note.text()
    key.directory.setText(str(tmp_path / "globus"))
    assert key.deploy_settings() == {"preset": "globus-user", "directory": str(tmp_path / "globus"), "hook": ""}
    assert key.nextId() == PAGE_PIN

    wizard.next()
    pin = wizard.pin_page
    pin.show_pin.setChecked(True)
    assert pin.pin.echoMode() == QLineEdit.EchoMode.Normal and pin.confirm.echoMode() == QLineEdit.EchoMode.Normal
    pin.show_pin.setChecked(False)
    assert pin.pin.echoMode() == QLineEdit.EchoMode.Password and pin.confirm.echoMode() == QLineEdit.EchoMode.Password

    wizard.next()
    assert wizard.currentId() == PAGE_REVIEW
    review = wizard.review_page
    summary = review.summary.text()
    assert "EC P-256" in summary and "Java keystore" in summary and ">site<" in summary
    assert f"globus-user in {tmp_path / 'globus'}" in summary and "generated and shown after submission" in summary
    assert review.wait.text().startswith("Keep checking in the background")
    details.name.clear()  # changed behind the review page's back
    assert not review.validatePage() and review.error.text() == "enter your full name"
    details.name.setText("Jane Doe")
    assert review.validatePage()
    assert wizard.specs[0].keystore == "site" and wizard.specs[0].ec_curve == "P-256"
    target = wizard.deploy_target(wizard.specs[0].alias or wizard.specs[0].cn)
    assert target["cert"] == str(tmp_path / "globus" / "usercert.pem")


def test_host_request_authenticated_by_a_personal_certificate(qtbot, parent, ctx, runner, issued):
    user = issued("auth person")
    issued("web.example.org", type="host", auth_alias=user.alias)
    wizard = _wizard(qtbot, parent, ctx, runner, cert_type="host")
    wizard.show()
    wizard.next()
    details = wizard.details_page
    assert [details.auth.itemData(i) for i in range(details.auth.count())] == [user.alias]  # hosts cannot authenticate
    assert details.auth_hint.text().startswith("Your personal certificate signs")
    details.hosts.setPlainText("web.example.org")
    with pytest.raises(PyCertError, match="already in your list: web.example.org"):
        details.build_specs()
    details.hosts.setPlainText("new.example.org")
    wizard.next()
    assert wizard.key_page.preset.currentData() == "grid-host"
    wizard.next()
    wizard.next()
    summary = wizard.review_page.summary.text()
    assert "Authenticated by" in summary and "auth person" in summary and "grid-host in /etc/grid-security" in summary
    assert wizard.review_page.validatePage() and wizard.specs[0].auth_alias == user.alias


def test_host_request_without_a_personal_certificate_and_the_ra_list(qtbot, monkeypatch, parent, ctx, runner, ca):
    from pycert import workflow

    wizard = _wizard(qtbot, parent, ctx, runner, cert_type="host")
    wizard.show()
    wizard.next()
    details = wizard.details_page
    assert details.auth.count() == 0
    assert details.auth_hint.text().startswith("You need a valid RSA personal certificate")

    details.ra.setEditText("CLRC DL")
    details._fetch_ras()
    assert not details.fetch.isEnabled()
    qtbot.waitUntil(lambda: details.fetch.isEnabled() and not runner.busy, timeout=30000)
    labels = [details.ra.itemText(i) for i in range(details.ra.count())]
    assert len(labels) >= 2 and details.ra.currentText() == "CLRC DL" and details.error.text() == ""

    def offline(*_args):
        raise PyCertError("the CA is offline")

    monkeypatch.setattr(workflow, "list_ras", offline)
    details._fetch_ras()
    qtbot.waitUntil(lambda: details.fetch.isEnabled() and not runner.busy, timeout=30000)
    assert details.error.text() == "Could not fetch the RA list: the CA is offline"
    assert [details.ra.itemText(i) for i in range(details.ra.count())] == labels


def test_ra_list_arriving_after_the_wizard_closed_is_dropped(qtbot, monkeypatch, parent, ctx, runner):
    from pycert import workflow
    from pycert.gui.wizard import NewRequestWizard

    gate = threading.Event()
    calls = []

    def slow_list(*args):
        calls.append(args)
        gate.wait(10)
        return []

    monkeypatch.setattr(workflow, "list_ras", slow_list)
    wizard = NewRequestWizard(parent, ctx, runner)
    details = wizard.details_page
    details._fetch_ras()
    shiboken6.delete(wizard)  # closed and destroyed while the CA is still answering
    assert not shiboken6.isValid(details)
    gate.set()
    qtbot.waitUntil(lambda: not runner.busy, timeout=10000)
    assert len(calls) == 1
