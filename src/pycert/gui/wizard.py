"""The 'New certificate' wizard.

Steps: certificate authority and type -> details -> key and deployment ->
RA PIN (CAs that use one) -> review.  Each step validates with the same
:class:`~pycert.workflow.RequestSpec` rules the CLI uses, so an invalid
request is caught before a key is generated.  Several host names can be
requested at once; each becomes its own certificate.
"""

from html import escape
from typing import Any

import shiboken6
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from .. import deploy as deploy_module
from ..errors import PyCertError
from ..providers import capabilities_for
from ..workflow import PIN_MIN_LENGTH, RequestSpec
from . import icons, theme
from .widgets import button, muted_label

PAGE_TYPE, PAGE_DETAILS, PAGE_KEY, PAGE_PIN, PAGE_REVIEW = range(5)


def _error_label() -> QLabel:
    label = QLabel()
    label.setWordWrap(True)
    label.setStyleSheet(f"color: {theme.tokens().expired};")
    return label


class ChoiceCard(QPushButton):
    """A large checkable option: icon, bold title and a muted description."""

    def __init__(self, title: str, description: str, icon_name: str, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(84)
        t = theme.tokens()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(16)
        art = QLabel()
        art.setPixmap(icons.pixmap(icon_name, t.accent, 34))
        texts = QVBoxLayout()
        texts.setSpacing(2)
        heading = QLabel(title)
        heading.setStyleSheet("font-size: 15px; font-weight: 700; background: transparent;")
        detail = QLabel(description)
        detail.setWordWrap(True)
        detail.setStyleSheet(f"color: {t.muted}; background: transparent;")
        texts.addWidget(heading)
        texts.addWidget(detail)
        for widget in (art, heading, detail):
            widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout.addWidget(art)
        layout.addLayout(texts, 1)
        self.setAccessibleName(title)
        self.setToolTip(description)
        self.setStyleSheet(
            "QPushButton { border-radius: 12px; "
            f"border: 1px solid {t.border}; background: {t.surface}; }}"
            f"QPushButton:hover {{ border-color: {t.accent}; }}"
            f"QPushButton:checked {{ border: 2px solid {t.accent}; background: {t.accent_soft}; }}"
            f"QPushButton:disabled {{ background: {t.surface_alt}; }}"
        )


class TypePage(QWizardPage):
    def __init__(self, wizard: "NewRequestWizard"):
        super().__init__()
        self.w = wizard
        self.setTitle("What do you need?")
        self.setSubTitle("Choose the certificate authority and the kind of certificate.")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.ca = QComboBox()
        config = wizard.ctx.config
        for name, profile in config.cas.items():
            label = profile.display_name + (" (default)" if name == config.default_ca else "")
            self.ca.addItem(icons.icon("globe"), label, name)
        self.ca.setCurrentIndex(max(0, self.ca.findData(config.default_ca)))
        form.addRow("Certificate authority", self.ca)
        layout.addLayout(form)
        layout.addSpacing(8)
        self.user = ChoiceCard(
            "Personal certificate",
            "Identifies you: grid and cloud services, signed e-mail, web log-in.",
            "user",
        )
        self.host = ChoiceCard(
            "Host certificate",
            "Identifies a server or service. Request one or many host names at once.",
            "server",
        )
        group = QButtonGroup(self)
        group.setExclusive(True)
        group.addButton(self.user)
        group.addButton(self.host)
        layout.addWidget(self.user)
        layout.addWidget(self.host)
        self.note = muted_label()
        layout.addWidget(self.note)
        layout.addStretch(1)
        self.ca.currentIndexChanged.connect(self._ca_changed)
        self.user.toggled.connect(self.completeChanged)
        self.host.toggled.connect(self.completeChanged)
        self._ca_changed()

    def _ca_changed(self) -> None:
        profile = self.w.ctx.config.profile_for(self.ca.currentData())
        caps = capabilities_for(profile.kind)
        self.user.setEnabled(caps.user_certificates)
        self.host.setEnabled(caps.host_certificates)
        if not caps.user_certificates and self.user.isChecked():
            self.host.setChecked(True)
        if not caps.host_certificates and self.host.isChecked():
            self.user.setChecked(True)
        if not self.user.isChecked() and not self.host.isChecked():
            (self.user if caps.user_certificates else self.host).setChecked(True)
        notes = []
        if caps.domain_validation:
            notes.append("This CA checks that you control each host name (ACME http-01 or dns-01 validation).")
        if caps.manual_approval:
            notes.append("A Registration Authority approves each request; issuance can take a day or more.")
        self.note.setText(" ".join(notes))
        self.completeChanged.emit()

    def isComplete(self) -> bool:  # noqa: N802
        return self.user.isChecked() or self.host.isChecked()

    @property
    def cert_type(self) -> str:
        return "host" if self.host.isChecked() else "user"


class DetailsPage(QWizardPage):
    def __init__(self, wizard: "NewRequestWizard"):
        super().__init__()
        self.w = wizard
        self.setTitle("Details")
        layout = QVBoxLayout(self)
        self.form = QFormLayout()
        self.form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. Jane Doe")
        self.hosts = QPlainTextEdit()
        self.hosts.setPlaceholderText("one fully qualified host name per line, e.g.\nweb1.example.ac.uk\nweb2.example.ac.uk")
        self.hosts.setMaximumHeight(110)
        self.extra_dns = QLineEdit()
        self.extra_dns.setPlaceholderText("optional, comma separated (only with a single host)")
        config = wizard.ctx.config
        self.email = QLineEdit(config.identity.email)
        self.email.setPlaceholderText("you@example.ac.uk")
        self.auth = QComboBox()
        self.auth_hint = muted_label()
        self.ra = QComboBox()
        self.ra.setEditable(True)
        self.ra.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.fetch = button("Fetch list", "refresh")
        self.fetch.clicked.connect(self._fetch_ras)
        ra_row = QWidget()
        ra_layout = QHBoxLayout(ra_row)
        ra_layout.setContentsMargins(0, 0, 0, 0)
        ra_layout.addWidget(self.ra, 1)
        ra_layout.addWidget(self.fetch)
        self.ra_row = ra_row
        self.description = QLineEdit()
        self.description.setPlaceholderText("optional note, e.g. 'grid storage front-end'")
        self.org_toggle = QCheckBox("Override the organisation (O) and country (C) for this request")
        self.org = QWidget()
        org_form = QFormLayout(self.org)
        org_form.setContentsMargins(24, 0, 0, 0)
        self.o = QLineEdit(config.identity.o)
        self.c = QLineEdit(config.identity.c)
        self.c.setMaxLength(2)
        org_form.addRow("Organisation (O)", self.o)
        org_form.addRow("Country (C)", self.c)
        self.form.addRow("Full name", self.name)
        self.form.addRow("Host names", self.hosts)
        self.form.addRow("Extra DNS names", self.extra_dns)
        self.form.addRow("Contact e-mail", self.email)
        self.form.addRow("Authenticate with", self.auth)
        self.form.addRow("", self.auth_hint)
        self.form.addRow("Registration Authority", self.ra_row)
        self.form.addRow("Description", self.description)
        layout.addLayout(self.form)
        layout.addWidget(self.org_toggle)
        layout.addWidget(self.org)
        self.org.setVisible(False)
        self.org_toggle.toggled.connect(self.org.setVisible)
        self.error = _error_label()
        layout.addWidget(self.error)
        layout.addStretch(1)
        self._ras_loaded_for = ""

    def _set_row_visible(self, field: QWidget, visible: bool) -> None:
        self.form.setRowVisible(field, visible)

    def initializePage(self) -> None:  # noqa: N802
        caps = self.w.capabilities
        host = self.w.cert_type == "host"
        self.setSubTitle(
            "Each host name becomes its own certificate." if host else "Enter your name as it appears officially."
        )
        self._set_row_visible(self.name, not host)
        self._set_row_visible(self.hosts, host)
        self._set_row_visible(self.extra_dns, host)
        self._set_row_visible(self.auth, host and caps.host_authentication)
        self._set_row_visible(self.auth_hint, host and caps.host_authentication)
        self._set_row_visible(self.ra_row, caps.ra)
        self.org_toggle.setVisible(caps.organisation_subject)
        self.org.setVisible(caps.organisation_subject and self.org_toggle.isChecked())
        self.form.labelForField(self.email).setText("Administrator e-mail" if host else "Contact e-mail")
        profile = self.w.profile
        if caps.ra and self._ras_loaded_for != profile.name:
            self.ra.clear()
            if profile.identity.ra:
                self.ra.addItem(profile.identity.ra)
            self.ra.setEditText(profile.identity.ra)
            self._ras_loaded_for = profile.name
        if host and caps.host_authentication:
            self.auth.clear()
            for state in self.w.ctx.store.list():
                usable = (
                    state.type == "user"
                    and state.cert.not_after
                    and state.status != "REVOKED"
                    and (state.days_remaining or 0) > 0
                    and state.key_algorithm.upper().startswith("RSA")
                )
                if usable:
                    self.auth.addItem(icons.icon("user"), f"{state.cn} ({state.days_remaining} days left)", state.alias)
            if self.auth.count():
                self.auth_hint.setText("Your personal certificate signs the host request so the RA knows it is from you.")
            else:
                self.auth_hint.setText(
                    "You need a valid RSA personal certificate from this CA before you can request host certificates."
                )
        self.error.clear()

    def _fetch_ras(self) -> None:
        self.fetch.setEnabled(False)
        self.error.setText("")
        profile_name = self.w.profile.name
        from ..workflow import list_ras

        def done(result: Any) -> None:
            if not shiboken6.isValid(self):  # the wizard was closed meanwhile
                return
            self.fetch.setEnabled(True)
            current = self.ra.currentText()
            self.ra.clear()
            self.ra.addItems([ra.label for ra in result])
            self.ra.setEditText(current)

        def failed(exc: BaseException) -> None:
            if not shiboken6.isValid(self):  # pragma: no cover - the same race as done()
                return
            self.fetch.setEnabled(True)
            self.error.setText(f"Could not fetch the RA list: {exc}")

        self.w.runner.start(lambda _p, _s: list_ras(self.w.ctx, profile_name), done, failed)

    def names(self) -> "list[str]":
        if self.w.cert_type == "host":
            return [line.strip() for line in self.hosts.toPlainText().splitlines() if line.strip()]
        return [self.name.text().strip()] if self.name.text().strip() else []

    def build_specs(self, *, pin: str = "", key: "dict | None" = None) -> "list[RequestSpec]":
        names = self.names()
        if not names:
            raise PyCertError("enter a host name" if self.w.cert_type == "host" else "enter your full name")
        if len({n.lower() for n in names}) != len(names):
            raise PyCertError("the same host name is listed twice")
        caps = self.w.capabilities
        extra = [n.strip() for n in self.extra_dns.text().split(",") if n.strip()]
        if extra and len(names) > 1:
            raise PyCertError("extra DNS names can only be added when requesting a single host")
        options: "dict[str, Any]" = {
            "type": self.w.cert_type,
            "email": self.email.text().strip(),
            "ca": self.w.profile.name,
            "description": self.description.text().strip(),
            "pin": pin,
        }
        if caps.ra:
            options["ra"] = self.ra.currentText().strip()
        if caps.organisation_subject and self.org_toggle.isChecked():
            options["o"] = self.o.text().strip()
            options["c"] = self.c.text().strip().upper()
        if self.w.cert_type == "host" and caps.host_authentication:
            options["auth_alias"] = self.auth.currentData() or ""
        if key:
            options.update(key)
        specs = []
        for name in names:
            spec_options = dict(options)
            if extra:
                spec_options["san_dns"] = [name, *extra]
            specs.append(RequestSpec.build(self.w.ctx.config, name, **spec_options))
        existing = [spec.cn for spec in specs if self.w.ctx.store.exists(spec.alias or spec.cn)]
        if existing:
            raise PyCertError(f"already in your list: {', '.join(existing)}")
        return specs

    def validatePage(self) -> bool:  # noqa: N802
        try:
            self.build_specs()
        except PyCertError as exc:
            self.error.setText(str(exc))
            return False
        self.error.clear()
        return True


class KeyPage(QWizardPage):
    def __init__(self, wizard: "NewRequestWizard"):
        super().__init__()
        self.w = wizard
        self.setTitle("Key and deployment")
        self.setSubTitle("The private key is generated on this computer and never leaves it.")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.algorithm = QComboBox()
        self.size = QComboBox()
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.addWidget(self.algorithm)
        row_layout.addWidget(self.size)
        row_layout.addStretch(1)
        form.addRow("Key type", row)
        self.key_note = muted_label()
        form.addRow("", self.key_note)
        layout.addLayout(form)
        self.deploy_group = QGroupBox("Deploy automatically (optional)")
        deploy_form = QFormLayout(self.deploy_group)
        self.preset = QComboBox()
        self.preset.addItem("Don't deploy", "")
        for name, preset in deploy_module.PRESETS.items():
            self.preset.addItem(f"{name} — {preset['description']}", name)
        self.directory = QLineEdit()
        self.hook = QLineEdit()
        self.hook.setPlaceholderText("e.g. systemctl reload nginx")
        deploy_form.addRow("Layout", self.preset)
        deploy_form.addRow("Directory", self.directory)
        deploy_form.addRow("Reload hook", self.hook)
        layout.addWidget(self.deploy_group)
        self.keystore = QComboBox()
        self.keystore.addItem("Don't store in a Java keystore", "")
        for link in wizard.ctx.config.keystores:
            self.keystore.addItem(icons.icon("package"), f"Store in keystore “{link.name}”", link.name)
        keystore_form = QFormLayout()
        keystore_form.addRow("Java keystore", self.keystore)
        self.keystore_row = QWidget()
        self.keystore_row.setLayout(keystore_form)
        self.keystore_row.setVisible(bool(wizard.ctx.config.keystores))
        layout.addWidget(self.keystore_row)
        layout.addStretch(1)
        self.algorithm.currentIndexChanged.connect(self._sizes)
        self.preset.currentIndexChanged.connect(self._preset_changed)

    def initializePage(self) -> None:  # noqa: N802
        caps = self.w.capabilities
        config = self.w.ctx.config
        self.algorithm.blockSignals(True)
        self.algorithm.clear()
        self.algorithm.addItem("RSA" + (" (required for renewals with this CA)" if caps.host_authentication else ""), "rsa")
        self.algorithm.addItem("Elliptic curve (EC)", "ec")
        default = config.keys.algorithm if not caps.host_authentication else "rsa"
        self.algorithm.setCurrentIndex(max(0, self.algorithm.findData(default)))
        self.algorithm.blockSignals(False)
        self._sizes()
        self.deploy_group.setVisible(True)
        default_preset = "grid-host" if self.w.cert_type == "host" and caps.host_authentication else ""
        self.preset.setCurrentIndex(max(0, self.preset.findData(default_preset)))
        self._preset_changed()

    def _sizes(self) -> None:
        config = self.w.ctx.config
        self.size.clear()
        if self.algorithm.currentData() == "ec":
            for curve in ("P-256", "P-384", "P-521"):
                self.size.addItem(curve, curve)
            self.size.setCurrentIndex(max(0, self.size.findData(config.keys.ec_curve)))
            if self.w.capabilities.host_authentication:
                self.key_note.setText(
                    "This CA authenticates renewals and host requests with RSA keys only, so an EC "
                    "certificate cannot be renewed in place. Choose RSA unless you know you need EC."
                )
            else:
                self.key_note.setText("EC keys are small and fast and are widely supported.")
        else:
            for bits in (2048, 3072, 4096):
                self.size.addItem(f"{bits} bits" + (" (recommended)" if bits == 3072 else ""), bits)
            self.size.setCurrentIndex(max(0, self.size.findData(config.keys.rsa_bits)))
            self.key_note.setText("RSA 3072 is a good balance of strength and compatibility.")

    def _preset_changed(self) -> None:
        name = self.preset.currentData()
        self.directory.setEnabled(bool(name))
        self.hook.setEnabled(bool(name))
        if name:
            preset = deploy_module.PRESETS[name]
            self.directory.setText(preset["dir"])
            self.hook.setText(preset.get("hook", ""))
        else:
            self.directory.clear()
            self.hook.clear()

    def key_options(self) -> dict:
        algorithm = self.algorithm.currentData()
        return {
            "key_algorithm": algorithm,
            "rsa_bits": int(self.size.currentData()) if algorithm == "rsa" else 0,
            "ec_curve": self.size.currentData() if algorithm == "ec" else "",
            "keystore": self.keystore.currentData() or "",
        }

    def deploy_settings(self) -> "dict | None":
        name = self.preset.currentData()
        if not name:
            return None
        return {"preset": name, "directory": self.directory.text().strip(), "hook": self.hook.text().strip()}

    def validatePage(self) -> bool:  # noqa: N802
        settings = self.deploy_settings()
        if settings:
            try:
                deploy_module.target_from_preset(
                    settings["preset"], directory=settings["directory"], alias="x", hook=settings["hook"] or None
                )
            except PyCertError as exc:
                self.key_note.setText(str(exc))
                return False
        return True

    def nextId(self) -> int:  # noqa: N802
        return PAGE_PIN if self.w.capabilities.pin else PAGE_REVIEW


class PinPage(QWizardPage):
    def __init__(self, wizard: "NewRequestWizard"):
        super().__init__()
        self.w = wizard
        self.setTitle("PIN for the Registration Authority")
        self.setSubTitle(
            "The RA asks for this PIN when they confirm your identity. pyCertWiz sends only a hash of it and never stores it."
        )
        layout = QVBoxLayout(self)
        self.generate = QRadioButton("Generate a strong PIN for me (recommended)")
        self.own = QRadioButton("Use my own PIN")
        self.generate.setChecked(True)
        layout.addWidget(self.generate)
        layout.addWidget(self.own)
        form = QFormLayout()
        self.pin = QLineEdit()
        self.pin.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin.setPlaceholderText(f"at least {PIN_MIN_LENGTH} characters")
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_pin = QCheckBox("Show")
        self.show_pin.toggled.connect(self._toggle_show)
        form.addRow("PIN", self.pin)
        form.addRow("Confirm", self.confirm)
        form.addRow("", self.show_pin)
        self.own_box = QWidget()
        self.own_box.setLayout(form)
        layout.addWidget(self.own_box)
        self.error = _error_label()
        layout.addWidget(self.error)
        layout.addStretch(1)
        self.own.toggled.connect(self.own_box.setEnabled)
        self.own_box.setEnabled(False)

    def _toggle_show(self, show: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password
        self.pin.setEchoMode(mode)
        self.confirm.setEchoMode(mode)

    def chosen_pin(self) -> str:
        return self.pin.text() if self.own.isChecked() else ""

    def validatePage(self) -> bool:  # noqa: N802
        if self.own.isChecked():
            if len(self.pin.text()) < PIN_MIN_LENGTH:
                self.error.setText(f"The PIN must be at least {PIN_MIN_LENGTH} characters.")
                return False
            if self.pin.text() != self.confirm.text():
                self.error.setText("The PINs do not match.")
                return False
        self.error.clear()
        return True


class ReviewPage(QWizardPage):
    def __init__(self, wizard: "NewRequestWizard"):
        super().__init__()
        self.w = wizard
        self.setTitle("Review and submit")
        layout = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.wait = QCheckBox()
        self.wait.setChecked(True)
        layout.addWidget(self.wait)
        self.error = _error_label()
        layout.addWidget(self.error)
        layout.addStretch(1)
        self.setFinalPage(True)
        self.setButtonText(QWizard.WizardButton.FinishButton, "Submit request")

    def initializePage(self) -> None:  # noqa: N802
        caps = self.w.capabilities
        details = self.w.details_page
        names = details.names()
        key = self.w.key_page.key_options()
        key_text = f"RSA {key['rsa_bits']}" if key["key_algorithm"] == "rsa" else f"EC {key['ec_curve']}"
        rows = [
            ("Certificate authority", self.w.profile.display_name),
            ("Type", "Host" if self.w.cert_type == "host" else "Personal"),
            ("Name" + ("s" if len(names) > 1 else ""), "<br>".join(escape(n) for n in names)),
            ("E-mail", details.email.text().strip()),
            ("Key", key_text),
        ]
        if caps.ra:
            rows.append(("RA", details.ra.currentText().strip()))
        if self.w.cert_type == "host" and caps.host_authentication:
            rows.append(("Authenticated by", details.auth.currentText()))
        deploy = self.w.key_page.deploy_settings()
        if deploy:
            rows.append(("Deploy to", f"{deploy['preset']} in {deploy['directory']}"))
        if key.get("keystore"):
            rows.append(("Java keystore", key["keystore"]))
        if caps.pin:
            rows.append(("PIN", "generated and shown after submission" if not self.w.pin_page.chosen_pin() else "your own"))
        t = theme.tokens()
        table = "".join(
            f"<tr><td style='color:{t.muted}; padding:4px 16px 4px 0'>{escape(k)}</td><td style='padding:4px 0'>{v if k.startswith('Name') else escape(v)}</td></tr>"
            for k, v in rows
        )
        self.summary.setText(f"<table>{table}</table>")
        if caps.manual_approval:
            self.wait.setText("Keep checking in the background and collect the certificate when it is issued")
        else:
            self.wait.setText("Wait for the certificate now (usually a few seconds)")

    def validatePage(self) -> bool:  # noqa: N802
        try:
            self.w.specs = self.w.details_page.build_specs(pin=self.w.pin_page.chosen_pin(), key=self.w.key_page.key_options())
        except PyCertError as exc:
            self.error.setText(str(exc))
            return False
        return True


class NewRequestWizard(QWizard):
    def __init__(self, parent: QWidget, ctx: Any, runner: Any, *, cert_type: str = ""):
        super().__init__(parent)
        self.ctx = ctx
        self.runner = runner
        self.specs: "list[RequestSpec]" = []
        self.setWindowTitle("New certificate")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setMinimumSize(720, 560)
        self.type_page = TypePage(self)
        self.details_page = DetailsPage(self)
        self.key_page = KeyPage(self)
        self.pin_page = PinPage(self)
        self.review_page = ReviewPage(self)
        self.setPage(PAGE_TYPE, self.type_page)
        self.setPage(PAGE_DETAILS, self.details_page)
        self.setPage(PAGE_KEY, self.key_page)
        self.setPage(PAGE_PIN, self.pin_page)
        self.setPage(PAGE_REVIEW, self.review_page)
        if cert_type == "host" and self.type_page.host.isEnabled():
            self.type_page.host.setChecked(True)
        elif cert_type == "user" and self.type_page.user.isEnabled():
            self.type_page.user.setChecked(True)

    @property
    def profile(self):
        return self.ctx.config.profile_for(self.type_page.ca.currentData())

    @property
    def capabilities(self):
        return capabilities_for(self.profile.kind)

    @property
    def cert_type(self) -> str:
        return self.type_page.cert_type

    @property
    def wait(self) -> bool:
        return self.review_page.wait.isChecked()

    def deploy_target(self, alias: str) -> "dict | None":
        settings = self.key_page.deploy_settings()
        if not settings:
            return None
        return deploy_module.target_from_preset(
            settings["preset"],
            directory=settings["directory"],
            alias=alias,
            hook=settings["hook"] or None,
            per_certificate_dir=len(self.specs) > 1,
        )
