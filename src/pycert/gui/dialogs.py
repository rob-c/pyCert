"""Dialogs: PIN display, progress, renewal, revocation, deployment, import, reports."""

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import deploy as deploy_module
from ..errors import PyCertError
from ..store import RequestState
from . import icons, theme
from .widgets import button, copy_to_clipboard, muted_label


def _title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("DetailTitle")
    return label


def _mono() -> QFont:
    font = QFont("Menlo")
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font


# ---------------------------------------------------------------------------
# PIN
# ---------------------------------------------------------------------------


class PinDialog(QDialog):
    """Show RA PINs once.  pyCertWiz never stores or logs them."""

    def __init__(self, parent: QWidget, pins: "list[tuple[str, str]]"):
        super().__init__(parent)
        self.setWindowTitle("PIN for the RA")
        self.setModal(True)
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        header = QHBoxLayout()
        lock = QLabel()
        lock.setPixmap(icons.pixmap("lock", theme.tokens().accent, 30))
        header.addWidget(lock)
        header.addWidget(_title("Write down your PIN" if len(pins) == 1 else "Write down your PINs"), 1)
        layout.addLayout(header)
        layout.addWidget(
            muted_label(
                "Your RA (Registration Authority) will ask for this PIN when they verify your identity. "
                "pyCertWiz does not store it anywhere: it only sent a hash of it with the request. "
                "Keep it until the certificate has been issued."
            )
        )
        self.copy_buttons = []
        for name, pin in pins:
            box = QHBoxLayout()
            if len(pins) > 1:
                caption = QLabel(name)
                caption.setMinimumWidth(160)
                box.addWidget(caption)
            field = QLineEdit(pin)
            field.setReadOnly(True)
            font = _mono()
            font.setPointSize(20)
            field.setFont(font)
            field.setAlignment(Qt.AlignmentFlag.AlignCenter)
            field.setMinimumHeight(48)
            box.addWidget(field, 1)
            copy = button("Copy", "copy")
            copy.clicked.connect(lambda _c=False, value=pin, b=copy: (copy_to_clipboard(value), b.setText("Copied")))
            self.copy_buttons.append(copy)
            box.addWidget(copy)
            layout.addLayout(box)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("I have recorded it")
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------


class ProgressDialog(QDialog):
    """A live log for a long-running task, with a cooperative Cancel."""

    def __init__(self, parent: QWidget, title: str, runner: Any, work: Callable, on_done: Callable, on_error: Callable):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(640, 380)
        self._on_done = on_done
        self._on_error = on_error
        layout = QVBoxLayout(self)
        self.status = QLabel("Starting…")
        self.status.setObjectName("DetailTitle")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(8)
        layout.addWidget(self.bar)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(_mono())
        layout.addWidget(self.log, 1)
        row = QHBoxLayout()
        row.addWidget(muted_label("You can close this window: the request stays stored and pyCertWiz keeps checking in the background."))
        self.cancel_button = button("Cancel", "stop")
        self.cancel_button.clicked.connect(self._cancel)
        row.addWidget(self.cancel_button)
        layout.addLayout(row)
        self.task = runner.start(work, self._done, self._error, self._progress, name=title)

    def _progress(self, message: str) -> None:
        self.status.setText(message)
        self.log.appendPlainText(f"{datetime.now():%H:%M:%S}  {message}")

    def _cancel(self) -> None:
        self.task.cancel()
        self.status.setText("Cancelling…")
        self.cancel_button.setEnabled(False)

    def reject(self) -> None:  # window close or Escape
        if not self.task.done:
            self._cancel()
            return
        super().reject()

    def _done(self, result: Any) -> None:
        self.accept()
        try:
            self._on_done(result)
        finally:
            self.deleteLater()  # a finished dialog must not linger as a hidden child

    def _error(self, exc: BaseException) -> None:
        super().reject()
        try:
            self._on_error(exc)
        finally:
            self.deleteLater()


# ---------------------------------------------------------------------------
# Renew / revoke
# ---------------------------------------------------------------------------


class RenewDialog(QDialog):
    def __init__(self, parent: QWidget, state: RequestState, capabilities: Any, config: Any, record_email: str = ""):
        super().__init__(parent)
        self.setWindowTitle(f"Renew {state.cn}")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.addWidget(_title(f"Renew “{state.cn}”"))
        if capabilities is not None and capabilities.host_authentication:
            text = (
                "A new key is generated and the renewal is signed with the current certificate, so the RA "
                "can approve it without re-checking your identity. Your current certificate keeps working "
                "until the new one is issued and verified."
            )
        else:
            text = "A new key is generated and a new certificate is requested for the same names."
        layout.addWidget(muted_label(text))
        form = QFormLayout()
        self.algorithm = QComboBox()
        self.algorithm.addItem("RSA", "rsa")
        if capabilities is None or not capabilities.host_authentication:
            self.algorithm.addItem("Elliptic curve (EC)", "ec")
        current = "ec" if state.key_algorithm.lower().startswith("ec") else "rsa"
        self.algorithm.setCurrentIndex(max(0, self.algorithm.findData(current)))
        self.size = QComboBox()
        self.algorithm.currentIndexChanged.connect(self._sizes)
        self._config = config
        self._sizes()
        form.addRow("Key", self._row(self.algorithm, self.size))
        # The CA's record wins, as in CertWizard: the renewal sets the contact it holds.
        self.record_email = record_email
        self.email = QLineEdit(record_email or state.email or config.identity.email)
        form.addRow("Contact e-mail", self.email)
        self.email_note = muted_label("")
        self.email_note.setWordWrap(True)
        form.addRow("", self.email_note)
        self.email.textChanged.connect(self._email_changed)
        self._email_changed()
        sans = [value.split(":", 1)[-1] for value in state.cert.sans if value.lower().startswith("dns:")]
        self.san_dns = QLineEdit(", ".join(sans))
        self.san_dns.setPlaceholderText("keep the current names")
        if state.type == "host":
            form.addRow("DNS names", self.san_dns)
        self.wait = QCheckBox("Wait and collect the certificate when it is issued")
        self.wait.setChecked(True)
        form.addRow("", self.wait)
        layout.addLayout(form)
        if capabilities is not None and capabilities.pin:
            layout.addWidget(muted_label("A new RA PIN will be generated and shown once after submission."))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = button("Submit renewal", "renew", primary=True)
        buttons.addButton(ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _row(*widgets: QWidget) -> QWidget:
        container = QWidget()
        row = QHBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)
        for widget in widgets:
            row.addWidget(widget)
        row.addStretch(1)
        return container

    def _email_changed(self) -> None:
        typed = self.email.text().strip()
        if not self.record_email:
            self.email_note.setText("")
        elif typed.lower() == self.record_email.lower():
            self.email_note.setText("The contact the CA holds for this certificate.")
        else:
            self.email_note.setText(
                f"The CA holds {self.record_email} for this certificate. Renewing with a different "
                "address replaces it."
            )

    def _sizes(self) -> None:
        self.size.clear()
        if self.algorithm.currentData() == "ec":
            for curve in ("P-256", "P-384", "P-521"):
                self.size.addItem(curve, curve)
            self.size.setCurrentIndex(max(0, self.size.findData(self._config.keys.ec_curve)))
        else:
            for bits in (2048, 3072, 4096):
                self.size.addItem(f"{bits} bits", bits)
            self.size.setCurrentIndex(max(0, self.size.findData(self._config.keys.rsa_bits)))

    def options(self) -> dict:
        algorithm = self.algorithm.currentData()
        options: "dict[str, Any]" = {
            "key_algorithm": algorithm,
            "rsa_bits": int(self.size.currentData()) if algorithm == "rsa" else 0,
            "ec_curve": self.size.currentData() if algorithm == "ec" else "",
            "email": self.email.text().strip(),
        }
        names = [name.strip() for name in self.san_dns.text().split(",") if name.strip()]
        if self.san_dns.isVisibleTo(self) and names:
            options["san_dns"] = names
        return options


class RevokeDialog(QDialog):
    def __init__(self, parent: QWidget, state: RequestState, reasons: "tuple[str, ...]"):
        super().__init__(parent)
        self.state = state
        self.setWindowTitle("Revoke certificate")
        self.setMinimumWidth(500)
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        warn = QLabel()
        warn.setPixmap(icons.pixmap("alert", theme.tokens().expired, 30))
        header.addWidget(warn)
        header.addWidget(_title(f"Revoke “{state.cn}”?"), 1)
        layout.addLayout(header)
        layout.addWidget(
            muted_label(
                "Revocation is permanent and is published to every relying service. The local files are "
                "kept, but the certificate can no longer be used or renewed."
            )
        )
        form = QFormLayout()
        self.reason = QComboBox()
        for reason in reasons:
            self.reason.addItem(_reason_label(reason), reason)
        form.addRow("Reason", self.reason)
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(state.alias)
        form.addRow(f"Type “{state.alias}” to confirm", self.confirm)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.ok = button("Revoke", "revoke", danger=True)
        self.ok.setEnabled(False)
        buttons.addButton(self.ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.confirm.textChanged.connect(lambda text: self.ok.setEnabled(text.strip() == state.alias))
        layout.addWidget(buttons)

    def reason_code(self) -> str:
        return self.reason.currentData()


def _reason_label(reason: str) -> str:
    return {
        "unspecified": "Unspecified",
        "keyCompromise": "Key compromise (the private key may be known to someone else)",
        "cACompromise": "CA compromise",
        "affiliationChanged": "Affiliation changed",
        "superseded": "Superseded by a new certificate",
        "cessationOfOperation": "No longer needed",
        "certificateHold": "Certificate hold",
    }.get(reason, reason)


# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------


class DeployTargetDialog(QDialog):
    """Add a deployment target from a preset or by choosing files."""

    def __init__(self, parent: QWidget, state: RequestState):
        super().__init__(parent)
        self.state = state
        self.setWindowTitle(f"Deploy {state.cn}")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.addWidget(_title("Add a deployment target"))
        layout.addWidget(
            muted_label(
                "Files are written atomically whenever the certificate is issued or renewed. Private keys are "
                "always encrypted with pyCertWiz's saved passphrase (pyCertWiz never writes an unprotected key): give "
                "the service that passphrase, e.g. nginx ssl_password_file or Apache SSLPassPhraseDialog."
            )
        )
        form = QFormLayout()
        self.preset = QComboBox()
        self.preset.addItem("Custom files", "")
        default = "grid-host" if state.type == "host" else "globus-user"
        for name, preset in deploy_module.PRESETS.items():
            self.preset.addItem(f"{name} — {preset['description']}", name)
        self.preset.setCurrentIndex(max(0, self.preset.findData(default)))
        form.addRow("Layout", self.preset)
        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. grid or nginx")
        form.addRow("Target name", self.name)
        self.directory = QLineEdit()
        form.addRow("Directory", self._with_browse(self.directory, directory=True))
        layout.addLayout(form)

        self.stack = QStackedWidget()
        preset_page = QWidget()
        preset_page.setLayout(QVBoxLayout())
        self.preset_summary = muted_label()
        preset_page.layout().addWidget(self.preset_summary)
        self.stack.addWidget(preset_page)
        custom = QWidget()
        custom_form = QFormLayout(custom)
        self.paths: "dict[str, QLineEdit]" = {}
        for kind, label in (
            ("cert", "Certificate"),
            ("key", "Private key"),
            ("chain", "Chain"),
            ("fullchain", "Full chain"),
            ("bundle", "Key + chain (one PEM)"),
            ("p12", "PKCS#12 copy"),
        ):
            edit = QLineEdit()
            edit.setPlaceholderText("not written")
            self.paths[kind] = edit
            custom_form.addRow(label, self._with_browse(edit))
        self.stack.addWidget(custom)
        layout.addWidget(self.stack)

        options = QFormLayout()
        self.hook = QLineEdit()
        self.hook.setPlaceholderText("optional, e.g. systemctl reload nginx")
        options.addRow("Reload hook", self.hook)
        perms = QHBoxLayout()
        self.cert_mode = QLineEdit("0644")
        self.cert_mode.setMaximumWidth(70)
        self.key_mode = QLineEdit("0600")
        self.key_mode.setMaximumWidth(70)
        self.owner = QLineEdit()
        self.owner.setPlaceholderText("owner")
        self.group = QLineEdit()
        self.group.setPlaceholderText("group")
        for caption, widget in (("cert", self.cert_mode), ("key", self.key_mode)):
            perms.addWidget(muted_label(caption, wrap=False))
            perms.addWidget(widget)
        perms.addWidget(self.owner)
        perms.addWidget(self.group)
        options.addRow("Permissions", perms)
        self.unencrypted = QCheckBox("Write the key file without a passphrase (asks you to confirm; never for bundles)")
        options.addRow("", self.unencrypted)
        self.deploy_now = QCheckBox("Deploy now")
        self.deploy_now.setChecked(bool(state.cert.sha256))
        self.deploy_now.setEnabled(bool(state.cert.sha256))
        options.addRow("", self.deploy_now)
        layout.addLayout(options)

        self.error = QLabel()
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = button("Add target", "deploy", primary=True)
        buttons.addButton(ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.preset.currentIndexChanged.connect(self._preset_changed)
        self._preset_changed()
        self.target: "dict | None" = None

    def _with_browse(self, edit: QLineEdit, *, directory: bool = False) -> QWidget:
        container = QWidget()
        row = QHBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(edit, 1)
        browse = button("…", flat=True)
        browse.setToolTip("Browse")

        def choose():
            if directory:
                path = QFileDialog.getExistingDirectory(self, "Choose a directory", edit.text() or str(Path.home()))
            else:
                path, _ = QFileDialog.getSaveFileName(self, "Choose a file", edit.text() or str(Path.home()))
            if path:
                edit.setText(path)

        browse.clicked.connect(choose)
        row.addWidget(browse)
        return container

    def _preset_changed(self) -> None:
        name = self.preset.currentData()
        self.stack.setCurrentIndex(0 if name else 1)
        self.directory.parentWidget().setEnabled(bool(name))
        if name:
            preset = deploy_module.PRESETS[name]
            self.directory.setText(preset["dir"])
            self.name.setText(name)
            self.hook.setText(preset.get("hook", ""))
            self.key_mode.setText(preset.get("key_mode", "0600"))
            self.cert_mode.setText(preset.get("cert_mode", "0644"))
            files = [f"{kind}: {value}" for kind, value in preset.items() if kind in deploy_module.FILE_KINDS]
            self.preset_summary.setText("Writes " + "; ".join(files).replace("{dir}", "<directory>"))
        else:
            self.name.setText("custom")

    def _accept(self) -> None:
        try:
            name = self.preset.currentData()
            if name:
                target = deploy_module.target_from_preset(
                    name,
                    name=self.name.text().strip() or name,
                    directory=self.directory.text().strip(),
                    alias=self.state.alias,
                    hook=self.hook.text().strip() or None,
                    owner=self.owner.text().strip(),
                    group=self.group.text().strip(),
                )
                target["cert_mode"] = self.cert_mode.text().strip() or target.get("cert_mode", "0644")
                target["key_mode"] = self.key_mode.text().strip() or target.get("key_mode", "0600")
                if not self.hook.text().strip():
                    target.pop("hook", None)
            else:
                target = {"name": self.name.text().strip() or "custom"}
                for kind, edit in self.paths.items():
                    if edit.text().strip():
                        target[kind] = str(Path(edit.text().strip()).expanduser())
                for key, edit in (("cert_mode", self.cert_mode), ("key_mode", self.key_mode), ("owner", self.owner), ("group", self.group), ("hook", self.hook)):
                    if edit.text().strip():
                        target[key] = edit.text().strip()
            if self.unencrypted.isChecked():
                if not target.get("key") or target.get("bundle"):
                    raise PyCertError("only a single key file can be written without a passphrase; bundles are always encrypted")
                if not confirm_unencrypted(self, f"the private key of '{self.state.alias}' to {target['key']} on every deployment"):
                    raise PyCertError("not confirmed: the key will be encrypted unless you confirm")
                from ..util import iso

                target["unencrypted_key"] = True
                target["unencrypted_key_confirmed"] = iso()
            self.target = deploy_module.validate_target(target)
        except Exception as exc:  # noqa: BLE001 - shown inline
            self.error.setText(str(exc))
            return
        self.accept()


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


class ImportDialog(QDialog):
    def __init__(self, parent: QWidget, config: Any, path: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Import a PKCS#12 bundle")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.addWidget(_title("Import an existing certificate"))
        layout.addWidget(
            muted_label(
                "Bring a certificate and key you already have (for example a CertWizard export) under pyCertWiz "
                "management, so it can be tracked, renewed, deployed and re-exported."
            )
        )
        form = QFormLayout()
        self.path = QLineEdit(path)
        browse = button("Browse…", "folder")
        browse.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        form.addRow("File", row)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Passphrase", self.password)
        self.alias = QLineEdit()
        self.alias.setPlaceholderText("default: the certificate's common name")
        form.addRow("Name in pyCertWiz", self.alias)
        self.ca = QComboBox()
        for name, profile in config.cas.items():
            self.ca.addItem(profile.display_name, name)
        form.addRow("Issued by", self.ca)
        self.allow_unverified = QCheckBox("Import even if the chain cannot be verified")
        form.addRow("", self.allow_unverified)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = button("Import", "import", primary=True)
        buttons.addButton(ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import PKCS#12", str(Path.home()), "PKCS#12 (*.p12 *.pfx);;All files (*)")
        if path:
            self.path.setText(path)
            if not self.alias.text():
                self.alias.setText(Path(path).stem)


# ---------------------------------------------------------------------------
# Reports (verify, doctor, CA info)
# ---------------------------------------------------------------------------


class ReportDialog(QDialog):
    """A table of (status, name, detail) rows with coloured status labels."""

    def __init__(self, parent: QWidget, title: str, summary: str, rows: "list[tuple[str, str, str]]", *, ok: bool = True):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 460)
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        mark = QLabel()
        t = theme.tokens()
        mark.setPixmap(icons.pixmap("verify" if ok else "alert", t.valid if ok else t.expired, 30))
        header.addWidget(mark)
        header.addWidget(_title(summary), 1)
        layout.addLayout(header)
        table = QTableWidget(len(rows), 3)
        table.setHorizontalHeaderLabels(["", "Check", "Detail"])
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setWordWrap(True)
        colours = {"ok": t.valid, "pass": t.valid, "warn": t.expiring, "fail": t.expired, "info": t.muted, "skip": t.muted}
        for index, (status, name, detail) in enumerate(rows):
            status_item = QTableWidgetItem(status.upper())
            status_item.setForeground(QColor(colours.get(status.lower(), t.text)))
            font = status_item.font()
            font.setBold(True)
            status_item.setFont(font)
            table.setItem(index, 0, status_item)
            table.setItem(index, 1, QTableWidgetItem(name))
            detail_item = QTableWidgetItem(detail)
            detail_item.setToolTip(detail)
            table.setItem(index, 2, detail_item)
        table.resizeColumnToContents(0)
        table.resizeColumnToContents(1)
        table.resizeRowsToContents()
        layout.addWidget(table, 1)
        self.table = table
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        copy = button("Copy", "copy")
        copy.clicked.connect(lambda: copy_to_clipboard("\n".join(f"[{s.upper()}] {n}: {d}" for s, n, d in rows)))
        buttons.addButton(copy, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class ProxyDialog(QDialog):
    def __init__(self, parent: QWidget, state: RequestState):
        super().__init__(parent)
        self.setWindowTitle("Create a proxy certificate")
        layout = QVBoxLayout(self)
        layout.addWidget(_title("RFC 3820 proxy certificate"))
        layout.addWidget(
            muted_label(
                "A short-lived proxy lets grid jobs act on your behalf without your long-term key. "
                "The proxy's private key is encrypted with pyCertWiz's saved passphrase; delete the file when "
                "the job finishes."
            )
        )
        form = QFormLayout()
        self.hours = QSpinBox()
        self.hours.setRange(1, 24 * 14)
        self.hours.setValue(12)
        self.hours.setSuffix(" hours")
        form.addRow("Lifetime", self.hours)
        self.limited = QCheckBox("Limited proxy (cannot be used to start new jobs)")
        form.addRow("", self.limited)
        self.out = QLineEdit()
        self.out.setPlaceholderText("default: the request folder / proxy.pem")
        form.addRow("Output file", self.out)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def flash(widget: QWidget, text: str, ms: int = 1600) -> None:
    """Briefly change a button's text (e.g. 'Copied')."""
    original = widget.text()
    widget.setText(text)
    QTimer.singleShot(ms, lambda: widget.setText(original))


# ---------------------------------------------------------------------------
# Java keystores
# ---------------------------------------------------------------------------


class LinkKeystoreDialog(QDialog):
    """Link a Java PKCS#12 keystore (CertWizard's cakeystore.pkcs12) as a certificate store."""

    def __init__(self, parent: QWidget, config: Any, path: str = "", password: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Use a Java keystore as a certificate store")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.addWidget(_title("Link a Java keystore"))
        layout.addWidget(
            muted_label(
                "Every certificate in the keystore appears in pyCertWiz and is kept in step with it: entries added "
                "by Java tools are picked up, and certificates pyCertWiz issues or renews are written back into the "
                "keystore (other entries are left byte-for-byte untouched; a .bak copy is kept). CertWizard "
                "requests still waiting for the CA are imported as pending and finished by pyCertWiz."
            )
        )
        form = QFormLayout()
        self.path = QLineEdit(path)
        self.path.setPlaceholderText("~/.ca/cakeystore.pkcs12")
        browse = button("Browse…", "folder")
        browse.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        form.addRow("Keystore file", row)
        self.password = QLineEdit(password)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Passphrase", self.password)
        self.name = QLineEdit()
        self.name.setPlaceholderText("default: from the file name")
        form.addRow("Name in pyCertWiz", self.name)
        self.ca = QComboBox()
        for name, profile in config.cas.items():
            self.ca.addItem(profile.display_name, name)
        form.addRow("Certificates are from", self.ca)
        self.auto_import = QCheckBox("Import entries pyCertWiz does not manage yet, automatically")
        self.auto_import.setChecked(True)
        self.write_back = QCheckBox("Write issued and renewed certificates back into the keystore")
        self.write_back.setChecked(True)
        form.addRow("", self.auto_import)
        form.addRow("", self.write_back)
        layout.addLayout(form)
        layout.addWidget(
            muted_label(
                "The passphrase is used for this session only and is never stored: pyCertWiz asks for it each time it starts."
            )
        )
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = button("Link keystore", "package", primary=True)
        buttons.addButton(ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a Java keystore", str(Path.home()), "PKCS#12 keystores (*.p12 *.pfx *.pkcs12 *.keystore);;All files (*)"
        )
        if path:
            self.path.setText(path)

    def _accept(self) -> None:
        if not self.path.text().strip():
            self.error.setText("Choose the keystore file.")
            return
        if not self.password.text():
            self.error.setText("Enter the keystore passphrase.")
            return
        self.accept()


# ---------------------------------------------------------------------------
# Protection of individually exported keys
# ---------------------------------------------------------------------------

UNENCRYPTED_CONFIRMATION = "unencrypted"


PASSPHRASE_HINT = (
    "At least 8 characters, and not pyCertWiz's own saved passphrase. pyCertWiz does not keep it: "
    "store it somewhere safe, you will need it to use the file."
)


def passphrase_problem(password: str, repeat: str) -> str:
    """Why a new export passphrase is not acceptable ('' if it is)."""
    from ..exporter import MIN_PASSPHRASE

    if not password:
        return "Enter a new passphrase."
    if len(password) < MIN_PASSPHRASE:
        return f"The passphrase must be at least {MIN_PASSPHRASE} characters."
    if password != repeat:
        return "The passphrases do not match."
    return ""


def confirm_unencrypted(parent: QWidget, what: str) -> bool:
    """The explicit override for writing one private key without a passphrase."""
    from PySide6.QtWidgets import QInputDialog

    text, ok = QInputDialog.getText(
        parent,
        "Write a key without a passphrase?",
        f"You asked to write {what} WITHOUT a passphrase.\n"
        "Anyone who can read that file can use the key and impersonate the certificate's owner.\n\n"
        f"Type '{UNENCRYPTED_CONFIRMATION}' to confirm:",
    )
    return bool(ok) and text.strip() == UNENCRYPTED_CONFIRMATION


class KeyProtectionDialog(QDialog):
    """How to protect an individually exported private key."""

    def __init__(self, parent: QWidget, title: str, what: str, *, directory: str = ""):
        super().__init__(parent)
        self.what = what
        self.setWindowTitle(title)
        self.setMinimumWidth(540)
        layout = QVBoxLayout(self)
        layout.addWidget(_title(title))
        form = QFormLayout()
        self.directory = QLineEdit(directory)
        if directory:
            row = QHBoxLayout()
            row.addWidget(self.directory, 1)
            browse = button("…", flat=True)
            browse.clicked.connect(self._browse)
            row.addWidget(browse)
            form.addRow("Folder", row)
        layout.addLayout(form)
        from PySide6.QtWidgets import QButtonGroup, QRadioButton

        self.own = QRadioButton("Encrypt with a new passphrase I choose (recommended)")
        self.none = QRadioButton("No passphrase (not recommended; you will be asked to confirm)")
        self.own.setChecked(True)
        group = QButtonGroup(self)
        for widget in (self.own, self.none):
            group.addButton(widget)
            layout.addWidget(widget)
        own_form = QFormLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        own_form.addRow("New passphrase", self.password)
        own_form.addRow("Repeat", self.confirm)
        own_form.addRow("", muted_label(PASSPHRASE_HINT))
        self.own_box = QWidget()
        self.own_box.setLayout(own_form)
        self.own.toggled.connect(self.own_box.setEnabled)
        layout.addWidget(self.own_box)
        self.error = QLabel()
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.chosen_password: "str | None" = None
        self.no_passphrase = False

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose a folder", self.directory.text() or str(Path.home()))
        if path:
            self.directory.setText(path)

    def _accept(self) -> None:
        self.chosen_password, self.no_passphrase = None, False
        if self.own.isChecked():
            problem = passphrase_problem(self.password.text(), self.confirm.text())
            if problem:
                self.error.setText(problem)
                return
            self.chosen_password = self.password.text()
        elif self.none.isChecked():
            if not confirm_unencrypted(self, self.what):
                self.error.setText("Not confirmed: choose a passphrase option.")
                return
            self.no_passphrase = True
        self.accept()


class ExportDialog(QDialog):
    """Choose what to export, in which format and encryption, with a new passphrase."""

    def __init__(self, parent: QWidget, ctx: Any, state: RequestState, *, format: str = "p12", directory: str = ""):
        from ..exporter import FORMATS, default_destination

        super().__init__(parent)
        self.ctx = ctx
        self.state = state
        self.setWindowTitle(f"Export {state.alias}")
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        layout.addWidget(_title(f"Export “{state.alias}”"))
        form = QFormLayout()
        self.format = QComboBox()
        for fmt in FORMATS.values():
            self.format.addItem(fmt.label, fmt.name)
        form.addRow("Format", self.format)
        self.format_note = muted_label("")
        self.format_note.setWordWrap(True)
        form.addRow("", self.format_note)
        self.encryption = QComboBox()
        self.encryption_label = QLabel("Encryption")
        form.addRow(self.encryption_label, self.encryption)
        self.encryption_note = muted_label("")
        self.encryption_note.setWordWrap(True)
        form.addRow("", self.encryption_note)
        self.include_chain = QCheckBox("Include the issuing CA certificates (the chain)")
        self.include_chain.setChecked(True)
        form.addRow("", self.include_chain)
        self.destination = QLineEdit()
        row = QHBoxLayout()
        row.addWidget(self.destination, 1)
        browse = button("…", flat=True)
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        form.addRow("Save to", row)
        layout.addLayout(form)
        self.key_box = QWidget()
        key_form = QFormLayout(self.key_box)
        key_form.setContentsMargins(0, 0, 0, 0)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        key_form.addRow("New passphrase", self.password)
        key_form.addRow("Repeat", self.confirm)
        key_form.addRow("", muted_label(PASSPHRASE_HINT))
        self.no_passphrase = QCheckBox("Write the key without a passphrase (you will be asked to confirm)")
        self.no_passphrase.toggled.connect(self._no_passphrase_toggled)
        key_form.addRow("", self.no_passphrase)
        layout.addWidget(self.key_box)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = button("Export", "export", primary=True)
        buttons.addButton(ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._directory = Path(directory or Path.home()).expanduser()
        self._default = str(default_destination(state.alias, format, self._directory))
        self.destination.setText(self._default)
        self.format.currentIndexChanged.connect(self._format_changed)
        self.encryption.currentIndexChanged.connect(self._encryption_changed)
        self.format.setCurrentIndex(max(0, self.format.findData(format)))
        self._format_changed()
        self.request: "dict[str, Any] | None" = None

    def selected_format(self):
        from ..exporter import get_format

        return get_format(self.format.currentData())

    def _format_changed(self) -> None:
        from ..exporter import default_destination

        fmt = self.selected_format()
        self.format_note.setText(fmt.description)
        self.encryption.blockSignals(True)
        self.encryption.clear()
        for encryption in fmt.encryptions.values():
            self.encryption.addItem(encryption.label, encryption.name)
        self.encryption.blockSignals(False)
        for widget in (self.encryption, self.encryption_label, self.encryption_note):
            widget.setVisible(bool(fmt.encryptions))
        self._encryption_changed()
        self.include_chain.setVisible(fmt.chain_option)
        self.key_box.setVisible(fmt.has_key)
        self.no_passphrase.setVisible(fmt.has_key and not fmt.bundle)
        if fmt.bundle and self.no_passphrase.isChecked():
            self.no_passphrase.setChecked(False)
        # Follow the format with the suggested name unless the user typed their own.
        if self.destination.text() == self._default:
            self._default = str(default_destination(self.state.alias, fmt, self._directory))
            self.destination.setText(self._default)

    def _encryption_changed(self) -> None:
        fmt = self.selected_format()
        chosen = fmt.encryptions.get(self.encryption.currentData() or "")
        self.encryption_note.setText(chosen.description if chosen else "")

    def _no_passphrase_toggled(self, checked: bool) -> None:
        self.password.setEnabled(not checked)
        self.confirm.setEnabled(not checked)

    def _browse(self) -> None:
        fmt = self.selected_format()
        current = self.destination.text().strip() or str(self._directory)
        if fmt.is_directory:
            path = QFileDialog.getExistingDirectory(self, "Choose a folder", current)
        else:
            path, _filter = QFileDialog.getSaveFileName(self, "Export to", current)
        if path:
            self.destination.setText(path)

    def _accept(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        from ..exporter import check_passphrase

        fmt = self.selected_format()
        destination = self.destination.text().strip()
        if not destination:
            self.error.setText("Choose where to save the export.")
            return
        password: "str | None" = None
        no_passphrase = False
        if fmt.has_key:
            if self.no_passphrase.isChecked() and not fmt.bundle:
                if not confirm_unencrypted(self, f"the private key of '{self.state.alias}'"):
                    self.error.setText("Not confirmed: enter a passphrase instead.")
                    return
                no_passphrase = True
            else:
                problem = passphrase_problem(self.password.text(), self.confirm.text())
                if problem:
                    self.error.setText(problem)
                    return
                password = self.password.text()
            try:
                check_passphrase(self.ctx, fmt, password, no_passphrase)
            except PyCertError as exc:
                self.error.setText(str(exc)[:1].upper() + str(exc)[1:] + ".")
                return
        from ..exporter import file_base

        path = Path(destination).expanduser()
        if fmt.is_directory:
            targets = [path / f"{file_base(self.state.alias)}{suffix}" for suffix in (".pem", ".key")]
        elif path.is_dir():
            targets = [path / f"{file_base(self.state.alias)}{fmt.suffix}"]
        else:
            targets = [path]
        existing = [str(t) for t in targets if t.exists() and not t.is_dir()]
        overwrite = False
        if existing:
            answer = QMessageBox.question(self, "Replace existing files?", "These files exist:\n" + "\n".join(existing) + "\n\nReplace them?")
            if answer != QMessageBox.StandardButton.Yes:
                return
            overwrite = True
        self.request = {
            "format": fmt.name,
            "encryption": self.encryption.currentData() or "",
            "destination": path,
            "password": password,
            "no_passphrase": no_passphrase,
            "include_chain": self.include_chain.isChecked() or not fmt.chain_option,
            "overwrite": overwrite,
        }
        self.accept()


class RenameDialog(QDialog):
    """A new name for a certificate (and, if linked, its Java keystore entry)."""

    def __init__(self, parent: QWidget, ctx: Any, state: RequestState):
        super().__init__(parent)
        self.ctx = ctx
        self.state = state
        self.setWindowTitle(f"Rename {state.alias}")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.addWidget(_title("Rename certificate"))
        layout.addWidget(
            muted_label("The name is how pyCertWiz lists the certificate. Its files and the certificate itself do not change.")
        )
        form = QFormLayout()
        self.name = QLineEdit(state.alias)
        self.name.selectAll()
        form.addRow("New name", self.name)
        layout.addLayout(form)
        self.keystore_entry = QCheckBox()
        link_name = state.keystore.get("name") if state.keystore else ""
        self.link = None
        if link_name:
            try:
                self.link = ctx.config.keystore(link_name)
            except PyCertError:
                self.link = None
        if self.link is not None:
            java_alias = state.keystore.get("alias") or state.alias
            # The Java alias can be long: keep it out of the (non-wrapping) checkbox label.
            self.keystore_entry.setText(f"Also rename its entry in Java keystore '{self.link.name}'")
            self.keystore_entry.setChecked(bool(self.link.write_back))
            self.keystore_entry.setEnabled(bool(self.link.write_back))
            if not self.link.write_back:
                self.keystore_entry.setToolTip("The keystore is linked read-only.")
            layout.addWidget(self.keystore_entry)
            entry = muted_label(f"Current entry: {java_alias}")
            entry.setWordWrap(True)
            entry.setContentsMargins(24, 0, 0, 0)
            layout.addWidget(entry)
        else:
            self.keystore_entry.setVisible(False)
        self.error = QLabel()
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = button("Rename", "edit", primary=True)
        buttons.addButton(ok, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.new_name = ""

    def _accept(self) -> None:
        from ..workflow import validate_alias

        try:
            name = validate_alias(self.name.text())
        except PyCertError as exc:
            self.error.setText(str(exc).capitalize() + ".")
            return
        clash = [s for s in self.ctx.store.list() if s.slug != self.state.slug and s.alias.lower() == name.lower()]
        if clash:
            self.error.setText(f"Another certificate is already called '{clash[0].alias}'.")
            return
        self.new_name = name
        self.accept()

    @property
    def rename_keystore_entry(self) -> bool:
        """The linked, writable Java keystore entry is to be renamed too."""
        return self.link is not None and self.keystore_entry.isEnabled() and self.keystore_entry.isChecked()
