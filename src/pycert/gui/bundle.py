"""Inspect, export and update legacy Java / PKCS#12 / PEM certificate bundles."""

import hmac
import shutil
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import bundles, certs
from ..errors import PyCertError
from . import icons
from .widgets import button, copy_to_clipboard, muted_label

FILE_FILTER = (
    "Java keystores and PKCS#12 (*.p12 *.pfx *.pkcs12 *.jks *.keystore *.jceks);;"
    "PEM/DER certificates (*.pem *.crt *.cer *.der *.bundle);;All files (*)"
)


class BundleInspector(QDialog):
    """Open CertWizard's cakeystore.pkcs12, a JKS/JCEKS trust store or a PEM/DER bundle."""

    #: (path, passphrase): import every key entry into pyCertWiz
    import_all_requested = Signal(str, str)
    #: (path, passphrase): keep using this keystore as a certificate store
    link_requested = Signal(str, str)

    def __init__(self, parent: QWidget, path: "str | Path | None" = None):
        super().__init__(parent)
        self.setWindowTitle("Certificate bundle inspector")
        self.resize(1100, 720)
        self.bundle: "bundles.CertificateBundle | None" = None
        self._loaded_password = ""
        layout = QVBoxLayout(self)
        title = QLabel("Java and PKCS#12 bundles")
        title.setObjectName("DetailTitle")
        layout.addWidget(title)
        layout.addWidget(
            muted_label(
                "Open a CertWizard cakeystore.pkcs12, a Java JKS/JCEKS trust store or a PEM/DER bundle. "
                "Every certificate is listed; private keys are never displayed."
            )
        )
        row = QHBoxLayout()
        self.path = QLineEdit(str(path) if path else "")
        self.path.setPlaceholderText("bundle file")
        browse = button("Browse…", "folder")
        browse.clicked.connect(self._browse)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("passphrase (if any)")
        self.password.returnPressed.connect(self.load)
        show = QCheckBox("Show")
        show.toggled.connect(
            lambda on: self.password.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password)
        )
        decode = button("Decode", "eye", primary=True)
        decode.clicked.connect(self.load)
        row.addWidget(self.path, 2)
        row.addWidget(browse)
        row.addWidget(self.password, 1)
        row.addWidget(show)
        row.addWidget(decode)
        layout.addLayout(row)
        self.summary = muted_label("Choose a file and decode it.")
        layout.addWidget(self.summary)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["#", "Role", "Subject", "Issuer", "Expires", "Key", "Alias"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_details)
        splitter.addWidget(self.table)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        mono = QFont("Menlo")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.details.setFont(mono)
        splitter.addWidget(self.details)
        splitter.setSizes([320, 280])
        layout.addWidget(splitter, 1)

        actions = QHBoxLayout()
        self.copy_button = button("Copy PEM", "copy")
        self.copy_button.clicked.connect(self._copy_selected)
        self.copy_all_button = button("Copy all PEM", "copy")
        self.copy_all_button.clicked.connect(self._copy_all)
        self.save_pem_button = button("Save all as PEM…", "download")
        self.save_pem_button.clicked.connect(self.save_pem)
        self.save_java_button = button("Save as Java PKCS#12…", "package")
        self.save_java_button.clicked.connect(self.save_java)
        self.update_button = button("Update bundle in place…", "refresh")
        self.update_button.clicked.connect(self.update_in_place)
        for widget in (self.copy_button, self.copy_all_button, self.save_pem_button, self.save_java_button, self.update_button):
            actions.addWidget(widget)
        actions.addStretch(1)
        self.import_button = button("Import all into pyCertWiz", "import")
        self.import_button.setToolTip("Bring every key entry under pyCertWiz management (one-off)")
        self.import_button.clicked.connect(
            lambda: self.import_all_requested.emit(str(Path(self.path.text().strip()).expanduser()), self._loaded_password)
        )
        self.link_button = button("Use as certificate store…", "package", primary=True)
        self.link_button.setToolTip("Keep this keystore in step with pyCertWiz: import its entries and write renewals back")
        self.link_button.clicked.connect(
            lambda: self.link_requested.emit(str(Path(self.path.text().strip()).expanduser()), self._loaded_password)
        )
        actions.addWidget(self.import_button)
        actions.addWidget(self.link_button)
        close = button("Close")
        close.clicked.connect(self.accept)
        actions.addWidget(close)
        layout.addLayout(actions)
        self._set_enabled(False)
        if path:
            self.load(auto=True)

    # -- loading ---------------------------------------------------------------
    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open certificate bundle", str(Path.home()), FILE_FILTER)
        if path:
            self.path.setText(path)
            self.load(auto=True)

    def load(self, auto: bool = False) -> bool:
        raw = self.path.text().strip()
        if not raw:
            self.summary.setText("Choose a bundle file first.")
            return False
        try:
            bundle = bundles.load_bundle(Path(raw).expanduser(), self.password.text())
        except PyCertError as exc:
            self.summary.setText(str(exc))
            if not auto:
                QMessageBox.warning(self, "Could not decode the bundle", str(exc))
            else:
                self.password.setFocus()
            return False
        self.bundle = bundle
        self._loaded_password = self.password.text()
        self._populate()
        return True

    def _populate(self) -> None:
        assert self.bundle is not None
        bundle = self.bundle
        self.table.setRowCount(0)
        now = datetime.now(timezone.utc)
        for entry in bundle.certificates:
            info = certs.describe_certificate(entry.certificate)
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (str(entry.index), entry.role, info.subject, info.issuer, str(info.not_after.date()), info.key, entry.alias)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                # days_remaining is clamped at 0, so compare the dates to find expired certificates.
                if column == 4 and info.not_after < now:
                    item.setForeground(Qt.GlobalColor.red)
                self.table.setItem(row, column, item)
            self.table.item(row, 1).setIcon(
                icons.icon({"leaf": "award", "chain": "chain", "trusted": "shield"}.get(entry.role, "list"))
            )
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(1)
        parts = [bundle.format.upper(), f"{len(bundle)} certificate{'s' if len(bundle) != 1 else ''}"]
        parts.append(
            f"private key: {bundle.key_description or 'present'} (not displayed)" if bundle.has_private_key else "no private key"
        )
        if bundle.key_count > 1:
            parts.append(f"{bundle.key_count} key entries")
        if bundle.integrity_checked:
            parts.append("integrity verified")
        text = " · ".join(parts)
        if bundle.warnings:
            text += "\n" + " · ".join(bundle.warnings)
        self.summary.setText(text)
        self._set_enabled(True)
        if bundle.certificates:
            self.table.selectRow(0)

    def _set_enabled(self, enabled: bool) -> None:
        for widget in (self.copy_button, self.copy_all_button, self.save_pem_button, self.save_java_button):
            widget.setEnabled(enabled)
        self.update_button.setEnabled(enabled and self.bundle is not None and self.bundle.format == "pkcs12")
        has_keys = enabled and self.bundle is not None and self.bundle.format == "pkcs12" and self.bundle.key_count > 0
        self.import_button.setEnabled(has_keys)
        self.link_button.setEnabled(has_keys)

    def _selected(self) -> "bundles.BundleCertificate | None":
        if self.bundle is None:
            return None
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        index = rows[0].row()
        return self.bundle.certificates[index] if 0 <= index < len(self.bundle.certificates) else None

    def _show_details(self) -> None:
        entry = self._selected()
        if entry is None:
            self.details.clear()
            return
        info = certs.describe_certificate(entry.certificate)
        lines = [
            f"Role         {entry.role}" + (f"   alias {entry.alias}" if entry.alias else ""),
            f"Subject      {info.subject}",
            f"Issuer       {info.issuer}",
            f"Serial       {info.serial}",
            f"Validity     {info.not_before.date()} .. {info.not_after.date()}  ({_remaining(info.not_after)})",
            f"Key          {info.key}",
            f"Signature    {info.signature}",
            f"SHA-256      {info.fingerprint_sha256}",
            f"Basic        {info.basic_constraints}",
            f"Key usage    {', '.join(info.key_usage) or '(none)'}",
            f"EKU          {', '.join(info.extended_key_usage) or '(none)'}",
            f"SANs         {', '.join(info.subject_alt_names) or '(none)'}",
        ]
        if info.aia_urls:
            lines.append(f"AIA          {', '.join(info.aia_urls)}")
        if info.crl_urls:
            lines.append(f"CRL          {', '.join(info.crl_urls)}")
        lines += ["", certs.cert_pem(entry.certificate)]
        self.details.setPlainText("\n".join(lines))

    # -- actions ---------------------------------------------------------------
    def _all_pem(self) -> str:
        return "" if self.bundle is None else "".join(certs.cert_pem(e.certificate) for e in self.bundle.certificates)

    def _copy_selected(self) -> None:
        entry = self._selected()
        if entry is not None:
            copy_to_clipboard(certs.cert_pem(entry.certificate))
            self.summary.setText("Selected certificate copied to the clipboard.")

    def _copy_all(self) -> None:
        copy_to_clipboard(self._all_pem())
        self.summary.setText("All certificates copied to the clipboard.")

    def save_pem(self, path: "str | None" = None) -> "str | None":
        if self.bundle is None:
            return None
        if path is None:
            default = str(Path(self.bundle.path).with_suffix(".pem")) if self.bundle.path else "certificates.pem"
            path, _ = QFileDialog.getSaveFileName(self, "Save certificates as PEM", default, "PEM (*.pem);;All files (*)")
        if not path:
            return None
        Path(path).write_text(self._all_pem())
        self.summary.setText(f"Saved {len(self.bundle)} certificates to {path}.")
        return path

    def _new_password(self, *, new_file: bool = False) -> "str | None":
        if self.bundle is not None and self.bundle.raw_key_bags:
            # Raw Java key bags stay encrypted with the passphrase used to open the
            # bundle; changing it would make those keys unreadable.
            return self._loaded_password
        password, ok = QInputDialog.getText(
            self, "Bundle passphrase", "Passphrase for the new PKCS#12 bundle:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return None
        if new_file and self.bundle is not None and self.bundle.has_private_key:
            repeat, ok = QInputDialog.getText(self, "Bundle passphrase", "Repeat the passphrase:", QLineEdit.EchoMode.Password)
            if not ok or repeat != password:
                QMessageBox.warning(self, "Not saved", "The passphrases do not match.")
                return None
        return password

    def _export_problem(self, password: str) -> str:
        """A new file holding private keys needs a new passphrase (as every pyCertWiz export)."""
        from ..exporter import MIN_PASSPHRASE

        if self.bundle is None or not self.bundle.has_private_key or self.bundle.raw_key_bags:
            return ""
        if len(password) < MIN_PASSPHRASE:
            return f"The passphrase must be at least {MIN_PASSPHRASE} characters."
        ctx = getattr(self.parent(), "ctx", None)
        saved = ctx.secrets.get(allow_missing=True) if ctx is not None else None
        if saved and hmac.compare_digest(password.encode("utf-8"), saved.encode("utf-8")):
            return "Choose a new passphrase for this file, not pyCertWiz's own saved passphrase."
        return ""

    def save_java(self, path: "str | None" = None, password: "str | None" = None) -> "str | None":
        if self.bundle is None:
            return None
        if path is None:
            default = str(Path(self.bundle.path).with_suffix(".java.p12")) if self.bundle.path else "certificates.p12"
            path, _ = QFileDialog.getSaveFileName(self, "Save Java-compatible PKCS#12", default, "PKCS#12 (*.p12 *.pfx)")
        if not path:
            return None
        if self.bundle.path and Path(path).resolve() == Path(self.bundle.path).resolve():
            QMessageBox.information(self, "Use Update", "That is the open bundle; use 'Update bundle in place' instead.")
            return None
        password = password if password is not None else self._new_password(new_file=True)
        if not password:
            return None
        problem = self._export_problem(password)
        if problem:
            QMessageBox.warning(self, "Choose another passphrase", problem)
            return None
        try:
            bundles.write_java_bundle(path, self.bundle, password)
        except (OSError, PyCertError) as exc:
            QMessageBox.warning(self, "Could not save the bundle", str(exc))
            return None
        self.summary.setText(f"Java-compatible PKCS#12 written to {path}.")
        return path

    def update_in_place(self, *, confirm: bool = True, password: "str | None" = None) -> bool:
        if self.bundle is None or self.bundle.format != "pkcs12":
            return False
        path = Path(self.bundle.path)
        if confirm and QMessageBox.question(
            self,
            "Update bundle",
            f"Rewrite {path} with its decoded certificates and keys?\n\nA backup named {path.name}.bak is kept.",
        ) != QMessageBox.StandardButton.Yes:
            return False
        password = password if password is not None else self._new_password()
        if not password:
            return False
        backup = path.with_name(path.name + ".bak")
        try:
            shutil.copy2(path, backup)
            bundles.write_java_bundle(path, self.bundle, password)
        except (OSError, PyCertError) as exc:
            QMessageBox.warning(self, "Could not update the bundle", str(exc))
            return False
        self.summary.setText(f"Bundle updated in place; backup: {backup}")
        return True


def _remaining(not_after: datetime) -> str:
    """'N days left', or how long ago the certificate expired."""
    now = datetime.now(timezone.utc)
    if not_after >= now:
        return f"{(not_after - now).days} days left"
    return f"expired {(now - not_after).days} days ago"
