"""A viewer for a certificate's chain, public key and (on request) private key.

The certificate chain and the public key are public. The private key is only
decrypted and shown after the user types a confirmation, is never offered for
copying, and is cleared when it is hidden or the viewer closes.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import certs
from ..errors import PyCertError
from . import theme
from .widgets import _home_relative, button, copy_to_clipboard, kind_description, muted_label

#: What the user types to show a private key on screen.
REVEAL_CONFIRMATION = "show"


def _hex(data: bytes, group: int = 2) -> str:
    text = data.hex().upper()
    return " ".join(text[i : i + group] for i in range(0, len(text), group))


def _wrap(text: str, width: int = 64) -> str:
    return "\n".join(text[i : i + width] for i in range(0, len(text), width))


def _extension_lines(certificate: x509.Certificate) -> "list[str]":
    lines: "list[str]" = []
    for extension in certificate.extensions:
        value = extension.value
        name = extension.oid._name if extension.oid._name != "Unknown OID" else extension.oid.dotted_string
        critical = " (critical)" if extension.critical else ""
        if isinstance(value, x509.SubjectAlternativeName):
            detail = ", ".join(f"{type(g).__name__.replace('Name', '').replace('RFC822', 'email')}:{g.value}" for g in value)
        elif isinstance(value, x509.KeyUsage):
            flags = [
                label
                for label, attr in (
                    ("digitalSignature", "digital_signature"),
                    ("nonRepudiation", "content_commitment"),
                    ("keyEncipherment", "key_encipherment"),
                    ("dataEncipherment", "data_encipherment"),
                    ("keyAgreement", "key_agreement"),
                    ("keyCertSign", "key_cert_sign"),
                    ("cRLSign", "crl_sign"),
                )
                if getattr(value, attr)
            ]
            detail = ", ".join(flags)
        elif isinstance(value, x509.ExtendedKeyUsage):
            detail = ", ".join(oid._name for oid in value)
        elif isinstance(value, x509.BasicConstraints):
            detail = f"CA={value.ca}" + (f", pathlen={value.path_length}" if value.path_length is not None else "")
        elif isinstance(value, (x509.SubjectKeyIdentifier,)):
            detail = _hex(value.digest)
        elif isinstance(value, x509.AuthorityKeyIdentifier) and value.key_identifier:
            detail = _hex(value.key_identifier)
        elif isinstance(value, x509.CertificatePolicies):
            detail = ", ".join(p.policy_identifier.dotted_string for p in value)
        elif isinstance(value, x509.CRLDistributionPoints):
            detail = ", ".join(str(n.value) for point in value for n in (point.full_name or []))
        else:
            detail = ""
        lines.append(f"  {name}{critical}" + (f": {detail}" if detail else ""))
    return lines


def certificate_text(certificate: x509.Certificate, role: str = "") -> str:
    """A readable description of one certificate followed by its PEM."""
    info = certs.describe_certificate(certificate)
    lines = [f"Role:          {role}"] if role else []
    lines += [
        f"Subject:       {certificate.subject.rfc4514_string()}",
        f"Issuer:        {certificate.issuer.rfc4514_string()}",
        f"Serial:        {_hex(certificate.serial_number.to_bytes((certificate.serial_number.bit_length() + 7) // 8 or 1, 'big'))}",
        f"Valid from:    {info.not_before.isoformat()}",
        f"Valid until:   {info.not_after.isoformat()}",
        f"Key:           {info.key}",
        f"Signature:     {certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else 'n/a'}",
        f"SHA-256:       {_hex(certificate.fingerprint(hashes.SHA256()))}",
        f"SHA-1:         {_hex(certificate.fingerprint(hashes.SHA1()))}",  # noqa: S303 - an identifier people compare
        "Extensions:",
        *_extension_lines(certificate),
        "",
        certs.cert_pem(certificate).rstrip(),
    ]
    return "\n".join(lines)


def public_key_text(public_key: Any) -> str:
    """Algorithm, parameters, identifiers and PEM of a public key."""
    lines = [f"Algorithm:     {certs.key_description(public_key)}"]
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        lines.append(f"Exponent:      {numbers.e} (0x{numbers.e:X})")
        lines.append("Modulus:")
        lines.extend("  " + line for line in _wrap(_hex(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")), 48).splitlines())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        lines.append(f"Curve:         {public_key.curve.name}")
        point = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        lines.append("Point:")
        lines.extend("  " + line for line in _wrap(_hex(point), 48).splitlines())
    elif isinstance(public_key, ed25519.Ed25519PublicKey):  # pragma: no cover - the CAs issue RSA/EC
        lines.append("Point:         " + _hex(public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    lines.append(f"SPKI SHA-256:  {certs.key_fingerprint(public_key)}")
    lines.append("SPKI (base64, as the UK CA looks it up):")
    lines.append(_wrap(base64.b64encode(der).decode("ascii")))
    lines.append("")
    lines.append(
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii").rstrip()
    )
    return "\n".join(lines)


def _mono_text() -> QPlainTextEdit:
    from PySide6.QtGui import QFontDatabase

    edit = QPlainTextEdit()
    edit.setReadOnly(True)
    edit.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    return edit


class CertificateViewer(QDialog):
    """Tabs: the certificate chain, the public key, and the private key on request."""

    def __init__(self, parent: QWidget, ctx: Any, state: Any):
        super().__init__(parent)
        self.ctx = ctx
        self.state = state
        self.setWindowTitle(f"{state.alias} — certificate, keys and chain")
        self.resize(860, 640)
        layout = QVBoxLayout(self)
        heading = QLabel(f"<b>{state.alias}</b>")
        heading.setStyleSheet("font-size: 16px;")
        layout.addWidget(heading)
        layout.addWidget(muted_label(f"{kind_description(state.type)} · status {state.status}"))
        self.certificate = ctx.store.load_certificate(state)
        self.chain = ctx.store.load_chain(state)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._chain_tab(), "Certificate chain")
        self.tabs.addTab(self._public_tab(), "Public key")
        self.tabs.addTab(self._private_tab(), "Private key")
        layout.addWidget(self.tabs, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # -- chain -----------------------------------------------------------------
    def full_chain(self) -> "list[x509.Certificate]":
        return [self.certificate, *self.chain]

    def _chain_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        chain = self.full_chain()
        explanation = (
            f"{len(chain)} certificate(s), from this certificate up to the root."
            if self.chain
            else "Only the certificate itself is stored; its issuers were not found."
        )
        layout.addWidget(muted_label(explanation))
        splitter = QSplitter()
        self.chain_list = QListWidget()
        for index, certificate in enumerate(chain):
            role = self._role(index, len(chain), certificate)
            item = QListWidgetItem(f"{role}: {certs.common_name(certificate.subject) or certificate.subject.rfc4514_string()}")
            item.setToolTip(certificate.subject.rfc4514_string())
            self.chain_list.addItem(item)
        self.chain_text = _mono_text()
        splitter.addWidget(self.chain_list)
        splitter.addWidget(self.chain_text)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)
        self.chain_list.currentRowChanged.connect(self._show_chain_entry)
        self.chain_list.setCurrentRow(0)
        row = QHBoxLayout()
        copy_one = button("Copy this certificate (PEM)", "copy")
        copy_one.clicked.connect(self.copy_selected)
        copy_all = button("Copy full chain (PEM)", "copy")
        copy_all.clicked.connect(self.copy_full_chain)
        save = button("Save full chain…", "download")
        save.clicked.connect(self.save_full_chain)
        for widget in (copy_one, copy_all, save):
            row.addWidget(widget)
        row.addStretch(1)
        layout.addLayout(row)
        return tab

    @staticmethod
    def _role(index: int, count: int, certificate: x509.Certificate) -> str:
        if index == 0:
            return "Certificate"
        if certificate.subject == certificate.issuer:
            return "Root"
        return "Intermediate" if index < count - 1 or count == 2 else "Issuer"

    def _show_chain_entry(self, row: int) -> None:
        chain = self.full_chain()
        if 0 <= row < len(chain):
            self.chain_text.setPlainText(certificate_text(chain[row], self._role(row, len(chain), chain[row])))

    def copy_selected(self) -> None:
        row = max(0, self.chain_list.currentRow())
        copy_to_clipboard(certs.cert_pem(self.full_chain()[row]))

    def copy_full_chain(self) -> None:
        copy_to_clipboard("".join(certs.cert_pem(c) for c in self.full_chain()))

    def save_full_chain(self) -> "Path | None":
        from ..exporter import default_destination, export_material

        suggested = default_destination(self.state.alias, "fullchain", Path.home())
        path, _filter = QFileDialog.getSaveFileName(self, "Save the full chain", str(suggested), "PEM files (*.pem *.crt);;All files (*)")
        if not path:
            return None
        try:
            result = export_material(
                alias=self.state.alias,
                certificate=self.certificate,
                chain=self.chain,
                load_key=None,
                fmt="fullchain",
                destination=path,
                ctx=self.ctx,
                overwrite=True,
            )
        except PyCertError as exc:
            QMessageBox.warning(self, "Could not save", str(exc))
            return None
        return result.files["fullchain"]

    # -- public key ------------------------------------------------------------
    def _public_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(muted_label("The public key from the certificate. It is public: share it freely."))
        self.public_text = _mono_text()
        self.public_text.setPlainText(public_key_text(self.certificate.public_key()))
        layout.addWidget(self.public_text, 1)
        row = QHBoxLayout()
        copy = button("Copy public key (PEM)", "copy")
        copy.clicked.connect(self.copy_public_key)
        row.addWidget(copy)
        row.addStretch(1)
        layout.addLayout(row)
        return tab

    def public_key_pem(self) -> str:
        return self.certificate.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def copy_public_key(self) -> None:
        copy_to_clipboard(self.public_key_pem())

    # -- private key -----------------------------------------------------------
    def _private_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        key_file = self.ctx.store.file(self.state, "key.pem")
        lines = [
            f"Key: {self.state.cert.key or self.state.key_algorithm or certs.key_description(self.certificate.public_key())}",
            f"Stored encrypted (PKCS#8, AES-256) with pyCertWiz's saved passphrase in {_home_relative(str(key_file))}",
        ]
        if self.state.keystore.get("name"):
            lines.append(
                f"Also held in Java keystore '{self.state.keystore['name']}' as '{self.state.keystore.get('alias', '')}'"
            )
        if self.state.renewal:
            lines.append("A renewal is in progress: a new key is waiting for its certificate.")
        layout.addWidget(muted_label("\n".join(lines)))
        warning = QLabel(
            "Anyone who sees the private key can impersonate this certificate. It is shown only after you "
            "confirm, is not copied anywhere, and is cleared when you hide it or close this window."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(f"color: {theme.tokens().expiring};")
        layout.addWidget(warning)
        self.private_text = _mono_text()
        self.private_text.setPlaceholderText("Hidden")
        layout.addWidget(self.private_text, 1)
        row = QHBoxLayout()
        self.reveal_button = button("Show private key…", "key")
        self.reveal_button.clicked.connect(self.reveal_private_key)
        self.hide_button = button("Hide", "close")
        self.hide_button.clicked.connect(self.hide_private_key)
        self.hide_button.setEnabled(False)
        row.addWidget(self.reveal_button)
        row.addWidget(self.hide_button)
        row.addStretch(1)
        layout.addLayout(row)
        return tab

    def reveal_private_key(self) -> bool:
        text, ok = QInputDialog.getText(
            self,
            "Show the private key?",
            "The private key will be decrypted and shown on screen.\n"
            "Make sure nobody else can see your screen.\n\n"
            f"Type '{REVEAL_CONFIRMATION}' to continue:",
        )
        if not ok or text.strip().lower() != REVEAL_CONFIRMATION:
            return False
        try:
            key = self.ctx.store.load_key(self.state, self.ctx.key_passphrase())
        except PyCertError as exc:
            QMessageBox.warning(self, "Cannot show the key", str(exc))
            return False
        matches = certs.certificate_matches_key(self.certificate, key)
        pem = certs.unprotected_key_pem(key, confirmed=True)
        note = "matches the certificate" if matches else "DOES NOT match the certificate"
        self.private_text.setPlainText(f"# {certs.key_description(key.public_key())}, {note}\n{pem}")
        self.hide_button.setEnabled(True)
        return True

    def hide_private_key(self) -> None:
        self.private_text.clear()
        self.hide_button.setEnabled(False)

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        self.hide_private_key()
        super().done(result)
