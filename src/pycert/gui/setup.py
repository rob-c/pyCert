"""First-run setup: create pyCertWiz's configuration from the GUI.

A freshly installed pyCertWiz (from a package, the AppImage or the macOS app)
has no configuration yet. Instead of telling the user to run ``pycert init``,
the GUI asks the same few questions and writes the same files.
"""

import platform
import shutil
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ..config import DEFAULT_BASE_URL
from ..errors import PyCertError
from ..secrets_store import auto_backend
from . import theme
from .widgets import button, muted_label

#: How each secret backend offered here keeps pyCertWiz's saved secret.
BACKEND_DESCRIPTIONS = {
    "keychain": "your macOS login keychain",
    "secret-service": "your desktop's secret service (GNOME Keyring or KWallet)",
    "file": "a private file (readable only by you) in pyCertWiz's data folder",
}


def backend_choices() -> "list[tuple[str, str]]":
    """(backend, label) pairs for this system, the recommended automatic choice first."""
    choices = [("auto", f"Automatic: {BACKEND_DESCRIPTIONS[auto_backend()]}")]
    if platform.system() == "Darwin" and shutil.which("security"):
        choices.append(("keychain", "macOS keychain"))
    if shutil.which("secret-tool"):
        choices.append(("secret-service", "Desktop secret service"))
    choices.append(("file", "Private file in the data folder"))
    return choices


def _home_relative(path: Path) -> str:
    try:
        return "~/" + str(path.relative_to(Path.home()))
    except ValueError:
        return str(path)


class SetupDialog(QDialog):
    """Ask for the e-mail address, RA and secret storage, then write the configuration."""

    def __init__(self, parent: "QWidget | None" = None, directory: "Path | None" = None):
        from ..workflow import default_config_dir

        super().__init__(parent)
        self.directory = directory or default_config_dir()
        self.context: Any = None
        self.setWindowTitle("Welcome to pyCertWiz")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        title = QLabel("Welcome to pyCertWiz")
        font = title.font()
        font.setPointSizeF(font.pointSizeF() * 1.4)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)
        layout.addWidget(
            muted_label(
                "pyCertWiz has not been set up on this computer yet. Answer a few questions and it "
                f"writes its configuration to {_home_relative(self.directory / 'pycert.toml')}. "
                "You can change all of it later."
            )
        )
        form = QFormLayout()
        self.email = QLineEdit()
        self.email.setPlaceholderText("you@example.ac.uk")
        form.addRow("E-mail address", self.email)
        form.addRow("", muted_label("The contact address on your certificate requests. Optional now."))
        self.ra = QLineEdit()
        self.ra.setPlaceholderText("e.g. CLRC DL")
        form.addRow("Your RA", self.ra)
        form.addRow("", muted_label("The Registration Authority that checks your requests, as 'OU L'. Optional now."))
        self.backend = QComboBox()
        for value, label in backend_choices():
            self.backend.addItem(label, value)
        form.addRow("Keep the saved secret in", self.backend)
        form.addRow(
            "",
            muted_label(
                "pyCertWiz protects the keys in its own store with a random secret kept here. "
                "Passphrases for files you export, and for linked Java keystores, are never saved."
            ),
        )
        form.addRow("Certificate authority", QLabel(f"UK e-Science CA ({DEFAULT_BASE_URL})"))
        form.addRow("", muted_label("Other CAs, such as ACME CAs, can be added afterwards."))
        layout.addLayout(form)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox()
        quit_button = button("Quit")
        buttons.addButton(quit_button, QDialogButtonBox.ButtonRole.RejectRole)
        create = button("Set up pyCertWiz", "check", primary=True)
        create.setDefault(True)
        buttons.addButton(create, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        from ..workflow import create_configuration

        try:
            self.context = create_configuration(
                self.directory,
                email=self.email.text(),
                ra=self.ra.text(),
                backend=self.backend.currentData(),
            )
        except PyCertError as exc:
            text = str(exc)
            self.error.setText(text[:1].upper() + text[1:] + ("" if text.endswith(".") else "."))
            return
        self.accept()

    @property
    def config_path(self) -> "Path | None":
        return self.context.config.path if self.context is not None else None
