"""Settings: identity defaults, keys and export, CA profiles, secrets, appearance and monitoring."""

from typing import Any

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..config import (
    ACME_CHALLENGES,
    ACME_HTTP_MODES,
    ConfigError,
    load_config,
    new_acme_profile,
    new_ukca_profile,
    validate_config,
    write_config,
)
from ..errors import PyCertError
from ..secrets_store import BACKENDS, SecretStore
from . import icons, theme
from .widgets import button, muted_label

ORGANISATION = "pyCert"
APPLICATION = "pyCert"


def preferences() -> QSettings:
    """Per-user GUI preferences (appearance, monitoring) - not the pyCertWiz configuration file.

    ``PYCERT_GUI_SETTINGS=/path/file.ini`` keeps them in an INI file instead of the
    platform store (portable installs, tests).
    """
    import os

    override = os.environ.get("PYCERT_GUI_SETTINGS")
    if override:
        return QSettings(override, QSettings.Format.IniFormat)
    return QSettings(ORGANISATION, APPLICATION)


def pref(key: str, default: Any) -> Any:
    value = preferences().value(key, default)
    if isinstance(default, bool):
        return value in (True, "true", "1", 1)
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return value


DEFAULT_PREFS = {
    "appearance": "system",
    "warn_days": 30,
    "crit_days": 7,
    "refresh_minutes": 30,
    "auto_collect": True,
    "tray": True,
    "notify": True,
}


class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget, config_path: "str | None"):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.resize(780, 560)
        self.config_path = config_path
        self.config = load_config(config_path)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self._general_tab()
        self._keys_tab()
        self._ca_tab()
        self._secrets_tab()
        self._app_tab()
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet(f"color: {theme.tokens().expired};")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.saved = False

    # -- tabs ----------------------------------------------------------------
    def _page(self, title: str, icon_name: str, intro: str = "") -> QFormLayout:
        page = QWidget()
        outer = QVBoxLayout(page)
        if intro:
            outer.addWidget(muted_label(intro))
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        outer.addLayout(form)
        outer.addStretch(1)
        self.tabs.addTab(page, icons.icon(icon_name), title)
        return form

    def _general_tab(self) -> None:
        identity = self.config.identity
        form = self._page("Identity", "user", "Defaults used for new requests. Each request can override them.")
        self.email = QLineEdit(identity.email)
        self.ra = QLineEdit(identity.ra)
        self.ra.setPlaceholderText("e.g. CLRC DL (see 'Fetch list' in the request wizard)")
        self.o = QLineEdit(identity.o)
        self.ou = QLineEdit(identity.ou)
        self.l = QLineEdit(identity.l)
        self.c = QLineEdit(identity.c)
        self.c.setMaxLength(2)
        form.addRow("E-mail", self.email)
        form.addRow("Default RA", self.ra)
        form.addRow("Organisation (O)", self.o)
        form.addRow("Unit (OU)", self.ou)
        form.addRow("Locality (L)", self.l)
        form.addRow("Country (C)", self.c)

    def _keys_tab(self) -> None:
        form = self._page("Keys && export", "key")
        self.algorithm = QComboBox()
        self.algorithm.addItems(["rsa", "ec"])
        self.algorithm.setCurrentText(self.config.keys.algorithm)
        self.rsa_bits = QComboBox()
        self.rsa_bits.addItems(["2048", "3072", "4096"])
        self.rsa_bits.setCurrentText(str(self.config.keys.rsa_bits))
        self.ec_curve = QComboBox()
        self.ec_curve.addItems(["P-256", "P-384", "P-521"])
        self.ec_curve.setCurrentText(self.config.keys.ec_curve)
        self.p12_template = QLineEdit(self.config.p12.filename_template)
        self.p12_dir = QLineEdit(self.config.p12.export_dir)
        self.p12_dir.setPlaceholderText("the request folder")
        self.include_chain = QCheckBox("Include the CA chain in exported .p12 files")
        self.include_chain.setChecked(self.config.p12.include_chain)
        self.data_dir = QLineEdit(self.config.paths.data_dir)
        form.addRow("Default key type", self.algorithm)
        form.addRow("RSA size", self.rsa_bits)
        form.addRow("EC curve", self.ec_curve)
        form.addRow(".p12 file name", self.p12_template)
        form.addRow(".p12 folder", self.p12_dir)
        form.addRow("", self.include_chain)
        form.addRow("Data folder", self.data_dir)

    def _ca_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(
            muted_label(
                "pyCertWiz can manage certificates from several CAs. The primary CA is the UK e-Science CA "
                "(CertWizard protocol); add ACME CAs such as Let's Encrypt or a Sectigo/Jisc account for host certificates."
            )
        )
        row = QHBoxLayout()
        self.ca_list = QListWidget()
        self.ca_list.currentRowChanged.connect(self._show_ca)
        row.addWidget(self.ca_list, 1)
        self.ca_form_host = QWidget()
        self.ca_form = QFormLayout(self.ca_form_host)
        self.ca_display = QLineEdit()
        self.ca_url = QLineEdit()
        self.ca_trust = QComboBox()
        self.ca_trust.addItems(["chain", "system", "both"])
        self.ca_default = QCheckBox("Use for new requests")
        self.acme_contact = QLineEdit()
        self.acme_tos = QCheckBox("I have read and accept the CA's terms of service")
        self.acme_challenge = QComboBox()
        self.acme_challenge.addItems(list(ACME_CHALLENGES))
        self.acme_mode = QComboBox()
        self.acme_mode.addItems(list(ACME_HTTP_MODES))
        self.acme_port = QSpinBox()
        self.acme_port.setRange(1, 65535)
        self.acme_webroot = QLineEdit()
        self.acme_hook = QLineEdit()
        self.acme_kid = QLineEdit()
        for label, widget in (
            ("Name shown", self.ca_display),
            ("URL", self.ca_url),
            ("TLS trust", self.ca_trust),
            ("", self.ca_default),
            ("Contact e-mail", self.acme_contact),
            ("", self.acme_tos),
            ("Challenge", self.acme_challenge),
            ("http-01 mode", self.acme_mode),
            ("Standalone port", self.acme_port),
            ("Webroot", self.acme_webroot),
            ("dns-01 hook", self.acme_hook),
            ("EAB key id", self.acme_kid),
        ):
            self.ca_form.addRow(label, widget)
        eab = button("Set EAB key…", "key")
        eab.clicked.connect(self._set_eab)
        self.ca_form.addRow("", eab)
        self.eab_button = eab
        row.addWidget(self.ca_form_host, 2)
        layout.addLayout(row, 1)
        buttons = QHBoxLayout()
        add_acme = button("Add ACME CA…", "plus")
        add_acme.clicked.connect(self._add_acme)
        add_ukca = button("Add CertWizard-protocol CA…", "plus")
        add_ukca.clicked.connect(self._add_ukca)
        remove = button("Remove", "trash")
        remove.clicked.connect(self._remove_ca)
        buttons.addWidget(add_acme)
        buttons.addWidget(add_ukca)
        buttons.addStretch(1)
        buttons.addWidget(remove)
        layout.addLayout(buttons)
        self.tabs.addTab(page, icons.icon("globe"), "Certificate authorities")
        self._current_ca = ""
        self._reload_ca_list()

    def _reload_ca_list(self, select: str = "") -> None:
        self.ca_list.blockSignals(True)
        self.ca_list.clear()
        for name, profile in self.config.cas.items():
            item = QListWidgetItem(icons.icon("globe"), f"{profile.display_name}\n{name} · {profile.kind}")
            item.setData(Qt.ItemDataRole.UserRole, name)
            self.ca_list.addItem(item)
        self.ca_list.blockSignals(False)
        names = list(self.config.cas)
        self.ca_list.setCurrentRow(names.index(select) if select in names else 0)
        self._show_ca(self.ca_list.currentRow())

    def _store_ca_form(self) -> None:
        name = self._current_ca
        if not name or name not in self.config.cas:
            return
        profile = self.config.cas[name]
        profile.display_name = self.ca_display.text().strip()
        profile.ca.base_url = self.ca_url.text().strip()
        profile.ca.tls_trust = self.ca_trust.currentText()
        if self.ca_default.isChecked():
            self.config.default_ca = name
        if profile.kind == "acme":
            profile.acme.contact = [c.strip() for c in self.acme_contact.text().split(",") if c.strip()]
            profile.acme.terms_agreed = self.acme_tos.isChecked()
            profile.acme.challenge = self.acme_challenge.currentText()
            profile.acme.http_mode = self.acme_mode.currentText()
            profile.acme.http_port = self.acme_port.value()
            profile.acme.webroot = self.acme_webroot.text().strip()
            profile.acme.dns_hook = self.acme_hook.text().strip()
            profile.acme.eab_kid = self.acme_kid.text().strip()
        profile.invalidate()

    def _show_ca(self, row: int) -> None:
        self._store_ca_form()
        item = self.ca_list.item(row)
        if item is None:
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        self._current_ca = name
        profile = self.config.cas[name]
        self.ca_display.setText(profile.display_name)
        self.ca_url.setText(profile.ca.base_url)
        self.ca_trust.setCurrentText(profile.ca.tls_trust)
        self.ca_default.setChecked(name == self.config.default_ca)
        acme = profile.kind == "acme"
        for widget in (
            self.acme_contact,
            self.acme_tos,
            self.acme_challenge,
            self.acme_mode,
            self.acme_port,
            self.acme_webroot,
            self.acme_hook,
            self.acme_kid,
            self.eab_button,
        ):
            self.ca_form.setRowVisible(widget, acme)
        self.ca_form.labelForField(self.ca_url).setText("Directory URL" if acme else "Server URL")
        if acme:
            self.acme_contact.setText(", ".join(profile.acme.contact))
            self.acme_tos.setChecked(profile.acme.terms_agreed)
            self.acme_challenge.setCurrentText(profile.acme.challenge)
            self.acme_mode.setCurrentText(profile.acme.http_mode)
            self.acme_port.setValue(profile.acme.http_port)
            self.acme_webroot.setText(profile.acme.webroot)
            self.acme_hook.setText(profile.acme.dns_hook)
            self.acme_kid.setText(profile.acme.eab_kid)

    def _ask_name(self, title: str, default: str) -> str:
        name, ok = QInputDialog.getText(self, title, "Short name (lower case, e.g. letsencrypt):", text=default)
        return name.strip() if ok else ""

    def _add_acme(self) -> None:
        name = self._ask_name("Add ACME CA", "letsencrypt")
        if not name:
            return
        url, ok = QInputDialog.getText(
            self, "ACME directory", "Directory URL:", text="https://acme-staging-v02.api.letsencrypt.org/directory"
        )
        if not ok or not url.strip():
            return
        self._store_ca_form()
        try:
            self.config.add_ca(
                new_acme_profile(
                    name, url.strip(), display_name=name, contact=[self.email.text().strip()] if self.email.text().strip() else []
                )
            )
        except ConfigError as exc:
            self.error.setText(str(exc))
            return
        self._current_ca = ""
        self._reload_ca_list(name)

    def _add_ukca(self) -> None:
        name = self._ask_name("Add CertWizard-protocol CA", "ukca-test")
        if not name:
            return
        url, ok = QInputDialog.getText(self, "CA server", "Base URL:", text="https://localhost:8443")
        if not ok or not url.strip():
            return
        self._store_ca_form()
        try:
            self.config.add_ca(new_ukca_profile(name, url.strip(), display_name=name, tls_trust="system"))
        except ConfigError as exc:
            self.error.setText(str(exc))
            return
        self._current_ca = ""
        self._reload_ca_list(name)

    def _remove_ca(self) -> None:
        name = self._current_ca
        if not name:
            return
        if self.config.cas[name].primary:
            self.error.setText("The primary CA cannot be removed; edit it instead.")
            return
        if QMessageBox.question(self, "Remove CA", f"Remove the CA profile '{name}'? Stored certificates are kept.") != QMessageBox.StandardButton.Yes:
            return
        self.config.remove_ca(name)
        self._current_ca = ""
        self._reload_ca_list()

    def _set_eab(self) -> None:
        name = self._current_ca
        key, ok = QInputDialog.getText(
            self, "External Account Binding", f"HMAC key for '{name}' (base64url, from the CA):", QLineEdit.EchoMode.Password
        )
        if not ok or not key.strip():
            return
        try:
            from ..providers.acme import store_eab_key
            from ..workflow import AppContext

            store_eab_key(AppContext.from_config(self.config), name, key.strip())
        except PyCertError as exc:
            self.error.setText(str(exc))
            return
        QMessageBox.information(self, "EAB key stored", "The EAB key was stored in the secret store.")

    def _secrets_tab(self) -> None:
        form = self._page(
            "Secrets",
            "lock",
            "The passphrase protecting private keys and exported .p12 files lives in a secret store, never in "
            "the configuration file. 'auto' uses the macOS Keychain or the Linux Secret Service when available.",
        )
        self.backend = QComboBox()
        self.backend.addItems(list(BACKENDS))
        self.backend.setCurrentText(self.config.secrets.backend)
        self.account = QLineEdit(self.config.secrets.account)
        self.command = QLineEdit(self.config.secrets.command)
        self.command.setPlaceholderText("for 'command': e.g. pass show pycert")
        test = button("Test secret store", "verify")
        test.clicked.connect(self._test_secret)
        self.secret_status = muted_label()
        form.addRow("Backend", self.backend)
        form.addRow("Account", self.account)
        form.addRow("Command", self.command)
        form.addRow("", test)
        form.addRow("", self.secret_status)

    def _test_secret(self) -> None:
        try:
            store = SecretStore(self.config.secrets, self.config.data_dir, self.config.profile)
            exists = store.exists(self.config.secrets.account)
            self.secret_status.setText(f"{store}: secret {'present' if exists else 'not stored yet'}")
        except PyCertError as exc:
            self.secret_status.setText(f"Problem: {exc}")

    def _app_tab(self) -> None:
        form = self._page(
            "Appearance && monitoring",
            "bell",
            "These preferences belong to this computer's account, not the pyCertWiz configuration file.",
        )
        self.appearance = QComboBox()
        for value, label in (("system", "Follow the system"), ("light", "Light"), ("dark", "Dark")):
            self.appearance.addItem(label, value)
        self.appearance.setCurrentIndex(max(0, self.appearance.findData(pref("appearance", "system"))))
        self.warn_days = QSpinBox()
        self.warn_days.setRange(1, 365)
        self.warn_days.setValue(pref("warn_days", 30))
        self.warn_days.setSuffix(" days")
        self.crit_days = QSpinBox()
        self.crit_days.setRange(0, 365)
        self.crit_days.setValue(pref("crit_days", 7))
        self.crit_days.setSuffix(" days")
        self.refresh = QSpinBox()
        self.refresh.setRange(5, 24 * 60)
        self.refresh.setValue(pref("refresh_minutes", 30))
        self.refresh.setSuffix(" minutes")
        self.auto_collect = QCheckBox("Download and export certificates as soon as the CA issues them")
        self.auto_collect.setChecked(pref("auto_collect", True))
        self.tray = QCheckBox("Show an icon in the menu bar / system tray")
        self.tray.setChecked(pref("tray", True))
        self.notify = QCheckBox("Notify me about issued and expiring certificates")
        self.notify.setChecked(pref("notify", True))
        form.addRow("Appearance", self.appearance)
        form.addRow("Warn when expiring within", self.warn_days)
        form.addRow("Critical within", self.crit_days)
        form.addRow("Check the CA every", self.refresh)
        form.addRow("", self.auto_collect)
        form.addRow("", self.tray)
        form.addRow("", self.notify)

    # -- save ----------------------------------------------------------------
    def _save(self) -> None:
        try:
            self._store_ca_form()
            config = self.config
            config.identity.email = self.email.text().strip()
            config.identity.ra = self.ra.text().strip()
            config.identity.o = self.o.text().strip()
            config.identity.ou = self.ou.text().strip()
            config.identity.l = self.l.text().strip()
            config.identity.c = self.c.text().strip().upper()
            config.keys.algorithm = self.algorithm.currentText()
            config.keys.rsa_bits = int(self.rsa_bits.currentText())
            config.keys.ec_curve = self.ec_curve.currentText()
            config.p12.filename_template = self.p12_template.text().strip()
            config.p12.export_dir = self.p12_dir.text().strip()
            config.p12.include_chain = self.include_chain.isChecked()
            config.paths.data_dir = self.data_dir.text().strip()
            config.secrets.backend = self.backend.currentText()
            config.secrets.account = self.account.text().strip() or "default"
            config.secrets.command = self.command.text().strip()
            if self.crit_days.value() > self.warn_days.value():
                raise ConfigError("the critical threshold must not be longer than the warning threshold")
            validate_config(config)
            write_config(config.path, config)
        except PyCertError as exc:
            self.error.setText(str(exc))
            return
        settings = preferences()
        settings.setValue("appearance", self.appearance.currentData())
        settings.setValue("warn_days", self.warn_days.value())
        settings.setValue("crit_days", self.crit_days.value())
        settings.setValue("refresh_minutes", self.refresh.value())
        settings.setValue("auto_collect", self.auto_collect.isChecked())
        settings.setValue("tray", self.tray.isChecked())
        settings.setValue("notify", self.notify.isChecked())
        settings.sync()
        self.saved = True
        self.accept()
