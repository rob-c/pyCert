"""Reusable widgets: dashboard cards, banners, the detail panel and the activity log."""

from datetime import datetime
from typing import Any

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QGuiApplication, QPainter
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import certs
from ..errors import PyCertError
from ..store import PENDING_STATUSES, RequestState
from . import icons, theme
from .models import HEALTH_LABELS


def kind_description(cert_type: str) -> str:
    """What a certificate of this type identifies (user/host)."""
    if cert_type == "host":
        return "Host certificate: identifies a server or service by its DNS names"
    return "User certificate: identifies a person"

# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------


def button(text: str, icon_name: str = "", *, primary: bool = False, danger: bool = False, flat: bool = False) -> QPushButton:
    widget = QPushButton(text)
    if icon_name:
        icons.themed(widget, icon_name, "accent_text" if primary else ("expired" if danger else "text"))
        widget.setIconSize(QSize(16, 16))
    if primary:
        widget.setProperty("primary", True)
    if danger:
        widget.setProperty("danger", True)
    if flat:
        widget.setProperty("flat", True)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if text:
        # Style-sheet padding is not always reflected in the size hint; never clip the label.
        metrics = widget.fontMetrics()
        bold = QFont(widget.font())
        bold.setWeight(QFont.Weight.DemiBold)
        width = QFontMetrics(bold).horizontalAdvance(text.replace("&&", "&")) if primary else metrics.horizontalAdvance(text.replace("&&", "&"))
        widget.setMinimumWidth(width + (52 if icon_name else 34))
    return widget


def muted_label(text: str = "", *, wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setProperty("muted", True)
    label.setWordWrap(wrap)
    return label


def copy_to_clipboard(text: str) -> None:
    QGuiApplication.clipboard().setText(text)


class Pill(QLabel):
    """A small rounded status label."""

    def __init__(self, text: str = "", health: str = "", parent=None):
        super().__init__(text, parent)
        self.health = health
        self.set_status(text, health)

    def set_status(self, text: str, health: str) -> None:
        self.health = health
        color = QColor(theme.status_color(health))
        fill = QColor(color)
        fill.setAlphaF(0.16)
        self.setText(f"● {text}")
        self.setStyleSheet(
            f"QLabel {{ color: {color.name()}; background: rgba({fill.red()},{fill.green()},{fill.blue()},{fill.alpha()});"
            " border-radius: 10px; padding: 3px 10px; font-weight: 600; }"
        )


class StatCard(QFrame):
    """A clickable dashboard tile: big number, label, icon."""

    clicked = Signal()

    def __init__(self, label: str, icon_name: str, health: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.health = health
        self.icon_name = icon_name
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumWidth(150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        text = QVBoxLayout()
        self.value = QLabel("0")
        self.value.setObjectName("CardValue")
        self.label = QLabel(label)
        self.label.setObjectName("CardLabel")
        text.addWidget(self.value)
        text.addWidget(self.label)
        layout.addLayout(text)
        layout.addStretch(1)
        self.icon = QLabel()
        layout.addWidget(self.icon, 0, Qt.AlignmentFlag.AlignTop)
        self.refresh_style()

    def refresh_style(self) -> None:
        color = theme.status_color(self.health)
        self.icon.setPixmap(icons.pixmap(self.icon_name, color, 22))
        self.value.setStyleSheet(f"color: {color};")

    def set_value(self, value: int) -> None:
        self.value.setText(str(value))

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class Banner(QFrame):
    """A dismissible message strip with an optional action button."""

    action = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Banner")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 8, 8)
        self.icon = QLabel()
        self.text = QLabel()
        self.text.setWordWrap(True)
        self.text.setTextFormat(Qt.TextFormat.RichText)
        self.button = button("")
        self.button.clicked.connect(self.action.emit)
        close = QToolButton()
        close.setIcon(icons.icon("close"))
        close.setToolTip("Dismiss")
        close.clicked.connect(self.hide)
        layout.addWidget(self.icon)
        layout.addWidget(self.text, 1)
        layout.addWidget(self.button)
        layout.addWidget(close)
        self.hide()

    def show_message(self, kind: str, html: str, action_text: str = "") -> None:
        self.setProperty("kind", kind)
        self.style().unpolish(self)
        self.style().polish(self)
        t = theme.tokens()
        color = {"info": t.accent, "warning": t.expiring, "danger": t.expired}.get(kind, t.text)
        self.icon.setPixmap(icons.pixmap("alert" if kind != "info" else "info", color, 20))
        self.text.setText(html)
        self.button.setVisible(bool(action_text))
        self.button.setText(action_text)
        self.show()


class ValidityBar(QWidget):
    """Lifetime remaining, drawn as a rounded bar with the dates underneath."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.fraction = 0.0
        self.health = "pending"
        self.setMinimumHeight(10)
        self.setMaximumHeight(10)

    def set_values(self, fraction: float, health: str) -> None:
        self.fraction = max(0.0, min(1.0, fraction))
        self.health = health
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        t = theme.tokens()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(t.surface_alt if not t.dark else t.border))
        rect = self.rect().adjusted(0, 1, 0, -1)
        painter.drawRoundedRect(rect, 4, 4)
        if self.fraction > 0:
            filled = rect.adjusted(0, 0, -int(rect.width() * (1 - self.fraction)), 0)
            painter.setBrush(QColor(theme.status_color(self.health)))
            painter.drawRoundedRect(filled, 4, 4)
        painter.end()


class EmptyState(QWidget):
    """Shown when the store has no certificates yet."""

    request = Signal()
    import_p12 = Signal()
    open_bundle = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addStretch(1)
        art = QLabel()
        art.setPixmap(icons.pixmap("shield-check", theme.tokens().accent, 72))
        art.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel("No certificates yet")
        title.setObjectName("PageTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text = muted_label(
            "Request a personal or host certificate from the UK e-Science CA (or any configured CA), "
            "import an existing .p12, or inspect an old CertWizard/Java bundle."
        )
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text.setMaximumWidth(520)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        first = button("Request a certificate", "plus", primary=True)
        first.clicked.connect(self.request.emit)
        second = button("Import .p12…", "import")
        second.clicked.connect(self.import_p12.emit)
        third = button("Open Java bundle…", "package")
        third.clicked.connect(self.open_bundle.emit)
        for widget in (first, second, third):
            buttons.addWidget(widget)
        buttons.addStretch(1)
        layout.addWidget(art)
        layout.addSpacing(8)
        layout.addWidget(title)
        layout.addWidget(text, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addSpacing(16)
        layout.addLayout(buttons)
        layout.addStretch(2)


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------


class ActivityLog(QWidget):
    MAX_LINES = 2000

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 8)
        bar = QHBoxLayout()
        bar.addWidget(muted_label("Progress and results of background work. PINs and secrets are never logged.", wrap=False))
        bar.addStretch(1)
        copy = button("Copy", "copy", flat=True)
        copy.clicked.connect(lambda: copy_to_clipboard(self.text.toPlainText()))
        clear = button("Clear", "trash", flat=True)
        clear.clicked.connect(lambda: self.text.clear())
        bar.addWidget(copy)
        bar.addWidget(clear)
        layout.addLayout(bar)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setMaximumBlockCount(self.MAX_LINES)
        font = QFont("Menlo")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSizeF(max(9.0, self.font().pointSizeF() - 1))
        self.text.setFont(font)
        layout.addWidget(self.text)

    def add(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.text.appendPlainText(f"{stamp}  {message}")


# ---------------------------------------------------------------------------
# Detail panel
# ---------------------------------------------------------------------------


def _selectable(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setWordWrap(True)
    label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
    label.setMinimumWidth(0)
    return label


def _path_field() -> QLineEdit:
    """A borderless read-only line for long paths: scrolls instead of overflowing, copies exactly."""
    field = QLineEdit()
    field.setReadOnly(True)
    field.setFrame(False)
    field.setStyleSheet("QLineEdit { background: transparent; border: none; padding: 0; }")
    return field


def _readable_dn(dn: str) -> str:
    """'C=UK,O=eScience,CN=x' -> 'CN=x, O=eScience, C=UK' (most specific first, wraps nicely)."""
    import re

    if not dn:
        return ""
    parts = [part.strip() for part in re.split(r"(?<!\\),", dn) if part.strip()]
    if parts and not parts[0].upper().startswith("CN=") and parts[-1].upper().startswith("CN="):
        parts.reverse()
    return ", ".join(parts)


class DetailPanel(QFrame):
    """Everything about one certificate, with the actions that apply to it."""

    action_requested = Signal(str)
    auto_renew_changed = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Panel")
        self.state: "RequestState | None" = None
        self.ctx: Any = None
        self.capabilities: Any = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 12)
        outer.setSpacing(10)

        header = QHBoxLayout()
        self.type_icon = QLabel()
        header.addWidget(self.type_icon, 0, Qt.AlignmentFlag.AlignTop)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.title = QLabel()
        self.title.setObjectName("DetailTitle")
        self.title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.subtitle = muted_label()
        titles.addWidget(self.title)
        titles.addWidget(self.subtitle)
        header.addLayout(titles, 1)
        self.pill = Pill()
        header.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        self.validity = ValidityBar()
        self.validity_text = muted_label()
        outer.addWidget(self.validity)
        outer.addWidget(self.validity_text)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.primary = button("", "", primary=True)
        self.primary.clicked.connect(lambda: self.action_requested.emit(self.primary.property("action")))
        self.export_button = button("Export", "export")
        self.export_button.setToolTip("Write the PKCS#12 (.p12) file again, protected with the saved secret")
        self.export_button.clicked.connect(lambda: self.action_requested.emit("export"))
        self.deploy_button = button("Deploy", "deploy")
        self.deploy_button.setToolTip("Copy the certificate and key to their deployment targets and run the hooks")
        self.deploy_button.clicked.connect(lambda: self.action_requested.emit("deploy"))
        self.verify_button = button("Verify", "verify")
        self.verify_button.clicked.connect(lambda: self.action_requested.emit("verify"))
        self.more_button = QToolButton()
        self.more_button.setText("More")
        self.more_button.setIcon(icons.icon("more"))
        self.more_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.more_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.more_menu = QMenu(self)
        self.more_button.setMenu(self.more_menu)
        self.verify_button.hide()  # offered in the More menu; keeps the action row narrow
        for widget in (self.primary, self.export_button, self.deploy_button):
            widget.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            actions.addWidget(widget)
        actions.addStretch(1)
        actions.addWidget(self.more_button)
        outer.addLayout(actions)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        outer.addWidget(self.tabs, 1)
        self._build_overview()
        self._build_chain()
        self._build_deploy()
        self._build_history()

    # -- tabs ----------------------------------------------------------------
    def _build_overview(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        form = QFormLayout(body)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(8)
        self.fields: "dict[str, QLabel | QLineEdit]" = {}
        for key, label in (
            ("status", "Status"),
            ("type", "Type"),
            ("ca", "Certificate authority"),
            ("subject", "Subject"),
            ("issuer", "Issuer"),
            ("sans", "Alternative names"),
            ("key", "Key"),
            ("serial", "Serial"),
            ("fingerprint", "SHA-256"),
            ("verified", "Chain verified"),
            ("server", "CA record"),
            ("p12", "PKCS#12"),
            ("keystore", "Java keystore"),
            ("directory", "Folder"),
            ("description", "Description"),
            ("notes", "Notes"),
        ):
            value = _path_field() if key in ("p12", "directory") else _selectable()
            self.fields[key] = value
            caption = muted_label(label, wrap=False)
            form.addRow(caption, value)
        self.auto_renew = QCheckBox("Renew automatically")
        self.auto_renew.setToolTip("Include this certificate in 'Renew everything due' and 'pycert renew --due'")
        self.auto_renew.toggled.connect(self._auto_renew_toggled)
        form.addRow(muted_label("Renewal", wrap=False), self.auto_renew)
        scroll.setWidget(body)
        self.tabs.addTab(scroll, "Overview")

    def _build_chain(self) -> None:
        self.chain_tree = QTreeWidget()
        self.chain_tree.setHeaderLabels(["Certificate", "Expires", "Key"])
        header = self.chain_tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.chain_tree.setRootIsDecorated(True)
        self.chain_tree.setAlternatingRowColors(True)
        self.tabs.addTab(self.chain_tree, "Chain")

    def _build_deploy(self) -> None:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addWidget(
            muted_label(
                "Deployment targets receive the certificate and key whenever it is issued or renewed, "
                "then run their reload hook (e.g. systemctl reload nginx)."
            )
        )
        self.deploy_table = QTableWidget(0, 4)
        self.deploy_table.setHorizontalHeaderLabels(["Target", "Files", "Hook", "Last deployed"])
        self.deploy_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.deploy_table.verticalHeader().setVisible(False)
        self.deploy_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.deploy_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.deploy_table, 1)
        row = QHBoxLayout()
        add = button("Add target…", "plus")
        add.clicked.connect(lambda: self.action_requested.emit("deploy_add"))
        remove = button("Remove", "trash")
        remove.clicked.connect(self._remove_target)
        run = button("Deploy now", "deploy")
        run.clicked.connect(lambda: self.action_requested.emit("deploy"))
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch(1)
        row.addWidget(run)
        layout.addLayout(row)
        self.tabs.addTab(widget, "Deployment")

    def _build_history(self) -> None:
        self.history = QListWidget()
        self.history.setAlternatingRowColors(True)
        self.history.setWordWrap(True)
        self.tabs.addTab(self.history, "History")

    def _remove_target(self) -> None:
        rows = self.deploy_table.selectionModel().selectedRows()
        if rows:
            name = self.deploy_table.item(rows[0].row(), 0).text()
            self.action_requested.emit(f"deploy_remove:{name}")

    def _auto_renew_toggled(self, value: bool) -> None:
        if self.state is not None and value != self.state.auto_renew:
            self.auto_renew_changed.emit(value)

    # -- rendering -------------------------------------------------------------
    def show_state(self, ctx: Any, state: RequestState, category: str, message: str) -> None:
        from ..providers import capabilities_for

        self.ctx = ctx
        self.state = state
        try:
            profile = ctx.profile(state.ca)
            ca_label = profile.display_name
            self.capabilities = capabilities_for(profile.kind)
        except Exception:  # noqa: BLE001 - a removed CA profile
            ca_label = f"{state.ca} (not configured)"
            self.capabilities = None
        color = theme.status_color(category)
        self.type_icon.setPixmap(icons.pixmap("server" if state.type == "host" else "user", color, 34))
        self.title.setText(state.cn)
        kind = "Host certificate" if state.type == "host" else "User certificate"
        alias = f" · alias “{state.alias}”" if state.alias != state.cn else ""
        self.subtitle.setText(f"{kind} · {ca_label}{alias}")
        label = HEALTH_LABELS.get(category, state.status.title())
        if state.renewal and category != "pending":
            label += " · renewal pending"
        self.pill.set_status(label, category)

        days = state.days_remaining
        if state.cert.not_after and days is not None:
            from .models import _lifetime

            lifetime = _lifetime(state) or 365
            self.validity.set_values(days / float(lifetime) if days > 0 else 0.0, category)
            when = state.cert.not_after[:10]
            if days < 0:
                text = f"Expired {-days} day(s) ago ({when})"
            else:
                text = f"{days} day(s) left · valid {state.cert.not_before[:10]} → {when}"
            extra = message if message and category not in ("valid", "expiring", "expired") else ""
            self.validity_text.setText(text + (f" · {extra}" if extra else ""))
            self.validity.show()
        else:
            self.validity.hide()
            self.validity_text.setText(message or f"Status {state.status}")

        self._configure_actions(state, category)
        self._render_overview(state, ca_label)
        self._render_chain(state)
        self._render_deploy(state)
        self._render_history(state)

    def _configure_actions(self, state: RequestState, category: str) -> None:
        has_cert = bool(state.cert.sha256)
        caps = self.capabilities
        if state.renewal or (state.status in PENDING_STATUSES and not has_cert):
            action, text, icon_name = "wait", "Check for certificate", "download"
            if state.status in ("SIGNED",):
                action, text, icon_name = "download", "Download && export", "download"
        elif has_cert and state.status != "REVOKED":
            action, text, icon_name = "renew", "Renew…", "renew"
        elif state.status == "FAILED" and not has_cert:
            action, text, icon_name = "delete", "Remove request…", "trash"
        else:
            action, text, icon_name = "", "", ""
        self.primary.setVisible(bool(action))
        self.primary.setText(text)
        bold = QFont(self.primary.font())
        bold.setWeight(QFont.Weight.DemiBold)
        self.primary.setMinimumWidth(QFontMetrics(bold).horizontalAdvance(text.replace("&&", "&")) + 56)
        self.primary.setProperty("action", action)
        if icon_name:
            self.primary.setIcon(icons.icon(icon_name, theme.tokens().accent_text))
        self.export_button.setEnabled(has_cert)
        self.deploy_button.setEnabled(has_cert)
        self.verify_button.setEnabled(has_cert)
        self.more_menu.clear()

        def add(text: str, name: str, icon_name: str, enabled: bool = True) -> None:
            item = self.more_menu.addAction(icons.icon(icon_name), text)
            item.setEnabled(enabled)
            item.triggered.connect(lambda _checked=False, n=name: self.action_requested.emit(n))

        add("Check status at the CA", "wait", "refresh", state.status in PENDING_STATUSES or state.renewal)
        add("Download && export again", "download", "download", has_cert or state.status in PENDING_STATUSES)
        add("Renew…", "renew", "renew", has_cert and not state.renewal and state.status != "REVOKED")
        add("Verify key, chain and .p12", "verify", "verify", has_cert)
        self.more_menu.addSeparator()
        add("View certificate, keys and chain…", "view", "eye", has_cert)
        add("Copy SHA-256 fingerprint", "copy_fingerprint", "copy", has_cert)
        add("Copy certificate (PEM)", "copy_pem", "copy", has_cert)
        add("Save key and certificate (PEM)…", "save_pem", "download", has_cert)
        add("Install as ~/.globus usercert/userkey…", "install_globus", "key", has_cert and state.type == "user")
        add("Create proxy certificate…", "proxy", "clock", has_cert and state.type == "user")
        add("Open folder", "folder", "folder")
        add("Rename…", "rename", "edit")
        add("Edit description…", "edit", "edit")
        self.more_menu.addSeparator()
        can_revoke = bool(caps is None or caps.revoke)
        add("Revoke at the CA…", "revoke", "revoke", has_cert and state.status != "REVOKED" and can_revoke)
        add("Delete local copy…", "delete", "trash")

    def _render_overview(self, state: RequestState, ca_label: str) -> None:
        server = " · ".join(
            part
            for part in (
                f"CSR {state.server.csr_id}" if state.server.csr_id else "",
                f"certificate {state.server.cert_id}" if state.server.cert_id and len(state.server.cert_id) < 40 else "",
                state.server.status,
                f"contact {state.server.email}" if state.server.email else "",
                f"checked {state.server.last_checked[:16].replace('T', ' ')}" if state.server.last_checked else "",
            )
            if part
        )
        values = {
            "status": state.status + (" (renewal in progress)" if state.renewal else ""),
            "type": kind_description(state.type),
            "ca": ca_label,
            "subject": _readable_dn(state.cert.subject or state.subject),
            "issuer": _readable_dn(state.cert.issuer) or "—",
            "sans": ", ".join(state.cert.sans) or "—",
            "key": state.cert.key or state.key_algorithm or "—",
            "serial": _group(state.cert.serial) if state.cert.serial else "—",
            "fingerprint": _group(state.cert.sha256) if state.cert.sha256 else "—",
            "verified": ("Yes — reaches a trusted root" if state.cert.verified else "No") if state.cert.sha256 else "—",
            "server": server or "—",
            "p12": state.p12_path or "not exported",
            "keystore": _keystore_text(state),
            "directory": str(self.ctx.store.path(state)) if self.ctx is not None else "",
            "description": state.description or "—",
            "notes": "\n".join(state.notes[-4:]) or "—",
        }
        for key, value in values.items():
            field = self.fields[key]
            if isinstance(field, QLineEdit):
                field.setText(_home_relative(value))
                field.setCursorPosition(0)
                field.setToolTip(value)
            else:
                field.setText(value)
        if state.cert.verified or not state.cert.sha256:
            self.fields["verified"].setStyleSheet("")
        else:
            self.fields["verified"].setStyleSheet(f"color: {theme.tokens().expiring};")
        self.auto_renew.blockSignals(True)
        self.auto_renew.setChecked(state.auto_renew)
        self.auto_renew.blockSignals(False)

    def _render_chain(self, state: RequestState) -> None:
        self.chain_tree.clear()
        if self.ctx is None:
            return
        try:
            leaf = self.ctx.store.load_certificate(state)
            chain = self.ctx.store.load_chain(state)
        except PyCertError:
            item = QTreeWidgetItem(["No certificate issued yet", "", ""])
            self.chain_tree.addTopLevelItem(item)
            return
        ordered = [leaf, *chain]
        parent = None
        for cert in reversed(ordered):
            info = certs.describe_certificate(cert)
            cn = info.subject
            for part in info.subject.split(","):
                if part.startswith("CN="):
                    cn = part[3:]
                    break
            item = QTreeWidgetItem([cn, str(info.not_after.date()), info.key])
            item.setToolTip(0, f"{info.subject}\nSHA-256 {info.fingerprint_sha256}")
            role = "root" if info.is_self_signed else ("leaf" if cert is leaf else "intermediate")
            item.setIcon(0, icons.icon({"root": "shield", "intermediate": "chain", "leaf": "award"}[role]))
            if parent is None:
                self.chain_tree.addTopLevelItem(item)
            else:
                parent.addChild(item)
            parent = item
        self.chain_tree.expandAll()

    def _render_deploy(self, state: RequestState) -> None:
        self.deploy_table.setRowCount(0)
        for target in state.deploy:
            row = self.deploy_table.rowCount()
            self.deploy_table.insertRow(row)
            files = ", ".join(_home_relative(str(target[k])) for k in ("cert", "key", "chain", "fullchain", "bundle", "p12") if target.get(k))
            last = str(target.get("last_deployed", "never"))[:16].replace("T", " ")
            if target.get("last_error"):
                last = "FAILED: " + str(target["last_error"])[:80]
            for column, value in enumerate((str(target.get("name")), files, str(target.get("hook", "")), last)):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 3 and target.get("last_error"):
                    item.setForeground(QColor(theme.tokens().expired))
                self.deploy_table.setItem(row, column, item)
        self.deploy_table.resizeColumnToContents(0)

    def _render_history(self, state: RequestState) -> None:
        self.history.clear()
        for entry in reversed(state.history):
            at = str(entry.get("at", ""))[:19].replace("T", " ")
            detail = entry.get("detail") or ""
            item = QListWidgetItem(f"{at}   {entry.get('status', '')}\n{detail}".rstrip())
            self.history.addItem(item)
        if not state.history:
            self.history.addItem("No history yet.")


def _keystore_text(state: RequestState) -> str:
    link = state.keystore
    if not link.get("name"):
        return "—"
    text = f"{link['name']} · alias “{link.get('alias', state.alias)}”"
    if state.cert.sha256 and link.get("written") != state.cert.sha256 and state.status != "REVOKED":
        text += " · not written yet"
    return text


def _home_relative(path: str) -> str:
    """Show paths under the home directory as '~/…' (the tooltip keeps the full path)."""
    from pathlib import Path

    home = str(Path.home())
    if path.startswith(home + "/"):
        return "~" + path[len(home):]
    return path


def _group(hex_digest: str) -> str:
    """Group a fingerprint for readability: 'ab12 cd34 …'."""
    return " ".join(hex_digest[i : i + 4] for i in range(0, len(hex_digest), 4))
