"""The pyCertWiz main window.

Layout::

    ┌ sidebar ───────────┬ header: title · search · [Check now] [New certificate] ┐
    │ pyCertWiz             │ banner (expiring / unreachable / renewals due)          │
    │ ▸ All certificates │ [Valid 12] [Expiring 2] [Pending 1] [Expired 0]         │
    │ ▸ Needs attention  │ ┌ certificate table ─────────┐ ┌ detail panel ────────┐ │
    │ ▸ Personal         │ │ ● jane doe   Personal  …   │ │ jane doe  ● Valid    │ │
    │ ▸ Hosts            │ │ ● web1.ac.uk Host      …   │ │ ▓▓▓▓▓▓░░ 241 days    │ │
    │ ▸ Pending          │ └────────────────────────────┘ │ Renew Export Deploy… │ │
    │ CERTIFICATE AUTH.  │                                │ Overview Chain …     │ │
    │ ▸ UK e-Science ●   │                                └──────────────────────┘ │
    │ TOOLS              │                                                         │
    └────────────────────┴─ status bar · activity log (dock) ────────────────────┘

Every action runs the shared workflow functions on a worker thread.
"""

import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QModelIndex, QObject, QSize, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, certs
from ..config import load_config
from ..errors import ConfigNotFound, PyCertError
from ..workflow import AppContext
from . import icons, theme
from .dialogs import (
    DeployTargetDialog,
    ExportDialog,
    ImportDialog,
    KeyProtectionDialog,
    PinDialog,
    ProgressDialog,
    ProxyDialog,
    RenameDialog,
    RenewDialog,
    ReportDialog,
    RevokeDialog,
)
from .models import (
    COL_CA,
    COL_DAYS,
    COL_DEPLOY,
    COL_EXPIRES,
    COL_NAME,
    COL_STATUS,
    COL_TYPE,
    CertificateFilter,
    CertificateModel,
    DaysDelegate,
    HealthRole,
    NameDelegate,
    StateRole,
    StatusPillDelegate,
    build_rows,
)
from .settings import SettingsDialog, pref, preferences
from .tray import BackgroundMonitor, TrayController
from .widgets import (
    ActivityLog,
    Banner,
    DetailPanel,
    EmptyState,
    StatCard,
    button,
    copy_to_clipboard,
    muted_label,
)
from .workers import MainThreadCollector, TaskRunner

APP_NAME = "pyCertWiz"

VIEWS = (
    ("all", "All certificates", "list", {}),
    ("attention", "Needs attention", "alert", {"categories": {"expiring", "expired", "failed"}}),
    ("personal", "Personal", "user", {"cert_type": "user"}),
    ("hosts", "Hosts", "server", {"cert_type": "host"}),
    ("pending", "Pending", "clock", {"categories": {"pending"}}),
)
TOOLS = (
    ("tool:link", "Link a Java keystore…", "package"),
    ("tool:bundle", "Java bundle inspector", "package"),
    ("tool:import", "Import .p12…", "import"),
    ("tool:doctor", "Diagnostics", "activity"),
    ("tool:settings", "Settings", "settings"),
)


class Prompter(QObject):
    """``AppContext.confirm``: ask the person to complete a step (e.g. publish a DNS record).

    Workflow code runs on worker threads, so the question is marshalled to the UI
    thread with a blocking queued signal and the worker waits for the answer.
    """

    request = Signal(str, str)

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.parent_widget = parent
        self.answer = False
        self.request.connect(self._ask, Qt.ConnectionType.BlockingQueuedConnection)

    def _ask(self, title: str, instructions: str) -> None:
        box = QMessageBox(self.parent_widget)
        box.setWindowTitle(title)
        box.setText(f"<b>{title}</b>")
        box.setInformativeText(instructions)
        box.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        box.button(QMessageBox.StandardButton.Ok).setText("Done")
        self.answer = box.exec() == QMessageBox.StandardButton.Ok

    def __call__(self, title: str, instructions: str) -> bool:
        if QThread.currentThread() is self.thread():
            self._ask(title, instructions)
        else:
            self.request.emit(title, instructions)
        return self.answer


class MainWindow(QMainWindow):
    def __init__(self, config_path: "str | None" = None, *, start_background: bool = True):
        super().__init__()
        self.config_path = config_path
        self.cfg = load_config(config_path)
        self.ctx = AppContext.from_config(self.cfg)
        self.runner = TaskRunner(self)
        self.prompter = Prompter(self)
        self.ctx.confirm = self.prompter
        self.runner.progress.connect(self.log)
        self.runner.busy_changed.connect(self._busy)
        self._selected_alias: "str | None" = None
        self._ca_status: "dict[str, bool | None]" = {}
        self._quitting = False
        self.setWindowTitle(f"{APP_NAME} — certificate manager")
        self.setWindowIcon(icons.app_icon())
        self.resize(1320, 840)
        self.setMinimumSize(1000, 640)
        self._build_ui()
        self._build_menus()
        self.monitor = BackgroundMonitor(self)
        self.monitor.checked.connect(self._background_checked)
        self.monitor.failed.connect(lambda message: self.log(f"Background check failed: {message}"))
        self.tray = TrayController(self)
        from PySide6.QtCore import QFileSystemWatcher

        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(self._keystore_file_changed)
        self.watcher.directoryChanged.connect(self._keystore_file_changed)
        self._sync_timer = QTimer(self)
        self._sync_timer.setSingleShot(True)
        self._sync_timer.setInterval(1500)
        self._sync_timer.timeout.connect(self.sync_keystores)
        self._watch_keystores()
        self.refresh()
        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            # A bound method (not a lambda) is disconnected when the window is destroyed.
            hints.colorSchemeChanged.connect(self._color_scheme_changed)
        if start_background:
            QTimer.singleShot(300, self.ping_cas)
            QTimer.singleShot(200, self.unlock_keystores_at_startup)
            QTimer.singleShot(1500, self.monitor.run_now)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        main = QWidget()
        layout = QVBoxLayout(main)
        layout.setContentsMargins(22, 18, 22, 10)
        layout.setSpacing(14)
        layout.addLayout(self._build_header())
        self.banner = Banner()
        self.banner.action.connect(self._banner_action)
        self._banner_kind = ""
        layout.addWidget(self.banner)
        layout.addLayout(self._build_cards())
        self.stack = QStackedWidget()
        self.empty = EmptyState()
        self.empty.request.connect(self.new_request)
        self.empty.import_p12.connect(self.import_p12)
        self.empty.open_bundle.connect(self.open_bundle)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self._build_content())
        layout.addWidget(self.stack, 1)
        # The sidebar drives the table filter, so it is built after the table exists.
        outer.addWidget(self._build_sidebar())
        outer.addWidget(main, 1)
        self.setCentralWidget(root)

        self.activity = ActivityLog()
        self.log_dock = QDockWidget("Activity", self)
        self.log_dock.setObjectName("ActivityDock")
        self.log_dock.setWidget(self.activity)
        self.log_dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetClosable | QDockWidget.DockWidgetFeature.DockWidgetMovable)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.log_dock)
        self.log_dock.hide()

        status = self.statusBar()
        self.status_text = QLabel("Ready")
        self.status_ca = QLabel()
        self.busy_bar = QProgressBar()
        self.busy_bar.setRange(0, 0)
        self.busy_bar.setMaximumWidth(120)
        self.busy_bar.setMaximumHeight(6)
        self.busy_bar.setTextVisible(False)
        self.busy_bar.hide()
        log_button = button("Activity", "terminal", flat=True)
        log_button.clicked.connect(lambda: self.log_dock.setVisible(not self.log_dock.isVisible()))
        status.addWidget(self.status_text, 1)
        status.addPermanentWidget(self.busy_bar)
        status.addPermanentWidget(self.status_ca)
        status.addPermanentWidget(log_button)

    def _build_sidebar(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("Sidebar")
        frame.setFixedWidth(236)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 16, 0, 12)
        layout.setSpacing(2)
        brand = QHBoxLayout()
        brand.setContentsMargins(16, 0, 16, 8)
        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(30, 30))
        brand.addWidget(logo)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        name = QLabel(APP_NAME)
        name.setObjectName("AppTitle")
        sub = QLabel("Certificate manager")
        sub.setObjectName("AppSubtitle")
        titles.addWidget(name)
        titles.addWidget(sub)
        brand.addLayout(titles, 1)
        layout.addLayout(brand)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.setIconSize(QSize(18, 18))
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.currentItemChanged.connect(self._nav_changed)
        self.nav.itemClicked.connect(self._nav_clicked)
        self.nav.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.nav.customContextMenuRequested.connect(self._nav_menu)
        layout.addWidget(self.nav, 1)
        version = muted_label(f"pyCertWiz {__version__}", wrap=False)
        version.setContentsMargins(16, 0, 0, 0)
        layout.addWidget(version)
        self._populate_nav()
        return frame

    def _section(self, text: str) -> None:
        item = QListWidgetItem(text.upper())
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        font = item.font()
        font.setPointSizeF(max(8.0, font.pointSizeF() - 2))
        font.setBold(True)
        item.setFont(font)
        item.setForeground(Qt.GlobalColor.gray)
        item.setSizeHint(QSize(200, 34))
        self.nav.addItem(item)

    def _nav_item(self, key: str, text: str, icon_name: str, color: "str | None" = None) -> QListWidgetItem:
        item = QListWidgetItem(icons.icon(icon_name, color), text)
        item.setData(Qt.ItemDataRole.UserRole, key)
        item.setSizeHint(QSize(200, 34))
        self.nav.addItem(item)
        return item

    def _populate_nav(self) -> None:
        current = self.nav.currentItem().data(Qt.ItemDataRole.UserRole) if self.nav.currentItem() else "all"
        self.nav.blockSignals(True)
        self.nav.clear()
        self._nav_items: "dict[str, QListWidgetItem]" = {}
        for key, text, icon_name, _filters in VIEWS:
            self._nav_items[key] = self._nav_item(key, text, icon_name)
        self._section("Certificate authorities")
        t = theme.tokens()
        for name, profile in self.cfg.cas.items():
            online = self._ca_status.get(name)
            color = t.valid if online else (t.expired if online is False else t.muted)
            item = self._nav_item(f"ca:{name}", profile.display_name, "globe", color)
            item.setToolTip(f"{profile.display_name}\n{profile.ca.base_url}\n" + (
                "reachable" if online else ("unreachable" if online is False else "not checked yet")))
            self._nav_items[f"ca:{name}"] = item
        if self.cfg.keystores:
            self._section("Java keystores")
            from ..keystore import is_unlocked

            for link in self.cfg.keystores:
                unlocked = is_unlocked(self.ctx, link.name)
                item = self._nav_item(
                    f"keystore:{link.name}", link.name if unlocked else f"{link.name}  (locked)", "package" if unlocked else "lock"
                )
                item.setToolTip(
                    f"{link.path}\n"
                    + ("Unlocked for this session" if unlocked else "Locked: its passphrase is never stored. Right-click → Unlock…")
                )
                self._nav_items[f"keystore:{link.name}"] = item
        self._section("Tools")
        for key, text, icon_name in TOOLS:
            self._nav_item(key, text, icon_name)
        self.nav.blockSignals(False)
        target = self._nav_items.get(current) or self._nav_items["all"]
        self.nav.setCurrentItem(target)

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self.page_title = QLabel("All certificates")
        self.page_title.setObjectName("PageTitle")
        row.addWidget(self.page_title)
        row.addStretch(1)
        self.search = QLineEdit()
        self.search.setObjectName("Search")
        self.search.setPlaceholderText("Search names, hosts, descriptions…")
        self.search.setClearButtonEnabled(True)
        self.search.addAction(icons.icon("search"), QLineEdit.ActionPosition.LeadingPosition)
        self.search.textChanged.connect(lambda text: self.proxy.set_text(text))
        row.addWidget(self.search)
        self.check_button = button("Check now", "refresh")
        self.check_button.setToolTip("Ask the CA about pending requests and collect issued certificates")
        self.check_button.clicked.connect(self.check_now)
        row.addWidget(self.check_button)
        self.new_button = button("New certificate", "plus", primary=True)
        self.new_button.clicked.connect(self.new_request)
        row.addWidget(self.new_button)
        return row

    def _build_cards(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)
        self.cards = {
            "valid": StatCard("Valid", "shield-check", "valid"),
            "expiring": StatCard("Expiring soon", "clock", "expiring"),
            "pending": StatCard("Waiting for the CA", "refresh", "pending"),
            "expired": StatCard("Expired or failed", "alert", "expired"),
        }
        views = {"valid": "all", "expiring": "attention", "pending": "pending", "expired": "attention"}
        for key, card in self.cards.items():
            card.clicked.connect(lambda k=key: self._select_view(views[k], categories={"expired", "failed"} if k == "expired" else ({k} if k in ("valid", "expiring") else None)))
            row.addWidget(card)
        return row

    def _build_content(self) -> QWidget:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.model = CertificateModel(self)
        self.proxy = CertificateFilter(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_STATUS, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(False)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(48)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda _index: self.detail.tabs.setCurrentIndex(0))
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setMinimumSectionSize(60)
        header.setSectionResizeMode(COL_NAME, QHeaderView.ResizeMode.Stretch)
        for column, width in ((COL_TYPE, 78), (COL_CA, 120), (COL_STATUS, 116), (COL_EXPIRES, 96), (COL_DAYS, 122), (COL_DEPLOY, 78)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            self.table.setColumnWidth(column, width)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._header_menu)
        self.table.setMinimumWidth(520)
        self.table.setItemDelegateForColumn(COL_NAME, NameDelegate(self.table))
        self.table.setItemDelegateForColumn(COL_STATUS, StatusPillDelegate(self.table))
        self.table.setItemDelegateForColumn(COL_DAYS, DaysDelegate(self.table))
        self.table.selectionModel().currentRowChanged.connect(self._selection_changed)
        splitter.addWidget(self.table)
        self.detail = DetailPanel()
        self.detail.action_requested.connect(self.perform)
        self.detail.auto_renew_changed.connect(self._set_auto_renew)
        self.detail.setMinimumWidth(460)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([700, 470])
        self.splitter = splitter
        return splitter

    def _build_menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        self._action(file_menu, "New certificate…", self.new_request, QKeySequence.StandardKey.New, "plus")
        self._action(file_menu, "New host certificates…", lambda: self.new_request("host"), None, "server")
        file_menu.addSeparator()
        self._action(file_menu, "Import .p12…", self.import_p12, "Ctrl+I", "import")
        self._action(file_menu, "Open Java bundle…", self.open_bundle, "Ctrl+B", "package")
        file_menu.addSeparator()
        self._action(file_menu, "Open data folder", lambda: _open_path(self.cfg.data_dir), None, "folder")
        self._action(file_menu, "Open configuration file", lambda: _open_path(self.cfg.path), None, "edit")
        file_menu.addSeparator()
        quit_action = self._action(file_menu, "Quit", self.quit_application, QKeySequence.StandardKey.Quit)
        quit_action.setMenuRole(QAction.MenuRole.QuitRole)

        cert = bar.addMenu("&Certificate")
        self.cert_actions = {}
        for key, text, shortcut, icon_name in (
            ("wait", "Check status at the CA", "Ctrl+R", "refresh"),
            ("download", "Download && export", None, "download"),
            ("export", "Export…", "Ctrl+E", "export"),
            ("view", "View certificate, keys and chain…", "Ctrl+K", "eye"),
            ("rename", "Rename…", "F2", "edit"),
            ("deploy", "Deploy now", None, "deploy"),
            ("deploy_add", "Add deployment target…", None, "plus"),
            ("verify", "Verify", None, "verify"),
            ("renew", "Renew…", None, "renew"),
            ("revoke", "Revoke…", None, "revoke"),
            ("delete", "Delete local copy…", None, "trash"),
        ):
            self.cert_actions[key] = self._action(cert, text, lambda _c=False, k=key: self.perform(k), shortcut, icon_name)
        cert.addSeparator()
        self._action(cert, "Renew everything due…", self.renew_due, None, "renew")

        view = bar.addMenu("&View")
        self._action(view, "Find", lambda: self.search.setFocus(), QKeySequence.StandardKey.Find, "search")
        self._action(view, "Activity log", lambda: self.log_dock.setVisible(not self.log_dock.isVisible()), "Ctrl+L", "terminal")
        appearance = view.addMenu("Appearance")
        for value, label in (("system", "Follow the system"), ("light", "Light"), ("dark", "Dark")):
            action = appearance.addAction(label)
            action.setCheckable(True)
            action.setChecked(pref("appearance", "system") == value)
            action.triggered.connect(lambda _c=False, v=value, menu=appearance: self.set_appearance(v, menu))

        tools = bar.addMenu("&Tools")
        self._action(tools, "Check all CAs", self.ping_cas, None, "globe")
        self._action(tools, "CA information…", self.show_ca_info, None, "info")
        self._action(tools, "Diagnostics…", self.run_doctor, None, "activity")
        tools.addSeparator()
        settings = self._action(tools, "Settings…", self.open_settings, QKeySequence.StandardKey.Preferences, "settings")
        settings.setMenuRole(QAction.MenuRole.PreferencesRole)

        help_menu = bar.addMenu("&Help")
        self._action(help_menu, "Documentation", lambda: QDesktopServices.openUrl(QUrl("https://github.com/rob-c/pyCertWiz#readme")))
        about = self._action(help_menu, "About pyCertWiz", self.show_about)
        about.setMenuRole(QAction.MenuRole.AboutRole)

    def _action(self, menu: QMenu, text: str, slot: Callable, shortcut: Any = None, icon_name: str = "") -> QAction:
        action = QAction(text, self)
        if icon_name:
            icons.themed(action, icon_name)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut) if isinstance(shortcut, str) else shortcut)
        action.triggered.connect(slot)
        menu.addAction(action)
        return action

    # ------------------------------------------------------------- refresh
    def refresh(self, select: "str | None" = None) -> None:
        if select:
            self._selected_alias = select
        warn = int(pref("warn_days", 30))
        crit = min(int(pref("crit_days", 7)), warn)
        try:
            states = self.ctx.store.list()
            rows = build_rows(self.ctx, states, warn_days=warn, crit_days=crit)
        except PyCertError as exc:  # pragma: no cover - corrupt store
            self.show_error("Could not read the certificate store", exc)
            rows = []
        self.model.set_rows(rows)
        self._apply_columns(rows)
        counts = {"valid": 0, "expiring": 0, "pending": 0, "expired": 0}
        for row in rows:
            if row.category in ("expired", "failed"):
                counts["expired"] += 1
            elif row.category in counts:
                counts[row.category] += 1
        for key, card in self.cards.items():
            card.set_value(counts[key])
        self.stack.setCurrentIndex(0 if not rows else 1)
        self._update_banner(rows)
        self._restore_selection()

    OPTIONAL_COLUMNS = ((COL_TYPE, "Type"), (COL_CA, "CA"), (COL_EXPIRES, "Expires"), (COL_DAYS, "Days left"), (COL_DEPLOY, "Deploy"))

    def _hidden_columns(self) -> "set[int]":
        value = pref("hidden_columns", "expires")
        names = {name.strip() for name in str(value).split(",") if name.strip()}
        lookup = {label.lower().split()[0]: column for column, label in self.OPTIONAL_COLUMNS}
        return {lookup[name] for name in names if name in lookup}

    def _apply_columns(self, rows: "list | None" = None) -> None:
        rows = self.model.rows if rows is None else rows
        hidden = self._hidden_columns()
        for column, _label in self.OPTIONAL_COLUMNS:
            self.table.setColumnHidden(column, column in hidden)
        # Columns that carry no information for this store are hidden too.
        if len(self.cfg.cas) < 2:
            self.table.setColumnHidden(COL_CA, True)
        if not any(row.state.deploy for row in rows):
            self.table.setColumnHidden(COL_DEPLOY, True)

    def _header_menu(self, position) -> None:
        menu = QMenu(self)
        hidden = self._hidden_columns()
        for column, label in self.OPTIONAL_COLUMNS:
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(column not in hidden)
            action.toggled.connect(lambda on, c=column: self._toggle_column(c, on))
        menu.exec(self.table.horizontalHeader().mapToGlobal(position))

    def _toggle_column(self, column: int, visible: bool) -> None:
        hidden = self._hidden_columns()
        (hidden.discard if visible else hidden.add)(column)
        names = [label.lower().split()[0] for c, label in self.OPTIONAL_COLUMNS if c in hidden]
        preferences().setValue("hidden_columns", ",".join(names))
        self._apply_columns()

    def _restore_selection(self) -> None:
        alias = self._selected_alias
        index = QModelIndex()
        if alias:
            source_row = self.model.row_for_alias(alias)
            if source_row >= 0:
                index = self.proxy.mapFromSource(self.model.index(source_row, 0))
        if not index.isValid() and self.proxy.rowCount() > 0:
            index = self.proxy.index(0, 0)
        if index.isValid():
            self.table.selectionModel().setCurrentIndex(
                index, self.table.selectionModel().SelectionFlag.ClearAndSelect | self.table.selectionModel().SelectionFlag.Rows
            )
            self._show_index(index)
        else:
            self.detail.setVisible(False)

    def _selection_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if current.isValid():
            self._show_index(current)

    def _show_index(self, index: QModelIndex) -> None:
        state = index.data(StateRole)
        if state is None:
            return
        self._selected_alias = state.alias
        category = index.data(HealthRole)
        source = self.proxy.mapToSource(index)
        message = self.model.rows[source.row()].message
        self.detail.setVisible(True)
        self.detail.show_state(self.ctx, state, category, message)

    def _update_banner(self, rows: list) -> None:
        if self._banner_kind == "unreachable" and self.banner.isVisible():
            return
        due = [r for r in rows if r.category in ("expiring", "expired") and not r.state.renewal and r.state.cert.sha256 and r.state.status != "REVOKED"]
        if due:
            names = ", ".join(r.state.alias for r in due[:3]) + (f" and {len(due) - 3} more" if len(due) > 3 else "")
            self._banner_kind = "renew"
            self.banner.show_message(
                "danger" if any(r.category == "expired" for r in due) else "warning",
                f"<b>{len(due)} certificate{'s need' if len(due) != 1 else ' needs'} renewing</b> — {names}",
                "Renew…",
            )
        elif self._banner_kind == "renew":
            self.banner.hide()
            self._banner_kind = ""

    def _banner_action(self) -> None:
        if self._banner_kind == "renew":
            self.renew_due()
        elif self._banner_kind == "unreachable":
            self.run_doctor()

    # ----------------------------------------------------------- navigation
    def _nav_changed(self, current: "QListWidgetItem | None", _previous) -> None:
        if current is None:
            return
        key = current.data(Qt.ItemDataRole.UserRole) or ""
        if key.startswith("tool:"):
            return
        self._apply_view(key, current.text())

    def _nav_clicked(self, item: QListWidgetItem) -> None:
        key = item.data(Qt.ItemDataRole.UserRole) or ""
        if not key.startswith("tool:"):
            return
        previous = self.page_view if hasattr(self, "page_view") else "all"
        QTimer.singleShot(0, lambda: self.nav.setCurrentItem(self._nav_items.get(previous) or self._nav_items["all"]))
        {
            "tool:link": self.link_keystore,
            "tool:bundle": self.open_bundle,
            "tool:import": self.import_p12,
            "tool:doctor": self.run_doctor,
            "tool:settings": self.open_settings,
        }[key]()

    def _apply_view(self, key: str, title: str) -> None:
        self.page_view = key
        if key.startswith("ca:"):
            name = key[3:]
            self.proxy.set_view(ca=name)
            self.page_title.setText(title)
        elif key.startswith("keystore:"):
            self.proxy.set_view(keystore=key[len("keystore:"):])
            self.page_title.setText(f"Keystore “{title}”")
        else:
            filters = next((f for k, _t, _i, f in VIEWS if k == key), {})
            self.proxy.set_view(**filters)
            self.page_title.setText(title)
        self._restore_selection()

    def _select_view(self, key: str, *, categories: "set[str] | None" = None) -> None:
        item = self._nav_items.get(key)
        if item is not None:
            self.nav.setCurrentItem(item)
        if categories:
            self.proxy.set_view(categories=categories)
            self.page_title.setText({frozenset({"valid"}): "Valid", frozenset({"expiring"}): "Expiring soon",
                                     frozenset({"expired", "failed"}): "Expired or failed"}.get(frozenset(categories), self.page_title.text()))
            self._restore_selection()

    # ------------------------------------------------------------- helpers
    def log(self, message: str) -> None:
        self.activity.add(message)
        self.status_text.setText(message[:200])

    def _busy(self, busy: bool) -> None:
        self.busy_bar.setVisible(busy)
        if not busy:
            self.status_text.setText("Ready")

    def selected_state(self, *, require_cert: bool = False):
        if not self._selected_alias:
            QMessageBox.information(self, APP_NAME, "Select a certificate first.")
            return None
        try:
            state = self.ctx.store.get(self._selected_alias)
        except PyCertError:
            self.refresh()
            return None
        if require_cert and not state.cert.sha256:
            QMessageBox.information(self, APP_NAME, "This request has no certificate yet.")
            return None
        return state

    def show_error(self, title: str, error: BaseException) -> None:
        self.log(f"{title}: {error}")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle(title)
        box.setText(f"<b>{title}</b>")
        box.setInformativeText(str(error) or error.__class__.__name__)
        if not isinstance(error, PyCertError):
            details = getattr(error, "__pycert_traceback__", "") or "".join(
                traceback.format_exception(type(error), error, error.__traceback__)
            )
            box.setDetailedText(details)
        box.exec()

    def run_task(self, title: str, work: Callable, on_done: Callable, *, modal: bool = True, error_title: str = "") -> None:
        """Run *work(progress, stop_event)*; show a progress dialog unless *modal* is false."""

        def failed(exc: BaseException) -> None:
            if "cancelled" in str(exc).lower():
                self.log(f"{title}: cancelled")
                self.refresh()
                return
            self.show_error(error_title or f"{title} failed", exc)
            self.refresh()

        if modal:
            dialog = ProgressDialog(self, title, self.runner, work, on_done, failed)
            dialog.open()
        else:
            self.runner.start(work, on_done, failed, name=title)

    # ---------------------------------------------------------------- actions
    def perform(self, action: str) -> None:
        if action.startswith("deploy_remove:"):
            self.remove_deploy_target(action.split(":", 1)[1])
            return
        handlers = {
            "wait": self.check_selected,
            "download": self.download_selected,
            "export": self.export_selected,
            "deploy": self.deploy_selected,
            "deploy_add": self.add_deploy_target,
            "verify": self.verify_selected,
            "renew": self.renew_selected,
            "revoke": self.revoke_selected,
            "delete": self.delete_selected,
            "folder": self.open_folder,
            "copy_fingerprint": self.copy_fingerprint,
            "copy_pem": self.copy_pem,
            "install_globus": self.install_globus,
            "save_pem": self.save_pem,
            "proxy": self.create_proxy,
            "edit": self.edit_description,
            "rename": self.rename_selected,
            "view": self.view_selected,
        }
        handler = handlers.get(action)
        if handler is not None:
            handler()

    def new_request(self, cert_type: str = "") -> None:
        from .wizard import NewRequestWizard

        wizard = NewRequestWizard(self, self.ctx, self.runner, cert_type=cert_type if isinstance(cert_type, str) else "")
        try:
            if wizard.exec() != NewRequestWizard.DialogCode.Accepted or not wizard.specs:
                return
            specs = wizard.specs
            caps = wizard.capabilities
            wait_now = wizard.wait and not caps.manual_approval
            deploy_targets = {spec.cn: wizard.deploy_target(spec.alias or spec.cn) for spec in specs}
        finally:
            # A wizard left alive as a hidden child makes later application-wide
            # re-styling (a theme change) crash inside Qt.
            _dispose(wizard)
        ctx = self.ctx

        def work(progress, stop_event):
            from ..deploy import add_target
            from ..workflow import create_request, wait_for_certificate

            pins: "list[tuple[str, str]]" = []
            results, errors = [], []
            for spec in specs:
                if stop_event.is_set():
                    break
                progress(f"— {spec.cn} —")
                try:
                    state = create_request(
                        ctx,
                        spec,
                        progress=progress,
                        on_pin=lambda pin, name=spec.cn: pins.append((name, pin)),
                        stop_event=stop_event,
                    )
                    target = deploy_targets.get(spec.cn)
                    if target:
                        add_target(ctx, state, target)
                        state = ctx.store.get(state.alias)
                    if wait_now:
                        state = wait_for_certificate(ctx, state, progress=progress, timeout=900, interval=3, stop_event=stop_event)
                    results.append(state)
                except PyCertError as exc:
                    if len(specs) == 1:
                        raise
                    errors.append((spec.cn, str(exc)))
                    progress(f"{spec.cn}: {exc}")
            return results, errors, pins

        def done(result):
            results, errors, pins = result
            if pins:
                _show_modal(PinDialog(self, pins))
            if results:
                self.refresh(select=results[-1].alias)
                issued = [s for s in results if s.cert.sha256]
                if issued:
                    self.log(f"Issued: {', '.join(s.alias for s in issued)}")
                elif caps.manual_approval:
                    self.log("Submitted. pyCertWiz checks the CA in the background and collects the certificate when it is issued.")
            if errors:
                QMessageBox.warning(self, "Some requests failed", "\n".join(f"{name}: {error}" for name, error in errors))

        self.run_task("Submitting certificate request", work, done, error_title="The request could not be submitted")

    def check_now(self) -> None:
        self.log("Checking the CA for pending requests…")
        self.monitor.run_now()

    def check_selected(self) -> None:
        state = self.selected_state()
        if state is None:
            return
        ctx = self.ctx

        def work(progress, stop_event):
            from ..workflow import PENDING_STATUSES, download_and_export, poll_once, refresh_records

            if not state.renewal and state.status not in PENDING_STATUSES:
                records = refresh_records(ctx, aliases={state.alias}, stop_event=stop_event)
                if records:
                    return records[0][0], records[0][1]
            outcome = poll_once(ctx, state, progress=progress, stop_event=stop_event)
            if outcome.certificate is not None:
                progress("Certificate issued — verifying and exporting…")
                return download_and_export(
                    ctx, outcome.state, certificate=outcome.certificate, cert_id=outcome.cert_id,
                    chain_hint=outcome.chain, progress=progress, stop_event=stop_event,
                ), ""
            return outcome.state, outcome.message

        def done(result):
            new_state, message = result
            self.refresh(select=new_state.alias)
            if message:
                self.log(f"{new_state.alias}: {message}")
                self.status_text.setText(f"{new_state.alias}: {message}")
            else:
                self.notify_done("Certificate ready", f"“{new_state.alias}” has been issued and exported.", new_state.p12_path)

        self.run_task(f"Checking {state.alias}", work, done)

    def download_selected(self) -> None:
        state = self.selected_state()
        if state is None:
            return
        ctx = self.ctx

        def work(progress, stop_event):
            from ..workflow import download_and_export

            return download_and_export(ctx, state, progress=progress, stop_event=stop_event)

        self.run_task("Downloading", work, lambda s: (self.refresh(select=s.alias), self.notify_done("Certificate stored", f"“{s.alias}” downloaded and verified.", s.p12_path)))

    def export_selected(self, format: str = "p12") -> None:
        """Export with a new passphrase, in the format the user chooses (PKCS#12 by default)."""
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        dialog = ExportDialog(self, self.ctx, state, format=format, directory=str(pref("export_dir", str(Path.home()))))
        accepted = dialog.exec() == ExportDialog.DialogCode.Accepted
        request = dialog.request
        _dispose(dialog)  # it holds the passphrase
        if not accepted or request is None:
            return
        preferences().setValue(
            "export_dir",
            str(request["destination"] if request["format"] == "pem-files" else Path(request["destination"]).parent),
        )
        ctx = self.ctx
        alias = state.alias

        def work(progress, _stop):
            from ..workflow import export_certificate

            return export_certificate(ctx, alias, request.pop("destination"), progress=progress, **request)

        def done(result):
            files = list(result.files.values())
            detail = "\n".join(str(p) for p in files)
            if result.unprotected_key:
                detail += "\n\nThe key has NO passphrase, as you confirmed."
            self.notify_done("Exported", detail, str(files[0]))

        self.run_task(f"Exporting {alias}", work, done, error_title="Export failed")

    def rename_selected(self) -> None:
        state = self.selected_state()
        if state is None:
            return
        dialog = RenameDialog(self, self.ctx, state)
        if dialog.exec() != RenameDialog.DialogCode.Accepted:
            return
        new_name = dialog.new_name
        keystore_entry = dialog.rename_keystore_entry
        _dispose(dialog)
        if keystore_entry:
            from ..keystore import is_unlocked

            name = state.keystore["name"]
            if not is_unlocked(self.ctx, name) and not self.unlock_keystore(name):
                QMessageBox.information(self, APP_NAME, f"Not renamed: keystore '{name}' is still locked.")
                return
        ctx = self.ctx
        old = state.alias

        def work(progress, _stop):
            from ..workflow import rename_certificate

            return rename_certificate(ctx, old, new_name, keystore_entry=keystore_entry, progress=progress)

        def done(renamed):
            self.refresh(select=renamed.alias)
            self.log(f"Renamed '{old}' to '{renamed.alias}'")

        self.run_task(f"Renaming {old}", work, done, error_title="Could not rename")

    def view_selected(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        from .viewer import CertificateViewer

        try:
            viewer = CertificateViewer(self, self.ctx, state)
        except PyCertError as exc:
            self.show_error("Cannot show the certificate", exc)
            return
        viewer.exec()
        _dispose(viewer)

    def deploy_selected(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        if not state.deploy:
            self.add_deploy_target()
            return
        ctx = self.ctx

        def work(progress, _stop):
            from ..deploy import deploy_state

            return deploy_state(ctx, state, progress=progress)

        def done(results):
            self.refresh()
            rows = [("ok" if r.ok else "fail", r.target, ", ".join(r.written) + (f" · hook: {r.hook}" if r.hook else "")) for r in results]
            _show_modal(ReportDialog(self, "Deployment", f"Deployed “{state.alias}”", rows))

        self.run_task(f"Deploying {state.alias}", work, done)

    def add_deploy_target(self) -> None:
        state = self.selected_state()
        if state is None:
            return
        dialog = DeployTargetDialog(self, state)
        accepted = dialog.exec() == DeployTargetDialog.DialogCode.Accepted
        target, deploy_now = dialog.target, dialog.deploy_now.isChecked()
        _dispose(dialog)
        if not accepted or target is None:
            return
        from ..deploy import add_target

        try:
            add_target(self.ctx, self.ctx.store.get(state.alias), target)
        except PyCertError as exc:
            self.show_error("Could not add the target", exc)
            return
        self.log(f"Added deployment target '{target['name']}' to {state.alias}")
        self.refresh()
        if deploy_now:
            self.deploy_selected()

    def remove_deploy_target(self, name: str) -> None:
        state = self.selected_state()
        if state is None:
            return
        if QMessageBox.question(self, "Remove target", f"Stop deploying “{state.alias}” to '{name}'?\n\nFiles already written are left in place.") != QMessageBox.StandardButton.Yes:
            return
        from ..deploy import remove_target

        try:
            remove_target(self.ctx, state, name)
        except PyCertError as exc:
            self.show_error("Could not remove the target", exc)
        self.refresh()

    def verify_selected(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        ctx = self.ctx

        def work(_progress, _stop):
            from ..workflow import verify

            return verify(ctx, state.alias)

        def done(report):
            rows = [("ok" if passed else "fail", name, detail) for name, passed, detail in report.checks]
            rows += [("warn", "warning", message) for message in report.warnings]
            summary = "All checks passed" if report.ok else "Some checks failed"
            _show_modal(ReportDialog(self, f"Verify {state.alias}", summary, rows, ok=report.ok))

        self.run_task("Verifying", work, done, modal=False)

    def renew_selected(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        if state.renewal:
            QMessageBox.information(self, APP_NAME, "A renewal is already in progress for this certificate.")
            return
        ctx = self.ctx

        # First ask the CA what it holds for the certificate (status, contact),
        # so the dialog starts from the CA's record and refusals come early.
        def check(progress, stop_event):
            from ..workflow import check_renewal

            return check_renewal(ctx, state.alias, progress=progress, stop_event=stop_event)

        def checked(result):
            self.refresh(select=state.alias)
            if result.problem:
                QMessageBox.warning(self, "Cannot renew", f"“{state.alias}” cannot be renewed: {result.problem}.")
                return
            self._open_renew_dialog(result.state, result.record_email)

        self.run_task(f"Checking {state.alias} with the CA", check, checked, error_title="Could not check the certificate")

    def _open_renew_dialog(self, state: "Any", record_email: str) -> None:
        provider = self.ctx.provider_for(state)
        dialog = RenewDialog(self, state, provider.capabilities, self.cfg, record_email)
        accepted = dialog.exec() == RenewDialog.DialogCode.Accepted
        options = dialog.options()
        wait_now = dialog.wait.isChecked() and not provider.capabilities.manual_approval
        _dispose(dialog)
        if not accepted:
            return
        ctx = self.ctx

        def work(progress, stop_event):
            from ..workflow import renew, wait_for_certificate

            pins: "list[tuple[str, str]]" = []
            renewed = renew(ctx, state.alias, progress=progress, on_pin=lambda pin: pins.append((state.cn, pin)), stop_event=stop_event, **options)
            if wait_now:
                renewed = wait_for_certificate(ctx, renewed, progress=progress, timeout=900, interval=3, stop_event=stop_event)
            return renewed, pins

        def done(result):
            renewed, pins = result
            if pins:
                _show_modal(PinDialog(self, pins))
            self.refresh(select=renewed.alias)
            self.log(f"Renewal for {renewed.alias}: {renewed.status}")

        self.run_task(f"Renewing {state.alias}", work, done, error_title="Renewal failed")

    def renew_due(self) -> None:
        from ..workflow import renew_due

        warn = int(pref("warn_days", 30))
        try:
            due = renew_due(self.ctx, warn, dry_run=True)
        except PyCertError as exc:
            self.show_error("Could not list renewals", exc)
            return
        if not due:
            QMessageBox.information(self, "Renewals", f"Nothing expires within {warn} days (or renewals are already in progress).")
            return
        names = "\n".join(f"• {state.alias} ({state.days_remaining} days left)" for state, _ in due)
        if QMessageBox.question(self, "Renew certificates", f"Request renewals for:\n\n{names}\n\nNew keys are generated; current certificates keep working until the new ones are issued.") != QMessageBox.StandardButton.Yes:
            return
        ctx = self.ctx

        def work(progress, _stop):
            pins: "list[tuple[str, str]]" = []
            current: "dict[str, str]" = {}

            def on_pin(pin: str) -> None:
                pins.append((current.get("alias", "?"), pin))

            def tracking(message: str) -> None:
                if message.startswith("renewing "):  # "renewing <alias> (<n> days remaining)"
                    current["alias"] = message[len("renewing "):].rsplit(" (", 1)[0]
                progress(message)

            results = renew_due(ctx, warn, progress=tracking, on_pin=on_pin)
            return results, pins

        def done(result):
            results, pins = result
            if pins:
                _show_modal(PinDialog(self, pins))
            failed = [(s.alias, e) for s, e in results if e]
            self.refresh()
            if failed:
                QMessageBox.warning(self, "Some renewals failed", "\n".join(f"{a}: {e}" for a, e in failed))

        self.run_task("Renewing certificates", work, done)

    def revoke_selected(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        provider = self.ctx.provider_for(state)
        dialog = RevokeDialog(self, state, provider.capabilities.revocation_reasons)
        accepted = dialog.exec() == RevokeDialog.DialogCode.Accepted
        reason = dialog.reason_code()
        _dispose(dialog)
        if not accepted:
            return
        ctx = self.ctx

        def work(progress, stop_event):
            from ..workflow import revoke

            return revoke(ctx, state.alias, reason, progress=progress, stop_event=stop_event)

        self.run_task(f"Revoking {state.alias}", work, lambda s: (self.refresh(select=s.alias), self.log(f"{s.alias} revoked")), error_title="Revocation failed")

    def delete_selected(self) -> None:
        state = self.selected_state()
        if state is None:
            return
        text, ok = QInputDialog.getText(
            self,
            "Delete local copy",
            f"This deletes the private key, certificate and files for “{state.alias}” from this computer.\n"
            "It does not revoke the certificate at the CA.\n\nType the name to confirm:",
        )
        if not ok or text.strip() != state.alias:
            return
        try:
            self.ctx.store.delete(state)
        except OSError as exc:
            self.show_error("Could not delete", exc)
            return
        self.log(f"Deleted the local copy of {state.alias}")
        self._selected_alias = None
        self.refresh()

    def open_folder(self) -> None:
        state = self.selected_state()
        if state is not None:
            _open_path(self.ctx.store.path(state))

    def copy_fingerprint(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is not None:
            copy_to_clipboard(state.cert.sha256)
            self.status_text.setText("SHA-256 fingerprint copied")

    def copy_pem(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is not None:
            copy_to_clipboard(certs.cert_pem(self.ctx.store.load_certificate(state)))
            self.status_text.setText("Certificate PEM copied")

    def install_globus(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        dialog = KeyProtectionDialog(self, "Install as ~/.globus", "userkey.pem", directory=str(Path.home() / ".globus"))
        accepted = dialog.exec() == KeyProtectionDialog.DialogCode.Accepted
        directory = dialog.directory.text().strip() or str(Path.home() / ".globus")
        chosen_password, no_passphrase = dialog.chosen_password, dialog.no_passphrase
        _dispose(dialog)  # it holds the passphrase
        if not accepted:
            return
        from ..workflow import install_pem

        try:
            paths = install_pem(
                self.ctx,
                state.alias,
                Path(directory),
                password=chosen_password,
                no_passphrase=no_passphrase,
                progress=self.log,
            )
        except PyCertError as exc:
            self.show_error("Install failed", exc)
            return
        self.notify_done("Installed", "\n".join(str(p) for p in paths.values()), str(paths["cert"]))

    def save_pem(self) -> None:
        self.export_selected("pem-files")

    def create_proxy(self) -> None:
        state = self.selected_state(require_cert=True)
        if state is None:
            return
        dialog = ProxyDialog(self, state)
        accepted = dialog.exec() == ProxyDialog.DialogCode.Accepted
        chosen_out, hours, limited = dialog.out.text().strip(), dialog.hours.value(), dialog.limited.isChecked()
        _dispose(dialog)
        if not accepted:
            return
        from ..proxy import create_proxy_bundle

        out = Path(chosen_out).expanduser() if chosen_out else self.ctx.store.path(state) / "proxy.pem"
        ctx = self.ctx
        self.run_task(
            "Creating proxy",
            lambda _p, _s: create_proxy_bundle(ctx, state.alias, out, hours=hours, limited=limited),
            lambda result: self.notify_done("Proxy created", f"Valid until {result.not_after}", str(result.path)),
            modal=False,
        )

    def edit_description(self) -> None:
        state = self.selected_state()
        if state is None:
            return
        text, ok = QInputDialog.getText(self, "Description", f"Description for “{state.alias}”:", text=state.description)
        if not ok:
            return
        with self.ctx.store.lock(state):
            current = self.ctx.store.get(state.alias)
            current.description = text.strip()
            current.touch()
            self.ctx.store.save(current)
        self.refresh()

    def _set_auto_renew(self, value: bool) -> None:
        state = self.selected_state()
        if state is None:
            return
        with self.ctx.store.lock(state):
            current = self.ctx.store.get(state.alias)
            current.auto_renew = value
            self.ctx.store.save(current)
        self.log(f"Automatic renewal {'on' if value else 'off'} for {state.alias}")
        self.refresh()

    def import_p12(self) -> None:
        dialog = ImportDialog(self, self.cfg)
        accepted = dialog.exec() == ImportDialog.DialogCode.Accepted and bool(dialog.path.text().strip())
        path = Path(dialog.path.text().strip()).expanduser()
        password = dialog.password.text()
        alias = dialog.alias.text().strip()
        ca = dialog.ca.currentData()
        allow = dialog.allow_unverified.isChecked()
        _dispose(dialog)  # it holds the passphrase
        if not accepted:
            return
        ctx = self.ctx

        def work(progress, _stop):
            from ..workflow import export_p12, import_p12

            state = import_p12(ctx, path, password, alias=alias, progress=progress, require_verified_chain=not allow, ca=ca)
            export_p12(ctx, state, progress=progress)
            return ctx.store.get(state.alias)

        self.run_task("Importing", work, lambda s: (self.refresh(select=s.alias), self.log(f"Imported {s.alias}")), error_title="Import failed")

    # ------------------------------------------------------------ keystores
    def _watch_keystores(self) -> None:
        watched = self.watcher.files() + self.watcher.directories()
        if watched:
            self.watcher.removePaths(watched)
        for link in self.cfg.keystores:
            path = self.cfg.resolve(link.path)
            # Java tools replace the file, so watch its directory too.
            for target in (path, path.parent):
                if target.exists():
                    self.watcher.addPath(str(target))

    def _keystore_file_changed(self, _path: str) -> None:
        self._sync_timer.start()  # debounce bursts of change notifications

    def sync_keystores(self, name: str = "") -> None:
        if not self.cfg.keystores:
            return
        ctx = self.ctx
        only_changed = not name

        def work(progress, _stop):
            from ..keystore import sync, sync_all

            if name:
                return [sync(ctx, ctx.config.keystore(name), progress=progress)]
            return sync_all(ctx, progress=progress, only_if_changed=only_changed)

        def done(reports):
            for report in reports:
                if report.locked:
                    continue
                if report.error:
                    self.log(f"Keystore '{report.keystore}' not synchronised: {report.error}")
                elif not report.skipped:
                    self.log(report.summary())
                for problem in report.problems:
                    self.log(f"Keystore '{report.keystore}': {problem}")
            self._watch_keystores()
            self.refresh()

        self.runner.start(work, done, lambda exc: self.log(f"Keystore sync failed: {exc}"), name="keystore sync")

    def unlock_keystore(self, name: str) -> bool:
        """Ask for a keystore's passphrase; it is kept in memory for this session only."""
        from PySide6.QtWidgets import QInputDialog

        from ..keystore import unlock

        link = self.cfg.keystore(name)
        prompt = (
            f"pyCertWiz never stores keystore passphrases.\n\nPassphrase for '{name}'\n{link.path}\n\n"
            "Cancel leaves it locked for this session."
        )
        for _attempt in range(3):
            password, ok = QInputDialog.getText(self, "Unlock Java keystore", prompt, QLineEdit.EchoMode.Password)
            if not ok or not password:
                self.log(f"Keystore '{name}' left locked for this session")
                return False
            try:
                unlock(self.ctx, link, password)
            except PyCertError as exc:
                prompt = f"That passphrase did not open '{name}' ({exc}).\n\nTry again, or Cancel to leave it locked."
                continue
            self.log(f"Keystore '{name}' unlocked for this session")
            self._populate_nav()
            self.sync_keystores(name)
            return True
        return False

    def unlock_keystores_at_startup(self) -> None:
        from ..keystore import is_unlocked

        for link in list(self.cfg.keystores):
            if not is_unlocked(self.ctx, link.name):
                self.unlock_keystore(link.name)

    def link_keystore(self, path: str = "", password: str = "") -> None:
        from .dialogs import LinkKeystoreDialog

        dialog = LinkKeystoreDialog(self, self.cfg, path if isinstance(path, str) else "", password if isinstance(password, str) else "")
        accepted = dialog.exec() == LinkKeystoreDialog.DialogCode.Accepted
        options = {
            "name": dialog.name.text().strip(),
            "ca": dialog.ca.currentData(),
            "auto_import": dialog.auto_import.isChecked(),
            "write_back": dialog.write_back.isChecked(),
        }
        keystore_path, keystore_password = dialog.path.text().strip(), dialog.password.text()
        _dispose(dialog)  # it holds the passphrase
        if not accepted:
            return
        ctx = self.ctx

        def work(progress, _stop):
            from ..keystore import link_keystore, sync

            link, _keystore = link_keystore(ctx, keystore_path, keystore_password, **options)
            return link, sync(ctx, link, progress=progress)

        def done(result):
            link, report = result
            self.log(f"Linked keystore '{link.name}' ({link.path})")
            self.reload_config()
            self._select_view(f"keystore:{link.name}")
            detail = report.summary() + ("\n\n" + "\n".join(report.problems) if report.problems else "")
            self.notify_done("Keystore linked", detail, link.path)

        self.run_task("Linking keystore", work, done, error_title="The keystore could not be linked")

    def import_keystore_entries(self, path: str, password: str) -> None:
        ctx = self.ctx

        def work(progress, _stop):
            from ..keystore import import_keystore

            return import_keystore(ctx, path, password, progress=progress)

        def done(result):
            states, problems = result
            self.refresh(select=states[-1].alias if states else None)
            text = f"Imported {len(states)} certificate(s)." + ("\n\n" + "\n".join(problems) if problems else "")
            self.notify_done("Import finished", text)

        self.run_task("Importing keystore entries", work, done, error_title="Import failed")

    def _nav_menu(self, position) -> None:
        item = self.nav.itemAt(position)
        key = item.data(Qt.ItemDataRole.UserRole) if item is not None else ""
        if not key or not str(key).startswith("keystore:"):
            return
        name = key[len("keystore:"):]
        menu = QMenu(self)
        from ..keystore import is_unlocked

        if not is_unlocked(self.ctx, name):
            unlock_action = menu.addAction(icons.icon("lock"), "Unlock…")
            unlock_action.triggered.connect(lambda: self.unlock_keystore(name))
        sync_action = menu.addAction(icons.icon("refresh"), "Synchronise now")
        sync_action.triggered.connect(lambda: self.sync_keystores(name))
        reveal = menu.addAction(icons.icon("folder"), "Show the keystore file")
        reveal.triggered.connect(lambda: _open_path(self.cfg.resolve(self.cfg.keystore(name).path).parent))
        menu.addSeparator()
        unlink = menu.addAction(icons.icon("close"), "Unlink…")
        unlink.triggered.connect(lambda: self.unlink_keystore(name))
        menu.exec(self.nav.viewport().mapToGlobal(position))
        menu.deleteLater()

    def unlink_keystore(self, name: str) -> None:
        if QMessageBox.question(
            self,
            "Unlink keystore",
            f"Stop keeping keystore '{name}' in step with pyCertWiz?\n\nThe keystore file is not changed and its "
            "certificates stay managed by pyCertWiz.",
        ) != QMessageBox.StandardButton.Yes:
            return
        from ..keystore import unlink_keystore

        try:
            count = unlink_keystore(self.ctx, name)
        except PyCertError as exc:
            self.show_error("Could not unlink the keystore", exc)
            return
        self.log(f"Unlinked keystore '{name}' ({count} certificate(s) stay managed)")
        self.reload_config()

    def open_bundle(self, path: "str | None" = None) -> None:
        from .bundle import BundleInspector

        dialog = BundleInspector(self, path if isinstance(path, str) else None)
        # Act only once the inspector has closed.  Opening the link dialog from
        # inside the inspector's modal loop nests two modal sessions, which
        # macOS reports as "modalSession has been exited prematurely".
        chosen: "list[tuple[Callable[[str, str], None], str, str]]" = []
        dialog.import_all_requested.connect(lambda p, pw: (chosen.append((self.import_keystore_entries, p, pw)), dialog.accept()))
        dialog.link_requested.connect(lambda p, pw: (chosen.append((self.link_keystore, p, pw)), dialog.accept()))
        dialog.exec()
        _dispose(dialog)  # it holds the passphrase
        if chosen:
            action, chosen_path, chosen_password = chosen[0]
            chosen.clear()
            action(chosen_path, chosen_password)

    def ping_cas(self) -> None:
        ctx = self.ctx

        def work(_progress, _stop):
            results = {}
            for name in ctx.config.cas:
                try:
                    results[name] = ctx.provider(name).ping()
                except PyCertError as exc:
                    from ..providers.base import PingResult

                    results[name] = PingResult(ok=False, detail=str(exc))
            return results

        def done(results):
            self._ca_status = {name: result.ok for name, result in results.items()}
            self._populate_nav()
            online = [n for n, r in results.items() if r.ok]
            offline = [n for n, r in results.items() if not r.ok]
            t = theme.tokens()
            primary = self.cfg.primary_profile.name
            ok = results.get(primary)
            if ok is not None and ok.ok:
                self.status_ca.setText(f"● {self.cfg.primary_profile.display_name} online ({ok.latency_ms:.0f} ms)")
                self.status_ca.setStyleSheet(f"color: {t.valid};")
            else:
                self.status_ca.setText(f"● {self.cfg.primary_profile.display_name} unreachable")
                self.status_ca.setStyleSheet(f"color: {t.expired};")
            for name in offline:
                self.log(f"CA '{name}' is unreachable: {results[name].detail or 'no response'}")
            if offline:
                self._banner_kind = "unreachable"
                self.banner.show_message(
                    "warning",
                    "<b>Cannot reach " + ", ".join(self.cfg.cas[n].display_name for n in offline) + "</b> — "
                    "requests can still be prepared; pyCertWiz retries in the background.",
                    "Diagnose…",
                )
            elif self._banner_kind == "unreachable":
                self.banner.hide()
                self._banner_kind = ""
                self.refresh()
            if online:
                self.log("Reachable: " + ", ".join(online))

        self.runner.start(work, done, lambda exc: self.log(f"CA check failed: {exc}"), name="ping")

    def show_ca_info(self) -> None:
        key = getattr(self, "page_view", "")
        name = key[3:] if key.startswith("ca:") else self.cfg.default_ca
        ctx = self.ctx

        def work(_progress, _stop):
            return ctx.provider(name).info()

        def done(info):
            rows = []
            for field, value in info.items():
                if field == "certificates":
                    for cert in value:
                        description = certs.describe_certificate(cert)
                        rows.append(("info", "CA certificate", f"{description.subject} (expires {description.not_after.date()})"))
                    continue
                if isinstance(value, (list, tuple)):
                    value = ", ".join(str(v) for v in value[:40])
                elif isinstance(value, dict):
                    value = ", ".join(f"{k}={v}" for k, v in value.items())
                rows.append(("info", field.replace("_", " "), str(value)))
            _show_modal(ReportDialog(self, "CA information", self.cfg.profile_for(name).display_name, rows))

        self.run_task("Reading CA information", work, done, modal=False)

    def run_doctor(self) -> None:
        ctx = self.ctx

        def work(_progress, _stop):
            from ..diagnostics import run_doctor

            return run_doctor(ctx)

        def done(results):
            failures = [r for r in results if r.status == "fail"]
            rows = [(r.status, r.name, r.detail) for r in results]
            summary = f"{len(failures)} problem(s) found" if failures else "Everything looks healthy"
            _show_modal(ReportDialog(self, "Diagnostics", summary, rows, ok=not failures))

        self.run_task("Running diagnostics", work, done, modal=False)

    def open_settings(self) -> None:
        dialog = SettingsDialog(self, self.config_path)
        accepted = dialog.exec() == SettingsDialog.DialogCode.Accepted
        saved = dialog.saved
        _dispose(dialog)
        if accepted and saved:
            self.reload_config()
            self.set_appearance(pref("appearance", "system"))
            self.monitor.reschedule()
            self.tray.apply_preferences()
            self.log("Settings saved")

    def reload_config(self) -> None:
        try:
            self.cfg = load_config(self.config_path)
        except PyCertError as exc:
            self.show_error("The configuration could not be loaded", exc)
            return
        sessions = self.ctx.keystore_passwords  # passphrases given this session survive a reload
        self.ctx = AppContext.from_config(self.cfg)
        self.ctx.confirm = self.prompter
        self.ctx.keystore_passwords = {name: value for name, value in sessions.items() if any(l.name == name for l in self.cfg.keystores)}
        self._populate_nav()
        self._watch_keystores()
        self.refresh()
        QTimer.singleShot(100, self.ping_cas)

    def set_appearance(self, appearance: str, menu: "QMenu | None" = None) -> None:
        settings = preferences()
        settings.setValue("appearance", appearance)
        theme.apply(appearance)
        self._retheme()
        if menu is not None:
            for action in menu.actions():
                action.setChecked(action.text().lower().startswith(appearance) or (appearance == "system" and action.text().startswith("Follow")))

    def _color_scheme_changed(self, _scheme: Any = None) -> None:
        self._system_scheme_changed()

    def _system_scheme_changed(self) -> None:
        if pref("appearance", "system") == "system":
            theme.apply("system")
            self._retheme()

    def _retheme(self) -> None:
        icons.refresh_themed()
        for card in self.cards.values():
            card.refresh_style()
        self._populate_nav()
        self.table.viewport().update()
        self._restore_selection()

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            "About pyCertWiz",
            f"<h3>pyCertWiz {__version__}</h3>"
            "<p>A certificate manager for the UK e-Science CA and ACME certificate authorities: "
            "request, track, renew, deploy and export personal and host certificates.</p>"
            "<p>Replaces the Java CertWizard client. Cryptography by <i>python-cryptography</i> (OpenSSL); "
            "interface by Qt for Python.</p>"
            f"<p>Configuration: {self.cfg.path}<br>Data: {self.cfg.data_dir}</p>",
        )

    def notify_done(self, title: str, text: str, path: str = "") -> None:
        self.log(f"{title}: {text}" + (f" ({path})" if path else ""))
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle(title)
        box.setText(f"<b>{title}</b>")
        box.setInformativeText(text + (f"\n\n{path}" if path else ""))
        reveal = None
        if path:
            reveal = box.addButton("Show in folder", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Ok)
        box.exec()
        if reveal is not None and box.clickedButton() is reveal:
            _open_path(Path(path).parent)

    # ------------------------------------------------------- background / tray
    def _background_checked(self, report: Any, collected: list) -> None:
        self.refresh()
        for alias in collected:
            self.log(f"Collected the newly issued certificate for {alias}")
        self.tray.update(report, collected)

    def _context_menu(self, position) -> None:
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        self.detail.more_menu.exec(self.table.viewport().mapToGlobal(position))

    def bring_to_front(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_application(self) -> None:
        self._quitting = True
        self.close()

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.tray.tray is not None and not self._quitting and pref("tray", True) and sys.platform != "darwin":
            # Keep monitoring from the tray; Quit from its menu exits.
            self.hide()
            self.tray.tray.showMessage("pyCertWiz is still running", "Certificates are monitored in the background.", icons.app_icon(), 4000)
            event.ignore()
            return
        self.runner.shutdown()
        self.monitor.timer.stop()
        self.runner.wait(3000)
        if self.tray.tray is not None:
            self.tray.tray.hide()
        event.accept()
        app = QApplication.instance()
        if app is not None:
            app.quit()


def _open_path(path: Path) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


def _show_modal(dialog: "Any") -> int:
    """Run a modal dialog, then dispose of it (see :func:`_dispose`)."""
    try:
        return dialog.exec()
    finally:
        _dispose(dialog)


def _dispose(dialog: QWidget) -> None:
    """Clear a finished dialog's passphrase fields and delete it.

    Dialogs are children of the main window, so without this each one, and any
    passphrase typed into it, would stay in memory until pyCertWiz quits.
    """
    for field in dialog.findChildren(QLineEdit):
        field.clear()
    dialog.deleteLater()


def create_application(argv: "list[str] | None" = None) -> QApplication:
    from . import protect_none

    protect_none()
    existing = QApplication.instance()
    if existing is not None and existing.property("pycert_ready"):
        return existing
    app = existing or QApplication(argv or sys.argv)
    app.setProperty("pycert_ready", True)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)
    # Matches the installed .desktop file, so Linux desktops show the right icon.
    app.setDesktopFileName("io.github.rob_c.pyCertWiz")
    app.setApplicationVersion(__version__)
    app.setWindowIcon(icons.app_icon())
    app.setQuitOnLastWindowClosed(False)
    theme.apply(pref("appearance", "system"))
    return app


def open_main_window(config_path: "str | None" = None, *, start_background: bool = True) -> "MainWindow | None":
    """The main window. On a first run (no configuration anywhere) the setup comes first.

    Returns ``None`` when the user quits the setup instead.
    """
    try:
        return MainWindow(config_path, start_background=start_background)
    except ConfigNotFound:
        from .setup import SetupDialog

        dialog = SetupDialog()
        if _show_modal(dialog) != QDialog.DialogCode.Accepted:
            return None
        return MainWindow(str(dialog.config_path), start_background=start_background)


def _render_once(app: QApplication, widget: QWidget, settle_seconds: float) -> "Any":
    import time

    widget.show()
    deadline = time.monotonic() + settle_seconds
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)
    return widget.grab()


def check(config_path: "str | None" = None, *, argv: "list[str] | None" = None, settle_seconds: float = 0.5) -> int:
    """Start the GUI without a user: build the main window, render it once, report, exit.

    Package tests use it (offscreen, or a real X11, Wayland or macOS display) to
    prove that Qt, its platform plugin and the main window load from the package.
    Before pyCertWiz is set up, it renders the first-run setup instead.
    """
    import PySide6
    from PySide6.QtCore import qVersion

    app = create_application(argv)
    collector = MainThreadCollector(app)
    try:
        try:
            window = MainWindow(config_path, start_background=False)
        except ConfigNotFound:
            from .setup import SetupDialog

            what, widget = "first-run setup", SetupDialog()
            image = _render_once(app, widget, settle_seconds)
            _dispose(widget)
        except PyCertError as exc:
            print(f"GUI check failed: {exc}", file=sys.stderr)
            return 1
        else:
            what = "window"
            image = _render_once(app, window, settle_seconds)
            window.runner.shutdown()
            window.runner.wait(5000)
            window.close()
        if image.isNull() or image.width() < 100:
            print(f"GUI check failed: the {what} did not render", file=sys.stderr)
            return 1
        print(
            f"GUI check OK: {app.platformName()} platform, Qt {qVersion()}, PySide6 {PySide6.__version__}, "
            f"{what} {image.width()}x{image.height()}"
        )
        return 0
    finally:
        collector.stop()


def run(config_path: "str | None" = None, *, argv: "list[str] | None" = None) -> int:  # pragma: no cover - event loop
    app = create_application(argv)
    collector = MainThreadCollector(app)  # garbage (and so widgets) is only freed on the UI thread
    app.aboutToQuit.connect(collector.stop)
    try:
        window = open_main_window(config_path)
    except PyCertError as exc:
        QMessageBox.critical(None, APP_NAME, f"Cannot start pyCertWiz:\n\n{exc}")
        return 1
    if window is None:  # the first-run setup was cancelled
        return 0
    window.show()
    return app.exec()
