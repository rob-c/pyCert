"""Background monitoring: collect issued certificates and warn about expiry.

Every few minutes (configurable) the monitor polls the CA for pending
requests - downloading, verifying and exporting any that have been issued -
then evaluates every stored certificate.  Results go to the main window and,
when enabled, to the menu-bar / system-tray icon as notifications.  Each
expiry warning is shown at most once a day per certificate.
"""

from datetime import date
from typing import Any

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from .. import monitor
from ..errors import PyCertError
from ..workflow import watch
from . import icons
from .settings import pref, preferences


class BackgroundMonitor(QObject):
    """Periodic CA polling plus health evaluation, run on the task runner."""

    checked = Signal(object, list)  # CheckReport, aliases collected this cycle
    failed = Signal(str)

    def __init__(self, window: Any):
        super().__init__(window)
        self.window = window
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.run_now)
        self.running = False
        self.reschedule()

    def reschedule(self) -> None:
        minutes = max(5, int(pref("refresh_minutes", 30)))
        self.timer.start(minutes * 60 * 1000)

    def run_now(self) -> None:
        if self.running:
            return
        ctx = self.window.ctx
        auto_collect = bool(pref("auto_collect", True))
        warn_days = int(pref("warn_days", 30))
        crit_days = min(int(pref("crit_days", 7)), warn_days)
        self.running = True

        def work(progress, stop_event):
            collected: "list[str]" = []
            if ctx.config.keystores:
                from ..keystore import sync_all

                sync_all(ctx, progress=progress, only_if_changed=True)
            # Certificates the CA has not been asked about yet (e.g. just imported).
            from ..workflow import refresh_records

            refresh_records(ctx, only_missing=True, stop_event=stop_event)
            pending = [s for s in ctx.store.pending() if s.active_spki_b64]
            if pending:
                before = {s.alias: bool(s.cert.sha256) and not s.renewal for s in pending}
                if auto_collect:
                    watch(ctx, max_cycles=1, progress=progress, stop_event=stop_event, sleep=lambda _s: None)
                else:
                    from ..workflow import refresh_all

                    refresh_all(ctx, progress=progress)
                for alias, had_cert in before.items():
                    try:
                        state = ctx.store.get(alias)
                    except PyCertError:
                        continue
                    if not had_cert and state.cert.sha256 and not state.renewal:
                        collected.append(alias)
            report = monitor.check(ctx, warn_days=warn_days, crit_days=crit_days)
            return report, collected

        def done(result):
            self.running = False
            report, collected = result
            self.checked.emit(report, collected)

        def error(exc):
            self.running = False
            self.failed.emit(str(exc))

        self.window.runner.start(work, done, error, name="background check")


class TrayController(QObject):
    """The menu-bar / system-tray icon and its notifications."""

    def __init__(self, window: Any):
        super().__init__(window)
        self.window = window
        self.tray: "QSystemTrayIcon | None" = None
        self.apply_preferences()

    @staticmethod
    def supported() -> bool:
        return QSystemTrayIcon.isSystemTrayAvailable()

    def apply_preferences(self) -> None:
        wanted = bool(pref("tray", True)) and self.supported()
        if wanted and self.tray is None:
            self.tray = QSystemTrayIcon(icons.app_icon(), self)
            self.tray.setToolTip("pyCertWiz")
            menu = QMenu()
            show = QAction("Show pyCertWiz", menu)
            show.triggered.connect(self.window.bring_to_front)
            check = QAction("Check now", menu)
            check.triggered.connect(self.window.monitor.run_now)
            new = QAction("New certificate…", menu)
            new.triggered.connect(lambda: (self.window.bring_to_front(), self.window.new_request()))
            quit_action = QAction("Quit", menu)
            quit_action.triggered.connect(self.window.quit_application)
            for action in (show, check, new):
                menu.addAction(action)
            menu.addSeparator()
            menu.addAction(quit_action)
            self.menu = menu
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._activated)
            self.tray.show()
        elif not wanted and self.tray is not None:
            self.tray.hide()
            self.tray.deleteLater()
            self.tray = None

    def _activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.window.bring_to_front()

    def update(self, report: "monitor.CheckReport", collected: "list[str]") -> "list[tuple[str, str]]":
        """Update the tooltip and send notifications; returns what was notified (for tests)."""
        notifications: "list[tuple[str, str]]" = []
        if self.tray is not None:
            counts = report.counts
            self.tray.setToolTip(
                f"pyCertWiz — {counts.get('valid', 0)} valid, {counts.get('expiring', 0)} expiring, "
                f"{counts.get('pending', 0)} pending"
            )
        if not pref("notify", True):
            return notifications
        for alias in collected:
            notifications.append(("Certificate issued", f"“{alias}” has been issued, verified and exported."))
        settings = preferences()
        today = date.today().isoformat()
        for finding in report.findings:
            if finding.level not in (monitor.WARNING, monitor.CRITICAL) or finding.days_remaining is None:
                continue
            if "expire" not in finding.message:
                continue
            key = f"notified/{finding.alias}"
            if settings.value(key, "") == today:
                continue
            settings.setValue(key, today)
            notifications.append((f"{finding.alias} {finding.message}", "Open pyCertWiz to renew it."))
        if self.tray is not None:
            for title, text in notifications[:4]:
                self.tray.showMessage(title, text, icons.app_icon(), 8000)
        return notifications
