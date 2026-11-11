"""Colours, palette and style sheet for light and dark appearance.

The application uses Qt's Fusion style everywhere (consistent on macOS, Linux
and Windows) with a hand-tuned palette and a small style sheet.  ``System``
appearance follows the operating system (Qt 6.5+ ``QStyleHints.colorScheme``)
and switches live when the OS does.
"""

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

APPEARANCES = ("system", "light", "dark")


@dataclass(frozen=True)
class Tokens:
    dark: bool
    window: str
    surface: str
    surface_alt: str
    sidebar: str
    border: str
    text: str
    muted: str
    accent: str
    accent_text: str
    accent_soft: str
    selection: str
    valid: str
    expiring: str
    expired: str
    pending: str
    revoked: str
    failed: str
    info_bg: str
    warn_bg: str
    danger_bg: str


LIGHT = Tokens(
    dark=False,
    window="#f4f5f7",
    surface="#ffffff",
    surface_alt="#f8f9fb",
    sidebar="#eceef2",
    border="#dfe3e8",
    text="#1d2127",
    muted="#667085",
    accent="#3554d1",
    accent_text="#ffffff",
    accent_soft="#e6ebfc",
    selection="#dbe4ff",
    valid="#15803d",
    expiring="#b45309",
    expired="#c62828",
    pending="#3554d1",
    revoked="#6b7280",
    failed="#c62828",
    info_bg="#e8efff",
    warn_bg="#fff4e0",
    danger_bg="#fde8e8",
)

DARK = Tokens(
    dark=True,
    window="#16181c",
    surface="#1f2227",
    surface_alt="#252930",
    sidebar="#1a1d21",
    border="#30353d",
    text="#e7e9ec",
    muted="#9aa3af",
    accent="#7b93ff",
    accent_text="#0f1220",
    accent_soft="#262f52",
    selection="#2c3a6e",
    valid="#4ade80",
    expiring="#fbbf24",
    expired="#f87171",
    pending="#93a8ff",
    revoked="#9ca3af",
    failed="#f87171",
    info_bg="#1e2747",
    warn_bg="#3a2e12",
    danger_bg="#3d1b1d",
)

_current: Tokens = LIGHT


def tokens() -> Tokens:
    return _current


def system_is_dark() -> bool:
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is not None:
        try:
            return scheme() == Qt.ColorScheme.Dark
        except Exception:  # noqa: BLE001 - very old Qt
            pass
    palette = QGuiApplication.palette()
    return palette.color(QPalette.ColorRole.Window).lightness() < 128


def resolve(appearance: str) -> Tokens:
    if appearance == "dark":
        return DARK
    if appearance == "light":
        return LIGHT
    return DARK if system_is_dark() else LIGHT


def status_color(health: str) -> str:
    t = tokens()
    return {
        "valid": t.valid,
        "expiring": t.expiring,
        "expired": t.expired,
        "pending": t.pending,
        "revoked": t.revoked,
        "failed": t.failed,
    }.get(health, t.muted)


def _palette(t: Tokens) -> QPalette:
    palette = QPalette()
    role = QPalette.ColorRole
    group = QPalette.ColorGroup
    palette.setColor(role.Window, QColor(t.window))
    palette.setColor(role.WindowText, QColor(t.text))
    palette.setColor(role.Base, QColor(t.surface))
    palette.setColor(role.AlternateBase, QColor(t.surface_alt))
    palette.setColor(role.ToolTipBase, QColor(t.surface))
    palette.setColor(role.ToolTipText, QColor(t.text))
    palette.setColor(role.PlaceholderText, QColor(t.muted))
    palette.setColor(role.Text, QColor(t.text))
    palette.setColor(role.Button, QColor(t.surface))
    palette.setColor(role.ButtonText, QColor(t.text))
    palette.setColor(role.BrightText, QColor(t.expired))
    palette.setColor(role.Highlight, QColor(t.accent))
    palette.setColor(role.HighlightedText, QColor(t.accent_text))
    palette.setColor(role.Link, QColor(t.accent))
    palette.setColor(role.Mid, QColor(t.border))
    palette.setColor(role.Midlight, QColor(t.surface_alt))
    palette.setColor(role.Dark, QColor(t.border))
    palette.setColor(role.Light, QColor(t.surface))
    palette.setColor(role.Shadow, QColor("#000000"))
    for disabled_role in (role.WindowText, role.Text, role.ButtonText):
        palette.setColor(group.Disabled, disabled_role, QColor(t.muted))
    return palette


def _arrow_image(color: str) -> str:
    """Write a small chevron SVG for combo boxes and return its path (style sheets need a file)."""
    from pathlib import Path

    from PySide6.QtCore import QStandardPaths

    base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.CacheLocation) or ""
    directory = Path(base or Path.home() / ".cache" / "pycert")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"chevron-{color.lstrip('#')}.svg"
        if not path.exists():
            path.write_text(
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
                f'stroke="{color}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
                '<path d="M6 9l6 6 6-6"/></svg>'
            )
        return path.as_posix()
    except OSError:  # pragma: no cover - read-only home; fall back to Qt's arrow
        return ""


def stylesheet(t: Tokens) -> str:
    arrow = _arrow_image(t.muted)
    arrow_rule = (
        f"QComboBox::down-arrow {{ image: url({arrow}); width: 12px; height: 12px; }}" if arrow else ""
    )
    return arrow_rule + f"""
    QComboBox::drop-down {{ border: none; width: 26px; subcontrol-origin: padding; subcontrol-position: center right; }}
    QComboBox QAbstractItemView {{ background: {t.surface}; border: 1px solid {t.border}; selection-background-color: {t.accent_soft}; selection-color: {t.text}; outline: 0; }}
    QWidget {{ font-size: 13px; }}
    QToolTip {{ background: {t.surface}; color: {t.text}; border: 1px solid {t.border}; padding: 6px; border-radius: 6px; }}
    QMainWindow, QDialog {{ background: {t.window}; }}
    QFrame#Sidebar {{ background: {t.sidebar}; border-right: 1px solid {t.border}; }}
    QLabel#AppTitle {{ font-size: 17px; font-weight: 700; }}
    QLabel#AppSubtitle, QLabel[muted="true"] {{ color: {t.muted}; }}
    QLabel#SectionLabel {{ color: {t.muted}; font-size: 11px; font-weight: 700; letter-spacing: 1px; padding: 10px 12px 4px 12px; }}
    QLabel#PageTitle {{ font-size: 22px; font-weight: 700; }}
    QLabel#DetailTitle {{ font-size: 19px; font-weight: 700; }}
    QLabel#CardValue {{ font-size: 26px; font-weight: 700; }}
    QLabel#CardLabel {{ color: {t.muted}; font-size: 12px; }}
    QListWidget#Nav {{ background: transparent; border: none; outline: 0; }}
    QListWidget#Nav::item {{ padding: 7px 10px; margin: 1px 8px; border-radius: 7px; color: {t.text}; }}
    QListWidget#Nav::item:selected {{ background: {t.accent_soft}; color: {t.accent}; font-weight: 600; }}
    QListWidget#Nav::item:hover:!selected {{ background: {t.surface_alt}; }}
    QFrame#Card {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px; }}
    QFrame#Card:hover {{ border-color: {t.accent}; }}
    QFrame#Panel {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px; }}
    QFrame#Banner {{ border-radius: 10px; }}
    QFrame#Banner[kind="info"] {{ background: {t.info_bg}; }}
    QFrame#Banner[kind="warning"] {{ background: {t.warn_bg}; }}
    QFrame#Banner[kind="danger"] {{ background: {t.danger_bg}; }}
    QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QComboBox {{
        background: {t.surface}; border: 1px solid {t.border}; border-radius: 7px; padding: 5px 8px;
        selection-background-color: {t.accent}; selection-color: {t.accent_text};
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {{ border: 1px solid {t.accent}; }}
    QLineEdit#Search {{ border-radius: 16px; padding: 6px 12px; min-width: 240px; }}
    QPushButton {{
        background: {t.surface}; border: 1px solid {t.border}; border-radius: 7px; padding: 6px 14px; color: {t.text};
    }}
    QPushButton:hover {{ border-color: {t.accent}; }}
    QPushButton:pressed {{ background: {t.surface_alt}; }}
    QPushButton:disabled {{ color: {t.muted}; background: {t.surface_alt}; }}
    QPushButton[primary="true"] {{ background: {t.accent}; color: {t.accent_text}; border: 1px solid {t.accent}; font-weight: 600; }}
    QPushButton[primary="true"]:hover {{ background: {t.accent}; border-color: {t.text}; }}
    QPushButton[danger="true"] {{ color: {t.expired}; }}
    QPushButton[flat="true"] {{ border: none; background: transparent; padding: 4px 8px; }}
    QPushButton[flat="true"]:hover {{ background: {t.surface_alt}; }}
    QToolButton {{ border: none; border-radius: 7px; padding: 5px 8px; }}
    QToolButton:hover {{ background: {t.surface_alt}; }}
    QToolBar {{ background: {t.window}; border: none; border-bottom: 1px solid {t.border}; padding: 4px 8px; spacing: 4px; }}
    QTableView {{
        background: {t.surface}; alternate-background-color: {t.surface_alt}; border: 1px solid {t.border};
        border-radius: 12px; gridline-color: transparent; selection-background-color: {t.selection};
        selection-color: {t.text}; outline: 0;
    }}
    QTableView::item {{ padding: 4px 6px; border: none; }}
    QHeaderView::section {{
        background: {t.surface}; color: {t.muted}; border: none; border-bottom: 1px solid {t.border};
        padding: 8px 6px; font-weight: 600; font-size: 12px;
    }}
    QTreeWidget, QListWidget {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 10px; }}
    QTabWidget::pane {{ border: none; }}
    QTabBar::tab {{ background: transparent; color: {t.muted}; padding: 8px 12px; border: none; border-bottom: 2px solid transparent; }}
    QTabBar::tab:selected {{ color: {t.text}; border-bottom: 2px solid {t.accent}; font-weight: 600; }}
    QTabBar::tab:hover:!selected {{ color: {t.text}; }}
    QProgressBar {{ background: {t.surface_alt}; border: none; border-radius: 4px; height: 8px; text-align: center; }}
    QProgressBar::chunk {{ background: {t.accent}; border-radius: 4px; }}
    QSplitter::handle {{ background: transparent; }}
    QScrollArea {{ border: none; background: transparent; }}
    QStatusBar {{ background: {t.window}; border-top: 1px solid {t.border}; color: {t.muted}; }}
    QDockWidget {{ titlebar-close-icon: none; }}
    QDockWidget::title {{ background: {t.window}; padding: 6px; border-top: 1px solid {t.border}; }}
    QMenu {{ background: {t.surface}; border: 1px solid {t.border}; padding: 4px; border-radius: 8px; }}
    QMenu::item {{ padding: 6px 18px; border-radius: 5px; }}
    QMenu::item:selected {{ background: {t.accent_soft}; color: {t.text}; }}
    QGroupBox {{ border: 1px solid {t.border}; border-radius: 10px; margin-top: 14px; padding: 10px; }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {t.muted}; font-weight: 600; }}
    """


_applied: "Tokens | None" = None


def apply(appearance: str) -> Tokens:
    """Apply *appearance* (system/light/dark) to the running application.

    Re-applying the same palette is a no-op: re-polishing every widget is
    expensive and can race with widgets that are being deleted.
    """
    global _current, _applied
    app = QApplication.instance()
    _current = resolve(appearance)
    if app is None:  # pragma: no cover - only called with an application
        return _current
    if _applied is _current:
        return _current
    if app.style().objectName().lower() != "fusion":
        app.setStyle("Fusion")
    app.setPalette(_palette(_current))
    app.setStyleSheet(stylesheet(_current))
    _applied = _current
    return _current
