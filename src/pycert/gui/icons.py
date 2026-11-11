"""A small, self-contained line-icon set rendered from inline SVG.

The icons are drawn on a 24x24 grid with a 1.8 px round stroke so they match
in weight; ``icon(name, color)`` recolours them for the current theme and
caches the result.  No icon font or external resource is needed.
"""

from functools import lru_cache

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from . import theme

_PATHS: "dict[str, str]" = {
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "refresh": '<path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v5h-5"/>',
    "download": '<path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/>',
    "export": '<path d="M12 15V4"/><path d="M7 9l5-5 5 5"/><path d="M5 20h14"/>',
    "verify": '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16.5 9.5"/>',
    "shield": '<path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.4-7.5 9.9-4.4-1.5-7.5-5.3-7.5-9.9V6z"/>',
    "shield-check": '<path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.4-7.5 9.9-4.4-1.5-7.5-5.3-7.5-9.9V6z"/><path d="M8.8 12.2l2.3 2.3 4.3-4.6"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5c.8-3.9 3.9-6.3 7.5-6.3s6.7 2.4 7.5 6.3"/>',
    "server": '<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01M11 7.5h5M11 16.5h5"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12l8.5-8.5"/><path d="M16.5 6.5l2.5 2.5"/><path d="M14 9l2 2"/>',
    "chain": '<path d="M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1.2 1.2"/><path d="M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1.2-1.2"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.2 2"/>',
    "alert": '<path d="M12 3.5l9.5 16.5h-19z"/><path d="M12 10v4.5M12 17.3h.01"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8h.01"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
    "deploy": '<path d="M21 3L10.5 13.5"/><path d="M21 3l-6.5 18-4-7.5-7.5-4z"/>',
    "bell": '<path d="M6 9a6 6 0 0 1 12 0c0 6.5 2.5 8.5 2.5 8.5h-17S6 15.5 6 9z"/><path d="M10 20.5a2.2 2.2 0 0 0 4 0"/>',
    "copy": '<rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5"/>',
    "trash": '<path d="M4 7h16M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/>',
    "folder": '<path d="M3.5 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
    "settings": '<path d="M4 6.5h9M17 6.5h3M4 12h3M11 12h9M4 17.5h11M19 17.5h1"/><circle cx="15" cy="6.5" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="17.5" r="2"/>',
    "revoke": '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
    "renew": '<path d="M3.5 12a8.5 8.5 0 0 1 14.6-5.9L20.5 8.5"/><path d="M20.5 3.5v5h-5"/><path d="M20.5 12a8.5 8.5 0 0 1-14.6 5.9L3.5 15.5"/><path d="M3.5 20.5v-5h5"/>',
    "dashboard": '<rect x="3.5" y="3.5" width="7" height="8" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="5" rx="1.5"/><rect x="13.5" y="11.5" width="7" height="9" rx="1.5"/><rect x="3.5" y="14.5" width="7" height="6" rx="1.5"/>',
    "list": '<path d="M8.5 6.5h12M8.5 12h12M8.5 17.5h12M4 6.5h.01M4 12h.01M4 17.5h.01"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.6 2.6 3.8 5.6 3.8 9s-1.2 6.4-3.8 9c-2.6-2.6-3.8-5.6-3.8-9s1.2-6.4 3.8-9z"/>',
    "package": '<path d="M20.5 7.5L12 3 3.5 7.5v9L12 21l8.5-4.5z"/><path d="M3.5 7.5L12 12l8.5-4.5M12 12v9"/>',
    "activity": '<path d="M3 12h4l2.5-7 5 14 2.5-7h4"/>',
    "import": '<path d="M14 3.5H6.5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V9z"/><path d="M14 3.5V9h5.5"/><path d="M12 11.5v6M9.2 14.8L12 17.6l2.8-2.8"/>',
    "close": '<path d="M6 6l12 12M18 6L6 18"/>',
    "play": '<path d="M7.5 4.5l12 7.5-12 7.5z"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
    "edit": '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
    "terminal": '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5"/>',
    "award": '<circle cx="12" cy="9" r="5.5"/><path d="M8.8 13.6L7.5 21l4.5-2.6 4.5 2.6-1.3-7.4"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "chevron-down": '<path d="M6 9l6 6 6-6"/>',
    "more": '<path d="M5.5 12h.01M12 12h.01M18.5 12h.01"/>',
    "lock": '<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    "eye": '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
}

ICON_NAMES = tuple(sorted(_PATHS))


def svg(name: str, color: str, stroke_width: float = 1.8) -> bytes:
    body = _PATHS[name]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round">'
        f"{body}</svg>"
    ).encode()


def pixmap(name: str, color: str, size: int = 20, ratio: float = 2.0) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg(name, color)))
    image = QPixmap(int(size * ratio), int(size * ratio))
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size * ratio, size * ratio))
    painter.end()
    image.setDevicePixelRatio(ratio)
    return image


@lru_cache(maxsize=512)
def _icon(name: str, color: str, disabled: str) -> QIcon:
    result = QIcon()
    for size in (16, 20, 24, 32, 48):
        result.addPixmap(pixmap(name, color, size), QIcon.Mode.Normal)
        result.addPixmap(pixmap(name, disabled, size), QIcon.Mode.Disabled)
    return result


def icon(name: str, color: "str | None" = None) -> QIcon:
    """A themed icon (default colour: the theme's text colour)."""
    t = theme.tokens()
    return _icon(name, color or t.text, t.muted)


_tracked: "list[tuple[object, str, str]]" = []


def _role_color(role: str) -> str:
    t = theme.tokens()
    value = getattr(t, role, None)
    return value if isinstance(value, str) else t.text


def themed(target, name: str, role: str = "text") -> None:
    """Set an icon on a widget or action and re-colour it whenever the theme changes."""
    target.setIcon(icon(name, _role_color(role)))
    _tracked.append((target, name, role))


def refresh_themed() -> None:
    """Re-apply every tracked icon in the current theme's colours."""
    import shiboken6

    alive = []
    for target, name, role in _tracked:
        if shiboken6.isValid(target):
            target.setIcon(icon(name, _role_color(role)))
            alive.append((target, name, role))
    _tracked[:] = alive


def app_icon() -> QIcon:
    """The application icon: a filled shield with a check mark."""
    accent = "#3554d1"
    body = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        f'<path d="M32 4l22 8.5v15.5c0 13.6-9.2 24.6-22 29-12.8-4.4-22-15.4-22-29V12.5z" fill="{accent}"/>'
        '<path d="M22.5 32.5l7 7 13-14" fill="none" stroke="#ffffff" stroke-width="5" '
        'stroke-linecap="round" stroke-linejoin="round"/></svg>'
    ).encode()
    renderer = QSvgRenderer(QByteArray(body))
    result = QIcon()
    for size in (16, 32, 64, 128, 256):
        image = QPixmap(size, size)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        renderer.render(painter, QRectF(0, 0, size, size))
        painter.end()
        result.addPixmap(image)
    return result
