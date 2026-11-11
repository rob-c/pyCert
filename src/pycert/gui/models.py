"""Table model, filter proxy and painted delegates for the certificate list."""

from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QRect, QRectF, QSize, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionViewItem

from .. import monitor
from ..store import RequestState
from . import icons, theme

COLUMNS = ("Certificate", "Type", "CA", "Status", "Expires", "Days left", "Deploy")
COL_NAME, COL_TYPE, COL_CA, COL_STATUS, COL_EXPIRES, COL_DAYS, COL_DEPLOY = range(len(COLUMNS))

StateRole = Qt.ItemDataRole.UserRole + 1
HealthRole = Qt.ItemDataRole.UserRole + 2
DaysRole = Qt.ItemDataRole.UserRole + 3
LifetimeRole = Qt.ItemDataRole.UserRole + 4
SortRole = Qt.ItemDataRole.UserRole + 5
SubtitleRole = Qt.ItemDataRole.UserRole + 6

HEALTH_LABELS = {
    "valid": "Valid",
    "expiring": "Expiring",
    "expired": "Expired",
    "pending": "Pending",
    "revoked": "Revoked",
    "failed": "Failed",
}
#: Category -> sort weight (most urgent first)
HEALTH_ORDER = {"expired": 0, "failed": 1, "expiring": 2, "pending": 3, "valid": 4, "revoked": 5}


@dataclass
class Row:
    state: RequestState
    category: str
    message: str
    level: str
    ca_label: str
    lifetime_days: "int | None"
    ca_name: str = ""


def _lifetime(state: RequestState) -> "int | None":
    from ..util import parse_iso

    if not state.cert.not_before or not state.cert.not_after:
        return None
    try:
        return max(1, (parse_iso(state.cert.not_after) - parse_iso(state.cert.not_before)).days)
    except ValueError:  # pragma: no cover - corrupt dates
        return None


def build_rows(ctx: Any, states: "list[RequestState]", warn_days: int = 30, crit_days: int = 7) -> "list[Row]":
    rows = []
    for state in states:
        category, findings = monitor.evaluate(ctx, state, warn_days=warn_days, crit_days=crit_days)
        severity = {"OK": 0, "WARNING": 1, "UNKNOWN": 2, "CRITICAL": 3}
        worst = max(findings, key=lambda f: severity.get(f.level, 0)) if findings else None
        try:
            ca_label = ctx.profile(state.ca).display_name
        except Exception:  # noqa: BLE001 - a profile removed from the configuration
            ca_label = f"{state.ca} (not configured)"
        rows.append(
            Row(
                state=state,
                category=category,
                message=worst.message if worst else "",
                level=worst.level if worst else "OK",
                ca_label=ca_label,
                lifetime_days=_lifetime(state),
                ca_name=state.ca or ctx.config.primary_profile.name,
            )
        )
    return rows


class CertificateModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: "list[Row]" = []

    def set_rows(self, rows: "list[Row]") -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def row_for_alias(self, alias: str) -> int:
        for index, row in enumerate(self.rows):
            if row.state.alias == alias:
                return index
        return -1

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.rows):
            return None
        row = self.rows[index.row()]
        state = row.state
        column = index.column()
        if role == StateRole:
            return state
        if role == HealthRole:
            return row.category
        if role == DaysRole:
            return state.days_remaining
        if role == LifetimeRole:
            return row.lifetime_days
        if role == SubtitleRole:
            parts = [state.cn if state.cn != state.alias else ""]
            if state.description:
                parts.append(state.description)
            return " · ".join(p for p in parts if p)
        if role == Qt.ItemDataRole.ToolTipRole:
            tip = f"{state.alias}\n{state.status}"
            if state.cert.not_after:
                tip += f"\nexpires {state.cert.not_after[:10]}"
            if row.message:
                tip += f"\n{row.message}"
            return tip
        if role == SortRole:
            if column == COL_NAME:
                return state.alias.lower()
            if column == COL_STATUS:
                return HEALTH_ORDER.get(row.category, 9)
            if column in (COL_EXPIRES, COL_DAYS):
                return state.days_remaining if state.days_remaining is not None else 10**6
            if column == COL_DEPLOY:
                return len(state.deploy)
        if role == Qt.ItemDataRole.DecorationRole and column == COL_NAME:
            return icons.icon("server" if state.type == "host" else "user", theme.status_color(row.category))
        if role == Qt.ItemDataRole.DisplayRole or role == SortRole:
            if column == COL_NAME:
                return state.alias
            if column == COL_TYPE:
                return "Host" if state.type == "host" else "User"
            if column == COL_CA:
                return row.ca_label
            if column == COL_STATUS:
                label = HEALTH_LABELS.get(row.category, state.status.title())
                if state.renewal and row.category != "pending":
                    label += " · renewing"
                return label
            if column == COL_EXPIRES:
                return state.cert.not_after[:10] if state.cert.not_after else "—"
            if column == COL_DAYS:
                return "" if state.days_remaining is None else str(state.days_remaining)
            if column == COL_DEPLOY:
                if not state.deploy:
                    return "—"
                failed = sum(1 for t in state.deploy if t.get("last_error"))
                if failed:
                    return f"{failed} failed"
                return f"{len(state.deploy)} target" + ("s" if len(state.deploy) != 1 else "")
        if role == Qt.ItemDataRole.ForegroundRole and column == COL_DEPLOY:
            if any(t.get("last_error") for t in state.deploy):
                return QColor(theme.tokens().expired)
            return QColor(theme.tokens().muted)
        if role == Qt.ItemDataRole.ForegroundRole and column in (COL_TYPE, COL_CA, COL_EXPIRES):
            return QColor(theme.tokens().muted)
        return None


class CertificateFilter(QSortFilterProxyModel):
    """Text search plus type / CA / health filters."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.text = ""
        self.cert_type = ""
        self.ca = ""
        self.categories: "set[str]" = set()
        self.keystore = ""
        self.setSortRole(SortRole)
        self.setDynamicSortFilter(True)

    def _change(self, apply) -> None:
        # Qt 6.10 replaced invalidateFilter() with begin/endFilterChange(). Qt 6.9
        # already has beginFilterChange() but not endFilterChange(), so require both.
        begin = getattr(self, "beginFilterChange", None)
        end = getattr(self, "endFilterChange", None)
        if begin is not None and end is not None:
            begin()
            apply()
            end()
        else:  # pragma: no cover - Qt < 6.10 (exercised in the AlmaLinux 8 container)
            apply()
            self.invalidateFilter()

    def set_text(self, text: str) -> None:
        def apply():
            self.text = text.strip().lower()

        self._change(apply)

    def set_view(
        self, *, cert_type: str = "", ca: str = "", categories: "set[str] | None" = None, keystore: str = ""
    ) -> None:
        def apply():
            self.cert_type = cert_type
            self.ca = ca
            self.categories = set(categories or ())
            self.keystore = keystore

        self._change(apply)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        row: Row = model.rows[source_row]
        state = row.state
        if self.cert_type and state.type != self.cert_type:
            return False
        if self.ca and row.ca_name != self.ca:
            return False
        if self.categories and row.category not in self.categories:
            return False
        if self.keystore and state.keystore.get("name") != self.keystore:
            return False
        if self.text:
            haystack = " ".join(
                [state.alias, state.cn, state.description, row.ca_label, state.status, state.keystore.get("name", ""), *state.cert.sans]
            ).lower()
            return all(word in haystack for word in self.text.split())
        return True


# ---------------------------------------------------------------------------
# Delegates
# ---------------------------------------------------------------------------


class NameDelegate(QStyledItemDelegate):
    """Bold alias with a muted subtitle (common name / description) and a type icon."""

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        return QSize(260, 46)

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        self.initStyleOption(option, index)
        painter.save()
        style = option.widget.style() if option.widget else None
        option_text = option.text
        option.text = ""
        option.icon = type(option.icon)()
        if style:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        option.text = option_text
        t = theme.tokens()
        rect = option.rect.adjusted(10, 0, -6, 0)
        decoration = index.data(Qt.ItemDataRole.DecorationRole)
        if decoration is not None:
            decoration.paint(painter, QRect(rect.left(), rect.center().y() - 10, 20, 20))
        text_left = rect.left() + 30
        subtitle = index.data(SubtitleRole) or ""
        title_font = QFont(option.font)
        title_font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(title_font)
        painter.setPen(QColor(t.text))
        if subtitle:
            title_rect = QRect(text_left, rect.top() + 5, rect.width() - 30, rect.height() // 2 - 2)
            sub_rect = QRect(text_left, rect.center().y() + 1, rect.width() - 30, rect.height() // 2 - 6)
            painter.drawText(title_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                             painter.fontMetrics().elidedText(option_text, Qt.TextElideMode.ElideRight, title_rect.width()))
            small = QFont(option.font)
            small.setPointSizeF(max(8.0, option.font.pointSizeF() - 1.5))
            painter.setFont(small)
            painter.setPen(QColor(t.muted))
            painter.drawText(sub_rect, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
                             painter.fontMetrics().elidedText(subtitle, Qt.TextElideMode.ElideRight, sub_rect.width()))
        else:
            title_rect = QRect(text_left, rect.top(), rect.width() - 30, rect.height())
            painter.drawText(title_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                             painter.fontMetrics().elidedText(option_text, Qt.TextElideMode.ElideRight, title_rect.width()))
        painter.restore()


class StatusPillDelegate(QStyledItemDelegate):
    """A rounded, colour-coded status label (colour is never the only signal)."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        self.initStyleOption(option, index)
        text = option.text
        option.text = ""
        style = option.widget.style() if option.widget else None
        if style:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        health = index.data(HealthRole) or ""
        color = QColor(theme.status_color(health))
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont(option.font)
        font.setWeight(QFont.Weight.DemiBold)
        font.setPointSizeF(max(8.0, option.font.pointSizeF() - 1))
        painter.setFont(font)
        metrics = painter.fontMetrics()
        width = metrics.horizontalAdvance(text) + 24
        height = metrics.height() + 6
        rect = QRectF(option.rect.left() + 6, option.rect.center().y() - height / 2, width, height)
        fill = QColor(color)
        fill.setAlphaF(0.16)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, height / 2, height / 2)
        painter.setBrush(color)
        painter.drawEllipse(QRectF(rect.left() + 8, rect.center().y() - 3, 6, 6))
        painter.setPen(color)
        painter.drawText(rect.adjusted(18, 0, -4, 0), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, text)
        painter.restore()


class DaysDelegate(QStyledItemDelegate):
    """Days remaining as a number plus a slim bar of the remaining lifetime."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        self.initStyleOption(option, index)
        option.text = ""
        style = option.widget.style() if option.widget else None
        if style:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        days = index.data(DaysRole)
        if days is None:
            return
        lifetime = index.data(LifetimeRole) or 365
        health = index.data(HealthRole) or "valid"
        color = QColor(theme.status_color(health))
        t = theme.tokens()
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = option.rect.adjusted(8, 0, -10, 0)
        painter.setPen(QColor(t.text))
        number_rect = QRect(rect.left(), rect.top(), 44, rect.height())
        painter.drawText(number_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, str(days))
        bar = QRectF(number_rect.right() + 8, rect.center().y() - 3, max(20, rect.width() - 56), 6)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(t.surface_alt if not t.dark else t.border))
        painter.drawRoundedRect(bar, 3, 3)
        fraction = max(0.0, min(1.0, days / float(lifetime))) if days > 0 else 0.0
        if fraction > 0:
            filled = QRectF(bar.left(), bar.top(), max(6.0, bar.width() * fraction), bar.height())
            painter.setBrush(color)
            painter.drawRoundedRect(filled, 3, 3)
        painter.setPen(QPen(color))
        painter.restore()
