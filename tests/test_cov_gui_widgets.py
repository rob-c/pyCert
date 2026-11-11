"""Qt GUI coverage: the detail panel and small widgets, the certificate model and
its delegates, the theme helpers and the preference accessors.

Run with ``QT_QPA_PLATFORM=offscreen`` like the other GUI tests.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from PySide6.QtCore import QModelIndex, QRect, QSize, Qt  # noqa: E402
from PySide6.QtGui import QImage, QPainter, QStandardItem, QStandardItemModel  # noqa: E402
from PySide6.QtWidgets import QApplication, QStyleOptionViewItem  # noqa: E402

from pycert import certs  # noqa: E402
from pycert.store import CertInfo, RequestState  # noqa: E402
from pycert.util import iso  # noqa: E402

pytestmark = pytest.mark.usefixtures("gui_env")


def _certificate(attributes, *, days=(-1, 30)):
    """A small self-signed EC certificate with the given subject attributes."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(oid, value) for oid, value in attributes])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days[0]))
        .not_valid_after(now + timedelta(days=days[1]))
        .sign(key, hashes.SHA256())
    )


def _when(days: int) -> str:
    return iso(datetime.now(timezone.utc) + timedelta(days=days))


def _state(alias="stored", **changes) -> RequestState:
    cert = changes.pop("cert", CertInfo())
    return RequestState(alias=alias, slug=alias.replace(" ", "_"), type=changes.pop("type", "user"), cn=alias, cert=cert, **changes)


# ---------------------------------------------------------------------------
# Small widgets
# ---------------------------------------------------------------------------


def test_stat_card_reacts_to_the_left_button_only(qtbot):
    from pycert.gui.widgets import StatCard

    card = StatCard("Valid", "verify", "valid")
    qtbot.addWidget(card)
    card.show()
    clicks = []
    card.clicked.connect(lambda: clicks.append("click"))
    qtbot.mouseClick(card, Qt.MouseButton.RightButton)
    assert clicks == []
    qtbot.mouseClick(card, Qt.MouseButton.LeftButton)
    assert clicks == ["click"]
    card.set_value(7)
    assert card.value.text() == "7"


def test_banner_shows_each_kind_with_and_without_an_action(qtbot):
    from pycert.gui.widgets import Banner

    banner = Banner()
    qtbot.addWidget(banner)
    assert banner.isHidden()
    actions = []
    banner.action.connect(lambda: actions.append("action"))
    banner.show_message("warning", "<b>2 certificates</b> expire soon", "Renew now")
    assert not banner.isHidden() and banner.property("kind") == "warning"
    assert banner.text.text() == "<b>2 certificates</b> expire soon"
    assert banner.button.isVisibleTo(banner) and banner.button.text() == "Renew now"
    banner.button.click()
    assert actions == ["action"]
    banner.show_message("info", "Checking the CA")
    assert not banner.button.isVisibleTo(banner)
    banner.show_message("unknown-kind", "plain text")  # an unknown kind falls back to the text colour
    assert banner.property("kind") == "unknown-kind" and not banner.isHidden()


def test_validity_bar_paints_empty_and_partly_filled(qtbot):
    from pycert.gui.widgets import ValidityBar

    bar = ValidityBar()
    qtbot.addWidget(bar)
    bar.resize(200, 10)
    bar.set_values(-3.0, "expired")  # clamped: nothing left to fill
    assert bar.fraction == 0.0
    assert not bar.grab().isNull()
    bar.set_values(7.5, "valid")  # clamped to full
    assert bar.fraction == 1.0
    assert not bar.grab().isNull()


def test_activity_log_and_empty_state(qtbot):
    from pycert.gui.widgets import ActivityLog, EmptyState

    log = ActivityLog()
    qtbot.addWidget(log)
    log.add("collected jane doe")
    assert log.text.toPlainText().endswith("collected jane doe")
    empty = EmptyState()
    qtbot.addWidget(empty)
    requested = []
    empty.request.connect(lambda: requested.append("request"))
    empty.open_bundle.connect(lambda: requested.append("bundle"))
    from PySide6.QtWidgets import QPushButton

    buttons = {b.text(): b for b in empty.findChildren(QPushButton)}
    buttons["Request a certificate"].click()
    buttons["Open Java bundle…"].click()
    assert requested == ["request", "bundle"]


def test_readable_dn_home_relative_and_grouping():
    from pycert.gui import widgets

    assert widgets._readable_dn("") == ""
    assert widgets._readable_dn("C=UK,O=eScience,CN=jane doe") == "CN=jane doe, O=eScience, C=UK"
    assert widgets._readable_dn("CN=x,O=y") == "CN=x, O=y"
    home = str(Path.home())
    assert widgets._home_relative(home + "/certs/a.p12") == "~/certs/a.p12"
    assert widgets._home_relative("/srv/certs/a.p12") == "/srv/certs/a.p12"
    assert widgets._group("abcdef0123") == "abcd ef01 23"
    assert widgets.kind_description("host").startswith("Host certificate")


# ---------------------------------------------------------------------------
# Detail panel
# ---------------------------------------------------------------------------


def test_detail_panel_expired_unverified_with_a_failed_deployment(qtbot, ctx):
    from pycert.gui.widgets import DetailPanel

    panel = DetailPanel()
    qtbot.addWidget(panel)
    home_p12 = str(Path.home() / "pycert-exports" / "old.p12")
    state = _state(
        "old.example.org",
        type="host",
        status="DOWNLOADED",
        cert=CertInfo(
            subject="C=UK,O=eScience,CN=old.example.org",
            issuer="C=UK,O=eScience,CN=Test CA",
            not_before=_when(-400),
            not_after=_when(-5),
            sha256="ab" * 32,
            serial="1f",
            verified=False,
        ),
        p12_path=home_p12,
        deploy=[
            {"name": "web", "cert": "/srv/tls/cert.pem", "key": "/srv/tls/key.pem", "hook": "reload", "last_error": "permission denied"},
            {"name": "backup", "fullchain": "/srv/tls/full.pem", "last_deployed": "2025-01-02T03:04:05Z"},
        ],
        history=[],
    )
    panel.show_state(ctx, state, "expired", "the certificate has expired")
    assert panel.validity_text.text().startswith("Expired ") and "day(s) ago" in panel.validity_text.text()
    assert panel.primary.property("action") == "renew"
    assert panel.fields["verified"].text() == "No" and "color" in panel.fields["verified"].styleSheet()
    assert panel.fields["p12"].text() == "~/pycert-exports/old.p12" and panel.fields["p12"].toolTip() == home_p12
    assert panel.fields["subject"].text() == "CN=old.example.org, O=eScience, C=UK"
    assert panel.history.count() == 1 and panel.history.item(0).text() == "No history yet."
    assert panel.chain_tree.topLevelItem(0).text(0) == "No certificate issued yet"
    from pycert.gui import theme

    failed = panel.deploy_table.item(0, 3)
    assert failed.text() == "FAILED: permission denied" and failed.foreground().color().name() == theme.tokens().expired
    assert panel.deploy_table.item(1, 3).text() == "2025-01-02 03:04"

    # removing a deployment target needs a selected row
    requested = []
    panel.action_requested.connect(requested.append)
    panel.deploy_table.clearSelection()
    panel._remove_target()
    assert requested == []
    panel.deploy_table.selectRow(1)
    panel._remove_target()
    assert requested == ["deploy_remove:backup"]

    # the auto-renew box only reports real changes
    changes = []
    panel.auto_renew_changed.connect(changes.append)
    panel._auto_renew_toggled(state.auto_renew)
    assert changes == []
    panel._auto_renew_toggled(not state.auto_renew)
    assert changes == [not state.auto_renew]


def test_detail_panel_signed_request_from_a_removed_ca(qtbot, ctx):
    from pycert.gui.widgets import DetailPanel

    panel = DetailPanel()
    qtbot.addWidget(panel)
    state = _state("signed person", status="SIGNED", ca="removed-ca")
    state.add_history("SIGNED", "the CA signed it")
    panel.show_state(ctx, state, "pending", "")
    assert panel.capabilities is None
    assert panel.subtitle.text() == "User certificate · removed-ca (not configured)"
    assert panel.primary.property("action") == "download" and panel.primary.text() == "Download && export"
    assert panel.validity.isHidden() and panel.validity_text.text() == "Status SIGNED"
    assert panel.fields["verified"].styleSheet() == ""
    revoke = [a for a in panel.more_menu.actions() if a.text() == "Revoke at the CA…"][0]
    assert not revoke.isEnabled()  # nothing issued yet, even though revocation is allowed
    assert "SIGNED" in panel.history.item(0).text()


def test_detail_panel_without_a_context_and_a_chain_without_common_names(qtbot):
    from pycert.gui.widgets import DetailPanel

    panel = DetailPanel()
    qtbot.addWidget(panel)
    state = _state("nameless")
    panel._auto_renew_toggled(True)  # no certificate shown yet: nothing to report
    panel._render_chain(state)  # no context yet: the tree stays empty
    assert panel.chain_tree.topLevelItemCount() == 0
    leaf = _certificate([(NameOID.ORGANIZATION_NAME, "No CN Org"), (NameOID.COUNTRY_NAME, "UK")])
    panel.ctx = SimpleNamespace(store=SimpleNamespace(load_certificate=lambda _s: leaf, load_chain=lambda _s: []))
    panel._render_chain(state)
    item = panel.chain_tree.topLevelItem(0)
    assert item.text(0) == certs.describe_certificate(leaf).subject  # no CN: the whole subject is shown
    assert "CN=" not in item.text(0)


# ---------------------------------------------------------------------------
# Certificate model, filter and delegates
# ---------------------------------------------------------------------------


def _rows():
    from pycert.gui.models import Row

    valid = _state(
        "Valid Person",
        cert=CertInfo(not_before=_when(-10), not_after=_when(355), sha256="cd" * 32),
        deploy=[
            {"name": "a", "cert": "/srv/a.pem", "last_error": "disk full"},
            {"name": "b", "cert": "/srv/b.pem", "last_error": "disk full"},
            {"name": "c", "cert": "/srv/c.pem"},
        ],
    )
    pending = _state("pending host", type="host", status="SUBMITTED", description="grid front-end")
    return [
        Row(state=valid, category="valid", message="valid for 355 days", level="OK", ca_label="UK CA", lifetime_days=365, ca_name="ukca"),
        Row(state=pending, category="pending", message="", level="OK", ca_label="UK CA", lifetime_days=None, ca_name="ukca"),
    ]


def test_build_rows_labels_a_removed_ca(ctx):
    from pycert.gui.models import build_rows

    rows = build_rows(ctx, [_state("orphan", status="SUBMITTED", ca="removed-ca")])
    assert rows[0].ca_label == "removed-ca (not configured)" and rows[0].ca_name == "removed-ca"
    assert rows[0].lifetime_days is None


def test_model_roles_sorting_and_display(qtbot):
    from pycert.gui import theme
    from pycert.gui.models import (
        COL_CA,
        COL_DAYS,
        COL_DEPLOY,
        COL_EXPIRES,
        COL_NAME,
        COL_STATUS,
        COL_TYPE,
        HEALTH_ORDER,
        CertificateModel,
        SortRole,
    )

    model = CertificateModel()
    model.set_rows(_rows())
    valid, pending = model.rows[0].state, model.rows[1].state
    assert model.row_for_alias("Valid Person") == 0 and model.row_for_alias("nobody") == -1
    assert model.data(QModelIndex()) is None
    assert model.data(model.index(5, 0)) is None  # past the last row
    assert model.data(model.createIndex(0, 99)) is None  # no such column
    assert model.headerData(COL_NAME, Qt.Orientation.Vertical) is None

    def at(row, column, role=Qt.ItemDataRole.DisplayRole):
        return model.data(model.index(row, column), role)

    tip = at(0, COL_NAME, Qt.ItemDataRole.ToolTipRole)
    assert tip.splitlines() == ["Valid Person", "DRAFT", f"expires {valid.cert.not_after[:10]}", "valid for 355 days"]
    assert at(1, COL_NAME, Qt.ItemDataRole.ToolTipRole).splitlines() == ["pending host", "SUBMITTED"]
    # sorting keys
    assert at(0, COL_NAME, SortRole) == "valid person"
    assert at(1, COL_STATUS, SortRole) == HEALTH_ORDER["pending"]
    assert at(0, COL_EXPIRES, SortRole) == valid.days_remaining and at(0, COL_DAYS, SortRole) == valid.days_remaining
    assert at(1, COL_EXPIRES, SortRole) == 10**6 and at(1, COL_DAYS, SortRole) == 10**6
    assert at(0, COL_DEPLOY, SortRole) == 3 and at(1, COL_DEPLOY, SortRole) == 0
    assert at(1, COL_TYPE, SortRole) == "Host"  # no special sort key: the display text
    # display
    assert at(0, COL_CA) == "UK CA"
    assert at(0, COL_EXPIRES) == valid.cert.not_after[:10] and at(1, COL_EXPIRES) == "—"
    assert at(1, COL_DAYS) == ""
    assert at(0, COL_DEPLOY) == "2 failed" and at(1, COL_DEPLOY) == "—"
    assert at(0, COL_DEPLOY, Qt.ItemDataRole.ForegroundRole).name() == theme.tokens().expired
    assert at(1, COL_DEPLOY, Qt.ItemDataRole.ForegroundRole).name() == theme.tokens().muted
    assert at(0, COL_CA, Qt.ItemDataRole.ForegroundRole).name() == theme.tokens().muted
    assert at(0, COL_STATUS, Qt.ItemDataRole.ForegroundRole) is None
    assert pending.description in at(1, COL_NAME, Qt.ItemDataRole.UserRole + 6)


def test_filter_by_ca_and_text(qtbot):
    from pycert.gui.models import CertificateFilter, CertificateModel

    model = CertificateModel()
    model.set_rows(_rows())
    proxy = CertificateFilter()
    proxy.setSourceModel(model)
    assert proxy.rowCount() == 2
    proxy.set_view(ca="another-ca")
    assert proxy.rowCount() == 0
    proxy.set_view(ca="ukca")
    proxy.set_text("grid front")
    assert proxy.rowCount() == 1


def _paint(delegate, index):
    rect = QRect(0, 0, 320, 46)
    image = QImage(rect.width(), rect.height(), QImage.Format.Format_ARGB32)
    image.fill(0)
    painter = QPainter(image)
    option = QStyleOptionViewItem()
    option.rect = rect
    option.font = QApplication.font()
    assert option.widget is None  # painted outside a view: no style to draw the background
    delegate.paint(painter, option, index)
    painter.end()
    return image


def test_delegates_paint_without_a_view(qtbot):
    from pycert.gui.models import (
        DaysDelegate,
        DaysRole,
        HealthRole,
        LifetimeRole,
        NameDelegate,
        StatusPillDelegate,
    )

    model = QStandardItemModel(1, 3)
    name = QStandardItem("no icon, no subtitle")
    model.setItem(0, 0, name)
    status = QStandardItem("Expired")
    status.setData("expired", HealthRole)
    model.setItem(0, 1, status)
    days = QStandardItem()
    days.setData(0, DaysRole)  # expires today: an empty bar
    days.setData(None, LifetimeRole)
    days.setData("expiring", HealthRole)
    model.setItem(0, 2, days)

    delegate = NameDelegate()
    assert delegate.sizeHint(QStyleOptionViewItem(), model.index(0, 0)) == QSize(260, 46)
    assert not _paint(delegate, model.index(0, 0)).isNull()
    assert not _paint(StatusPillDelegate(), model.index(0, 1)).isNull()
    assert not _paint(DaysDelegate(), model.index(0, 2)).isNull()
    days.setData(-4, DaysRole)  # already expired
    assert not _paint(DaysDelegate(), model.index(0, 2)).isNull()


# ---------------------------------------------------------------------------
# Theme helpers
# ---------------------------------------------------------------------------


def test_system_is_dark_without_a_usable_color_scheme(qtbot, monkeypatch):
    from PySide6.QtGui import QGuiApplication, QPalette

    from pycert.gui import theme

    expected = QGuiApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128

    class OldHints:
        """Qt before 6.5: no colorScheme()."""

    class BrokenHints:
        def colorScheme(self):  # noqa: N802 - Qt's name
            raise RuntimeError("not supported by this platform plugin")

    monkeypatch.setattr(QGuiApplication, "styleHints", staticmethod(lambda: OldHints()))
    assert theme.system_is_dark() is expected
    monkeypatch.setattr(QGuiApplication, "styleHints", staticmethod(lambda: BrokenHints()))
    assert theme.system_is_dark() is expected
    assert theme.resolve("system") is (theme.DARK if expected else theme.LIGHT)


def test_arrow_image_is_written_once_into_the_cache(qtbot, monkeypatch, tmp_path):
    from PySide6.QtCore import QStandardPaths

    from pycert.gui import theme

    cache = tmp_path / "cache"
    monkeypatch.setattr(QStandardPaths, "writableLocation", staticmethod(lambda *_a: str(cache)))
    path = Path(theme._arrow_image("#123456"))
    assert path.parent == cache and 'stroke="#123456"' in path.read_text()
    path.write_text("<svg>kept</svg>")
    assert Path(theme._arrow_image("#123456")) == path and path.read_text() == "<svg>kept</svg>"
    # no cache location: falls back to ~/.cache/pycert (a temporary home here)
    monkeypatch.setattr(QStandardPaths, "writableLocation", staticmethod(lambda *_a: ""))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    fallback = Path(theme._arrow_image("#654321"))
    assert fallback.parent == tmp_path / "home" / ".cache" / "pycert" and fallback.is_file()
    assert f"url({fallback.as_posix()})" in theme.stylesheet(theme.Tokens(**{**theme.LIGHT.__dict__, "muted": "#654321"}))


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------


def test_preferences_use_the_platform_store_without_an_override(monkeypatch):
    from pycert.gui import settings as settings_module

    created = []
    # Never touch the real per-user store: record how it would be opened.
    monkeypatch.setattr(settings_module, "QSettings", lambda *args: created.append(args) or "platform store")
    monkeypatch.delenv("PYCERT_GUI_SETTINGS", raising=False)
    assert settings_module.preferences() == "platform store"
    assert created == [(settings_module.ORGANISATION, settings_module.APPLICATION)]


def test_pref_falls_back_on_unreadable_numbers():
    from pycert.gui.settings import pref, preferences

    store = preferences()
    store.setValue("warn_days", "soon")
    store.setValue("notify", "false")
    store.sync()
    assert pref("warn_days", 30) == 30
    assert pref("notify", True) is False
    assert pref("appearance", "system") == "system"
