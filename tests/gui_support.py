"""Helpers for the Qt GUI tests (fixtures live in conftest.py)."""


def wait_idle(qtbot, main, timeout=30000):
    qtbot.waitUntil(lambda: not main.runner.busy, timeout=timeout)


def walk_menu(menu, found):
    """Every leaf action of *menu* (a menu bar or a menu) and its submenus, except Quit.

    Submenus are found with findChildren(): on PySide6 before 6.12,
    QAction.menu() hands the submenu's ownership to Python, so the temporary
    wrapper deletes the real menu (and its actions) when it is collected.
    """
    import shiboken6
    from PySide6.QtWidgets import QMenu

    menus = ([menu] if isinstance(menu, QMenu) else []) + menu.findChildren(QMenu)
    submenu_actions = {shiboken6.getCppPointer(m.menuAction())[0] for m in menus}
    for current in [menu, *menus] if not isinstance(menu, QMenu) else menus:
        for action in current.actions():
            if shiboken6.getCppPointer(action)[0] in submenu_actions:
                continue
            if action.isSeparator() or not action.text() or "Quit" in action.text() or action in found:
                continue
            found.append(action)
    return found


def close_popup_soon() -> None:
    """Close the next popup menu once it is open, so a real QMenu.exec returns."""
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    def close():
        popup = QApplication.activePopupWidget()
        if popup is not None:
            popup.close()
        else:
            QTimer.singleShot(20, close)

    QTimer.singleShot(20, close)
