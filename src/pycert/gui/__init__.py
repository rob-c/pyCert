"""The pyCertWiz desktop application (Qt / PySide6).

The GUI is a thin front-end: every action calls the same :mod:`pycert.workflow`
functions as the CLI, in a worker thread, so the two cannot drift apart.

PySide6 is an optional dependency (``pip install 'pyCertWiz[gui]'``).  Importing
this package does not import Qt, so the CLI stays fast and works on servers
without a display; :func:`gui_available` explains what is missing.

Security notes:

* PINs are shown once, in a dialog with a copy button, and never logged;
* the PKCS#12 passphrase is only ever handled by the secret store;
* private keys are never displayed, only their algorithm, size and fingerprint.
"""

import os
import sys

__all__ = ["gui_available", "main", "protect_none", "run_gui"]

INSTALL_HINT = "install the GUI extra: pip install 'pyCertWiz[gui]' (PySide6)"
#: In a packaged pyCertWiz (AppImage, .deb, .rpm, macOS app) Qt is bundled; what
#: can be missing are the system libraries it loads.
BUNDLED_HINT = (
    "install the desktop libraries Qt needs: EGL/OpenGL, xkbcommon-x11, fontconfig, D-Bus and "
    "xcb-util-cursor (e.g. 'apt install libegl1 libxkbcommon-x11-0 libxcb-cursor0' or "
    "'dnf install mesa-libEGL libxkbcommon-x11 xcb-util-cursor'). The pycertwiz command line works without them"
)


def _raise_refcount(obj: object, amount: int) -> bool:
    """Add *amount* to *obj*'s CPython reference count, if its layout is the expected one."""
    import ctypes

    cell = ctypes.c_ssize_t.from_address(id(obj))
    # getrefcount() counts its own argument up to Python 3.13, not from 3.14.
    count = sys.getrefcount(obj)
    if cell.value not in (count, count - 1):  # not a layout we know (e.g. a debug build)
        return False
    cell.value += amount
    return True


_none_protected = False


def protect_none() -> bool:
    """Stop PySide6 from wearing out ``None`` on Python 3.10 and 3.11.

    PySide6 (6.8 to 6.12 at least) drops a reference to ``None`` it never took
    each time a model index has no data for a role, which happens many times
    per repaint. Python 3.12 made ``None`` immortal (PEP 683), so the bug goes
    unnoticed there; on 3.10 and 3.11 the count reaches zero after a while and
    the interpreter aborts ("Fatal Python error: none_dealloc"). ``None`` is a
    static object that is never freed, so giving it a very large count, as
    Python 3.12 does, is safe. Returns True when the count was raised.
    """
    global _none_protected
    if _none_protected or sys.version_info >= (3, 12) or sys.implementation.name != "cpython":
        return False
    _none_protected = _raise_refcount(None, 1 << 40)
    return _none_protected


def gui_available() -> "str | None":
    """``None`` when the GUI can start, otherwise a human-readable reason."""
    try:
        import PySide6  # noqa: F401
        from PySide6 import QtWidgets  # noqa: F401
    except ImportError as exc:
        if getattr(sys, "frozen", False):
            return f"the desktop application cannot load Qt ({exc}); {BUNDLED_HINT}"
        return f"the graphical interface needs PySide6 ({exc}); {INSTALL_HINT}"
    if sys.platform.startswith("linux") and not (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.environ.get("QT_QPA_PLATFORM")
    ):
        return "no display is available (DISPLAY/WAYLAND_DISPLAY unset); use the pycert CLI or ssh -X"
    return None


def run_gui(config_path: "str | None" = None, *, argv: "list[str] | None" = None) -> int:
    """Start the application and run the Qt event loop."""
    from .app import run

    return run(config_path, argv=argv)


def main(argv: "list[str] | None" = None) -> int:
    import argparse

    from .. import __version__

    parser = argparse.ArgumentParser(prog="pycert-gui", description="pyCertWiz certificate manager")
    parser.add_argument("--config", help="configuration file to use")
    parser.add_argument("--version", action="version", version=f"pyCertWiz {__version__}")
    parser.add_argument("--check", action="store_true", help="open, render and close the main window (for tests)")
    args, qt_args = parser.parse_known_args(argv)
    problem = gui_available()
    if problem:
        print(f"pycert-gui: {problem}", file=sys.stderr)
        return 1
    if args.check:
        from .app import check

        return check(args.config, argv=[sys.argv[0], *qt_args])
    return run_gui(args.config, argv=[sys.argv[0], *qt_args])
