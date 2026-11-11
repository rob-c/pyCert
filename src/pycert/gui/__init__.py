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

__all__ = ["gui_available", "main", "run_gui"]

INSTALL_HINT = "install the GUI extra: pip install 'pyCertWiz[gui]' (PySide6)"
#: In a packaged pyCertWiz (AppImage, .deb, .rpm, macOS app) Qt is bundled; what
#: can be missing are the system libraries it loads.
BUNDLED_HINT = (
    "install the desktop libraries Qt needs: EGL/OpenGL, xkbcommon-x11, fontconfig, D-Bus and "
    "xcb-util-cursor (e.g. 'apt install libegl1 libxkbcommon-x11-0 libxcb-cursor0' or "
    "'dnf install mesa-libEGL libxkbcommon-x11 xcb-util-cursor'). The pycertwiz command line works without them"
)


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
