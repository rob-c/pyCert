"""Entry point of the bundled pyCertWiz (AppImage, .deb/.rpm/Arch packages, macOS app).

One executable serves both uses: started with no arguments (from a desktop
launcher, Finder or a double-click) it opens the GUI; with arguments it is the
`pycertwiz` command line, e.g. `pyCertWiz.AppImage renew --due 30`.
"""

import sys


def main() -> int:
    # Older macOS passes -psn_0_NNN when an app is launched from Finder.
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-psn_")]
    if not args:
        from pycert.gui import main as gui_main

        return gui_main([])
    from pycert.cli import main as cli_main

    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
