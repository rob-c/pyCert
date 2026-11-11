# PyInstaller spec: a one-folder bundle of pyCertWiz (Linux), or pyCertWiz.app (macOS).
#
#   pyinstaller packaging/pycertwiz.spec --distpath build/dist --workpath build/work
#
# Environment: PYCERTWIZ_ICNS (macOS icon), PYCERTWIZ_TARGET_ARCH (macOS: arm64,
# x86_64 or universal2).
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
sys.path.insert(0, str(ROOT / "src"))
from pycert import __version__  # noqa: E402

datas = collect_data_files("pycert") + copy_metadata("pyCertWiz")
hiddenimports = collect_submodules("pycert")
try:  # the keyring secret backend is optional
    datas += copy_metadata("keyring")
    hiddenimports += collect_submodules("keyring.backends")
except Exception:  # noqa: BLE001
    pass

a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT / "src")],
    datas=datas,
    hiddenimports=hiddenimports,
    # pyCertWiz uses QtCore, QtGui, QtWidgets and QtSvg only.
    excludes=[
        "tkinter",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.QtQuickWidgets",
        "PySide6.QtNetwork",
        "PySide6.QtPdf",
        "PySide6.QtWebEngineCore",
        "PySide6.QtMultimedia",
        "PySide6.QtSql",
        "PySide6.QtTest",
        "PySide6.Qt3DCore",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="pyCertWiz",
    console=sys.platform != "darwin",
    target_arch=os.environ.get("PYCERTWIZ_TARGET_ARCH") or None,
    codesign_identity=None,  # signed afterwards (ad hoc in CI, Developer ID locally)
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, name="pyCertWiz")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="pyCertWiz.app",
        icon=os.environ.get("PYCERTWIZ_ICNS") or None,
        bundle_identifier="io.github.rob-c.pycertwiz",
        version=__version__,
        info_plist={
            "CFBundleName": "pyCertWiz",
            "CFBundleDisplayName": "pyCertWiz",
            "CFBundleShortVersionString": __version__,
            "CFBundleVersion": __version__,
            "LSMinimumSystemVersion": "12.0",
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,
            "NSHumanReadableCopyright": "GPL-2.0-or-later",
        },
    )
