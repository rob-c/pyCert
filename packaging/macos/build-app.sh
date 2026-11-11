#!/bin/bash
# Build pyCertWiz.app and a .dmg for this Mac's architecture.
#
#   packaging/macos/build-app.sh            # -> dist/pyCertWiz-<version>-macos-<arch>.dmg
#
# The app is signed ad hoc, which is enough to run it locally and to test it in
# CI. For distribution, sign and notarize it with packaging/macos/sign-and-notarize.sh.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=$ROOT/build/macos
DIST=$ROOT/dist
PYTHON=${PYTHON:-python3}
ARCH=$(uname -m)

rm -rf "$BUILD" && mkdir -p "$BUILD" "$DIST"
"$PYTHON" -m venv "$BUILD/venv"
"$BUILD/venv/bin/python" -m pip install --quiet --upgrade pip
"$BUILD/venv/bin/python" -m pip install --quiet "pyinstaller>=6.10" "$ROOT[gui,keyring]"
VERSION=$("$BUILD/venv/bin/python" -c 'from importlib.metadata import version; print(version("pyCertWiz"))')

QT_QPA_PLATFORM=offscreen "$BUILD/venv/bin/python" "$ROOT/packaging/make_icons.py" "$BUILD/icons"
PYCERTWIZ_ICNS="$BUILD/icons/pyCertWiz.icns" "$BUILD/venv/bin/pyinstaller" --noconfirm --clean \
    "$ROOT/packaging/pycertwiz.spec" --distpath "$BUILD/dist" --workpath "$BUILD/work"
APP=$BUILD/dist/pyCertWiz.app
codesign --force --deep --sign - "$APP"

# The app must run before it is packaged.
"$APP/Contents/MacOS/pyCertWiz" --version
"$APP/Contents/MacOS/pyCertWiz" selftest

stage=$BUILD/dmg
mkdir -p "$stage"
cp -R "$APP" "$stage/"
ln -s /Applications "$stage/Applications"
DMG=$DIST/pyCertWiz-$VERSION-macos-$ARCH.dmg
hdiutil create -quiet -volname "pyCertWiz $VERSION" -srcfolder "$stage" -ov -format UDZO "$DMG"
echo "built $DMG"
