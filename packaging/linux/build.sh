#!/bin/sh
# Build the pyCertWiz Linux bundle inside an AlmaLinux container, then package it.
#
#   docker run --rm -v "$PWD:/src" -w /src almalinux:8 packaging/linux/build.sh
#
# x86_64 is built on AlmaLinux 8 (glibc 2.28, PySide6 6.9) so the result runs
# on RHEL/AlmaLinux 8 and every newer distribution; aarch64 on AlmaLinux 10,
# because PySide6's aarch64 wheels need glibc 2.39. Python comes from uv's
# standalone builds, so TLS uses a current OpenSSL rather than the build host's.
#
# Output in build/linux/: pyCertWiz/ (the one-folder bundle) and
# pyCertWiz-<version>-linux-<arch>.tar.gz. packaging/linux/package.sh turns the
# bundle into an AppImage and .deb/.rpm/Arch packages.
set -eu

PYTHON_VERSION=${PYTHON_VERSION:-3.13}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$ROOT/build/linux
arch=$(uname -m)

# Qt's runtime libraries (to render the icons and let PyInstaller collect what
# the Qt plugins link against), plus tools.
dnf install -y --setopt=install_weak_deps=False \
    tar gzip findutils binutils file ca-certificates \
    mesa-libEGL mesa-libGL libxkbcommon libxkbcommon-x11 fontconfig freetype dbus-libs glib2 \
    libX11 libX11-xcb libxcb libSM libICE
. /etc/os-release
major=${VERSION_ID%%.*}
dnf install -y epel-release
case "$major" in 8) dnf config-manager --set-enabled powertools ;; *) dnf config-manager --set-enabled crb ;; esac
dnf install -y xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm

curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/opt/uv sh
export PATH=/opt/uv:$PATH UV_PYTHON_INSTALL_DIR=/opt/uv-python
uv python install "$PYTHON_VERSION"
rm -rf "$OUT" && mkdir -p "$OUT"
uv venv --python "$PYTHON_VERSION" "$OUT/venv"
. "$OUT/venv/bin/activate"
uv pip install --only-binary cryptography "pyinstaller>=6.10" "$ROOT[gui,keyring]"

version=$(python -c 'from importlib.metadata import version; print(version("pyCertWiz"))')
QT_QPA_PLATFORM=offscreen python "$ROOT/packaging/make_icons.py" "$OUT/icons"
pyinstaller --noconfirm --clean "$ROOT/packaging/pycertwiz.spec" \
    --distpath "$OUT" --workpath "$OUT/work"

# The bundle must start, and its GUI must render, before anything is packaged.
"$OUT/pyCertWiz/pyCertWiz" --version
"$OUT/pyCertWiz/pyCertWiz" selftest
tar -C "$OUT" -czf "$OUT/pyCertWiz-$version-linux-$arch.tar.gz" pyCertWiz
echo "$version" > "$OUT/VERSION"
echo "built pyCertWiz $version for $arch (Python $PYTHON_VERSION, glibc $(ldd --version | head -1 | awk '{print $NF}'))"
