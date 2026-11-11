#!/bin/sh
# Install what pyCertWiz's test suite and GUI need on a Linux distribution image,
# then create /venv with the Python dependencies from pyproject.toml.
#
# Qt comes from the PySide6 wheels; the system provides the libraries those
# wheels load (EGL/GL, xkbcommon, fontconfig, the xcb libraries for X11
# displays such as XQuartz) plus fonts and openssl.
set -eu

. /etc/os-release
major=${VERSION_ID%%.*}

case "$ID" in
ubuntu | debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    glib=libglib2.0-0t64
    apt-cache show "$glib" >/dev/null 2>&1 || glib=libglib2.0-0
    apt-get install -y --no-install-recommends \
        python3 python3-venv ca-certificates openssl \
        libegl1 libgl1 libopengl0 libxkbcommon0 libxkbcommon-x11-0 libfontconfig1 libfreetype6 \
        libdbus-1-3 "$glib" libx11-6 libx11-xcb1 libxcb1 libxcb-cursor0 libxcb-icccm4 libxcb-image0 \
        libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xfixes0 \
        libxcb-xkb1 libsm6 libice6 fonts-dejavu-core x11-utils
    rm -rf /var/lib/apt/lists/*
    python=python3
    ;;
almalinux | rocky | rhel | centos | fedora)
    python=python3
    if [ "$ID" != fedora ]; then
        dnf install -y epel-release
        case "$major" in
        8) dnf config-manager --set-enabled powertools; python=python3.12 ;;
        9) dnf config-manager --set-enabled crb; python=python3.12 ;;
        *) dnf config-manager --set-enabled crb ;;
        esac
    fi
    dnf install -y \
        "$python" ca-certificates openssl \
        mesa-libEGL mesa-libGL libglvnd-opengl libxkbcommon libxkbcommon-x11 fontconfig freetype \
        dbus-libs glib2 libX11 libX11-xcb libxcb xcb-util-cursor xcb-util-image xcb-util-keysyms \
        xcb-util-renderutil xcb-util-wm libSM libICE dejavu-sans-fonts
    # xwininfo (for checking windows on an X display) is optional; its package name varies.
    dnf install -y xwininfo >/dev/null 2>&1 || dnf install -y xorg-x11-utils >/dev/null 2>&1 || true
    dnf clean all
    ;;
arch | archarm)
    # pacman's own seccomp sandbox cannot load under emulated x86_64 (Apple silicon).
    pacman -Syu --noconfirm --needed --disable-sandbox \
        python openssl ca-certificates libglvnd libxkbcommon libxkbcommon-x11 fontconfig freetype2 dbus \
        glib2 libx11 libxcb xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil \
        xcb-util-wm libsm libice ttf-dejavu xorg-xwininfo
    pacman -Scc --noconfirm --disable-sandbox
    python=python
    ;;
*)
    echo "install-deps.sh: unsupported distribution '$ID'" >&2
    exit 1
    ;;
esac

"$python" -c 'import sys; assert sys.version_info >= (3, 10), sys.version'
"$python" -m venv /venv
/venv/bin/pip install --quiet --upgrade pip
# Mirrors [project.dependencies] and the dev extra (gui, keyring and test tooling).
/venv/bin/pip install --quiet \
    "cryptography>=42" "tomli>=2.0; python_version < '3.11'" "PySide6-Essentials>=6.6" "keyring>=24" \
    "pytest>=8" "pytest-cov>=5" "pytest-qt>=4.4" "pytest-xdist>=3.5" "ruff>=0.6" "build>=1.2"
/venv/bin/python -c 'import sys, PySide6, cryptography; print(sys.version.split()[0], "PySide6", PySide6.__version__, "cryptography", cryptography.__version__)'
