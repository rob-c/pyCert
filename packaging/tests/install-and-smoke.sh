#!/bin/sh
# Install a built pyCertWiz package in a clean distribution container and run
# the end-to-end smoke test against the sandbox CA.
#
#   docker run --rm --network host -v "$PWD:/src" -w /src IMAGE \
#       packaging/tests/install-and-smoke.sh FORMAT DIST SANDBOX_DIR SANDBOX_URL
#
# FORMAT: deb, rpm, archlinux or appimage. DIST holds the built packages.
# Set SMOKE_X11=1 to also run the GUI on Xvfb.
#
# Packages install the way a user would (with recommended packages), so the
# GUI must work right after installing. The AppImage is first tried on a bare
# system with only its command line, then again after installing the desktop
# libraries an AppImage expects from the host.
set -eu

FORMAT=$1
DIST=$2
SANDBOX=$3
URL=$4
HERE=$(cd "$(dirname "$0")" && pwd)
. /etc/os-release
echo "== $PRETTY_NAME ($(uname -m)), $FORMAT"

only() { set -- "$DIST"/$1; [ -e "$1" ] || { echo "no $FORMAT package in $DIST" >&2; exit 1; }; echo "$1"; }

if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    install_os() { apt-get install -y -qq "$@"; }
    desktop="libegl1 libgl1 libxkbcommon0 libxkbcommon-x11-0 libfontconfig1 libdbus-1-3 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 fonts-dejavu-core"
    xvfb=xvfb
elif command -v dnf >/dev/null; then
    install_os() { dnf install -y -q --nogpgcheck "$@"; }
    desktop="mesa-libEGL mesa-libGL libxkbcommon-x11 fontconfig dejavu-sans-fonts dbus-libs xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm"
    xvfb=xorg-x11-server-Xvfb
    case "$ID:${VERSION_ID%%.*}" in almalinux:* | rocky:* | rhel:*)
        dnf install -y -q epel-release  # xcb-util-cursor and friends
        ;;
    esac
elif command -v zypper >/dev/null; then
    # Container images install only required packages; a desktop installs the recommended ones too.
    install_os() { zypper --non-interactive --no-gpg-checks install --allow-unsigned-rpm --recommends "$@"; }
    desktop="Mesa-libEGL1 Mesa-libGL1 libxkbcommon-x11-0 fontconfig dejavu-fonts libdbus-1-3 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0"
    xvfb=xvfb-run
elif command -v pacman >/dev/null; then
    # pacman's download sandbox needs seccomp, which emulated containers lack.
    pacman() { command pacman --disable-sandbox "$@"; }
    pacman -Sy --noconfirm --needed archlinux-keyring >/dev/null
    install_os() { pacman -S --noconfirm --needed "$@"; }
    desktop="libglvnd libxkbcommon-x11 fontconfig ttf-dejavu dbus xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm"
    xvfb=xorg-server-xvfb
else
    echo "unsupported distribution" >&2
    exit 1
fi

case "$FORMAT" in
deb)
    install_os "$(only '*.deb')"
    PYCW=pycertwiz
    ;;
rpm)
    install_os "$(only '*.rpm')"
    PYCW=pycertwiz
    ;;
archlinux)
    pacman -U --noconfirm "$(only '*.pkg.tar.zst')"
    install_os $desktop  # the package lists these as optional
    PYCW=pycertwiz
    ;;
appimage)
    cp "$(only '*.AppImage')" /tmp/pyCertWiz.AppImage  # downloaded artifacts lose the executable bit
    chmod +x /tmp/pyCertWiz.AppImage
    PYCW=/tmp/pyCertWiz.AppImage
    export APPIMAGE_EXTRACT_AND_RUN=1  # containers have no FUSE
    install_os ca-certificates >/dev/null 2>&1 || true
    echo "== command line on a bare system"
    SMOKE_GUI=0 SMOKE_X11=0 "$HERE/smoke.sh" "$PYCW" "$SANDBOX" "$URL"
    install_os $desktop
    ;;
*)
    echo "unknown format $FORMAT" >&2
    exit 1
    ;;
esac

if [ "${SMOKE_X11:-0}" = 1 ]; then install_os $xvfb; fi
command -v pycert >/dev/null && [ "$FORMAT" != appimage ] && pycert --version
"$HERE/smoke.sh" "$PYCW" "$SANDBOX" "$URL"
