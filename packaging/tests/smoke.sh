#!/bin/sh
# End-to-end test of an installed pyCertWiz against the sandbox CA.
#
#   packaging/tests/smoke.sh COMMAND SANDBOX_DIR SANDBOX_URL
#
# COMMAND runs pyCertWiz however it was installed: pycertwiz, the path to an
# AppImage, pyCertWiz.app/Contents/MacOS/pyCertWiz, ... SANDBOX_DIR is the
# sandbox CA's --data-dir (for its CA certificates) and SANDBOX_URL its URL.
# SMOKE_GUI=0 skips the GUI checks (for a system without the desktop
# libraries); SMOKE_X11=1 also opens the GUI on an Xvfb X server.
set -eu

PYCW=$1
SANDBOX=$2
URL=$3
PIN=1234567890AB
WORK=$(mktemp -d)
export HOME="$WORK/home" PYCERT_DATA_DIR="$WORK/data"
mkdir -p "$HOME"
CFG="$WORK/conf/pycert.toml"

step() { printf '\n== %s\n' "$*"; }
run() { step "pycertwiz $*"; "$PYCW" --config "$CFG" "$@"; }

step "version and self-test"
"$PYCW" --version
"$PYCW" selftest

if [ "${SMOKE_GUI:-1}" = 1 ]; then
    step "GUI before set-up: the first-run setup opens"
    QT_QPA_PLATFORM=offscreen "$PYCW" gui --check | tee "$WORK/first-run.txt"
    grep -q "first-run setup" "$WORK/first-run.txt"
fi

step "configuration pinned to the sandbox CA"
"$PYCW" init "$WORK/conf" --email ci@example.org --ra "CLRC DL" --backend file
run ca add-ukca sandbox --url "$URL" --chain "$SANDBOX/root.pem" --chain "$SANDBOX/issuing-ca.pem" --make-default
run ping

run request "Package Test" --pin "$PIN" --wait --interval 0.5 --timeout 120
run request pkg-host.example.org --type host --auth "package test" --pin "$PIN" --wait --interval 0.5 --timeout 120
run list
run verify "package test"
step "export with a new passphrase"
printf 'a package passphrase\n' | "$PYCW" --config "$CFG" export "package test" --out "$WORK/user.p12" --password-stdin
run export "package test" --format fullchain --out "$WORK"
run renew "package test" --yes --pin "$PIN" --wait --interval 0.5 --timeout 120
run check --warn 30 --crit 7
run status --refresh

if [ "${SMOKE_GUI:-1}" = 1 ]; then
    step "GUI (offscreen)"
    QT_QPA_PLATFORM=offscreen "$PYCW" --config "$CFG" gui --check
fi
if [ "${SMOKE_X11:-0}" = 1 ]; then
    step "GUI (X11, on Xvfb)"
    Xvfb :87 -screen 0 1280x1024x24 -nolisten tcp >"$WORK/xvfb.log" 2>&1 &
    xvfb=$!
    for _ in $(seq 50); do [ -e /tmp/.X11-unix/X87 ] && break; sleep 0.2; done
    DISPLAY=:87 QT_QPA_PLATFORM=xcb "$PYCW" --config "$CFG" gui --check
    kill "$xvfb"
fi
printf '\nSMOKE OK: %s\n' "$("$PYCW" --version)"
