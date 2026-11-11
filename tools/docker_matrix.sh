#!/usr/bin/env bash
# Run pyCertWiz's tests in containers for several Linux distributions, and show
# the GUI from a container on your display (XQuartz on macOS, X11 on Linux).
#
#   tools/docker_matrix.sh build [DISTRO...]          build the test images
#   tools/docker_matrix.sh test [DISTRO...]           run the whole suite in each
#   tools/docker_matrix.sh screenshots DISTRO DIR     the screenshot tool, drawn on your display
#   tools/docker_matrix.sh gui DISTRO                 an interactive demo (sandbox CA inside)
#
# With no DISTRO, every one is used: ubuntu24 ubuntu26 debian alma8 alma9 alma10
# fedora arch nix. Images are built for PLATFORM (default linux/amd64, what
# servers and CI run; Docker Desktop on Apple silicon emulates it). Logs go to
# LOG_DIR (default build/docker-matrix).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PLATFORM=${PLATFORM:-linux/amd64}
LOG_DIR=${LOG_DIR:-$ROOT/build/docker-matrix}
ALL="ubuntu24 ubuntu26 debian alma8 alma9 alma10 fedora arch nix"

base_image() {
    case "$1" in
    ubuntu24) echo ubuntu:24.04 ;;
    ubuntu26) echo ubuntu:26.04 ;;
    debian) echo debian:stable ;;
    alma8) echo almalinux:8 ;;
    alma9) echo almalinux:9 ;;
    alma10) echo almalinux:10 ;;
    fedora) echo fedora:latest ;;
    arch) echo archlinux:latest ;;
    nix) echo nixos/nix:latest ;;
    *) echo "unknown distribution '$1' (choose from: $ALL)" >&2; return 1 ;;
    esac
}

build() {
    local distro=$1 base
    base=$(base_image "$distro")
    mkdir -p "$LOG_DIR"
    echo "== build $distro ($base, $PLATFORM)"
    if [ "$distro" = nix ]; then
        docker build --platform "$PLATFORM" -f "$ROOT/docker/Dockerfile.nix" -t "pycert-test:$distro" "$ROOT" \
            >"$LOG_DIR/$distro.build.log" 2>&1
    else
        docker build --platform "$PLATFORM" -f "$ROOT/docker/Dockerfile" --build-arg "BASE=$base" \
            -t "pycert-test:$distro" "$ROOT" >"$LOG_DIR/$distro.build.log" 2>&1
    fi || { echo "   build FAILED: see $LOG_DIR/$distro.build.log"; return 1; }
    grep -E "PySide6 [0-9]" "$LOG_DIR/$distro.build.log" | tail -1 | sed 's/^#[0-9]* [0-9.]* /   /'
}

run_tests() {
    local distro=$1 log="$LOG_DIR/$1.test.log"
    mkdir -p "$LOG_DIR"
    echo "== test $distro"
    local status=0
    docker run --rm --platform "$PLATFORM" --shm-size=1g "pycert-test:$distro" >"$log" 2>&1 || status=$?
    echo "   $(grep -E '[0-9]+ (passed|failed)' "$log" | tail -1) (exit $status; log: $log)"
    return $status
}

# --- displays ---------------------------------------------------------------
X11_ARGS=()
BRIDGE_PID=""

cleanup() { [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true; }
trap cleanup EXIT

display_setup() {
    mkdir -p "$LOG_DIR"
    local xauth_file="$LOG_DIR/container.xauth"
    : >"$xauth_file"
    if [ "$(uname)" = Darwin ]; then
        # XQuartz keeps listening only on its local socket. A loopback-only relay
        # lets containers reach it without enabling XQuartz's TCP listener.
        # XQuartz treats the relay's connections as local clients of your user,
        # so while it runs, anything that can reach 127.0.0.1:6000 can use the
        # display: the relay is stopped as soon as this command ends.
        pgrep -qx Xquartz || open -a XQuartz
        local socket=${DISPLAY:-}
        for _ in $(seq 50); do [ -S "$socket" ] && break; sleep 0.2; done
        [ -S "$socket" ] || { echo "XQuartz is not running (DISPLAY=$socket)" >&2; return 1; }
        # Pass XQuartz's cookie too, for setups where access control is stricter.
        { /opt/X11/bin/xauth nlist "$DISPLAY"; /opt/X11/bin/xauth nlist :0; } 2>/dev/null \
            | sed -e 's/^..../ffff/' | /opt/X11/bin/xauth -f "$xauth_file" nmerge - 2>/dev/null || true
        python3 "$ROOT/tools/xquartz_bridge.py" --listen 127.0.0.1:6000 --socket "$socket" &
        BRIDGE_PID=$!
        sleep 0.5
        X11_ARGS=(-e DISPLAY=host.docker.internal:0)
    else
        xauth nlist "$DISPLAY" | sed -e 's/^..../ffff/' | xauth -f "$xauth_file" nmerge - || true
        X11_ARGS=(-e "DISPLAY=$DISPLAY" -v /tmp/.X11-unix:/tmp/.X11-unix:ro --network host)
    fi
    chmod 0644 "$xauth_file"  # read by the container's uid; it only authorises this X display
    X11_ARGS+=(-e XAUTHORITY=/tmp/container.xauth -v "$xauth_file:/tmp/container.xauth:ro" -e QT_QPA_PLATFORM=xcb)
}

screenshots() {
    local distro=$1 out
    out=$(mkdir -p "$2" && cd "$2" && pwd)
    display_setup
    echo "== screenshots from $distro on the X display -> $out"
    docker run --rm --platform "$PLATFORM" --shm-size=1g "${X11_ARGS[@]}" -v "$out:/out" \
        "pycert-test:$distro" python tools/screenshots.py /out
}

gui() {
    local distro=$1
    display_setup
    echo "== pyCertWiz from $distro on the X display (close the window to stop)"
    docker run --rm --platform "$PLATFORM" --shm-size=1g "${X11_ARGS[@]}" \
        "pycert-test:$distro" python tools/screenshots.py --interactive
}

command=${1:-}
shift || true
case "$command" in
build)
    failed=0
    for d in ${@:-$ALL}; do build "$d" || failed=1; done
    exit $failed
    ;;
test)
    failed=0
    for d in ${@:-$ALL}; do run_tests "$d" || failed=1; done
    exit $failed
    ;;
screenshots) screenshots "${1:?distro}" "${2:?output directory}" ;;
gui) gui "${1:?distro}" ;;
*) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
