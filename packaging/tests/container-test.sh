#!/bin/sh
# Install a built package in a clean distribution container and test it end to
# end against the sandbox CA, which runs in a second container. Works the same
# on a developer machine (Docker Desktop) and on CI.
#
#   packaging/tests/container-test.sh IMAGE FORMAT [DIST]
#
#   packaging/tests/container-test.sh debian:13 deb
#   packaging/tests/container-test.sh almalinux:8 appimage
#   SMOKE_X11=1 packaging/tests/container-test.sh fedora:latest rpm
#
# FORMAT: deb, rpm, archlinux or appimage; DIST (default dist/) holds the
# packages for this machine's architecture.
set -eu

IMAGE=$1
FORMAT=$2
DIST=${3:-dist}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
id=pycw-$$-$(date +%s)
sandbox_dir=build/sandbox-$id
cleanup() {
    docker rm -f "$id-ca" >/dev/null 2>&1 || true
    docker network rm "$id" >/dev/null 2>&1 || true
    rm -rf "$sandbox_dir" 2>/dev/null || docker run --rm -v "$ROOT/build:/build" alpine rm -rf "/build/sandbox-$id"
}
trap cleanup EXIT
mkdir -p build
docker network create "$id" >/dev/null

# The sandbox CA (the repository's sandbox_ca, needing only 'cryptography').
docker run -d --name "$id-ca" --network "$id" --network-alias sandbox-ca \
    -v "$ROOT:/src:ro" -v "$ROOT/build:/build" -w /src -e PYTHONPATH=/src/src python:3.13-slim \
    sh -c "pip install -q --root-user-action=ignore 'cryptography>=42' && exec python -m sandbox_ca \
        --host 0.0.0.0 --port 8443 --public-host sandbox-ca --data-dir /build/sandbox-$id --sign-after-polls 0" >/dev/null
for _ in $(seq 120); do
    [ -f "$sandbox_dir/sandbox.json" ] && break
    if [ "$(docker inspect -f '{{.State.Running}}' "$id-ca")" != true ]; then
        docker logs "$id-ca"
        exit 1
    fi
    sleep 1
done
[ -f "$sandbox_dir/sandbox.json" ] || { echo "the sandbox CA did not start" >&2; docker logs "$id-ca"; exit 1; }

docker run --rm --network "$id" -e SMOKE_X11="${SMOKE_X11:-0}" \
    -v "$ROOT:/src:ro" -v "$ROOT/build:/build:ro" -w /src "$IMAGE" \
    packaging/tests/install-and-smoke.sh "$FORMAT" "/src/$DIST" "/build/sandbox-$id" https://sandbox-ca:8443
