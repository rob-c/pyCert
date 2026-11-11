#!/bin/sh
# Start the repository's sandbox CA in the background on loopback and wait
# until it answers. For CI jobs that test a package on the runner itself.
#
#   packaging/tests/start-sandbox.sh DIR [PORT]     # then use https://localhost:PORT
#
# Needs a Python with 'cryptography' ($PYTHON, default python3).
set -eu

DIR=$1
PORT=${2:-8443}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$(dirname "$DIR")"
PYTHONPATH="$ROOT/src:$ROOT" nohup "${PYTHON:-python3}" -m sandbox_ca \
    --data-dir "$DIR" --port "$PORT" --sign-after-polls 0 >"$DIR.log" 2>&1 &
for _ in $(seq 90); do
    if [ -f "$DIR/sandbox.json" ] && curl -skf -o /dev/null "https://127.0.0.1:$PORT/pingservice"; then
        echo "sandbox CA running on https://localhost:$PORT (data in $DIR)"
        exit 0
    fi
    sleep 1
done
echo "the sandbox CA did not start:" >&2
cat "$DIR.log" >&2
exit 1
