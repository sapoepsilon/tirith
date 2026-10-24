#!/bin/sh
# Boot one analyst-lab variant without Docker, straight from the source tree.
#   ./run.sh <vulnerable|patched> <port>
# Binds loopback only (BIND=127.0.0.1); every other app setting keeps its default.
set -eu

usage() {
    echo "usage: $0 <vulnerable|patched> <port>" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
variant=$1
port=$2

case "$variant" in
    vulnerable|patched) ;;
    *) echo "run.sh: unknown variant: $variant" >&2; usage ;;
esac

case "$port" in
    ''|*[!0-9]*) echo "run.sh: port must be a number: $port" >&2; usage ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "run.sh: port out of range: $port" >&2; usage; }

cd "$(dirname "$0")/$variant"
BIND=127.0.0.1 PORT="$port" PYTHONUNBUFFERED=1 exec python3 app.py