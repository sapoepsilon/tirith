#!/usr/bin/env bash
# Push the Tirith repo to the LXC (CT 161, 192.168.50.161) and run the native installer there.
#   deploy/sync.sh               # sync + deploy/install.sh (venv, node builds, units, restart, health wait)
#   deploy/sync.sh --no-deploy   # sync only
set -euo pipefail

HOST="${TIRITH_HOST:-root@192.168.50.161}"
DEST="${TIRITH_DEST:-/opt/tirith}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rsync -az --delete \
  --exclude node_modules --exclude .next --exclude .data --exclude .venv \
  --exclude __pycache__ --exclude .pytest_cache \
  --include '/targets/' --include '/targets/analyst-lab/***' \
  --include '/targets/breach-lab/***' --exclude '/targets/*' \
  --exclude '/plugin/server/dist/' --exclude '/plugin/dist/' \
  --exclude '/deploy/tirith.env' --exclude '/deploy/mcp.env' --exclude .DS_Store \
  "$ROOT/" "$HOST:$DEST/"

[[ "${1:-}" == "--no-deploy" ]] && exit 0

# shellcheck disable=SC2029 # DEST is a plain path, expanded on the client on purpose.
ssh "$HOST" bash "$DEST/deploy/install.sh"