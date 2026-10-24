#!/usr/bin/env bash
# Split the compose env layout (deploy/tirith.env + deploy/mcp.env) into the native per-unit files in
# /etc/tirith, mode 0600 root. Run once on the box after the first native install; it is a no-op when
# the source files are gone.
#
#   backend.env    everything in tirith.env (GitHub/LLM secrets live only here)
#   mcp.env        API token, MCP path/public URL, widget domain, dashboard URL, OpenAI challenge
#   dashboard.env  backend token, basic-auth pair, evidence dir (never a GitHub/LLM secret)
#
# The API token is passed to the units on purpose (systemd Environment=), not only in the files, so the
# 0600/root files can stay unreadable by the service user while mcp and dashboard still see the token.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR=/etc/tirith
OLD_TIRITH="$HERE/tirith.env"
OLD_MCP="$HERE/mcp.env"

# MCP-only extras that used to be set by the compose file, not present in the old env files.
MCP_EXTRA="TIRITH_BACKEND_URL=http://127.0.0.1:8000"$'\n'"PORT=8787"

die() { echo "$*" >&2; exit 1; }

[[ -f $OLD_TIRITH ]] || die "$OLD_TIRITH not found (already migrated? nothing to do)"
if [[ -d $ENV_DIR ]] && compgen -G "$ENV_DIR/*.env" >/dev/null && [[ -z "${FORCE:-}" ]]; then
  die "$ENV_DIR already has env files; set FORCE=1 to overwrite them"
fi

install -d -m 0755 "$ENV_DIR"

# Value of a key from the old env file (last occurrence, empty when absent).
old_val() {
  local v
  v="$(grep -E "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  printf '%s' "${v:-}"
}
API_TOKEN="$(old_val "$OLD_TIRITH" TIRITH_API_TOKEN)"

# MCP-only keys: the old mcp.env wins, the token falls back to the backend file.
old_mcp() {
  local v
  v="$(old_val "$OLD_MCP" "${1#^}")"
  [[ -n $v || $1 != '^TIRITH_API_TOKEN=' ]] || v="$API_TOKEN"
  printf '%s' "$v"
}

umask 077
cp "$OLD_TIRITH" "$ENV_DIR/backend.env"
chmod 0600 "$ENV_DIR/backend.env"
printf '\n# --- native deploy workarounds ---\n# No Docker daemon on this box: force the stdlib-only native lab copies.\nTIRITH_NO_DOCKER=1\n' \
  >> "$ENV_DIR/backend.env"

{
  echo "# MCP server only (deploy/migrate-env.sh). No GitHub/LLM secrets."
  echo "# TIRITH_API_TOKEN (same value as backend.env) is also passed by the unit."
  for k in TIRITH_API_TOKEN TIRITH_MCP_PATH_SECRET TIRITH_MCP_PUBLIC_URL TIRITH_WIDGET_DOMAIN \
           TIRITH_DASHBOARD_PUBLIC_URL TIRITH_OPENAI_CHALLENGE; do
    printf '%s=%s\n' "$k" "$(old_mcp "^$k=")"
  done
  printf '%s\n' "$MCP_EXTRA"
} > "$ENV_DIR/mcp.env"
chmod 0600 "$ENV_DIR/mcp.env"

{
  echo "# Dashboard only (deploy/migrate-env.sh). No GitHub/LLM secrets."
  for k in TIRITH_API_TOKEN TIRITH_DASH_USER TIRITH_DASH_PASSWORD; do
    printf '%s=%s\n' "$k" "$(old_val "$OLD_TIRITH" "$k")"
  done
  printf 'TIRITH_EVIDENCE_DIR=/opt/tirith-data/evidence\n'
} > "$ENV_DIR/dashboard.env"
chmod 0600 "$ENV_DIR/dashboard.env"
umask 022

mv "$OLD_TIRITH" "$OLD_TIRITH.migrated"
[[ -f $OLD_MCP ]] && mv "$OLD_MCP" "$OLD_MCP.migrated"

# /etc/tirith stays root-only; the units get their handful of values through root:unit Environment=.
chown root:root "$ENV_DIR"/*.env; chmod 0600 "$ENV_DIR"/*.env
echo "wrote $ENV_DIR/{backend,mcp,dashboard}.env (0600 root); old files kept as *.migrated"
grep -E '^TIRITH_API_TOKEN=.+' "$ENV_DIR/backend.env" >/dev/null || echo "warning: TIRITH_API_TOKEN is empty in backend.env" >&2
grep -E '^TIRITH_API_TOKEN=.+' "$ENV_DIR/mcp.env" >/dev/null || echo "warning: TIRITH_API_TOKEN is empty in mcp.env" >&2
grep -E '^TIRITH_MCP_PATH_SECRET=.+' "$ENV_DIR/mcp.env" >/dev/null || echo "warning: TIRITH_MCP_PATH_SECRET is empty in mcp.env" >&2