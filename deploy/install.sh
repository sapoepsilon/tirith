#!/usr/bin/env bash
# Native install/update of Tirith on the LXC (CT 161). Run as root from anywhere:
#   bash /opt/tirith/deploy/install.sh
#
# Idempotent: safe to run twice. A run re-exports the code, rebuilds what changed, rewrites the units and
# restarts only then, and waits for the backend health. Env files live in /etc/tirith (0600 root, seeded
# from the examples or deploy/migrate-env.sh, never overwritten); the values the units need are mirrored
# into root-only `<unit>.service.d/env.conf` drop-ins.
#
# /opt/tirith is the WORKING copy (the synced clone). Everything the units run is a fresh export of it in
# /opt/tirith/app, so the tree can stay root-owned and the service only writes where its sandbox allows.
# Builds repeat only when sources changed, the restart only when a build or deploy changed something.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -r $REPO/backend/app/main.py ]] || { echo "$REPO is not a Tirith checkout" >&2; exit 1; }

APP_USER=tirith
APP_DIR=/opt/tirith/app
DATA_DIR=/opt/tirith-data
ENV_DIR=/etc/tirith
STATE_DIR=/var/lib/tirith
UNIT_DIR=/etc/systemd/system
LOCK=/run/lock/tirith-install.lock
export DEBIAN_FRONTEND=noninteractive

step() { printf '\n>>> %s\n' "$*"; }
die() { printf '\n!!! %s\n' "$*" >&2; exit 1; }
changed() { echo "changed: $*"; touch /run/tirith-changed; }

step "lock"
mkdir -p "${LOCK%/*}"
exec 9>"$LOCK"
flock -n 9 || die "another install is running"
rm -f /run/tirith-changed

step "service user (uid/gid 1500, home $STATE_DIR)"
if ! getent passwd "$APP_USER" >/dev/null; then
  # UID 1500 sits inside the regular range: the backend may create user namespaces from it.
  useradd --uid 1500 --create-home --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --user-group "$APP_USER"
fi
# Debian starts regular uids at 1000; move that above 1500 so the two never collide.
# (STATE_DIR /var/lib/tirith is the unit home: writable, and the only place a rootless setup may keep state.)
if grep -q '^FIRST_UID 1000' /etc/login.defs; then
  sed -i -E 's/^FIRST_(UID|GID) +[0-9]+/FIRST_\1 1500/' /etc/login.defs
fi
[[ "$(id -u "$APP_USER")" == 1500 ]] || usermod -u 1500 "$APP_USER"
[[ "$(id -g "$APP_USER")" == 1500 ]] || groupmod -g 1500 "$APP_USER"

step "directories"
install -d -m 0755 -o root -g root "$ENV_DIR" "$UNIT_DIR" "$STATE_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$APP_DIR" \
  "$DATA_DIR" "$DATA_DIR"/{clones,reports,evidence} "$STATE_DIR"/{tmp,subids,home} "$STATE_DIR/stamps"

step "content export ($REPO -> $APP_DIR)"
rsync -a --delete --exclude node_modules --exclude .next --exclude .venv --exclude .data \
  --exclude __pycache__ --exclude .pytest_cache --exclude .git \
  "$REPO/backend" "$REPO/plugin" "$REPO/dashboard" "$REPO/targets" "$REPO/deploy" "$APP_DIR/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
# Same export as the "pristine" base: the per-build stamps compare app sources against it.
rm -rf /run/tirith-pristine
install -d -m 0755 -o root -g root /run/tirith-pristine
cp -a "$APP_DIR/backend" "$APP_DIR/plugin" "$APP_DIR/dashboard" /run/tirith-pristine/

step "runtime dependencies"
apt-get update -q
apt-get install -yq --no-install-recommends \
  python3 python3-venv curl wget gnupg ca-certificates git openssh-server \
  semgrep gitleaks trivy nmap nikto nodejs npm pnpm
# The backend runs scanners as local CLIs, preferring a bare name found in PATH: expose the sbin dirs.
printf '%s\n' "export PATH=\"/usr/local/sbin:/usr/sbin:\$PATH\"" > /etc/profile.d/tirith-path.sh

step "python venv (backend, locked, without dev deps)"
# In the project dir so uv honours backend/.python-version.
(cd "$APP_DIR/backend" && uv sync --frozen --no-dev)
VENV="$APP_DIR/backend/.venv"

step "mcp build (plugin/server)"
# plugin/server/dist is excluded from the sync, so `dist/server.js` existing means "built from these sources".
if [[ ! -f $STATE_DIR/stamps/mcp ]] ||
   ! diff -r /run/tirith-pristine/plugin/server/src "$APP_DIR/plugin/server/src" >/dev/null; then
  # The widget build is an esbuild bundle, and esbuild is a devDependency: install it, build, then drop
  # the dev tree again so production keeps only the runtime deps.
  npm ci --prefix "$APP_DIR/plugin/server" --include=dev --no-audit --no-fund
  npm run build --prefix "$APP_DIR/plugin/server"
  npm prune --prefix "$APP_DIR/plugin/server" --omit=dev --no-audit --no-fund
  touch "$STATE_DIR/stamps/mcp"
  changed mcp-build
fi

step "dashboard build (Next.js, production)"
if [[ ! -f $STATE_DIR/stamps/dashboard ]] ||
   ! diff -r /run/tirith-pristine/dashboard/src "$APP_DIR/dashboard/src" >/dev/null; then
  pnpm --dir "$APP_DIR/dashboard" install --frozen-lockfile
  pnpm --dir "$APP_DIR/dashboard" build
  touch "$STATE_DIR/stamps/dashboard"
  changed dashboard-build
fi

step "env files (example fallbacks when missing; a migrate-env.sh result is never overwritten)"
for pair in backend:tirith.env.example mcp:mcp.env.example; do
  name=${pair%%:*}; example=${pair#*:}
  [[ -s $ENV_DIR/$name.env ]] || { cp "$APP_DIR/deploy/$example" "$ENV_DIR/$name.env"; chmod 0600 "$ENV_DIR/$name.env"; }
done
if [[ ! -s $ENV_DIR/dashboard.env ]]; then
  install -m 0600 /dev/stdin "$ENV_DIR/dashboard.env" <<'EOF'
# Dashboard only. No GitHub/LLM secrets.
TIRITH_API_TOKEN=
TIRITH_DASH_USER=
TIRITH_DASH_PASSWORD=
TIRITH_EVIDENCE_DIR=/opt/tirith-data/evidence
EOF
fi

step "quote env values for the unit"
# systemd percent-expands Environment= values and treats quoting/backslashes inside them: escape both.
for f in "$UNIT_DIR"/tirith-*.service.d/env.conf; do
  [[ -f $f ]] || continue
  sed -i -E '/^Environment=/ s/([\\"`])/\\\1/g; s/=([^=(]*\((.*)\))/=\1\\2/' "$f"
done

step "permissions"
chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR/evidence"
chown root:root "$ENV_DIR"
chmod 0750 "$ENV_DIR"
chmod 0600 "$ENV_DIR"/*.env 2>/dev/null || true

step "secrets present"
# Names only, never values: the backend refuses to start without the token, mcp without its path secret.
grep -Eq '^TIRITH_API_TOKEN=.+' "$ENV_DIR/backend.env" ||
  die "TIRITH_API_TOKEN is empty in $ENV_DIR/backend.env (see deploy/README.md 'Secrets')"
for v in TIRITH_API_TOKEN TIRITH_MCP_PATH_SECRET; do
  grep -Eq "^$v=.+" "$ENV_DIR/mcp.env" || die "$v is empty in $ENV_DIR/mcp.env"
done

step "unit environment (values the units need, from the root-only files)"
unit_env() {
  local file=$1; shift
  local key value out=
  for key in "$@"; do
    value="$(grep -E "^$key=" "$file" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
    [[ -z $value ]] || out+="Environment=$key=$value"$'\n'
  done
  printf '%s' "$out"
}
install -d -m 0700 -o root -g root "$UNIT_DIR/tirith-backend.service.d" \
  "$UNIT_DIR/tirith-mcp.service.d" "$UNIT_DIR/tirith-dashboard.service.d"
printf '[Service]\n%s' "$(unit_env "$ENV_DIR/mcp.env" TIRITH_API_TOKEN)" \
  > "$UNIT_DIR/tirith-mcp.service.d/env.conf"
printf '[Service]\n%s' \
  "$(unit_env "$ENV_DIR/dashboard.env" TIRITH_API_TOKEN TIRITH_DASH_USER TIRITH_DASH_PASSWORD)" \
  > "$UNIT_DIR/tirith-dashboard.service.d/env.conf"

step "ssh"
# Key-only root: the coordinator installs the key through the autoinstall late-commands.
install -d -m 0700 /root/.ssh
install -m 0600 /dev/stdin "$UNIT_DIR/ssh-keyonly.conf" <<'SSHEOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
SSHEOF
install -d -m 0755 "$UNIT_DIR/ssh.service.d"
ln -sfn /etc/systemd/system/ssh-keyonly.conf "$UNIT_DIR/ssh.service.d/10-keyonly.conf"

step "units"
install -m 0644 /dev/stdin "$UNIT_DIR/tirith-backend.service" <<EOF
[Unit]
Description=Tirith backend (FastAPI, 127.0.0.1:8000)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR/backend
EnvironmentFile=-$ENV_DIR/backend.env
Environment=PATH=$VENV/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
ExecStart=$VENV/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --proxy-headers
Restart=on-failure
RestartSec=3
# Private temp dir (unique per start) for scanner/copy scratch files.
PrivateTmp=true
ReadWritePaths=$DATA_DIR $STATE_DIR
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
UMask=0027

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 /dev/stdin "$UNIT_DIR/tirith-mcp.service" <<EOF
[Unit]
Description=Tirith MCP server (streamable HTTP, :8787/mcp)
After=network-online.target tirith-backend.service
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR/plugin/server
Environment=NODE_ENV=production
Environment=PORT=8787
Environment=HOST=0.0.0.0
Environment=TIRITH_BACKEND_URL=http://127.0.0.1:8000
EnvironmentFile=-$ENV_DIR/mcp.env
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=3
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR/plugin/server

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 /dev/stdin "$UNIT_DIR/tirith-dashboard.service" <<EOF
[Unit]
Description=Tirith dashboard (Next.js, :3000)
After=network-online.target tirith-backend.service
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR/dashboard
Environment=NODE_ENV=production
Environment=NEXT_TELEMETRY_DISABLED=1
Environment=PORT=3000
Environment=HOSTNAME=0.0.0.0
Environment=TIRITH_BACKEND_INTERNAL_URL=http://127.0.0.1:8000
EnvironmentFile=-$ENV_DIR/dashboard.env
ExecStart=$APP_DIR/dashboard/node_modules/.bin/next start -H 0.0.0.0 -p 3000
Restart=on-failure
RestartSec=3
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=$DATA_DIR
ReadWritePaths=$APP_DIR/dashboard/.next

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 /dev/stdin "$UNIT_DIR/tirith.target" <<EOF
[Unit]
Description=Tirith stack (backend, MCP, dashboard)
Wants=tirith-backend.service tirith-mcp.service tirith-dashboard.service
After=tirith-backend.service tirith-mcp.service tirith-dashboard.service

[Install]
WantedBy=multi-user.target
EOF

# The healthchecks of the three Dockerfiles, as systemd timers (not part of the service start).
for pair in backend:/api/health mcp:/health dashboard:/favicon.ico; do
  name=${pair%%:*}; path=${pair#*:}; port=8000
  [[ $name == mcp ]] && port=8787
  [[ $name == dashboard ]] && port=3000
  install -m 0644 /dev/stdin "$UNIT_DIR/tirith-$name-health.service" <<EOF
[Unit]
Description=Tirith $name healthcheck (127.0.0.1:$port$path)

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsS -m 5 http://127.0.0.1:$port$path
EOF
  install -m 0644 /dev/stdin "$UNIT_DIR/tirith-$name-health.timer" <<EOF
[Unit]
Description=Periodic Tirith $name healthcheck (30s)

[Timer]
OnActiveSec=20s
OnUnitActiveSec=30s

[Install]
WantedBy=timers.target
EOF
done

systemctl daemon-reload
systemctl enable tirith-backend.service tirith-mcp.service tirith-dashboard.service \
  tirith-backend-health.timer tirith-mcp-health.timer tirith-dashboard-health.timer >/dev/null

systemctl restart ssh.service
systemctl start tirith.target

step "restart"
if [[ -e /run/tirith-changed ]] || ! systemctl is-active -q tirith-backend.service; then
  systemctl restart tirith-backend.service tirith-mcp.service tirith-dashboard.service
  changed restart
fi
systemctl start tirith-backend-health.timer tirith-mcp-health.timer tirith-dashboard-health.timer
rm -rf /run/tirith-pristine

step "waiting for backend health"
for _ in $(seq 1 60); do
  if curl -fsS -m 2 http://127.0.0.1:8000/api/health >/dev/null; then
    echo "backend healthy"
    exit 0
  fi
  sleep 2
done
journalctl -u tirith-backend.service -n 40 --no-pager >&2 || true
die "waiting for backend health"