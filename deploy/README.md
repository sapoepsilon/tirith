# Tirith deploy (pve3 LXC)

Permanent home for the Tirith backend, MCP server and dashboard.

## Public connection (configured 2026-10-24)

- MCP origin: `https://tirith.mansurov.dev` (the full authenticated path is in the private plugin ZIP).
- Dashboard: `https://tirith-dash.mansurov.dev` (HTTP basic authentication).
- Tunnel: `tirith`, UUID `ed9a0a95-5ca1-4413-a29b-ce5a8aa9a295`, remotely managed through Cloudflare.
- Connector: `cloudflared-tirith.service` on CT161. Its token is in
  `/etc/cloudflared/tirith.token` (0600), backed up in Bitwarden as `TIRITH_CLOUDFLARE_TUNNEL_TOKEN`.
- The backend has the existing owner's GitHub credential, backed up as `TIRITH_GITHUB_TOKEN` in
  Bitwarden. Application scope restricts PRs to `sapoepsilon/tirith-demo-target`.
- `/etc/tirith/mcp.env` (migrated from `deploy/mcp.env`) sets the public MCP/widget origins and `TIRITH_DASHBOARD_PUBLIC_URL` so report
  links resolve directly to the dashboard. Neither the backend nor the vulnerable lab is tunneled.

`plugin/dist/tirith-plugin.zip` is the installable private package. It contains the secret MCP path;
do not commit or publicly distribute it. The source `plugin/mcp.json` deliberately retains a
placeholder: `npm run package` substitutes `TIRITH_MCP_PUBLIC_URL` into the packaged manifest only.

For a repeatable assessment in ChatGPT, install the package, select Tirith, and ask to assess the
training lab. The lab tools expose start, progress/evidence, reference-fix comparison, and reset
as separate actions. Repository fixes continue to use the ordinary finding/PR tools.

| | |
|---|---|
| Host | Proxmox node `pve3` (192.168.50.132), cluster `datacenter` |
| Guest | LXC **161** `tirith`, Ubuntu 26.04, unprivileged, `onboot=1` |
| Specs | 4 vCPU, 8 GB RAM, 32 GB disk |
| IP | **192.168.50.161/24** static, gw/dns 192.168.50.1 — the guest sits on the LAN by design |
| Access | `ssh root@192.168.50.161` (key auth), or `ssh root@192.168.50.132 'pct exec 161 -- …'` |
| Repo on box | `/opt/tirith` (rsynced from the Mac, root-owned working copy), deployed tree `/opt/tirith/app`, data in `/opt/tirith-data` |
| LLM | DeepSeek on CT160 `llm-pve3`, `http://192.168.50.160:8010/v1` (same node; do not touch CT160) |

## Native install

Note: CT161 actually runs this as the Docker compose stack in `docker-compose.yml` (containers `tirith-backend-1`, `-mcp-1`, `-dashboard-1`) plus the `cloudflared-tirith` and `tirith-lab-fw` systemd units; the systemd description below is the native-install path.

Everything runs as systemd units on the guest; the needed packages (python3 + venv, nodejs/npm/pnpm,
the scanner CLIs, git, curl, openssh-server) come from apt. The deploy leaves `/opt/tirith` (the
synced working copy) in place and installs a fresh export of it into `/opt/tirith/app`, which is what
the units execute.

| unit | port | notes |
|---|---|---|
| `tirith-backend.service` | 127.0.0.1:8000 | FastAPI in `backend/.venv` (uvicorn `app.main:app --proxy-headers`). Bound to the guest loopback only. User `tirith` (system account, uid/gid 1500); writable paths are `/opt/tirith-data` and its unit home `/var/lib/tirith`. Scanner CLIs (`semgrep`, `gitleaks`, `trivy`, `nmap`, `nikto`) run locally, never in containers. |
| `tirith-mcp.service` | 0.0.0.0:8787 (LAN by design) | `node dist/server.js` in `plugin/server`. Streamable-HTTP MCP at `/mcp/<TIRITH_MCP_PATH_SECRET>` (plain `/mcp` 404s), `/health`, `/.well-known/openai-apps-challenge`. |
| `tirith-dashboard.service` | 0.0.0.0:3000 (LAN by design) | `next start`, production build. Basic auth when `TIRITH_DASH_USER`/`TIRITH_DASH_PASSWORD` are set (unset = open); the server-side proxy adds the backend token. |
| `tirith-backend-health.timer`, `tirith-mcp-health.timer`, `tirith-dashboard-health.timer` | — | Every 30 s, first run 20 s after start: the curl/node healthchecks the Dockerfiles used to carry (`/api/health`, `/health`, `/favicon.ico`). |

`tirith.target` groups the three services. `mcp` and `dashboard` start after `backend` and reach it
on `127.0.0.1:8000`. The lab lane runs the demo targets as plain `python3` processes (no docker
daemon on the box), each held on a free loopback port in `18000-18999`.

The `*.Dockerfile`s and `docker-compose.yml` stay for reference; the live path is `install.sh`.

## Env layout (`/etc/tirith`, 0600 root, never overwritten by a deploy)

| file | contents | read by |
|---|---|---|
| `backend.env` | everything from `tirith.env`, including `TIRITH_GITHUB_TOKEN` and the LLM key | `tirith-backend.service` only |
| `mcp.env` | `TIRITH_API_TOKEN`, `TIRITH_MCP_PATH_SECRET`, `TIRITH_MCP_PUBLIC_URL`, `TIRITH_WIDGET_DOMAIN`, `TIRITH_DASHBOARD_PUBLIC_URL`, `TIRITH_OPENAI_CHALLENGE` | `tirith-mcp.service` |
| `dashboard.env` | `TIRITH_API_TOKEN`, `TIRITH_DASH_USER`, `TIRITH_DASH_PASSWORD`, `TIRITH_EVIDENCE_DIR` — no GitHub/LLM secrets | `tirith-dashboard.service` |

The files are root-only; `install.sh` mirrors the handful of values the units need (token, basic
auth) into root-only `tirith-*.service.d/env.conf` drop-ins, so the service user never reads them.
All three are written once by `deploy/migrate-env.sh` out of `deploy/tirith.env` + `deploy/mcp.env`
(`FORCE=1` to rebuild them); after that, edit `/etc/tirith/*.env` directly and restart the unit.

## Deploy / update

From the Mac:

```sh
deploy/sync.sh              # rsync repo -> /opt/tirith, then bash /opt/tirith/deploy/install.sh
deploy/sync.sh --no-deploy  # rsync only
```

`sync.sh` excludes `node_modules`, `.next`, `.data`, `.venv`, third-party targets, build output and
`deploy/tirith.env` and `deploy/mcp.env` (copies on the box are never overwritten). On first run
`deploy/migrate-env.sh` splits them into `/etc/tirith` and `install.sh` refuses to finish until
`TIRITH_API_TOKEN` (backend.env) and `TIRITH_API_TOKEN`, `TIRITH_MCP_PATH_SECRET` (mcp.env) are set;
the dashboard basic-auth pair is optional (empty = open, the normal single-operator setup behind the
tunnel). Set `TIRITH_ALLOW_AUTONOMOUS=1` in backend.env to permit autonomous remediation.

`install.sh` is idempotent: it re-exports the code, re-runs `uv sync --frozen --no-dev`, rebuilds the
node projects only when their sources changed, rewrites the units and restart drop-ins, restarts what
changed and waits for `/api/health`. It also creates the `tirith` service user, seeds missing env
files from the examples (0600, empty secrets) and sets up key-only ssh. It needs `uv` on PATH and
takes a lock (`/run/lock/tirith-install.lock`); a concurrent run is refused.

Only `targets/analyst-lab/` and `targets/breach-lab/` are synced. GitHub-repo assets are cloned into
`/opt/tirith-data/clones` by the backend; for `local_path` assets put the code under `/opt/tirith/targets/` on the box.

On the box:

```sh
systemctl status tirith.target                       # or the individual units
journalctl -u tirith-backend -ef                     # tail
systemctl restart tirith-backend                     # after editing /etc/tirith/backend.env
bash /opt/tirith/deploy/install.sh                   # full re-deploy (also done by sync.sh)
systemctl list-timers 'tirith-*'                     # healthcheck schedule and last run
```

## Verify

```sh
ssh root@192.168.50.161 curl -s http://127.0.0.1:8000/api/health   # {"ok":true,"service":"tirith-backend","docker":false,"missing_tools":[]}
ssh root@192.168.50.161 curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/assets   # 401 (no token)
curl -s -m 3 http://192.168.50.161:8000/api/health || echo "not reachable from LAN (expected)"
curl -s http://192.168.50.161:8787/health            # {"ok":true,"service":"tirith-mcp",...}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.168.50.161:8787/mcp   # 404 (secret path only)
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.50.161:3000/   # 401 (basic auth)
# tools/list against the secret path, without echoing it:
ssh root@192.168.50.161 'set -a; . /etc/tirith/mcp.env; npx -y @modelcontextprotocol/inspector@latest --cli "http://127.0.0.1:8787/mcp/$TIRITH_MCP_PATH_SECRET" --transport http --method tools/list' | head
ssh root@192.168.50.161 curl -s -o /dev/null -w '%{http_code}\n' http://192.168.50.160:8010/health   # 200
```

## LAN exposure

The guest is a normal LAN host (`.161`), so `:8787` (behind its secret path) and `:3000` (behind basic
auth) are reachable from the whole LAN by design. The backend stays on guest loopback `:8000` and is
never exposed directly — the dashboard proxies to it server side. Neither the backend nor any lab
target is tunneled.

## Secrets (owner only)

The examples carry no secret values. Access-control secrets live only on the box:

| variable | file(s) | used by |
|---|---|---|
| `TIRITH_API_TOKEN` | backend.env + mcp.env + dashboard.env (same value) | backend (checks), dashboard server + MCP (send) |
| `TIRITH_MCP_PATH_SECRET` | mcp.env | MCP endpoint path `/mcp/<secret>` |
| `TIRITH_DASH_USER`, `TIRITH_DASH_PASSWORD` | dashboard.env | optional dashboard basic auth; both empty = open |

Generate with `openssl rand -hex 24` on the box and write them without echoing (rotate the same way, then
`bash /opt/tirith/deploy/install.sh` to refresh the drop-ins and restart). Read the dashboard password on
the box when you need it: `grep ^TIRITH_DASH_PASSWORD= /etc/tirith/dashboard.env`. Empty both variables to drop the prompt.

Autonomous remediation is off unless `TIRITH_ALLOW_AUTONOMOUS=1` is in backend.env.

## Breach demo (30 seconds)

`breach-lab` is an intentional six-flaw target started on demand as a local process on the guest
loopback (`127.0.0.1:8090`, scoped in `backend/scope.yaml`). The flaws and their controls are listed in
`targets/breach-lab/README.md`.

From a chat with the plugin installed:

> `breach the demo box on localhost:8090 and prove it`

What a good run looks like: `asset` (url `http://127.0.0.1:8090`) -> `scan` (semgrep/zap) -> a control + one
payload per issue (`probe`/`reproduce`) -> only reproduced issues keep severity, each with steps -> `render`.
A step list that skips straight to `finish` is an overclaim; the proof gate should have demoted the issues.

Reset between takes: stop a running analysis (`tirith_pause_analysis` then `tirith_resume_analysis` does not help;
`POST /api/analyst/runs/{id}/pause` holds it), then register a fresh scan. `breach-lab` writes nothing outside
its own `/srv/data`, and `POST /api/analystlab/reset` clears the lab copies (and stops the processes).

## Second box: metasploitable 3 (guest 163)

A stock Metasploitable 3 box (192.168.50.129, guest 163) runs beside the breach lab for the Apache/Drupal/CTF-flaw demo.
It is a real VM, so it is **not** a lab copy: probes hit the LAN box and chat is stateful.

- Host side: `provision/meta3-shim.sh` forwards the 81xx ports to the guest (`8162` -> `:80`), as the
  `meta3-shim.service` unit. `8162` is the entry in `backend/scope.yaml`; the other 81xx ports are not scoped.
- Guest side: `scp provision/breach-lab.sh root@192.168.50.129:/root/` then
  `ssh root@192.168.50.129 META3_HOST=192.168.50.161 bash /root/breach-lab.sh` (idempotent; notes then carry
  the mapped URLs).
- Demo: register `url http://192.168.50.161:8162/` and scan — Apache 2.4.7, Drupal 7.5, the CTF payroll flag
  app and the chat room. `/chat` collects POSTs between takes; there is no reset.

## Lab firewall (on the box, persistent)

There is no daemon on the box, so there is no bridge to firewall: lab copies bind `127.0.0.1:<18000-18999>`
and are reachable only from the guest itself. `install.sh` does not touch the firewall; if containers are
ever added back, see the git history for the `tirith-lab-fw.service` rules (drop `DOCKER-USER`/`INPUT` for
`tirith-lab0`).

To go live with DeepSeek and GitHub PRs, on the box:

```sh
ssh root@192.168.50.161
chmod 600 /etc/tirith/backend.env
# edit it yourself: TIRITH_LLM_PROVIDER=openai, TIRITH_LLM_API_KEY=..., TIRITH_GITHUB_TOKEN=...
systemctl restart tirith-backend
```

Never paste the values into chat or commit them.

## Cloudflare tunnel (alternative manual setup)

The live deployment uses the remotely managed tunnel above; the steps below are an alternative
for a fresh installation. Do not create a second tunnel or overwrite its service on CT161.

The MCP server must be reachable over HTTPS for ChatGPT. Outbound-only tunnel, no inbound ports.

1. Install cloudflared in the LXC:

   ```sh
   ssh root@192.168.50.161
   mkdir -p --mode=0755 /usr/share/keyrings
   curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
   echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" > /etc/apt/sources.list.d/cloudflared.list
   apt-get update && apt-get install -y cloudflared
   ```

2. Log in and create the tunnel (opens a browser URL; pick the zone):

   ```sh
   cloudflared tunnel login
   cloudflared tunnel create tirith        # prints the tunnel UUID, writes /root/.cloudflared/<UUID>.json
   cloudflared tunnel route dns tirith tirith.<domain>
   cloudflared tunnel route dns tirith tirith-dash.<domain>
   ```

3. Write `/etc/cloudflared/config.yml` (replace `<UUID>` and `<domain>`):

   ```yaml
   tunnel: <UUID>
   credentials-file: /root/.cloudflared/<UUID>.json
   ingress:
     - hostname: tirith.<domain>
       path: ^/mcp
       service: http://localhost:8787
     - hostname: tirith.<domain>
       path: ^/\.well-known/
       service: http://localhost:8787
     - hostname: tirith.<domain>
       path: ^/health$
       service: http://localhost:8787
     - hostname: tirith.<domain>
       service: http_status:404
     - hostname: tirith-dash.<domain>
       service: http://localhost:3000
     - service: http_status:404
   ```

   Check and install as a service:

   ```sh
   cloudflared tunnel ingress validate
   cloudflared tunnel ingress rule https://tirith.<domain>/mcp     # should match the 8787 rule
   cloudflared service install
   systemctl enable --now cloudflared
   systemctl status cloudflared
   ```

4. Point the plugin at it: `plugin/mcp.json` → `https://tirith.<domain>/mcp/<TIRITH_MCP_PATH_SECRET>`, and set
   `TIRITH_MCP_PUBLIC_URL` (same URL), `TIRITH_WIDGET_DOMAIN=https://tirith.<domain>` (plus `TIRITH_OPENAI_CHALLENGE`
   if OpenAI asks for domain verification) in `/etc/tirith/mcp.env`, then `systemctl restart tirith-mcp`.

5. Test from anywhere:

   ```sh
   curl -s https://tirith.<domain>/health
   npx @modelcontextprotocol/inspector@latest --cli "https://tirith.<domain>/mcp/<secret>" --transport http --method tools/list
   ```

### Dashboard over the tunnel

The browser only talks to the dashboard (same-origin `/tirith/api/*` and `/tirith/events`); the dashboard server
calls `http://127.0.0.1:8000` with the API token. So `tirith-dash.<domain>` works remotely as-is, behind basic auth.
Adding a Cloudflare Access policy in front of it is still a good idea. Never route the backend (`:8000`) through
the tunnel.

The MCP endpoint is protected only by its secret path: keep `TIRITH_MCP_PATH_SECRET` out of chat, screenshots
and commits, and rotate it (plus the plugin URL) if it leaks.
