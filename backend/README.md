# Tirith backend (core)

FastAPI service on port 8000. Owns the store (SQLite), scope checks, audit log, mode, posture,
event bus, and the Docker-based scanners (Semgrep, Gitleaks, Trivy, ZAP baseline).
See `../CONTRACT.md` for models and routes.

## Run

```sh
cd backend
uv sync
uv run uvicorn app.main:app --port 8000          # add --host 0.0.0.0 to expose
uv run pytest -q                                  # normalization + scope + posture tests
```

Pre-pull scanner images once (first scan is slow otherwise):

```sh
docker pull semgrep/semgrep; docker pull zricethezav/gitleaks
docker pull aquasec/trivy;   docker pull zaproxy/zap-stable
```

## Try it

```sh
B=http://127.0.0.1:8000/api
curl -s $B/health
curl -s -X POST $B/assets -H 'content-type: application/json' \
  -d '{"kind":"local_path","ref":"'"$(cd .. && pwd)"'/targets/pygoat","name":"pygoat"}'
curl -s -X POST $B/scans -H 'content-type: application/json' -d '{"asset_id":"ast_..."}'
curl -s "$B/findings?asset_id=ast_...&severity=critical,high"
curl -s "$B/posture?asset_id=ast_..."
curl -s $B/events/recent?limit=20
# live events: ws://127.0.0.1:8000/ws/events   (also /api/ws/events; ?replay=N sends the last N first)
```

Filters on `/findings` (`severity`, `status`, `tool`, `component`) accept comma-separated values; default order is
priority (open first, priority desc), `sort=severity` for the old order, `limit=N` to cap.
Extra routes: `GET /api/scope`, `GET|PATCH /api/assets/{id}`, `GET /api/assets/{id}/profile`, `GET|DELETE /api/lab`.

## Config (env)

| var | default |
| --- | --- |
| `TIRITH_DATA_DIR` | `backend/.data` (SQLite `tirith.db`, `clones/`, `reports/`, `evidence/`) |
| `TIRITH_SCOPE_FILE` | `backend/scope.yaml` |
| `TIRITH_GITHUB_TOKEN` | optional; fallback `gh auth token`. Only used if the public clone fails. Passed to git via env config, never argv or logs. |
| `TIRITH_SCAN_TIMEOUT` | `900` seconds per tool container |
| `TIRITH_SEMGREP_CONFIGS` | `p/python,p/javascript,p/secrets` |
| `TIRITH_{SEMGREP,GITLEAKS,TRIVY,ZAP}_IMAGE` | the public images above |

## Scope (`scope.yaml`)

Default deny. `github_repos` (globs, default `sapoepsilon/*`), `local_paths` (default `..` = the
tirith folder; resolved with realpath so `..`/symlink escapes are denied), `url_hosts` (ZAP targets,
default localhost/127.0.0.1/host.docker.internal), `url_aliases` (extra `host:port`s of the same service,
honoured only while a `url_hosts` entry they belong to is listed), `lab_network`. Checked on asset create, scan
create, and again when the scan runs; every decision is written to the audit log and denials emit
`policy.denied`.

## Scanners

Each tool runs as `docker run --rm` with the target mounted read-only at `/src`; tools run in
parallel per scan, one scan at a time per asset.

- Semgrep: `semgrep scan --config p/python --config p/javascript --config p/secrets --json --metrics=off`
- Gitleaks: `gitleaks git|dir /src --redact` (git mode when `.git` exists, `--network none`)
- Trivy: `trivy fs --scanners vuln,misconfig --format json` (DB cached in volume `tirith-trivy-cache`)
- ZAP: `zap-baseline.py -t URL -J zap.json -I -m 1` (passive only). Runs for `url` assets whose host
  is in scope (localhost is rewritten to `host.docker.internal`), or for code assets with a Dockerfile:
  `remediation.install(app)` points `app.scanners.tools.get_lab_target` at `remediation.lab.get_lab_target`,
  which builds/boots the target on the internal `tirith-lab` network (the runner calls it via
  `asyncio.to_thread`, it blocks on docker). Otherwise `skipped`. `DELETE /api/lab` stops lab containers.

`TIRITH_ZAP_SCRIPT` is exec'd as one argv element (no splitting), so a mac dev box without
`zap-baseline.py` needs a wrapper script rather than a command line:

```sh
printf '#!/bin/sh\nexec docker run --rm -v "$PWD":/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py "$@"\n' > ~/bin/zap-baseline-docker
chmod +x ~/bin/zap-baseline-docker
TIRITH_ALLOW_NO_AUTH=1 TIRITH_ZAP_SCRIPT=$HOME/bin/zap-baseline-docker uv run uvicorn app.main:app --port 8000
```

Keep the default bridge: `--network host` resolves the LAN but drops the host's ports (Docker Desktop
returns its own loopback), so a forwarded guest port stops answering while a direct LAN address keeps
working. `$PWD` is the scan's report dir, which is what `-J zap.json` writes relative to.

Normalization (`app/scanners/normalize.py`) maps every tool to the contract `Finding`. Secrets are
never stored: gitleaks runs with `--redact` and snippets mask the secret span. Fingerprints are
line-shift tolerant (semgrep: rule+file+code; trivy: CVE+package+version+manifest; ZAP: alert+site).
Findings are deduped per asset by fingerprint: re-detection keeps id/status/validation/fix_id; a
finding a successful tool run no longer reports becomes `fixed` (and re-opens if it returns).

Signal over noise (`app/focus.py`, CONTRACT v1.1):
- Trivy advisories are grouped into one finding per package+manifest (`advisories[]`, max severity, the single
  `fixed_version` resolving the most). PyGoat: 692 raw findings -> 210 (48 dependency groups).
- Per-asset `focus` / `exclude` / `sub_apps` globs (asset fields, else `asset_profiles` in `scope.yaml`): excluded
  paths are dropped, lab sub-apps get `component="lab:<dir>"` + tag `lab-subapp` and rank lower but stay visible.
- `priority` = 100 × severity × confidence × reachability × validated, recomputed on every write; `/findings`
  sorts by it.

## Posture

Priority-weighted (see `app/posture.py`): each open finding carries risk = priority/10 (info 0); lab sub-app
risk saturates at ~10 points; `score = round(100·(25+c)/(25+c+risk))` where `c` is progress credit
(0.5 × risk already closed by *fixes*, capped). Grade A≥90 B≥80 C≥70 D≥60 else F; an open main-app critical
caps the grade at C. PyGoat after a full scan: 24/F; fixing the top finding (Django) -> 30, the top 10 -> 61/D.
A history point is recorded after each scan, validation, fix apply/rollback via `app.posture.record(asset_id)`;
it emits `posture.updated`.

## Validation (evidence, not opinion)

`POST /api/findings/{id}/validate` picks a fixed method per category (`app/remediation/triage.py`):
dependency range + import reachability, secret heuristics, static data-flow review, lab boot — and for
DAST data-flow findings (`sqli`, `xss`, `ssti`, `cmdi` by CWE/title) **controlled reproduction**
(`app/remediation/reproduce.py`).

Reproduction replays the finding's own request against the signed-in lab copy twice, varying one
parameter: a *benign control* first, then a payload from the class's fixed menu. `confirmed` requires
the class signal on the probe and none on the control, so an endpoint that always errors or always
echoes cannot pass. Signals: a database error trace (SQLi), a live `<script>` element rather than
escaped text (XSS), `{{7*7}}` evaluating to 49 (SSTI), an injected command's marker (cmdi); blind
SQLi additionally uses a row-count oracle (probe body changed, an immediate control repeat did not).

The model may propose the payload, but only if it matches the class's fixed character shape; the
proposal is sent once and judged like any other. Limits: ≤8 requests/finding, GET/POST form only,
inside the lab container to the lab app only, cookies redacted from evidence. Turn it off with
`TIRITH_REPRO=0` (falls back to the static/lab triage) and model proposals with `TIRITH_REPRO_LLM=0`.

## Autonomous analyst (v1.3)

`app/analyst/` turns the four scanners into an analyst that decides for itself what to do next.
`POST /api/analyst/runs {goal}` starts a loop; the model (`TIRITH_LLM_*`, DeepSeek by default)
returns one JSON decision per turn — `{"thought", "action": {"tool", "args"}}` or
`{"thought", "done": true, "report"}` — and `app/analyst/tools.py` executes it:

| tool | does |
|---|---|
| `asset` | register an in-scope host / url / local_path / github_repo |
| `discover` | read-only port + HTTP fingerprint of a `host` asset |
| `scan` | semgrep/gitleaks/trivy on code, ZAP on a URL; for a `host`, discovers then ZAPs each web service |
| `findings` / `posture` | read results and the score |
| `validate` / `reproduce` | evidence-based checks (see Validation, incl. controlled reproduction) |
| `evidence` | headless-Chromium screenshot of a URL target (recorded PNG) |
| `fix` | patch → PR → verify (refused in `observe` mode) |

Proof gate (`app/analyst/probe.py`, `loop.proof_gate`): a finding-class issue is proven by a control +
probe pair against the lab copy; the signal decides critical/high/suspected/not_reproduced, and an
unbacked claimed severity is demoted on the finished report. `mode: "approve"` on the run holds it at a
checkpoint after the first reproduction; `POST /analyst/runs/{id}/pause|resume` answers it.

Bounds live in code, not in the prompt: `TIRITH_ANALYST_MAX_STEPS` tool calls (default 8) and a
wall-clock budget; one identical call is refused; every tool re-checks `scope.py`, so a target the
operator did not allow is denied and returned to the model as an observation. A run writes
`evidence/analyst/<run>.json` (full transcript) and `.md` (report) and emits `analyst.*` events.
The endpoint is off unless `TIRITH_ALLOW_ANALYST=1`; screenshots need `TIRITH_ALLOW_SHOTS=1`.

### Host assets and scope

`kind: host` names one machine; `scope.yaml` `host_targets` lists the hostnames/IPs/CIDRs the
operator allows, and `host_ports` the only ports discovery may ever connect to. A CIDR authorises the
host you name — it is not a subnet sweep. Discovery sends no payload: connect, then one `GET /`.

### Importing discovered services

`POST /api/assets/import/discovery {host}` probes a `host` asset through the same allow-listed ports and
registers one `url` asset per web service it finds, for the ones already listed in `url_hosts` (others
are returned as `skipped` with the reason). This is how a chat client turns "my server" into scannable
targets without the operator hand-registering each port.

## For other modules

- Remediation (explain / validate / fix / apply / rollback) lives in `app/remediation/` and is mounted by
  `install(app)` in `main.py`.
- Store: `from app.store import get_store` → `get_finding`, `update_finding(id, **fields)`,
  `save_validation`, `save_fix`/`get_fix`/`list_fixes`, `get_mode`.
- Events: `from app.events import emit; emit("fix.started", "msg", finding_id=..., data={...})` (thread-safe).
- Audit: `from app.audit import audit; audit("fix.apply", target=..., allowed=True, details={...})`.
- Scope: `from app.scope import enforce; enforce("fix.apply", asset.kind, asset.ref)`; hosts go through
  `check_host` / `host_in_scope` (exact entries or CIDR from `host_targets`).
- Source tree of an asset: `app.assets.workdir_for(asset)`; clone/update: `await ensure_clone(asset)`.

Note: if the backend itself runs in a container using the host Docker socket, mount
`TIRITH_DATA_DIR` at the same path on host and container so scanner bind mounts resolve.
