# Tirith — integration contract (v1.2)

Tirith (Sindarin: "watch, guard") is an AI security assessment + remediation service delivered as a ChatGPT plugin. Every component builds against this file. Change it only via the orchestrator.

## Layout

```
tirith/
  CONTRACT.md
  targets/pygoat PyGoat (MIT) training app = scan target; fork github.com/sapoepsilon/tirith-demo-target (PRs go to the fork only)
  backend/       FastAPI (Python 3.12, uv). Port 8000 (any port; local integration runs used 8040). Owns scanners, store, lab, LLM, remediation, events.
  plugin/        ChatGPT plugin package (plugin.json, mcp.json, skills/, assets/) + server/ (TypeScript MCP server, port 8787 via PORT, path /mcp) + widget
  dashboard/     Next.js command center. Port 3000 (`next dev -p`). Same-origin server-side proxy /tirith/api/* -> backend /api/*
                 and /tirith/events (SSE relay of the backend WS); the proxy adds the backend token, the browser never sees it.
  deploy/        docker-compose + LXC/tunnel setup for pve3
```

## Principles

- No model ever gets a shell. LLMs (DeepSeek primary) only produce text: triage summaries, explanations, unified diffs. All execution is fixed, parameterized code paths.
- Every action is checked against scope (`backend/scope.yaml`: allowed repos, local paths, lab network) and written to the audit log.
  `github_repos` are exact `owner/name` entries (case-insensitive, no globs; currently only `sapoepsilon/tirith-demo-target`);
  `url_hosts` are exact `host:port` pairs (a URL without a port uses 80/443); `url_aliases` maps one listed
  `host:port` to further `host:port`s of the same service (a guest behind a published host port) and is only honoured
  while the listed entry exists; `asset_profiles.match` stays a glob (defaults only).
- Validation checks are fixed templates per weakness class (e.g. CWE-89), run only against the target deployed inside the isolated lab network (`tirith-lab`, Docker `internal: true`, no egress) seeded with dummy data. Non-destructive, read-only.
- Remediation modes: `observe` (A: report only), `assisted` (B: patch → PR → verify, human merges), `autonomous` (C: auto-apply only allowed categories, verify, rollback on failure, escalate the rest).

## Data models (JSON)

Asset: `{id, kind: "github_repo"|"local_path"|"url"|"host", ref, name, created_at, focus: [glob], exclude: [glob], sub_apps: [glob]}`
  - github_repo ref = "owner/name"; local_path ref = absolute path; url ref = base URL;
    host ref = a bare hostname or IP, allowed by `scope.yaml` `host_targets` (exact entry or CIDR).
  - focus/exclude/sub_apps (v1.1, optional, default []): repo-relative fnmatch globs. `exclude` drops findings;
    `sub_apps` marks directories that are separate lower-priority lab sub-apps; files outside `focus` are "periphery".
    Empty fields fall back to the first `asset_profiles` entry in `backend/scope.yaml` whose `match` glob matches the
    asset ref, name or ref basename (PyGoat ships one: focus `pygoat/** introduction/** requirements.txt Dockerfile ...`,
    sub_apps `dockerized_labs/* challenge/labs/* challenge`).

Scan: `{id, asset_id, status: "queued"|"running"|"done"|"failed", tools: {semgrep|gitleaks|trivy|zap: "pending"|"running"|"done"|"failed"|"skipped"}, counts: {critical, high, medium, low, info}, started_at, finished_at}`

Finding:
```
{id, scan_id, asset_id, fingerprint, tool, rule_id, title, description,
 severity: "critical"|"high"|"medium"|"low"|"info",
 category: "sast"|"secret"|"dependency"|"dast"|"config",
 file, line, snippet, cwe, cve, package, installed_version, fixed_version, url,
 status: "open"|"validated"|"not_reproduced"|"fixing"|"fixed",
 confidence: 0..1, ai_summary, validation: Validation|null, fix_id,
 # v1.1
 advisories: [Advisory],     # grouped dependency findings only, worst first; [] otherwise
 component: "main"|"periphery"|"lab:<dir>",
 tags: ["lab-subapp"|"periphery"|"test-path", ...],
 priority: 0..100}           # default sort key, see below
```

Advisory: `{id, severity, title, fixed_version, url, cwe}`

Dependency grouping (v1.1): Trivy advisories are collapsed to ONE finding per (manifest file, package):
`rule_id = "dependency:<normalized package>"`, `severity` = max over advisories, `cve` = the worst advisory's CVE,
`fixed_version` = the single version (from the advisories' fixed lists, above the installed one) that resolves the most
advisories (ties -> lowest), `title = "<pkg> <installed>: N known vulnerabilities (upgrade to X)"`, `description` lists
every advisory. Fingerprint = (package, manifest), so it survives bumps and turns `fixed` when no advisory remains.

Priority (v1.1): `100 × severity × confidence × reachability × validated`, 0 for fixed/not_reproduced.
severity critical 1, high .7, medium .4, low .15, info .03. confidence = validation.confidence when confirmed, else the
scanner's. reachability: main 1, periphery .6, lab sub-app .3, test path ×.5; dependencies additionally ×1 (validated &
imported) / .9 (runtime use) / .5 (not imported) / .8 (not validated). validated: confirmed 1, none .7,
unsupported/error .6, not_reproduced .05.

Validation: `{id, finding_id, check: "cwe-89-sqli"|"reproduce-sqli"|"reproduce-xss"|"reproduce-ssti"|"reproduce-cmdi"|..., result: "confirmed"|"not_reproduced"|"unsupported"|"error", confidence, evidence: [{kind: "request"|"response"|"log"|"note", label, content}], started_at, finished_at}`
  - Data-flow findings from DAST (`sqli`, `xss`, `ssti`, `cmdi` by CWE/title) are validated by
    **controlled reproduction** against the signed-in lab copy: the finding's own request is replayed
    twice with one parameter varied — a benign control, then a fixed payload — and confirmed only when
    the class signal appears for the probe and not the control. Requests go from inside the lab
    container to the lab app only (1 per control + ≤1 per payload, capped, GET/POST form, no
    redirects), and nothing off-lab is replayed. The LLM may propose the payload from a fixed
    character shape but never runs anything; unconfirmed proposals fall back to the fixed payload.

Fix: `{id, finding_id, mode, status: "proposed"|"pr_opened"|"verified"|"applied"|"rolled_back"|"failed"|"escalated", diff, branch, pr_url, verification: {tests_passed, validation_result, details}, created_at}`
  - verification = (a) rescan of the changed files with the finding's scanner rule + (b) rebuild/boot of the patched app in the lab. Tirith does not run the target project's own test suite: `tests_passed` is always `null` (kept for shape compatibility).

Posture: `{asset_id, score: 0..100, grade: "A".."F", counts: {critical, high, medium, low, info}, open, fixed, history: [{ts, score}],
          risk, risk_fixed, main_counts: {critical..info}, lab_open, top_actions}` (risk..lab_open v1.1, top_actions v1.4)
  - risk per open finding = priority/10 (info = 0). risk_open = main-app risk + 10·(1 − e^(−lab_risk/10)) (lab sub-apps saturate).
  - score = round(100·(25 + c) / (25 + c + risk_open)), c = 0.5·min(risk_fixed, 50) = progress credit for *fixed* findings.
  - Grade A≥90 B≥80 C≥70 D≥60 else F; an open main-app critical caps at C.
  - Open = status `open|validated|fixing` (closed = `fixed|not_reproduced`). `counts`/`open` = the severity tally of
    `GET /findings?asset_id=<same>&status=open,validated,fixing` (same store query, lab sub-apps included), so the
    two always agree for the same scope. `main_counts` = the same minus lab sub-apps (drives the grade cap);
    `lab_open` = open lab findings. A plain `GET /findings` (no status) also lists closed rows, and without
    `asset_id` it spans ALL assets: compare posture only with a listing of the same asset and status set.
  - Recorded (history point + `posture.updated`) after each scan, validation, fix apply and rollback.
  - `top_actions` (v1.4): up to 3 plain-language fixes for non-experts, `[{title, why, action, finding_ids, severity, fixable}]`.
    Deterministic, no LLM. Open findings (info excluded) are grouped by the one action that closes them: dependency
    findings by package (`action: "Upgrade Django to 4.2.30."`, highest chosen fixed version across the group), secrets
    by file (move to an env var + rotate), everything else by CWE, else by tool+rule_id. Groups rank by their best
    finding's priority, then total priority, then size. `why`/`action` are one sentence each; `finding_ids` are
    best-first (open the first one in a drawer); `severity` = worst in the group; `fixable` = `POST /findings/{id}/fix`
    supports at least one of them (dependency bump with a fixed version, secret in a `.py` file with a line, or a code
    patch on a non-build/CI file), ignoring mode and PR-target policy. Text embeds scanned data (package names,
    paths, titles): treat it as untrusted. Not included in the `posture.updated` event payload.

AuditEntry: `{id: int, ts, actor: "api"|"scanner"|"system"|"remediation", action, target, allowed: bool, details: object|null}`
  (GET /audit returns newest first.)

Explanation: `{summary, root_cause, exploitability, fix_plan}` (strings).

Errors: non-2xx bodies are `{detail: string}`. 401 = missing/invalid bearer token; 403 = scope/policy refusal (out-of-scope asset, observe mode fix,
PR target not allowed); 404 unknown id; 409 wrong fix state; 422 unfixable; 502 LLM/GitHub failure.

## Access control (v1.2)

Backend (FastAPI):
- Every HTTP route and both WebSocket paths require `Authorization: Bearer <TIRITH_API_TOKEN>` (constant-time compare),
  except `GET /health` and `GET /api/health`. Missing/wrong token -> 401 `{detail}` + `WWW-Authenticate: Bearer`;
  a rejected WebSocket handshake is closed before accept (HTTP 403 / close code 1008).
- WebSocket clients that cannot set headers may instead offer subprotocols `["tirith.v1", "bearer.<token>"]`;
  the server then selects `tirith.v1`. Server-side clients should use the header.
- `TIRITH_API_TOKEN` unset -> the backend refuses to start, unless `TIRITH_ALLOW_NO_AUTH=1` (local dev; auth off).
  Tests set a token or `TIRITH_ALLOW_NO_AUTH=1`.
- CORS: only the exact origins in `TIRITH_CORS_ORIGINS` (comma list; `*` ignored). Default none: no CORS headers.
- `PUT/PATCH /mode`: `mode` in {observe, assisted, autonomous} (else 422); a switch marks the mode
  `transient`, cleared by the next run that finishes (the owner's mode returns with it); `autonomous_categories` may only contain
  `"dependency_bump"` (else 422); `mode: autonomous` requires `TIRITH_ALLOW_AUTONOMOUS=1` on the server (else 403).
  Refusals are audited (`mode.set`, allowed=false) and emit `policy.denied`.

MCP server (plugin/server): calls the backend with `Authorization: Bearer $TIRITH_API_TOKEN`. When
`TIRITH_MCP_PATH_SECRET` is set the MCP endpoint is `/mcp/<secret>` and plain `/mcp` returns 404; `/health` and
`/.well-known/*` stay public. `TIRITH_MCP_PUBLIC_URL` is the full public URL including the secret path.

Dashboard (Next.js): HTTP basic auth on every page and route handler with `TIRITH_DASH_USER` / `TIRITH_DASH_PASSWORD`
(both unset = open, for a single operator behind the tunnel). Its server-side proxy (`/tirith/api/*`, `/tirith/events`) adds
`Authorization: Bearer $TIRITH_API_TOKEN` when calling `TIRITH_BACKEND_INTERNAL_URL`; the token is never sent to the browser.

Secrets are generated on the box (`openssl rand -hex 24`), never committed, logged or pasted into chat.

## REST API (backend, prefix /api)

```
GET  /health                    {ok, service, docker}   (also GET /health at the root; both public, no token)
GET  /assets                    POST /assets {kind, ref, name?, focus?, exclude?, sub_apps?}  (existing kind+ref -> returned, profile fields updated)
GET  /assets/{id}               PATCH /assets/{id} {name?, focus?, exclude?, sub_apps?}
GET  /assets/{id}/profile       -> {focus, exclude, sub_apps} effective (asset fields, else scope.yaml asset_profiles)
GET  /scope                     -> scope.yaml as loaded
POST /scans {asset_id, tools?: [..]}   -> Scan (runs async)
GET  /scans?asset_id=           GET  /scans/{id}
GET  /findings?scan_id=&asset_id=&severity=&status=&tool=&component=&sort=&limit=
     filters take comma lists; component = main|periphery|lab|lab:<dir>; sort = priority (default: open first,
     priority desc) | severity; limit optional
GET  /findings/{id}
POST /findings/{id}/explain     -> Explanation
POST /findings/{id}/validate    -> Validation   (?lab=true or {lab: true} adds the isolated-lab boot evidence)
POST /findings/{id}/fix {mode?} -> Fix          (?wait=true runs the pipeline synchronously; observe mode -> 403)
GET  /fixes/{id}
POST /fixes/{id}/apply          (autonomous mode / approval)
POST /fixes/{id}/rollback
POST /assets/import/discovery {host}  -> {host, created: [Asset], existing: [Asset], skipped: [{url, reason}]}
GET  /posture?asset_id=
GET  /mode                      -> {mode, autonomous_categories, transient}
PUT  /mode {mode, autonomous_categories: ["dependency_bump"]}
PATCH /mode {mode?, autonomous_categories?}   (partial, used by the chat mode tool)
GET  /audit?limit=
GET  /events/recent?limit=      oldest first
GET  /lab                       DELETE /lab   (running lab containers; stop all)
WS   /ws/events                 also served at /api/ws/events; ?replay=N sends the last N events first
                                (N clamped to 0..500; non-numeric = 0)
```

## Autonomous analyst (v1.3)

Enabled with `TIRITH_ALLOW_ANALYST=1`. The model plans; fixed code executes and bounds the run.

```
POST /analyst/runs {goal, max_steps?, mode?: "auto"|"approve", charge?: "observe"|"assisted"|"autonomous"}
                                       -> AnalystRun (202) | 409 while another run is active | 403 disabled/autonomous off
POST /analyst/runs/{id}/pause {reason?} -> {run_id, waiting_on} | 404 | 409 unless running
POST /analyst/runs/{id}/resume          -> {run_id, resumed, was_waiting_on} | 409 unless waiting
GET  /analyst/runs                    -> [AnalystRun] newest first
GET  /analyst/runs/{id}               -> AnalystRun
GET  /analyst/stream                  -> SSE of analyst.* events
POST /evidence/screenshot {url,label?} -> {url, ok, path, bytes} | 403 out of scope / shots disabled
```

AnalystRun: `{id, goal, status: "running"|"done"|"budget"|"error", waiting_on, steps: [Step], report, report_path, error, started_at, finished_at}`
Step: `{n, thought, tool, args, observation, ok, at, ms}`
  - Tools the model may call: `asset, discover, scan, findings, posture, validate, reproduce, probe, http,
    evidence, fix, mode`.
    Each re-checks scope; unknown tools and unknown arguments are refused. One identical call per run.
    `findings` and `posture` take `asset_id|kind+ref|name` (none = ALL assets) and echo `scope: {asset_id, asset}`;
    `findings` defaults to the open statuses (`status: "all"` for everything) and returns `total` + `counts` that
    equal `posture.counts` for the same scope; each row carries `asset_id`.
  - Bounds: `TIRITH_ANALYST_MAX_STEPS` (default 8, hard max 24) and `TIRITH_ANALYST_SECONDS` (default 600).
  - Artifacts: `evidence/analyst/<id>.json` (transcript) and `<id>.md` (report).

Proof gate (v1.5). A finding-class issue (CWE-89/79/94/1336/78/918/22/639/284/862) is proven only by a
reproduction that ran and worked. `reproduce` and `probe` project a class onto a request and send the benign
control first, then one payload in one parameter; the verdict is `confirmed` only when the class signal
appears for the probe and not the control. `critical` vs `high` comes from the signal (a database error or
output vs. echo), a confirmed-but-echo-only case is `suspected`, and a signal the control also produced is
`not_reproduced`. On finish (and on the forced report) the gate tries every finding-class issue once and
sets `proof` (confirmed|suspected|not_reproduced|unproven), `grade`, `prove` (the plan) and `reproduce`
(the exact steps); a failed probe caps the claimed severity at `suspected`, a working one may raise it to
the proven grade. A report from a run that never probed anything is not re-graded.
  - Issue fields: `{title, severity, where, finding_id?, evidence, prove?, proof, grade?, reproduce[], impact,
    fix, fix_status}`. The HTML report shows one proof badge per issue, the control/probe plan, and never
    counts an unproven issue as reproduced.
  - `mode: "approve"` holds the run twice: after the first successful reproduction and at the step cap (a
    30 min cap on the wait, then it continues). While held, `waiting_on` is set and `pause`/`resume` are the
    only run mutations. `mode: "auto"` (default) runs through. `charge` sets the remediation mode for that
    run only (restored afterwards, `transient` on GET /mode while it is lifted).
  - `http` runs ONE request inside the running isolated lab copy of a code asset (`url`, `method?`, `path`,
    `form?`, `headers?`); headers are limited to content-type/accept/x-demo-user/cookie, query values are
    printable ASCII, the identity is the lab session cookie or `demo-low`, redirects are never followed.
  - `mode` reads the mode, or switches it when given `mode` (observe|assisted|autonomous, audited as api).

Discovery (`kind: host`): connects only to `scope.yaml` `host_ports` on that one host, then one
`GET /` to fingerprint web services. No payloads, no credential use, no subnet sweep.

## Events (WebSocket /ws/events, one JSON per message)

`{ts, type, level: "info"|"warn"|"error"|"success", message, scan_id?, finding_id?, fix_id?, data?}`

Types: `analyst.started, analyst.thinking, analyst.action, analyst.observation, analyst.checkpoint,
analyst.resumed, analyst.finished, discovery.started, discovery.finished, evidence.shot, evidence.saved, scan.started, tool.started, tool.finished, finding.new, scan.finished, validation.started, validation.step, validation.result, ai.thinking, ai.summary, fix.started, fix.patch, fix.pr_opened, fix.verified, fix.applied, fix.rolled_back, posture.updated, policy.denied, mode.changed`

## Config (env)

```
TIRITH_LLM_BASE_URL   default http://192.168.50.160:8010/v1   (DeepSeek, OpenAI-compatible)
TIRITH_LLM_API_KEY    injected at runtime, never logged
TIRITH_LLM_MODEL      default: first id from /v1/models
TIRITH_LLM_PROVIDER   "stub" = deterministic offline LLM (tests, local integration)
TIRITH_GITHUB_TOKEN   optional; fallback `gh auth token` at runtime (never logged)
TIRITH_API_TOKEN      backend bearer token (backend, MCP server, dashboard server). Required unless TIRITH_ALLOW_NO_AUTH=1
TIRITH_ALLOW_NO_AUTH  1 = backend runs without auth (local dev only)
TIRITH_CORS_ORIGINS   backend CORS allowlist, comma list of exact origins; default none
TIRITH_ALLOW_AUTONOMOUS  1 = PUT /mode may select autonomous
TIRITH_BACKEND_URL    plugin server's backend, default http://localhost:8000
TIRITH_MCP_PATH_SECRET   MCP served at /mcp/<secret> (plain /mcp 404s)
TIRITH_MCP_PUBLIC_URL    public MCP URL incl. secret path (widget/CSP origin)
TIRITH_BACKEND_INTERNAL_URL  dashboard server's backend (proxy + WS relay), default http://localhost:8000
TIRITH_DASH_USER / TIRITH_DASH_PASSWORD  dashboard basic auth (both unset = open)
NEXT_PUBLIC_TIRITH_MOCK=1       dashboard forced demo mode (otherwise demo only when the backend is unreachable)
PORT / HOST           plugin MCP server listen address (default 8787 / 0.0.0.0)
TIRITH_DATA_DIR       default backend/.data (SQLite + clones + evidence)
TIRITH_ALLOW_ANALYST  1 = enable POST /analyst/runs (autonomous model-planned loop)
TIRITH_ANALYST_MAX_STEPS / TIRITH_ANALYST_SECONDS   per-run step + wall-clock budget (8 / 600)
TIRITH_ALLOW_SHOTS    1 = enable POST /evidence/screenshot (headless Chromium container)
TIRITH_CHROME_IMAGE   screenshot browser image, default zenika/alpine-chrome:latest
```
