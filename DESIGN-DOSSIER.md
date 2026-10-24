# Tirith — Engineering Design Dossier

*Working name: Tirith (Sindarin, "watch, guard"). Contract version 1.4. Written from the code as it
stands on 2026-10-24.*

---

## 0. How to read this document

This dossier is the long-form companion to `CONTRACT.md`. The contract is normative and terse — it is
the file that components build against, and it changes only through the orchestrator. This document is
explanatory: it says *why* each part of the contract exists, what breaks when it is violated, and what
the system deliberately refuses to do.

Three audiences are intended:

1. **A future maintainer** who inherits the repository without the chat history and needs to know which
   invariants are load-bearing.
2. **A reviewer** evaluating whether the security claims are honest — that the tool touches only what
   the owner scoped, that nothing about the lab is overclaimed, and that the model genuinely never gets
   a shell.
3. **The author, later**, who will have forgotten the reasoning behind a hundred small refusals and
   needs them written down before deciding to relax one.

Nothing in this document overrides `CONTRACT.md`. Where prose and contract disagree, the contract wins;
where the contract is silent, this document records the intent so the silence is not mistaken for an
invitation.

A note on vocabulary, because it recurs: **scope** is the allowlist that decides what Tirith may touch.
**Enforcement** is the code path that consults scope before an action. **Evidence** is recorded
observation — a request/response pair, a scanner output, a screenshot — that supports or refutes a
claim. **Grounding** is the discipline of keeping the model's prose tied to evidence that already
exists.

---

## 1. What Tirith is, and what it is not

Tirith is a security-assessment and remediation service delivered as a ChatGPT plugin. A user asks a
question in the language they already use — "what is exposed on my box", "is this finding real", "fix
it" — and a self-hosted model drives a fixed toolkit over infrastructure the owner has explicitly put
in scope. The interface is ChatGPT. The reasoning runs on the owner's own hardware. Nothing about the
user's estate, the findings, or the model's API key leaves the homelab.

The product exists because the gap between a scanner and a decision is real. A scanner produces a wall
of rows; a person needs three things: is it true, does it matter here, and what do I type to make it go
away. Tirith's structure is arranged around those three questions and nothing else:

- **Is it true** → validation and controlled reproduction, with a negative control.
- **Does it matter here** → priority arithmetic over severity, confidence, reachability and validation
  result; a posture score that saturates lab noise instead of drowning in it.
- **What do I type** → `top_actions`, ranked and phrased for a non-expert, and a fix pipeline that opens
  a pull request and verifies it.

Tirith is **not** an exploitation framework. It does not pivot, it does not maintain sessions, it does
not brute-force credentials, and it does not keep a foothold. It is also not a compliance product: it
does not map findings to control frameworks, and the posture score is a prioritisation aid, not an
attestation. It is not a SaaS: one deployment serves one owner, with operator-configured scope.
Multi-tenancy, per-user GitHub identities and per-user Cloudflare accounts are explicitly future work.

Finally, Tirith is not magic. Where it has no evidence, it says so. The analyst's system prompt
instructs it, in plain words, to leave out what it merely suspects and to state plainly what was not
checked. Nearly every design decision below is a mechanical reinforcement of that sentence, because a
prompt alone is not a guarantee.

---

## 2. Principles

The principles in `CONTRACT.md` are short enough to look like decoration. They are not; each one
corresponds to a class of failure that has already been designed out.

### 2.1 No model ever gets a shell

Every LLM in Tirith produces text. DeepSeek produces triage prose, explanations, unified diffs, and
planner decisions. It never produces a command line that is handed to `sh -c`. When the analyst wants
to scan something it selects the tool `scan` and fills an argument schema:

```json
{"tool": "scan", "args": {"kind": "url", "ref": "http://192.168.50.161:3000"}}
```

`app/analyst/tools.py` rejects unknown arguments outright (`unknown argument(s) ['flags'] for scan;
allowed: ['kind', 'ref', 'name', 'tools', 'wait_s']`) rather than ignoring them, so the model cannot
smuggle behaviour through a field the executor does not know about. The value of this is not tidiness:
it means the security properties of a run are properties of *our* code, reviewable in one file, rather
than properties of a string the model improvised that turn.

The one place a model touches an argv is remediation, where it writes a unified diff. That diff is
applied by `git apply` against a fresh clone, never by evaluating a shell fragment, and a failed apply
is an error rather than a fallback to something more permissive.

### 2.2 Every action is scope-checked and audited

`scope.enforce(action, kind, ref)` is called on the path of every operation that touches the world —
asset creation, scan start, validation, reproduction, screenshot, discovery, fix. It writes an
`AuditEntry` with `allowed: true|false` in both directions and emits a `policy.denied` event on
refusal. Enforcement is default-deny: an unrecognised asset kind, a URL with no port on an unlisted
host, a bare hostname outside `host_targets`, a local path outside the allowed roots — all refuse with
a reason string, and the reason is returned to the caller.

That last detail matters for the analyst loop. A refusal is not an exception that kills the run; it is
an **observation** the model reads and reacts to. The model learns "the host you named is not in
`host_targets`", registers it with the `asset` tool (which is itself scope-checked), and tries again.
Scope is therefore a teacher as well as a guard.

### 2.3 Fixed templates for active checks

Where Tirith does something active — send a request with a payload — the payload comes from a fixed
per-class template keyed by CWE, not from the model's imagination. `cwe-89-sqli`, `reproduce-xss`,
`reproduce-ssti`, `reproduce-cmdi` each carry a benign control and a probe. The model may *propose* a
payload from a fixed character shape (see §9.4 for the constraints), but if the proposal does not
produce the class signal the fixed payload is used and the run is not marked confirmed. Improvisation
can therefore add signal but cannot manufacture a pass.

### 2.4 Isolation for anything that might be hostile

Active validation runs only against a copy of the target deployed inside the `tirith-lab` Docker
network, which is declared `internal: true` — no egress. A probe that accidentally triggers an
outbound fetch cannot reach the internet, and dummy seed data means a successful injection reads dummy
rows. The screenshot browser joins the default bridge instead (it needs to reach the services it
photographs) but runs with `--cap-drop ALL`, `--no-new-privileges`, a 1 GB memory cap, a 256 PID limit
and a hard timeout.

### 2.5 Honest labels

Three labels are load-bearing and must never be exchanged:

- A **model-generated fix** and the **prepared reference patch** are different objects. Comparing
  against the reference proves the flaw exists; it does not prove the model wrote anything. The
  `tirith_compare_lab_fix` tool is documented to say so in its own output.
- A **captured flag** proves an application-layer authorization flaw. It does not prove host or shell
  compromise; the container is unprivileged, has no shell endpoint, and the flag is a constant.
- **`applied`** in an analyst report stands only when the store records the finding as `fixed` or one
  of its fixes as `verified`/`applied`. Otherwise it is downgraded to `proposed` (§10.5).

### 2.6 Bounded, not merely guided

Every loop has a bound enforced in code, not in a prompt: step budget, wall-clock budget, per-request
timeout, output truncation, screenshot byte cap, container timeout, duplicate-call refusal. The model
is never the thing that decides how long the run is.

---

## 3. Threat model

Tirith sits between an owner, a model, and a set of assets. The interesting adversaries are: the model
as an unreliable narrator, the scanned code as a source of untrusted text, the target as a possibly
hostile service, and the network path to the public tunnel.

### 3.1 The model as adversary-by-accident

Models hallucinate targets, loop, invent results, and assert things they cannot know. Controls:

| Failure | Control |
|---|---|
| Hallucinated host/URL | `scope.enforce` refuses; refusal returned as observation |
| Repeating a probe forever | `seen` set of `tool+args` keys; a repeated *successful* call is refused |
| Running forever | `max_steps` (default 8, hard cap 24) and `TIRITH_ANALYST_SECONDS` (default 600) |
| Fabricating a finding | Report `issues[].finding_id` should be a real id; `fix_status: applied` verified against the store |
| Overclaiming a fix | `_ground_report` downgrade |
| Malformed final report | One re-ask with the validator error, then coercion, never a crash |
| Unknown tool or arg | Refused by `ToolRegistry` before dispatch |

The forced-report path is the clearest illustration of the philosophy. When the step budget is
exhausted, the run does not end with an empty answer: `_forced_report` issues one last planner call
with a system prompt that forbids tool use and allows only a summary of observations already made. If
even that fails, the fallback returns the successful observations verbatim with a note that no final
answer was produced. A `budget` status is a legitimate, reportable outcome — but never a silent one.

### 3.2 The scanned project as untrusted text

Scanner output and source snippets flow into LLM context, and `top_actions` embeds package names, file
paths and titles. A malicious repository can therefore attempt prompt injection through, say, a rule
message or a package name. The contract states the convention: text built from scanned data is treated
as untrusted. The practical consequence is that the model's prose is never the authority for a state
change — the fix pipeline re-derives its own target from the finding id, and priority is computed in
Python, not prose.

### 3.3 The target as a hostile service

A service under test can hang, return a 40 MB body, redirect off-network, or serve a certificate that
expires. Controls: connect timeout 2 s, HTTP timeout 5 s, header read cap 8192 bytes, redirects disabled
in reproduction, `--ignore-certificate-errors` for the screenshot (a self-signed lab service is still a
live service), an 8 MB screenshot cap, and a body of work that only ever runs inside the lab.

### 3.4 The public path

The MCP endpoint is public through a Cloudflare tunnel. Three controls stack: a secret path segment
(`TIRITH_MCP_PATH_SECRET`, plain `/mcp` returns 404), bearer-token auth from the MCP server to the
backend, and backend auth on every route except the two health endpoints. The dashboard is behind HTTP
basic auth, and its server-side proxy injects the backend token so the browser never holds it. CORS
defaults to nothing at all: an empty `TIRITH_CORS_ORIGINS` means no CORS headers are emitted, which is
correct because the dashboard proxies same-origin server side.

### 3.5 What is explicitly out of the threat model

- An attacker with root on the LXC. The docker socket is mounted; root here is root everywhere in the
  compose project.
- Supply-chain compromise of the pinned images (`semgrep/semgrep`, `aquasec/trivy`, `zap-stable`,
  `python:3.12.15-slim-bookworm`, `node:22.23.4-bookworm-slim`, `uv:0.8.22`). Images are pinned by
  digest-adjacent tag, not verified by signature.
- Denial of service on the public tunnel, and cost control on the model (a run can be started by anyone
  who holds the MCP URL; there is no rate limit).
- Secrets at rest: `tirith.env` and `mcp.env` are `chmod 600` on the box and the token is present in the
  container environment. Root on the box reads both.

---

## 4. Architecture

### 4.1 Components

```
 ChatGTP / ChatGPT  ── skill + tool schemas
        │  (HTTPS, secret path, bearer)
        ▼
 plugin/server  (Node, port 8787)  ── nothing but transport + shaping
        │  (compose network, bearer)
        ▼
 backend (FastAPI, 127.0.0.1:8000) ── scope, store, scanners, triage, remediation, analyst loop
        │
        ├── docker socket → sibling containers: semgrep, gitleaks, trivy, zap, lab apps, chrome
        ├── SQLite under TIRITH_DATA_DIR
        └── DeepSeek on CT160 :8010/v1

 dashboard (Next.js, :3000) ── server-side proxy /tirith/api/*, SSE relay /tirith/events
```

The backend owns everything interesting. The MCP server is deliberately thin: it validates and shapes
tool arguments, calls the backend, and returns compact JSON. It holds no GitHub or LLM credential — it
gets its own env file (`mcp.env`) precisely so a transport compromise does not also yield the model key
and the PR token.

The dashboard renders posture, findings, activity, audit and reports. Its proxy is the only component
that adds the backend token, and only server side.

### 4.2 Ports and binding

| Component | Bind | Exposure |
|---|---|---|
| backend | `127.0.0.1:8000` on the LXC | loopback only; dashboard and MCP reach it as `backend:8000` on the compose network |
| mcp | `8787` | tunneled at `https://tirith.mansurov.dev/mcp/<secret>` |
| dashboard | `3000` | tunneled at `https://tirith-dash.mansurov.dev` behind basic auth |
| lab apps | `127.0.0.1:8081/8082` | host loopback, never tunneled |

The vulnerable lab is not on the internet. That is a deliberate scoping statement: everything reachable
from outside is either authenticated, on a secret path, or both.

### 4.3 Request lifecycle, end to end

A goal arrives at `POST /api/analyst/runs`. The route checks `TIRITH_ALLOW_ANALYST`, refuses with 409
if another run is active, and returns 202 with the run id. `loop.run` builds an `AnalystTools`
registry, formats the tool description into the system prompt, and enters the ReAct cycle. Each turn:
one model call in JSON mode with a 120 s deadline; parse one JSON object; either finish or dispatch a
tool. Dispatch is scope-checked inside the tool. The observation is truncated to 3000 characters and
fed back. Steps append to the transcript, each one emitted as an `analyst.*` event and each triggering a
transcript save. On exit — done, budget or error — `build_report` writes the Markdown artifact and the
run is audited.

### 4.4 Why FastAPI, SQLite and Docker-in-Docker-sibling

FastAPI because the contract is a REST surface with strict validation and the team already knows it;
SQLite because one owner, one writer, no operational surface; sibling containers because scanners ship
as images and the alternative is pinning four toolchains into the backend image forever.

The bare-metal cost of the sibling choice is the mounted `docker.sock`, which is root-equivalent. It is
also what makes the lab network, the browser sandbox and the scanner isolation possible at all, so it
is accepted and written down rather than hidden.
---

## 5. Scope enforcement

### 5.1 Four lists, four kinds of intent

`backend/scope.yaml` carries four allowlists that map one-to-one onto asset kinds:

- `github_repos` — exact `owner/name`, case-insensitive, no globs. Today exactly one entry, a fork, so
  every PR lands somewhere the owner controls.
- `local_paths` — absolute roots; a candidate path is realpath-resolved and must be equal to or under a
  root. The default entry is `..`, i.e. the repository itself.
- `url_hosts` — exact `host:port`. A URL without a port is normalised to 80/443 first, so
  `http://example.com` and `http://example.com:80` are the same claim.
- `host_targets` — bare hosts or CIDRs, used by discovery and active checks. A CIDR authorises the host
  you *name*, not a subnet walk.

The lists are disjoint on purpose. Adding a host to `host_targets` gives you discovery and screenshots;
it does not give you ZAP. ZAP needs the specific `host:port` in `url_hosts`. In practice that means
onboarding a service is one deliberate line per capability, and the diff shows exactly how much
authority was granted.

### 5.2 Why exact matching and not globs

Globs are pleasant and dangerous. `*.example.com` looks tight until a wildcard DNS record and an
attacker-controlled subdomain appear. `10.0.0.0/8` looks tight until the operator forgets that the
whole estate is in it. Exact entries make the deployment's authority legible in one screen, and when
that is too small the operator widens it consciously.

`asset_profiles[].match` is the one remaining glob, and it matches nothing but *defaults* — focus,
exclude, sub-apps. A glob mistake there changes ranking, not reach.

### 5.3 Host refs and the `host.docker.internal` dance

Inside the LXC, `127.0.0.1` means the backend container, not the LXC. Both `127.0.0.1:8000` and
`host.docker.internal:8000` therefore appear in `url_hosts`, and `screenshots._scope_candidates` checks
the URL both as given and in its container-facing form. `check_url` runs on the candidate that passes;
the loopback rewrite happens only for the container-side `--add-host host.docker.internal:host-gateway`
mapping. Without this, every screenshot of a loopback service would fail scope with a confusing reason.

### 5.4 Refusal ergonomics

`enforce` always produces a reason string that names the actual mismatch: `host 192.168.50.99 not in
host_targets`, `host:port 192.168.50.161:9999 not in scope allowlist`, `path /tmp/x not under an
allowed local path`. Those strings travel to the model, to the dashboard event feed, and to the audit
row. A user reading `policy.denied` learns what to add; a model reading it learns what to try next.

### 5.5 The scope file is not a config convenience

Two consequences follow. First, nothing in the code defaults to "allow" — an empty scope file denies
everything. Second, scope is loaded from `config.SCOPE_FILE` on each check rather than cached at
startup, so a deployment edit takes effect without a restart. The cost is a YAML parse per operation,
which is irrelevant at this scale and worth the immediacy.

---

## 6. Scanner layer

### 6.1 Tool selection

Four tools, each with one job and its own container: `semgrep` (SAST), `gitleaks` (secrets), `trivy`
(dependency and image CVEs), `zap` (DAST, baseline passive profile against a running URL). Selection is
by asset kind in `runner.plan_tools`: code assets get the first three, URL assets get ZAP. The analyst
may narrow the set through the `tools` argument but not widen it past the plan.

ZAP runs in baseline mode — spider plus passive rules, no attack policy — because its findings are
*inputs* to triage, not conclusions. The active work happens later, in reproduction, where each request
is controlled and paired with a negative control.

### 6.2 Execution and containment

Scanners run as sibling containers via the docker socket: `--network` set so code scanners can reach
nothing, source mounted read-only at the same absolute path inside and outside the container (which is
why `TIRITH_DATA_DIR` and `/opt/tirith/targets` are mounted path-identical), output captured to a file
under the data dir, and a hard `TIRITH_SCAN_TIMEOUT` (900 s default). A scan that times out is marked
`failed` with the tool kept at `timeout` in `Scan.tools`, so the run record says which tool died rather
than collapsing into a generic error.

### 6.3 Repositories come from a clone, not from the user's disk

`github_repo` assets are cloned into `TIRITH_DATA_DIR/clones` at scan time and scanned there. The
remote is the scope-checked `owner/name`. `local_path` assets are mounted directly. The clone path
matters for fixes: a diff is generated against a known-clean checkout, so a dirty working tree on the
owner's machine cannot contaminate the patch.

### 6.4 Normalisation

`scanners/normalize.py` maps each tool's native JSON into the `Finding` shape: tool, rule id, title,
description, severity, category, file, line, snippet, CWE, CVE, package, installed and fixed versions,
URL. Severity mapping is per tool and explicit; anything unrecognised becomes `info` rather than being
guessed upward. Normalisation is also where `focus.py` runs: a finding outside `focus` becomes
`component: "periphery"`, a finding under `sub_apps` becomes `lab:<dir>` with the `lab-subapp` tag, an
`exclude` glob drops it outright, and a test-path heuristic applies the `test-path` tag. These labels
feed priority and the posture grade cap.

### 6.5 Dependency grouping

Raw Trivy output is unusable as a task list: one Django pin produces dozens of advisories. Findings are
collapsed to one per `(manifest, package)`, with `rule_id = dependency:<normalized package>`, severity as
the max over the group, `cve` as the worst member's, and `fixed_version` as the single version above the
installed one that clears the most advisories (ties to the lowest). `description` still lists every
advisory, worst first.

Two properties fall out of the grouping. The fingerprint is `(package, manifest)`, not the advisory id,
so a bump that clears three of four CVEs does not create a new finding — it updates one, and the
remaining advisory keeps it open. And the `fixed_version` choice is a real upgrade target rather than a
per-advisory minimum that would need four separate PRs to satisfy.

### 6.6 Discovery

`scanners/discovery.py` answers exactly one question per host: which of the `host_ports` are open. Two
second connect timeout, no sweep, no banner grabbing beyond what a plain HTTP response volunteers, no
credentials, no POST. An open port that looks like HTTP (a small allowlist including 3000, 8000, 8787,
9090) gets one `GET /` to determine scheme, status, `Server` header and `<title>`; anything else is
reported as open-only and explicitly *not* scannable. SSH and Postgres therefore show up in a report as
exposure without pretending a ZAP run happened.

Product hints (`ssh`, `uvicorn|fastapi`, `proxmox`, `postgres`, `redis`, `ollama|llama`, …) are matched
only against text the service itself emitted.

### 6.7 What the scanner layer will not do

No scheduled scans — every scan is started by a person or by an analyst run. No authenticated ZAP scans;
the current profile is anonymous. No SARIF export. No custom rule packs beyond whatever ships inside
the pinned images. Those omissions are visible in the report, not papered over.

---

## 7. Findings and priority

### 7.1 The record

A `Finding` carries identity (`id`, `scan_id`, `asset_id`, `fingerprint`), provenance (`tool`, `rule_id`),
content (`title`, `description`, `severity`, `category`, `file`, `line`, `snippet`, `cwe`, `cve`,
`package`, versions, `url`), state (`status`), and ranking inputs (`confidence`, `component`, `tags`,
`advisories`, `priority`). `status` moves through `open → validated | not_reproduced → fixing → fixed`,
with `fix_id` linking the remediation.

`fingerprint` is what makes a finding stable across rescans: same rule and same location resolves to the
same row, so a fix that works turns the row `fixed` instead of producing a fresh `open` next to the old
one. Without fingerprints the posture history would be a sawtooth of noise.

### 7.2 The priority formula

```
priority = 100 × severity × confidence × reachability × validated
```

- severity: critical 1, high .7, medium .4, low .15, info .03
- confidence: validation confidence when the validation confirmed, else the scanner's
- reachability: main 1, periphery .6, lab sub-app .3, test path ×.5; dependencies additionally ×1
  (validated and imported), .9 (runtime use), .5 (not imported), .8 (not validated)
- validated: confirmed 1, no validation .7, unsupported/error .6, not_reproduced .05

`fixed` and `not_reproduced` both score 0 and sort last.

Two deliberate choices. First, an unvalidated finding is multiplied by .7, not by 1 — Tirith assumes a
raw scanner row is probably real but unproven, and orders it below anything it has actually reproduced.
Second, `not_reproduced` is .05 rather than 0: a data-flow finding that failed reproduction still
carries a little weight, because a bad control can be wrong in either direction.

### 7.3 Posture

`risk` per open finding is `priority/10` (info excluded). `risk_open` is main-app risk plus
`10 · (1 − e^(−lab_risk/10))`, so a hundred findings inside `dockerized_labs/` cannot bury the one real
bug in the main app — the lab contribution saturates. `score = round(100·(25 + c) / (25 + c +
risk_open))` with `c = 0.5·min(risk_fixed, 50)`, i.e. small credit for work already done, capped so
history cannot push a dirty estate to 100. Grades are A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F, and an
open main-app critical caps the grade at C regardless of arithmetic.

`counts` and `open` come from the same store query as `GET /findings?asset_id=…&status=open,validated,
fixing`, so the gauge and the table can never disagree for the same scope. `main_counts` is that query
minus lab sub-apps and drives the cap; `lab_open` is the lab portion. Posture is recorded after each
scan, validation, apply and rollback, which is what produces `history` — and also why posture is a
trend line rather than a snapshot.

The failure mode that motivated `main_counts` is worth naming: an early version counted lab findings in
the grade, so booting the training lab dropped a grade-A repository to F and taught the owner to close
the lab to keep the number green.

### 7.4 `top_actions`

Up to three plain-language actions, deterministic, no LLM, info excluded. Open findings are grouped by
the single action that closes them: dependency findings by package ("Upgrade Django to 4.2.30."), secrets
by file (move to env var and rotate), everything else by CWE, falling back to tool+rule. Groups rank by
their best member's priority, then total, then size. Each item carries `title`, one-sentence `why`, one
sentence `action`, best-first `finding_ids`, worst `severity`, and a `fixable` boolean computed against
the actual policy.

`fixable` exists so the UI does not offer a button that will 403. It is evaluated *ignoring* mode and
PR-target policy — it answers "could the pipeline patch this", not "will it be allowed right now".

Because the text embeds scanned data, it is untrusted, and it is excluded from the `posture.updated`
event payload so a long action list does not bloat the event feed.

---

## 8. Validation

Validation is the mechanism that turns a suspicion into a state. Six checks exist, each fixed:

| check | target kind | what it does |
|---|---|---|
| `cwe-89-sqli` | code | SQLi data-flow check against the lab copy |
| `reproduce-sqli` / `reproduce-xss` / `reproduce-ssti` / `reproduce-cmdi` | lab copy | controlled replay with control + probe |
| `dependency` | manifest | resolve whether an advisory applies to the installed version |
| `secret` | file | confirm the value is live-shaped, not a placeholder |
| `lab` | any | boot evidence: the app starts with the patch — see §11 |

Every validation writes a `Validation` row with `result` in `confirmed | not_reproduced | unsupported |
error`, a `confidence`, and an `evidence` array of `{kind, label, content}` where kind is `request`,
`response`, `log` or `note`. Evidence is the product here: the user is shown what was sent and what came
back, not a verdict.

`unsupported` is a first-class result. If no template applies — an XXE in a service with no lab copy, a
race condition, anything needing two concurrent identities — Tirith says it could not check rather than
guessing a verdict in either direction. `unsupported` also scores .6 rather than 0, because the finding
may still be entirely real.

A refuted finding stays in the estate with `not_reproduced` and a low priority instead of vanishing. It
re-enters the queue if a later scan re-reports it, which is the behaviour you want when the first
control was simply wrong.

---

## 9. Controlled reproduction

### 9.1 The negative control is the whole idea

A single request that returns a 500 proves very little: pages return 500 for their own reasons. So each
reproduction sends the finding's request **twice** with exactly one parameter varied — first with a
benign control value, then with the probe payload — and confirms only when the class signal appears for
the probe and not for the control. Signal means: a SQL error string or a row count change for SQLi, the
literal marker in the rendered output for XSS, `49` for a `{{7*7}}` SSTI probe, `uid=0` or the marker for
command injection.

The control is what makes the claim falsifiable. `confirmed` requires both halves; anything less is
`not_reproduced` with both exchanges in evidence, so a reviewer can see exactly where the model or the
template was wrong.

### 9.2 Direction and limits

Reproduction always goes from inside the lab container to the lab app. Nothing off-lab is replayed, and
no host is touched: the pattern is one booted pair of containers, requests over the internal network,
then teardown. Budgets: one control plus at most one request per payload in the class's payload list,
GET and POST-form only, redirects off, no cookies carried between attempts beyond what the finding's own
request had.

### 9.3 Identity continuity

The lab copy is seeded with the same synthetic identities the finding was observed under, and the replay
preserves the same identity. That is what makes the authorization demo meaningful: a low-privilege
request that succeeds against the vulnerable build and 403s against the patched one is a statement about
the same subject, not about a lucky anonymous request.

### 9.4 Model payload proposals

The model may propose a payload, but only inside a fixed shape: bounded length, printable ASCII, no
newlines beyond what a form encoding carries, must contain the class marker (`'`, `<tirith>`,
`{{7*7}}`, `;id`). If the proposal confirms, its exact string is recorded as evidence. If it does not,
the fixed payload runs and the run continues. Either way the recorded verdict comes from an observed
condition, never from the model's confidence.

### 9.5 Failure taxonomy

`TimeoutExpired` → `error`, browser/tool missing → `error`, out-of-scope URL → `unsupported` with the
reason, lab boot failure → `unsupported` with the container log tail, no parameter to vary → `unsupported`.
`error` and `unsupported` are visibly distinct in the UI because they have different remedies: one is
yours to fix, the other is a coverage gap.

---

## 10. Remediation

### 10.1 Three modes

- **observe** (A): report only. `POST /findings/{id}/fix` answers 403.
- **assisted** (B): patch → PR → verify. A human merges.
- **autonomous** (C): auto-apply a whitelisted category (`dependency_bump` is the only one), verify, roll
  back on failure, escalate everything else.

Mode is global, is changed through `PUT /mode`, and is itself audited including refusals. Selecting
`autonomous` requires `TIRITH_ALLOW_AUTONOMOUS=1` on the server: the guard exists so a deployment can
expose the mode switch in the UI without yet permitting unattended writes.

Why only dependency bumps are autonomous: the change is mechanical (one pin, one version), the correct
answer is already in the advisory data, and verification is decisive (rescan plus boot). Code patches
involve the model writing a diff, which deserves a human even when it verifies.

### 10.2 The pipeline

`remediation/fix.py` runs these stages, each recorded on the `Fix` row and emitted as an event:

1. **Triage gate.** Is the finding's category fixable at all (§10.3)?
2. **Context.** `context.py` pulls a bounded window around the finding: the file, the enclosing function,
   the imports, the manifest entry. Bounded because a whole-file prompt for a big file is both expensive
   and worse.
3. **Patch.** `deps.py` rewrites the pin to the recorded `fixed_version`; `llm.py` asks the model for a
   unified diff constrained to the context.
4. **Apply.** `git apply` against a clone on a branch named from the finding id. A non-applying diff is a
   failure, not a retry-but-lazier.
5. **Verify** (§10.4).
6. **Publish.** `github.py` pushes the branch and opens a PR targeted at the fork only.
7. **State.** `proposed → pr_opened → verified`; under autonomous mode `applied`, or `rolled_back` /
   `failed` / `escalated`.

`?wait=true` runs the pipeline synchronously — used by the analyst tool and by tests — while the UI polls
`GET /fixes/{id}`.

### 10.3 What is refusable, and why

- A finding with no `fixed_version` and no code location (422).
- Build and CI files, which are excluded from model patches because a broken Dockerfile is hard to verify
  from a scan.
- A secret in a non-`.py` file, where the move-to-env-var pattern does not apply.
- PR targets outside `TIRITH_PR_REPOS` (403). Today exactly the fork, so an upstream PyGoat pull request
  is a conscious later step and never an accident.
- observe mode (403, audited).

### 10.4 Verification

Verification has two halves and no third. (a) Rescan the changed files with the finding's own scanner
rule and confirm the rule no longer fires. (b) Rebuild and boot the patched app in the lab and confirm it
starts and answers. For a data-flow finding the reproduction is replayed too, which is the only way to
show the flaw is actually gone rather than merely quiet.

Tirith does **not** run the target project's own test suite. `verification.tests_passed` is therefore
always `null`, kept only for shape compatibility. This is an honest gap: "the scanner stopped firing and
the app boots" is weaker than "the test suite passes", and the report should not imply the stronger
claim.

### 10.5 Rollback and escalation

`POST /fixes/{id}/rollback` returns a `verified` or `applied` fix to the previous state and re-verifies.
In autonomous mode a failed verification rolls back without asking and marks the fix `rolled_back`; a
fix that verifies only partially is escalated instead of forced. Every one of these transitions writes
posture, because the estate's number changed in both directions.

### 10.6 The grounding rule

The analyst report may say `fix_status: "applied"`. `_ground_report` checks the store: unless the finding
is `fixed` or a fix row is `verified`/`applied`, the label is rewritten to `proposed`. The check is
conservative on purpose — if the store read throws, it returns false. A model that believes it applied a
fix therefore cannot make the report lie; only the store can.

If a report's schema is invalid the model is re-asked once with the validator error attached, and if that
fails the report is coerced rather than dropped. Losing a whole run over an extra field would be a worse
outcome than a slightly ragged report.

---

## 11. The autonomous analyst

### 11.1 Shape of a turn

The system prompt lists the tools with their argument schemas and seven rules: never invent targets, go
broad before narrow, discover before scan, scan before validate, validation before fix, do not repeat a
call, `finish` is the only exit. The model replies with exactly one JSON object:

```json
{"thought": "discover the hosts the owner named", "action": {"tool": "discover", "args": {"host": "192.168.50.161"}}}
```

or

```json
{"thought": "enough", "done": true, "report": {"summary": "...", "notable": [], "next_steps": [], "issues": []}}
```

The `thought` is one sentence and is shown live in the dashboard, so a human watches the reasoning rather
than a progress bar.

### 11.2 The nine tools

`asset`, `discover`, `scan`, `findings`, `validate`, `reproduce`, `evidence`, `fix`, `posture`. Every one
delegates to an existing, already-guarded subsystem — the analyst surface adds validation of argument
*schemas*, not new reach. `discover` on a host asset that has no scannable service returns the open ports
and a `not_scannable` list rather than an empty success; `scan` on a host asset discovers first, then
scans each in-scope URL it found, and reports out-of-scope URLs it skipped.

### 11.3 Scope echo

`findings` and `posture` take `asset_id`, or `kind`+`ref`, or `name`, and echo back
`scope: {asset_id, asset}` — `"ALL assets"` when none was given. This exists because of a real failure:
the model compared an all-assets posture ("0 critical") against a single-asset findings list ("1
critical") and concluded the estate was clean. The echo makes the mismatch visible in the observation
text, and `findings` defaults to exactly the open status set that posture counts.

### 11.4 Bounds

- `max_steps` default 8, request-overridable, hard ceiling 24.
- Wall clock default 600 s.
- One identical call per run, keyed `tool + sorted args`; the key is added only after the call actually
  ran, so a *refused* call can be retried after the model fixes the precondition. That distinction is
  what makes "register the host then discover it" work at all.
- Observation truncation at 3000 characters with an explicit `…[n chars omitted]` marker, so the model
  knows it is looking at a prefix.

A wall-clock or step exhaustion sets `status: "budget"` and runs the forced report. A model outage sets
`status: "error"` with the LLM error text. Both are reported to the user as-is.

### 11.5 Report schema

`summary`, `notable`, `next_steps`, and `issues[]` where each issue has `title`, `severity`, `where`,
optional `finding_id`, `evidence`, `reproduce[]`, `impact`, `fix`, and `fix_status`. The prompt's framing
is explicit: fill issues only for problems confirmed with evidence, omit suspicions, and say what was not
checked. `severity` and `reproduce` are lenient (a scalar is coerced to a list), `fix_status` is a strict
`Literal`.

### 11.6 Artifacts

`evidence/analyst/<id>.json` is the transcript; `<id>.md` is the report, written even on error. The
Markdown carries the goal, the status, the summary, the notable list, the next steps, the full step
table with per-step outcome and first observation line, an all-assets open-findings table labelled with
asset names, and links to the ten most recent screenshots. Labelling the table per asset is the same
lesson as §11.3: an untitled table reads as the named target's findings and usually is not.

### 11.7 Concurrency

One run at a time; a second `POST` answers 409. This is a resource decision (each run can boot containers
and hold a model slot) and a comprehension decision (two live transcripts in one SSE feed are hard to
follow).

---

## 12. Evidence

### 12.1 Screenshots

`evidence/screenshots.py` renders a URL once in a pinned headless Chromium container and keeps the PNG.
Containment: `--security-opt no-new-privileges`, `--cap-drop ALL`, `--memory 1g`, `--pids-limit 256`,
`--cpus 1`, `--rm`, a 90 s timeout with a forced `docker rm -f` on expiry, 1280×900 viewport, 8 s virtual
time budget, and an 8 MB post-hoc size cap that deletes the file if exceeded.

Narrowness is the point: one page load, no cookies, no storage state, no form submission, no script
injection. If a page needs a login to look interesting, the screenshot shows the login page and the
report says so.

Failure detection is deliberately paranoid. Chromium's "N bytes written to file" line must appear; the
file must then be visible on the host side and non-empty, which is the only proof the volume mount
actually took effect. A shot that Chromium claims to have written into a container-local path is reported
as `docker mount failed`, not as success. `_why` extracts `ERR_*`, `ERROR:` or `Failed to load` for the
error message instead of dumping the whole log.

The output directory is `chmod 777` because the browser image runs non-root and the bind mount keeps the
host UID/GID on plain Linux.

### 12.2 Discovery output as evidence

Open ports, `Server` banners and page titles are evidence of exposure, and the report quotes them. They
are also the kind of thing that leaks a version number to an outsider, which is exactly why they are
worth showing: the screenshot plus banner is a faithful model of the first thirty seconds an attacker
spends on a box.

### 12.3 Determinism of the record

Validation evidence preserves the actual request line, headers of interest and response prefix verbatim.
Nothing is paraphrased by a model before storage; the LLM writes the *summary*, the store keeps the
bytes. A reviewer can therefore re-derive every verdict without trusting prose.

---

## 13. The MCP surface and the plugin

### 13.1 Twenty-one tools

`tirith_list_assets`, `tirith_add_asset`, `tirith_start_scan`, `tirith_scan_status`, `tirith_list_findings`,
`tirith_get_finding`, `tirith_explain_finding`, `tirith_validate_finding`, `tirith_get_posture`,
`tirith_fix_finding`, `tirith_apply_fix`, `tirith_rollback_fix`, `tirith_get_fix`,
`tirith_start_analysis`, `tirith_get_analysis`, `tirith_start_lab`, `tirith_get_lab`,
`tirith_compare_lab_fix`, `tirith_reset_lab`, `tirith_get_mode`, `tirith_render_report`.

Descriptions are written for a model reader: what the tool needs, what it returns, when *not* to call it
(`tirith_reset_lab` destroys lab containers — call only when the user asks for a fresh lab). The MCP
transport is streamable HTTP at `/mcp/<secret>`; `/health` and `/.well-known/openai-apps-challenge` stay
public so the tunnel and the app-directory challenge work.

### 13.2 The skill

`plugin/skills/tirith/SKILL.md` is a routing table, not a tutorial. It maps four or five sentence
patterns a user actually types onto procedures, and it front-loads the constraints a user must know:
Tirith is defensive, it only touches scope, no model gets a shell, active checks run against a lab copy
with dummy data, everything is audited.

It also encodes the phrasing rules. Talk about assessing, discovering, reviewing and hardening — not
about breaking in — because that is what is happening. State `budget` plainly as a partial assessment and
offer more steps rather than dressing it up. Never call the reference patch the model's work.

### 13.3 The widget

An embedded report widget renders findings and posture inside the ChatGPT pane, with a CSP origin derived
from `TIRITH_MCP_PUBLIC_URL`. `tirith_render_report` produces the HTML report artifact; reports are also
served from the dashboard at `/reports/...`.

### 13.4 Packaging

`npm run package` builds `plugin/dist/tirith-plugin.zip`, substituting `TIRITH_MCP_PUBLIC_URL` into
`plugin/mcp.json` at package time. The source manifest keeps a placeholder, so the repository holds no
secret path while the distributable does. The ZIP is private and must not be published.

---

## 14. Dashboard

Pages: **posture** (gauge, severity counters, top actions), **findings** (table plus drawer with
evidence and actions), **activity** (live event feed over SSE), **audit** (the audit log), **analyst**
(run list, live transcript, report), **reports** (rendered artifacts).

The server-side proxy at `/tirith/api/*` and the SSE relay at `/tirith/events` add
`Authorization: Bearer $TIRITH_API_TOKEN` when calling `TIRITH_BACKEND_INTERNAL_URL`. The browser never
holds the backend token; it holds only basic-auth credentials. Screenshots are served through
`/tirith/shots/<name>` for the same reason — the evidence volume is mounted read-only into the dashboard
and the route is inside the authenticated surface.

`NEXT_PUBLIC_TIRITH_MOCK=1` forces demo mode; otherwise mock mode is used only when the backend is
unreachable, so the dashboard is presentable without a backend and honest when there is one.

---

## 15. Access control and secrets

### 15.1 Backend

Every HTTP route and both WebSocket paths require a constant-time-compared bearer token, except
`GET /health` and `GET /api/health`. Missing or wrong token → 401 with `WWW-Authenticate: Bearer`; a
rejected socket handshake is closed before `accept` (403 / close 1008). Sockets that cannot set headers
may offer subprotocols `["tirith.v1", "bearer.<token>"]` and the server then selects `tirith.v1`.
`TIRITH_API_TOKEN` unset means the backend refuses to start unless `TIRITH_ALLOW_NO_AUTH=1`, which is a
local-development convenience and never a deployment setting.

### 15.2 MCP and dashboard

MCP is protected by three layers (secret path, tunnel, and the bearer it presents to the backend). The
dashboard uses basic auth on every page and route handler; both credentials unset means open, again
development-only.

### 15.3 Secret hygiene

Generated on the box with `openssl rand -hex 24`, `chmod 600`, never committed, never printed into chat.
The LLM key and the GitHub token are injected at runtime and never logged; the GitHub token falls back to
`gh auth token` when the env var is absent. `sync.sh` refuses to build while any required secret is empty,
so a half-configured deployment fails at deploy time rather than at first request. The tunnel token lives
at `/etc/cloudflared/tirith.token` (0600) and is backed up in the password manager as
`TIRITH_CLOUDFLARE_TUNNEL_TOKEN`.

### 15.4 CORS

Only exact origins in `TIRITH_CORS_ORIGINS`; `*` is ignored rather than interpreted. Default is no CORS
headers, which is right while the dashboard proxies server side.

---

## 16. Operational reality

### 16.1 Topology

LXC **161** `tirith` on Proxmox node `pve3` (`192.168.50.132`), Debian 13, unprivileged, `nesting=1,
keyctl=1`, `onboot=1`, 8 cores, 16 GB RAM, 80 GB `local-lvm`, static `192.168.50.161/24`. Repo at
`/opt/tirith`, data at `/opt/tirith-data`. DeepSeek lives on CT160 `llm-pve3` at `:8010/v1` and must not
be touched; every feature depends on it.

The container is unprivileged but has `nesting`, which is what allows Docker inside. The alternative —
Privileged — was rejected because unprivileged plus keyctl is enough for the pinned images.

### 16.2 Compose

Three services, `restart: unless-stopped`, all with healthchecks; mcp and dashboard wait for backend
health. Backend has the docker CLI and the socket. Images pinned. The evidence volume is mounted
read-only into the dashboard and read-write into the backend.

### 16.3 Deploy loop

`deploy/sync.sh` rsyncs to `/opt/tirith` (excluding `node_modules`, `.next`, `.data`, `.venv`, third-party
targets, build output) and then `docker compose up -d --build`. `--no-build` rsyncs only. Feature flags
(`TIRITH_ALLOW_ANALYST`, `TIRITH_ALLOW_SHOTS`, `TIRITH_ALLOW_AUTONOMOUS`) are set in `tirith.env` on the
box and the stack is recreated with `--force-recreate`.

### 16.4 Verification gate

Each deployment is checked against a fixed list before anyone demos: health returns `ok: true`; an
unauthenticated `/api/assets` returns 401; the authenticated `/analyst` page returns 200; `/health` on
the MCP is 200 while plain `/mcp` is 404; a real analyst run reaches `done` or `budget` with real steps
and a non-empty summary; the JSON and Markdown artifacts exist and the shots directory is non-empty; one
shot is servable through the dashboard at 200. Any failing step stops the deployment with the exact error
rather than a workaround.

### 16.5 Clean starting state

Before a demo: `docker compose ps` all healthy, and `docker ps -a --filter label=tirith.lab=1` empty — no
stuck `tirith-lab-*` or `tirith-shot-*` containers.

### 16.6 Backup and recovery

Data is SQLite plus evidence under `/opt/tirith-data`; the estate is a rebuildable artifact (compose file
plus env files plus this repo). Recovery is: restore secrets from the password manager, rsync, `up -d`.
Evidence older than the last backup is the only genuinely irreplaceable thing, which is worth remembering
before a loud `docker volume prune`.

---

## 17. Testing

The backend suite is `pytest` over FastAPI's `TestClient` and reached 235 passed, 1 skipped at the last
recorded run. The shape of the suite follows the contract:

- **Scope** unit tests for every checker including the URL port normalisation and the CIDR-versus-name
  distinction.
- **Auth** tests for 401 on every route family, the websocket close path, and the no-auth dev mode.
- **Scanner** tests with captured tool output as fixtures, driving normalisation and grouping (including
  the "ties to the lowest version" rule).
- **Posture** tests that assert score, grade and the critical cap, plus the counts-must-agree invariant
  against the findings endpoint.
- **Reproduction** tests that stand in for the lab and assert confirmed-versus-not_reproduced on control
  divergence.
- **Analyst** tests with `TIRITH_LLM_PROVIDER=stub` covering duplicate refusal, budget exhaustion and the
  forced report, malformed decisions, unknown tools and arguments, and the `applied → proposed`
  downgrade.
- **Remediation** tests per refusal class and the full apply/verify/rollback ladder.

Ruff runs over the backend. Dashboard and MCP typecheck clean. The habit that keeps this honest: every
contract sentence with a number or a refusal in it has a test, because those are the sentences that rot
first.

---

## 18. The training lab

`targets/analyst-lab` is a stdlib-only Python app in two builds, `vulnerable` and `patched`, both
deliberately insecure and never to be deployed outside the lab. The flaw is CWE-639 broken access
control: `flag_page()` chooses identity from `?as=` *before* any authorization check and never compares it
with the caller. `GET /flag` as `demo-low` → 403; `GET /flag?as=demo-admin` → 200 with a dummy flag. The
patched build compares the two and 403s with `WWW-Authenticate: Demo`, deliberately not explaining why.

Identities arrive in an `X-Demo-User` header, standing in for a session cookie; no passwords. Everything
is dummy: no file read, no command execution, no other user's data, a constant flag.

The lab exists to make one claim precise and to keep the claim small. A captured flag demonstrates an
application-layer authorization bypass. It does not demonstrate host or shell compromise. The README says
so, the skill says so, and evidence is read through that frame.

`POST /api/assets/import/discovery` seeds assets from a host; `tirith_reset_lab` tears lab containers
down without touching prior evidence.

---

## 19. Honest limitations

- **Single-tenant.** One deployment, one owner, one set of scope lists. Two users need two deployments.
- **No auth scans.** ZAP is anonymous; everything behind a login is invisible to it.
- **No target test suite.** Verification is rescan plus boot, never the project's own tests.
- **Coverage is deliberately thin.** Six validation checks. XXE, SSRF, deserialization, race conditions
  and business-logic flaws generally land as `unsupported`.
- **Fingerprint drift.** A moved file or a renamed package opens a new finding rather than migrating the
  old one, so history has seams.
- **No rate limits or quotas** on the public MCP path.
- **`unsupported` is not a pass.** A clean report on an XXE-heavy codebase means little.
- **The reference patch is not the model's work** and must never be presented as such.
- **The universe of tools is fixed** at nine. Anything not in the registry does not get done.
- **Node pins and image digests** are maintained by hand.
- **The model can still be wrong** in prose. Grounding catches state claims, not tone.

---

## 20. Roadmap

1. Per-user GitHub and Cloudflare connections, then per-user scope (the multi-tenancy seam).
2. Authenticated ZAP profiles so logged-in surfaces become visible.
3. More validation classes, with SSRF and XXE first.
4. Rate limiting and per-day run quotas on the MCP path.
5. Fingerprint migration on file moves.
6. A signed image set and a supply-chain check on the pinned tags.
7. `tests_passed` filled in by running the target's suite where one exists.
8. A per-owner posture history export for trend review.

---

## 21. Appendix A — environment variables

| Variable | Default | Meaning |
|---|---|---|
| `TIRITH_LLM_BASE_URL` | `http://192.168.50.160:8010/v1` | OpenAI-compatible endpoint |
| `TIRITH_LLM_API_KEY` | injected | never logged |
| `TIRITH_LLM_MODEL` | first `/v1/models` id | |
| `TIRITH_LLM_PROVIDER` | — | `stub` = deterministic offline |
| `TIRITH_LLM_TIMEOUT` / `TIRITH_LLM_MAX_TOKENS` | 600 / 16384 | |
| `TIRITH_GITHUB_TOKEN` | `gh auth token` fallback | never logged |
| `TIRITH_PR_REPOS` | — | allowed PR targets |
| `TIRITH_API_TOKEN` | — | required unless no-auth |
| `TIRITH_ALLOW_NO_AUTH` | — | dev only |
| `TIRITH_CORS_ORIGINS` | none | exact origins |
| `TIRITH_ALLOW_AUTONOMOUS` | — | permit `mode: autonomous` |
| `TIRITH_ALLOW_ANALYST` | — | expose `POST /analyst/runs` |
| `TIRITH_ANALYST_MAX_STEPS` / `TIRITH_ANALYST_SECONDS` | 8 / 600 | hard cap 24 |
| `TIRITH_ALLOW_SHOTS` | — | permit screenshots |
| `TIRITH_CHROME_IMAGE` | `zenika/alpine-chrome:latest` | |
| `TIRITH_SHOT_TIMEOUT` / `TIRITH_SHOT_VIRTUAL_TIME_MS` / `TIRITH_SHOT_VIEWPORT` | 90 / 8000 / 1280x900 | |
| `TIRITH_SCAN_TIMEOUT` | 900 | |
| `TIRITH_DATA_DIR` | `backend/.data` | SQLite, clones, evidence |
| `TIRITH_BACKEND_URL` | `http://localhost:8000` | plugin server's backend |
| `TIRITH_BACKEND_INTERNAL_URL` | `http://localhost:8000` | dashboard proxy target |
| `TIRITH_MCP_PATH_SECRET` | — | `/mcp/<secret>`; plain `/mcp` 404s |
| `TIRITH_MCP_PUBLIC_URL` | — | public URL incl. secret (CSP origin) |
| `TIRITH_DASH_USER` / `TIRITH_DASH_PASSWORD` | — | basic auth; unset = open |
| `NEXT_PUBLIC_TIRITH_MOCK` | — | forced demo mode |
| `PORT` / `HOST` | 8787 / 0.0.0.0 | MCP listen |

## 22. Appendix B — error codes

401 missing/invalid bearer · 403 scope or policy refusal (out-of-scope asset, observe-mode fix, PR target
not allowed, feature flag off) · 404 unknown id · 409 wrong fix state or run already active · 422
unfixable or invalid mode · 502 LLM or GitHub failure. Bodies are `{detail}`; refusals are audited.

## 23. Appendix C — event catalogue

`analyst.started`, `analyst.thinking`, `analyst.action`, `analyst.observation`, `analyst.finished`,
`discovery.started`, `discovery.finished`, `evidence.shot`, `evidence.saved`, `scan.started`,
`tool.started`, `tool.finished`, `finding.new`, `scan.finished`, `validation.started`, `validation.step`,
`validation.result`, `ai.thinking`, `ai.summary`, `fix.started`, `fix.patch`, `fix.pr_opened`,
`fix.verified`, `fix.applied`, `fix.rolled_back`, `posture.updated`, `policy.denied`, `mode.changed`.

Each is `{ts, type, level, message, scan_id?, finding_id?, fix_id?, data?}` on the WebSocket, replayed
oldest-first by `GET /events/recent` and by `?replay=N` (clamped 0–500).

## 24. Appendix D — the demo, in order

1. `tirith_list_assets`; add the named hosts as `kind: "host"` if absent.
2. `tirith_start_analysis` with the goal verbatim; poll `tirith_get_analysis` until not `running`.
3. Report steps and `report` verbatim — the reasoning chain *is* the product.
4. `tirith_list_findings`, then `tirith_explain_finding` + `tirith_validate_finding` on the top item, and
   read the evidence aloud in plain language.
5. Collect the Markdown report and PNGs, hand over through Hermes under 30 lines, dashboard URL included.

## 25. Closing note

The product is one sentence long: ask about your own infrastructure in ChatGPT and get a reasoned, evidenced
answer with the three fixes that matter. Everything in this dossier exists to keep that sentence true when
the model misbehaves, the network is slow, and the operator is in a hurry — which is the only condition
under which software is ever actually used.
