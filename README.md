# Tirith

**An AI security analyst you work with through ChatGPT, powered by DeepSeek running in your own homelab.**

Tirith aims to let someone ask, “What is vulnerable in my app, can you prove it, and can you help me fix it?” and follow the investigation in plain language. The user selects a repository, application, or explicitly scoped homelab service. DeepSeek plans the assessment, chooses tools, interprets their results, investigates likely vulnerabilities, and proposes the next useful action.

The product should make security work understandable: show the three fixes that matter most, explain their impact, provide evidence for each finding, and verify whether a proposed change actually resolves the problem.

## What we are building

ChatGPT is the user's interface. Tirith's MCP tools connect it to a backend in the homelab, where DeepSeek provides the analyst's reasoning. Users interact with the product without handling the model's API key or administering its inference server.

The intended analyst workflow is:

1. Understand the requested assessment and its authorized scope.
2. Inspect the application and select appropriate discovery or scanning tools.
3. Investigate findings and choose bounded checks that can establish whether a vulnerability is real.
4. Record the requests, responses, and other evidence that support the conclusion.
5. Explain the highest-priority fixes and propose code changes or a pull request.
6. Repeat the relevant checks after a change and report what was actually fixed.

DeepSeek makes decisions throughout this workflow. Semgrep, Gitleaks, Trivy, and ZAP supply observations that it can investigate. Tirith's application code validates tool arguments, enforces scope, executes the allowed operations, and records results. The model is not given an unrestricted shell.

## The hackathon demonstration

The owner should be able to install the ChatGPT plugin and run the demonstration personally. The intended experience is to ask Tirith to assess a deliberately vulnerable training application hosted in the homelab, watch DeepSeek investigate it, and see a concrete finding backed by observed behavior.

For the access-control demonstration, a synthetic low-privilege user is initially denied an admin-only page. The analyst chooses HTTP requests to investigate whether the application incorrectly exposes a dummy capture-the-flag value. A subsequent check replays the successful request against a corrected version, preserving the same user identity.

This target runs in an isolated container with dummy data. A successful flag capture demonstrates an application authorization flaw. It does not establish access to the underlying host or compromise of another homelab service.

The prepared reference patch and a model-generated fix are distinct. A comparison against the reference patch must be labeled as such; a model-generated fix needs its own patch and verification evidence.

## How the analyst proves things

A scanner row is a suspicion until something was sent and answered. Every finding-class issue (SQLi, XSS,
SSTI, command injection, path traversal, SSRF, access-control) goes through the same shape against the
isolated lab copy: the benign control first, then one payload in the same parameter, and nothing counts
unless the probe shows the class signal and the control does not. The signal decides the grade: a database
error or real output is critical, an unescaped echo is high, an ambiguous case is `suspected`, a clean
control and a silent probe is `not_reproduced`. The analyst may propose the payload; fixed code parses it,
and an unusable proposal falls back to the built-in one.

The gate runs on the finished report: each finding-class issue is probed once and carries the plan and the
steps, so the HTML report shows how to redo every reproduced issue by hand. A claimed severity the probe did
not back is demoted, never left standing.

Two ways to drive it from chat: **find and prove** (`mode: "approve"`, observe) and **find, prove, fix**
(approve plus an assisted charge). Approve holds the run after the first reproduction and at the step cap,
so the user answers before anything else happens. The remediation mode is switchable from chat
(`tirith_set_mode`): observe, assisted (PRs for review) or autonomous (dependency bumps merged after
verification) when the operator allows it.

## Current state — 2026-10-24

- The homelab backend, public MCP connection, protected dashboard, widget, and HTML reports work.
- A real DeepSeek assessment of existing findings completed through the public MCP endpoint.
- GitHub credentials are configured and write permission to the demo fork is verified. A fresh live PR test remains outstanding.
- The training target and lab controls are implemented locally. The backend suite passed 235 tests, with one skipped.
- Proof gate, chat-switchable mode, approval checkpoints, lab POST and per-issue reproduction steps are in and tested (258 backend tests, one skipped).
- Untested end to end against a real DeepSeek and a real deployment: the gate's own lab probe on PyGoat, the autonomous apply path, and the plugin installation check.
- Deployment of the latest lab changes, a real DeepSeek flag-capture run and the reference-patch replay remain unfinished.
- The current deployment is single-tenant, with operator-configured scope. Per-user GitHub and Cloudflare account connections are future work.

## Project layout

- [`backend/`](backend/README.md): API, analyst loop, scanners, scope enforcement, evidence, and remediation.
- [`plugin/`](plugin/): ChatGPT plugin, MCP server, skills, and embedded widget.
- [`dashboard/`](dashboard/): Security status, findings, progress, and reports.
- [`targets/analyst-lab/`](targets/analyst-lab/): Dedicated vulnerable and reference-patched training apps.
- [`deploy/`](deploy/README.md): Homelab deployment and public connection runbook.
- [`CONTRACT.md`](CONTRACT.md): Component interfaces and behavior contracts.
