"""HTML report rendering for an analyst run.

Two variants from the same data:
  as-found  what is open now, with evidence and reproduction steps
  as-fixed  the same issues with what actually changed; anything not applied is labelled proposed

Prose comes from the analyst's structured `report` dict (written by the model during the run). This module
only formats it: no model call, no network. Voice follows the `humanizer` skill: short sentences, plain
words, sentence-case headings, no emojis, no em dashes, no "serves as"/"showcases" constructions.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import config

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PROOFS = ("confirmed", "suspected", "not_reproduced", "unproven")
_PROVED = ("critical", "high")
# Only a probe that reached a graded severity (critical/high) counts as proof the flaw works.
PROOF_LABEL = {"confirmed": "Reproduced", "suspected": "Only partly", "not_reproduced": "Not reproduced",
               "unproven": "Not reproduced"}
_AI_WORDS = re.compile(
    r"\b(actually|additionally|delve|seamless(ly)?|robust(ly)?|leverage|comprehensive|pivotal|"
    r"underscore[sd]?|showcase[sd]?|tapestry|testament to|landscape|vibrant|intricate|"
    r"cutting-edge|game-chang\w+|best-in-class|world-class|dive into)\b", re.I)


def _plain(text: str) -> str:
    """Light humanizer pass for text the model wrote: kill the worst tells without rewriting meaning."""
    t = html.unescape(str(text or "")).strip()
    t = _AI_WORDS.sub("", t)
    t = re.sub(r"\s+—\s+", ", ", t)          # em dash as a pause
    t = t.replace("—", ",").replace("–", "-")
    t = re.sub(r"[“”]", '"', t).replace("‘", "'").replace("’", "'")   # curly quotes
    t = re.sub(r"\s{2,}", " ", t).strip(" ,")
    if t and t[0].islower():
        t = t[0].upper() + t[1:]
    return t


def _esc(text: str) -> str:
    return html.escape(_plain(text), quote=True)


def _sev(sev: str) -> str:
    s = (sev or "info").lower()
    return s if s in SEV_ORDER else "info"


def _issues(run: dict, findings: list) -> list[dict[str, Any]]:
    """The analyst's issues, enriched with the live finding status so the page cannot go stale."""
    by_id = {f.id: f for f in findings}
    out = []
    for raw in (run.get("report") or {}).get("issues") or []:
        if not isinstance(raw, dict):
            continue
        it = {
            "title": str(raw.get("title") or "Untitled issue"),
            "severity": _sev(raw.get("severity")),
            "where": str(raw.get("where") or ""),
            "evidence": str(raw.get("evidence") or ""),
            "reproduce": [str(x) for x in (raw.get("reproduce") or []) if str(x).strip()],
            "impact": str(raw.get("impact") or ""),
            "fix": str(raw.get("fix") or ""),
            "finding_id": raw.get("finding_id") or None,
            "prove": str(raw.get("prove") or ""),
            "proof": str(raw.get("proof") or "unproven"),
            "grade": str(raw.get("grade") or ""),
        }
        if it["proof"] not in PROOFS:
            it["proof"] = "suspected" if it["proof"] else "unproven"
        f = by_id.get(it["finding_id"]) if it["finding_id"] else None
        if f is not None:
            it["live_status"] = f.status
            it["confidence"] = f.confidence
            it["validated"] = bool(f.validation and f.validation.result in ("valid", "reproduced", "fixed"))
            if f.url and not it["where"]:
                it["where"] = f.url
        # A fix counts as applied only when the record says so.
        if it["proof"] == "confirmed" and it["grade"] not in _PROVED:
            it["proof"] = "suspected"
        it["applied"] = bool(f is not None and f.status == "fixed") or raw.get("fix_status") == "applied"
        if f is not None and f.status != "fixed":
            it["applied"] = False
        out.append(it)
    out.sort(key=lambda i: SEV_ORDER[i["severity"]])
    return out


def _counts(issues: list[dict]) -> dict[str, int]:
    c = {k: 0 for k in SEV_ORDER}
    for i in issues:
        c[i["severity"]] += 1
    return c


def _row(label: str, value: str) -> str:
    return f'<div class="kv"><dt>{html.escape(label)}</dt><dd>{value}</dd></div>' if value else ""


def _proof_line(it: dict) -> str:
    """The control-vs-probe plan, verbatim, so a reader can rerun it (the values are validated shapes)."""
    rows = []
    for line in (it.get("prove") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip() in ("method", "path", "param", "payload", "signal"):
                rows.append(f'<div class="kv"><dt>{html.escape(k.strip())}</dt><dd><code>{html.escape(v.strip())}</code></dd></div>')
    return ('<h4>The probe (control first, then this value in that one parameter)</h4><dl class="probe">'
            + "".join(rows) + "</dl>") if rows else ""


def _issue_block(n: int, it: dict, fixed_view: bool) -> str:
    sev = it["severity"]
    applied = it["applied"]
    state = ("fixed" if applied else "proposed") if fixed_view else "open"
    badge = {"fixed": "Fixed", "proposed": "Proposed, not applied", "open": "Open"}[state]
    proof = it.get("proof") or "unproven"
    repro = "".join(f"<li>{_esc(s)}</li>" for s in it["reproduce"])
    if not repro:
        repro = ("<li>No working reproduction was recorded.</li>" if proof != "confirmed"
                 else "<li>Steps were not kept; see the activity table.</li>")
    where = f'<code>{_esc(it["where"])}</code>' if it["where"] else ""
    src = ""
    if it.get("finding_id"):
        conf = it.get("confidence")
        src = (f'<p class="src">Scanner finding <code>{_esc(it["finding_id"])}</code>'
               + (f", confidence {int(conf * 100)}%" if isinstance(conf, (int, float)) else "")
               + (f", live status {_esc(it['live_status'])}" if it.get("live_status") else "")
               + "</p>")
    body = [
        f'<article class="issue sev-{sev} {state}" id="issue-{n}">',
        f'<header><h3>{_esc(it["title"])}</h3><span class="pill p-{state}">{badge}</span>'
        f'<span class="pill sev">{sev}</span><span class="pill proof pf-{proof}">{PROOF_LABEL[proof]}</span></header>',
        f'<p class="where">{where}</p>' if where else "",
        f'<p class="evidence">{_esc(it["evidence"])}</p>' if it["evidence"] else "",
        _proof_line(it),
        '<h4>Reproduction</h4><ol class="repro">' + repro + "</ol>",
        f'<p class="impact"><strong>What it lets someone do.</strong> {_esc(it["impact"])}</p>' if it["impact"] else "",
        (f'<h4>{"How it was fixed" if applied else "Proposed fix"}</h4>' if it["fix"] else ""),
        f'<p class="fix">{_esc(it["fix"])}</p>' if it["fix"] else "",
        src,
        "</article>",
    ]
    return "".join(b for b in body if b)


def _activity(run: dict) -> str:
    rows = []
    for s in run.get("steps") or []:
        rows.append(
            f'<tr><td class="n">{s.get("n")}</td><td><code>{_esc(s.get("tool") or "?")}</code></td>'
            f'<td class="{"ok" if s.get("ok") else "no"}">{"ok" if s.get("ok") else "refused"}</td>'
            f'<td>{_esc((s.get("thought") or "")[:200])}</td></tr>')
    if not rows:
        return "<p>No steps were recorded.</p>"
    return ('<table class="steps"><thead><tr><th>#</th><th>tool</th><th>result</th><th>why it took this step</th>'
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _shots(run: dict) -> list[str]:
    """Screenshots this run actually took: named in its steps, never the whole directory."""
    d = config.EVIDENCE_DIR / "shots"
    if not d.is_dir():
        return []
    found: list[str] = []
    for s in run.get("steps") or []:
        obs = str(s.get("observation") or "")
        for name in re.findall(r"([A-Za-z0-9._-]{1,180}\.png)", obs):
            if name not in found and (d / name).is_file() and (d / name).stat().st_size > 0:
                found.append(name)
    return found


BLANK_SHOT_BYTES = 12_000  # a 1280x900 capture of a page with real content is far larger than this


def _shot_note(path: Path) -> str:
    """Say out loud when a capture is essentially empty, instead of showing a white rectangle."""
    try:
        if path.stat().st_size < BLANK_SHOT_BYTES:
            return " (almost blank: the page returned little or no visible content)"
    except OSError:
        pass
    return ""


CSS = """
:root{--bg:#0f1115;--fg:#e6e8ec;--muted:#9aa3b2;--line:#232936;--card:#151a22;--accent:#7aa2ff;
--critical:#ff4d5e;--high:#ff8a3d;--medium:#e8c547;--low:#4dabf7;--info:#8b95a7;--ok:#3ddc97}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:920px;margin:0 auto;padding:48px 24px 80px}
h1{font-size:28px;line-height:1.25;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:18px;margin:40px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:0;flex:1}
h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:16px 0 6px}
p{margin:8px 0}
.meta{color:var(--muted);font-size:13px}
.meta code{color:var(--fg)}
.summary{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:24px 0}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0 28px}
.counts span{border:1px solid var(--line);border-radius:999px;padding:4px 11px;font-size:12px;color:var(--muted)}
.counts b{color:var(--fg);margin-right:5px}
.issue{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--info);border-radius:8px;
padding:16px 18px;margin:14px 0}
.issue.sev-critical{border-left-color:var(--critical)} .issue.sev-high{border-left-color:var(--high)}
.issue.sev-medium{border-left-color:var(--medium)} .issue.sev-low{border-left-color:var(--low)}
.issue header{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.issue.fixed{opacity:.86}
.pill{font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:2px 8px;border-radius:999px;
border:1px solid var(--line);color:var(--muted)}
.p-fixed{border-color:var(--ok);color:var(--ok)}
.p-proposed{border-color:var(--medium);color:var(--medium)}
.p-open{border-color:var(--critical);color:var(--critical)}
.pill.sev{border-color:transparent}
.pf-confirmed{border-color:var(--ok);color:var(--ok)}
.pf-suspected{border-color:var(--medium);color:var(--medium)}
.pf-not_reproduced,.pf-unproven{border-color:var(--line);color:var(--muted)}
dl.probe{margin:4px 0;font-size:13px}dl.probe .kv{display:flex;gap:10px}
dl.probe dt{color:var(--muted);min-width:64px}dl.probe dd{margin:0}
.where code,code{background:#0b0e13;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:13px}
.repro{margin:6px 0 0;padding-left:20px}.repro li{margin:3px 0}
.src{font-size:12px;color:var(--muted)}
table.steps{width:100%;border-collapse:collapse;font-size:13px}
table.steps th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:6px 8px}
table.steps td{border-bottom:1px solid var(--line);padding:6px 8px;vertical-align:top}
td.n{color:var(--muted);width:28px} td.ok{color:var(--ok)} td.no{color:var(--high)}
.shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.shots figure{margin:0}.shots img{width:100%;border:1px solid var(--line);border-radius:6px;display:block}
.shots figcaption{font-size:11px;color:var(--muted);margin-top:5px;word-break:break-all}
.callout{border:1px solid var(--line);border-left:3px solid var(--medium);background:var(--card);border-radius:8px;
padding:12px 16px;font-size:14px;margin:16px 0}
ul.next{padding-left:20px} ul.next li{margin:4px 0}
footer{margin-top:56px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
@media print{body{background:#fff;color:#111}main{padding:0}
.issue,.summary{background:#fff;border-color:#ddd}code{background:#f4f4f4}}
"""


def render(run: dict, findings: list, variant: str) -> str:
    """variant: 'as-found' or 'as-fixed'. Returns a complete self-contained HTML document."""
    fixed_view = variant == "as-fixed"
    issues = _issues(run, findings)
    rep = run.get("report") or {}
    counts = _counts(issues)

    if fixed_view:
        applied = [i for i in issues if i["applied"]]
        pending = [i for i in issues if not i["applied"]]
        title = "What we found and fixed"
        intro = ("The issues below were confirmed with evidence. The ones marked fixed were changed and "
                 "re-checked. Anything marked proposed has not been applied, so treat it as work left on the table.")
        blocks = "".join(_issue_block(n, i, True) for n, i in enumerate(applied, 1))
        pending_blocks = "".join(_issue_block(n, i, True) for n, i in enumerate(pending, len(applied) + 1))
        body_issues = (blocks or "<p>No fix has been applied yet for this run.</p>")
        if pending:
            body_issues += ('<h2>Proposed, not applied</h2>'
                            '<div class="callout">These are still open. The fix column is a plan, not a record.'
                            "</div>" + pending_blocks)
        headline = (f"{len(applied)} fixed, {len(pending)} still open." if issues
                    else "Nothing was confirmed in this run.")
    else:
        title = "What we found"
        intro = ("Only problems with evidence behind them are listed. A reproduced issue was sent a request by the "
                 "analyst and answered with the expected signal after a clean control, and the steps are here so "
                 "you can repeat it.")
        body_issues = "".join(_issue_block(n, i, False) for n, i in enumerate(issues, 1)) or \
            "<p>No reproduced issues. That can also mean the checks that would have found them did not run; see the activity below.</p>"
        proved = sum(1 for i in issues if i["proof"] == "confirmed")
        unproven = len(issues) - proved
        headline = ((f"{proved} reproduced issue{'s' if proved != 1 else ''}." if proved else "Nothing was reproduced.")
                    + (f" {unproven} more could not be reproduced here." if unproven else ""))

    nexts = "".join(f"<li>{_esc(x)}</li>" for x in (rep.get("next_steps") or []))
    notable = "".join(f"<li>{_esc(x)}</li>" for x in (rep.get("notable") or []))
    shots = _shots(run)
    shot_html = ""
    if shots:
        shot_html = ('<h2>Screenshots</h2><div class="shots">' + "".join(
            f'<figure><img src="shots/{html.escape(s)}" alt="{html.escape(s)}" width="640">'
            f"<figcaption>{html.escape(s)}{_shot_note(config.EVIDENCE_DIR / 'shots' / s)}</figcaption></figure>"
            for s in shots) + "</div>")
    counter = "".join(f"<span><b>{counts[k]}</b>{k}</span>" for k in SEV_ORDER if counts[k])
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = run.get("status") or "unknown"
    status_note = ("" if status == "done" else
                   '<div class="callout">The analyst stopped early '
                   f'({html.escape(str(run.get("error") or status))}), so this assessment is partial.</div>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tirith, {html.escape(title)} ({html.escape(variant)})</title>
<style>{CSS}</style></head>
<body><main>
<p class="meta">Tirith assessment &middot; {html.escape(variant)} &middot; generated {stamp}</p>
<h1>{html.escape(title)}</h1>
<p class="meta">Run <code>{html.escape(str(run.get("id") or "?"))}</code> &middot; status {html.escape(status)}
&middot; {len(run.get("steps") or [])} steps &middot; started {html.escape(str(run.get("started_at") or "?"))}</p>
<div class="summary"><p>{html.escape(intro)}</p>
<strong>{html.escape(headline)}</strong>
<p class="meta">Asked: {_esc(run.get("goal") or "")}</p></div>
<div class="counts">{counter}</div>
{status_note}
{f'<h2>In short</h2><p>{_esc(rep.get("summary"))}</p>' if rep.get("summary") else ""}
{f'<h2>Worth knowing</h2><ul class="next">{notable}</ul>' if notable else ""}
<h2>Issues</h2>
{body_issues}
{f'<h2>What to do next</h2><ul class="next">{nexts}</ul>' if nexts else ""}
{shot_html}
<h2>What the analyst did</h2>
{_activity(run)}
<footer>Generated by Tirith from run data and the analyst's notes. Prose is trimmed by a humanizer pass:
short sentences, plain words. Nothing here was written to sound impressive.</footer>
</main></body></html>
"""


def render_run(run_id: str, variant: str = "as-found", out_dir: Path | None = None) -> Path:
    """Write one HTML report and copy the referenced screenshots next to it. Returns the file path."""
    from ..remediation import core

    run_file = config.EVIDENCE_DIR / "analyst" / f"{run_id}.json"
    if not run_file.is_file():
        raise FileNotFoundError(f"no analyst run {run_id!r}")
    run = json.loads(run_file.read_text())
    findings = core.list_findings()
    out_dir = out_dir or (config.EVIDENCE_DIR / "reports" / run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    shots_src = config.EVIDENCE_DIR / "shots"
    if shots_src.is_dir():
        dst = out_dir / "shots"
        dst.mkdir(exist_ok=True)
        for p in shots_src.glob("*.png"):
            if p.stat().st_size:
                try:
                    (dst / p.name).write_bytes(p.read_bytes())
                except OSError:
                    pass
    out = out_dir / f"{variant}.html"
    out.write_text(render(run, findings, variant))
    return out