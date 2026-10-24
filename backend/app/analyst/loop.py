"""Autonomous security analyst: the model plans, code executes.

The loop is a strict ReAct cycle. Exactly one JSON object comes back per turn:

    {"thought": "...", "action": {"tool": "<name>", "args": {...}}}
    {"thought": "...", "done": true, "report": {...}}

`app.analyst.tools.ToolRegistry` runs the action and returns an observation; the observation is the
only thing fed back. The model never executes anything, never names a command, and never sees or
produces a shell line — it selects a registered tool and fills a schema-validated argument object.

Bounds enforced here, not by the model:
  - `max_steps` tool calls per run (default ANALYST_MAX_STEPS), plus a wall-clock budget.
  - A tool call that succeeds may not be repeated (same tool + arguments): the model cannot loop on a
    probe. A call that was refused may be retried — the model is expected to fix the precondition
    (e.g. register the host, then discover it).
  - Tools are scope-checked internally (every host/URL/repo goes through `scope.enforce`), so a
    hallucinated target is refused and returned to the model as an observation, not executed.
  - `finish` is always available: the loop ends on a terminal answer, a step budget, or an error.

Every turn is appended to the run transcript (JSONL, secrets masked) and emitted as an
`analyst.*` event so the dashboard can show the reasoning live.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .. import config, events
from ..audit import audit
from ..events import emit
from ..models import new_id, now_iso
from ..remediation import llm
from ..store import get_store

SYSTEM = """You are Tirith's autonomous security analyst, working on infrastructure the owner explicitly put in scope.

Each turn you choose ONE tool call. Available tools and their JSON arguments:

{tools}

Rules:
- Never invent targets. Only use hosts/assets already in scope (discovery will refuse others).
- A web app given as `localhost:<port>` or `localhost` in the goal is the service published on that host, not the
  container's own loopback: register it as a `url` asset (`http://127.0.0.1:<port>` / `http://127.0.0.1`) before
  scanning it, otherwise scanners reach whatever their own container runs.
- Start broad, then narrow: discover what exists before scanning it; scan before validating; validate before fixing.
- Reproducing a finding is what turns a suspicion into evidence. Prefer it over guessing.
- For a code finding use `reproduce` (finding id) or `probe` (your own observation, with a `prove` block).
  A reproduction that works is the ONLY thing that proves a flaw; the report is checked against it.
- For a live service, `http` replays ONE request against its isolated lab copy: a benign control, then the
  same request with a payload in ONE parameter. Both must be sent; report what each answered.
- Do not repeat a call you already made; the recorder will refuse duplicates.
- Stop when the goal is met. `finish` is the only way to end the run.

Reply with ONLY one JSON object, no prose, either:
  {{"thought": "<one sentence>", "action": {{"tool": "<name>", "args": {{...}}}}}}
or, to finish:
  {{"thought": "<one sentence>", "done": true, "report": {{"summary": "...", "notable": ["..."], "next_steps": ["..."]}}}}

When you finish, also fill `issues` for every problem you actually confirmed with evidence — leave out anything you
merely suspect, and say plainly what was not checked:
  "issues": [{{
    "title": "<short, specific>",
    "severity": "critical|high|medium|low|info",
    "where": "<host:port, url, or file:line>",
    "finding_id": "<fnd_... if the issue came from a finding, else omit>",
    "evidence": "<what you saw, in one or two sentences: the actual response/observation>",
    "prove": "method: <GET|POST>\npath: </path>\nparam: <parameter you varied>\npayload: <what you sent>\nsignal: <what proves it>",
    "reproduce": ["<step 1>", "<step 2>"],
    "impact": "<what an attacker could actually do with it>",
    "fix": "<the concrete change that closes it>",
    "fix_status": "applied|proposed"
  }}]
`fix_status` is "applied" only if a fix was really applied and re-checked; otherwise "proposed". Never claim applied
for a change you did not make and verify. Set `severity` from what the reproduction showed: critical/high only when
the probe returned real data or output, medium for a strong static case, low/info for hygiene. Write for a busy
human: short sentences, no filler, no marketing."""

log = logging.getLogger("tirith.analyst")

OBS_MAX = 3000  # characters of tool output fed back per turn


@dataclass
class Step:
    n: int
    thought: str
    tool: str | None
    args: dict[str, Any] = field(default_factory=dict)
    observation: str = ""
    ok: bool = True
    at: str = field(default_factory=now_iso)
    ms: int = 0

    def to_dict(self) -> dict:
        return {"n": self.n, "thought": self.thought, "tool": self.tool, "args": self.args,
                "observation": self.observation, "ok": self.ok, "at": self.at, "ms": self.ms}


@dataclass
class AnalystRun:
    id: str
    goal: str
    steps: list[Step] = field(default_factory=list)
    status: str = "running"  # running | done | budget | error
    report: dict[str, Any] | None = None
    report_path: str | None = None
    error: str | None = None
    waiting_on: str | None = None
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None

    def to_dict(self) -> dict:
        return {"id": self.id, "goal": self.goal, "status": self.status, "waiting_on": self.waiting_on,
                "report": self.report,
                "report_path": self.report_path,
                "error": self.error, "started_at": self.started_at, "finished_at": self.finished_at,
                "steps": [s.to_dict() for s in self.steps]}


def max_steps() -> int:
    try:
        return max(1, min(24, int(__import__("os").environ.get("TIRITH_ANALYST_MAX_STEPS", "8"))))
    except ValueError:
        return 8


def run_path(run_id: str) -> Path:
    d = config.EVIDENCE_DIR / "analyst"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{run_id}.json"


def build_report(run: AnalystRun) -> str:
    """Markdown report: what was asked, what the analyst did, what it found, where the evidence is."""
    st = get_store()
    lines = [
        f"# Tirith analysis — {run.started_at}",
        "",
        f"**Goal.** {run.goal}",
        f"**Status.** {run.status}" + (f" ({run.error})" if run.error else ""),
        f"**Steps.** {len(run.steps)}",
        "",
    ]
    if run.report:
        lines += ["## Summary", "", str(run.report.get("summary") or "").strip(), ""]
        for key, title in (("notable", "Notable"), ("next_steps", "Recommended next steps"), ("risk", "Risk")):
            val = run.report.get(key)
            if isinstance(val, list) and val:
                lines += [f"### {title}", ""] + [f"- {v}" for v in val] + [""]
            elif isinstance(val, str) and val.strip():
                lines += [f"### {title}", "", val.strip(), ""]
    lines += ["## Activity", ""]
    for s in run.steps:
        status = "ok" if s.ok else "refused/failed"
        lines.append(f"{s.n}. **{s.tool}** ({status}, {s.ms} ms) — {s.thought}")
        if s.args:
            lines.append(f"   - args: `{json.dumps(s.args, default=str)[:300]}`")
        first = (s.observation or "").splitlines()[0][:300]
        lines.append(f"   - observed: `{first}`")
    # Same set posture counts (open statuses), labelled per asset: an all-assets table must not read as
    # the findings of the one target the goal names.
    findings = st.list_open_findings()[:20]
    if findings:
        names = {a.id: a.name or a.ref for a in st.list_assets()}
        lines += ["", "## Open findings across all assets (highest priority first)", "",
                  "| asset | severity | status | title | where |", "|---|---|---|---|---|"]
        for f in findings:
            where = f.url or (f"{f.file}:{f.line}" if f.file else "—")
            lines.append(f"| {names.get(f.asset_id, f.asset_id)} | {f.severity} | {f.status} | {f.title[:80]} | {where} |")
    shots = sorted((config.EVIDENCE_DIR / "shots").glob("*.png")) if (config.EVIDENCE_DIR / "shots").is_dir() else []
    if shots:
        lines += ["", "## Screenshots", ""] + [f"- `{p}`" for p in shots[-10:]]
    text = "\n".join(lines) + "\n"
    out = config.EVIDENCE_DIR / "analyst" / f"{run.id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    return str(out)


def _save(run: AnalystRun) -> None:
    try:
        run_path(run.id).write_text(json.dumps(run.to_dict(), indent=1))
    except OSError:
        pass


_TASK_OF = {"discover": "analyst_discover", "finish": "analyst_finish"}

_FORCED_SYSTEM = (
    "You are Tirith's analyst. You have run out of steps and may not call any tool. "
    "Summarise what the observations already show, in the owner's terms: what is exposed, what matters, "
    "and what to do next. Never invent a result that is not in an observation; say plainly when something "
    "was not checked. Reply with one JSON object: "
    '{"done": true, "report": {"summary": str, "notable": [str], "next_steps": [str], "issues": ['
    '{title, severity, where, evidence, reproduce: [str], impact, fix, fix_status}]}}.'
)


async def _forced_report(run_obj: AnalystRun) -> dict:
    """One last planner call that may only summarise: used when the step budget runs out."""
    steps = "\n".join(f"{s.n}. {s.tool or '?'} ok={s.ok}: {s.observation[:300]}" for s in run_obj.steps)
    ask = [
        {"role": "system", "content": _FORCED_SYSTEM},
        {"role": "user", "content": f"Goal: {run_obj.goal}\n\nObservations so far:\n{steps or '(none)'}\n\n"
                                    "Reply with one JSON object: {\"done\": true, \"report\": {...}}."},
    ]
    try:
        res = await asyncio.to_thread(llm.chat, ask, task=_TASK_OF.get("planner", "analyst_plan"),
                                      json_mode=True, deadline=llm.deadline_in(120))
        decision = _parse(res.content) or {}
        report = decision.get("report")
        if isinstance(report, dict):
            return await _checked_report(report, ask, res.content)
        if isinstance(report, str) and report.strip():
            return {"summary": report.strip()}
    except Exception:  # noqa: BLE001 - the fallback below must still produce something
        log.exception("forced report failed")
    ok = sum(1 for s in run_obj.steps if s.ok)
    return {"summary": f"Stopped after {len(run_obj.steps)} steps ({ok} succeeded) without a final answer; "
                       f"see the activity log for what was observed.",
            "notable": [f"{s.tool}: {s.observation[:160]}" for s in run_obj.steps if s.ok][-6:]}


def _parse(content: str) -> dict | None:
    """One JSON object out of the model's reply (tolerates a code fence or stray prose)."""
    text = (content or "").strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        return obj if isinstance(obj, dict) else None
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def _stub_turn(run_obj: AnalystRun, registry) -> dict[str, Any]:
    """Context for the deterministic stub plan: acted turns so far, and a tool worth calling first."""
    names = [n for n in registry.names() if n not in ("mode", "fix")] or registry.names()
    acted = sum(1 for s in run_obj.steps if s.ok)
    tool = names[acted] if acted < len(names) else ""
    args: dict[str, Any] = {}
    if tool == "findings":
        args = {"limit": 3}
    elif tool == "asset":
        args = {"kind": "host", "ref": "127.0.0.1"}
    elif tool in ("posture", "mode"):
        args = {}
    else:  # needs arguments the stub cannot know: keep them out of the plan
        tool = ""
    return {"turn": acted, "tool": tool, "args": args, "title": "stub"}


def _observation(payload: Any) -> str:
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    return text if len(text) <= OBS_MAX else text[:OBS_MAX] + f"…[{len(text) - OBS_MAX} chars omitted]"


class ReportIssue(BaseModel):
    """One `issues` item of the model's final report. `fix_status` is strict; `proof`/`severity` are
    left unset by validation so the gate's grading is not overwritten by a default."""
    model_config = ConfigDict(extra="allow")

    title: str | None = None
    severity: str | None = None  # critical|high|medium|low|info, plus `suspected` once graded
    where: str | None = None
    finding_id: str | None = None
    evidence: str | None = None
    prove: str | None = None          # the probe that established it (kept even when unproven)
    grade: str | None = None          # critical|high|suspected, what the probe actually reached
    proof: str | None = None          # confirmed|suspected|not_reproduced|unproven, set by the gate
    reproduce: list[str] = Field(default_factory=list)
    impact: str | None = None
    fix: str | None = None
    fix_status: Literal["applied", "proposed"] = "proposed"

    @field_validator("reproduce", mode="before")
    @classmethod
    def _steps(cls, v: Any) -> Any:
        if v is None:
            return []
        return [v] if isinstance(v, str) else v


class AnalystReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    issues: list[ReportIssue] = Field(default_factory=list)


def _validate_report(report: dict) -> dict:
    """Raises ValidationError when the report does not match the schema; returns the normalised dict."""
    return AnalystReport.model_validate(report).model_dump(exclude_none=True)


def _coerce_report(report: dict) -> dict:
    """Last resort after a failed retry: an unknown `fix_status` falls back to "proposed"; keep the rest."""
    issues = report.get("issues")
    if isinstance(issues, list):
        for it in issues:
            if not isinstance(it, dict):
                continue
            if it.get("fix_status") not in ("applied", "proposed"):
                it["fix_status"] = "proposed"
    try:
        return _validate_report(report)
    except ValidationError:
        return report


def _fix_really_applied(finding_id: Any) -> bool:
    """True only when the store records the finding as fixed or one of its fixes as verified/applied."""
    if not finding_id or not isinstance(finding_id, str):
        return False
    try:
        st = get_store()
        f = st.get_finding(finding_id)
        if f is None:
            return False
        return f.status == "fixed" or any(fx.status in ("applied", "verified") for fx in st.list_fixes(finding_id))
    except Exception:  # noqa: BLE001 - when in doubt, do not claim applied
        return False


def _ground_report(report: dict) -> dict:
    """"applied" stands only when the store backs it up; anything else is downgraded to "proposed"."""
    for it in report.get("issues") or []:
        if isinstance(it, dict) and it.get("fix_status") == "applied" and not _fix_really_applied(it.get("finding_id")):
            it["fix_status"] = "proposed"
    return report


_GRADES = {"critical": "critical", "high": "high", "suspected": "suspected", "not_reproduced": "not_reproduced"}
_PROVED = {"critical", "high"}


def issue_plan(it: dict, steps: list) -> tuple[dict, Any]:
    """The class probe that would prove this issue, plus the lab evidence already obtained for it.

    The model's own `prove` block wins, then a `probe`/`reproduce` step it made for this issue, then
    the finding's stored request. Observations (default titles) that match no class get no probe."""
    from . import probe

    proposal = str(it.get("prove") or "") or None
    evidence_text = str(it.get("evidence") or "")
    for s in reversed(steps or []):
        if not s.ok or s.tool not in ("reproduce", "probe"):
            continue
        f_ids = {s.args.get("finding_id"), s.args.get("url"), s.args.get("title")}
        where = str(it.get("where") or "")
        hit = (it.get("finding_id") and it["finding_id"] in f_ids) or (where and any(
            isinstance(col, str) and col and (col in where or where in col) for col in f_ids))
        if not hit:
            continue
        proposal = proposal or s.args.get("proposal") or None
        evidence_text += f"\n{s.observation[:600]}"
        break
    url = evidence_url_of(it)
    if it.get("finding_id"):
        try:
            f = get_store().get_finding(it["finding_id"])
        except Exception:  # noqa: BLE001 - a store hiccup must not lose the report
            f = None
        if f is not None:
            url = probe.evidence_url(f.url, f.snippet) or url
            evidence_text += f"\n{f.snippet or ''}"
    plan = probe.plan_for(f"{it.get('title') or ''} {where_text(it)}", url, evidence_text, proposal=proposal)
    return (plan.to_dict(), plan) if plan else ({}, None)


def evidence_url_of(it: dict) -> str:
    from . import probe

    return probe.evidence_url(str(it.get("where") or "").strip() or None, str(it.get("evidence") or ""))


def where_text(it: dict) -> str:
    return " ".join(str(it.get(k) or "") for k in ("where", "evidence", "prove"))


def _step_for(it: dict, run_obj: AnalystRun, prove: str) -> str:
    """Index ("step:<n>") of the step that proved this issue, or '' when none did."""
    for i in range(len(run_obj.steps) - 1, -1, -1):
        s = run_obj.steps[i]
        if s.ok and s.tool in ("probe", "reproduce") and s.args.get("proposal") == prove and prove:
            return f"step:{i}"
        if s.ok and s.tool in ("probe", "reproduce") and it.get("finding_id") and \
                s.args.get("finding_id") == it["finding_id"]:
            return f"step:{i}"
        if s.ok and s.tool in ("probe", "reproduce") and it.get("where") and \
                s.args.get("url") == it["where"]:
            return f"step:{i}"
    return ""


async def proof_gate(run_obj: AnalystRun, registry) -> None:
    """Every finding-class issue must have a probe that ran and worked. The loop tries it for the model.

    For each issue with no matching probe step: run the probe once against the lab. The result sets
    `proof`, `severity` (never below the validated grade) and the reproduction steps; a failed probe
    demotes the claimed severity to the grade it actually reached. `prove` keeps the plan so the
    report renderer can restate the steps. Issues that already ran are not re-sent. Every finding-class
    issue is tried, whether or not the model probed anything during the run."""
    for it in (run_obj.report or {}).get("issues") or []:
        if not isinstance(it, dict):
            continue
        done = _step_for(it, run_obj, str(it.get("prove") or ""))
        plan, _ = issue_plan(it, run_obj.steps)
        if not plan and not it.get("finding_id"):
            it.setdefault("proof", "unproven")
            continue
        if not plan and it.get("finding_id"):
            # the finding's URL and title were already in the text: let the class payload be built from them
            from . import probe as _probe

            p2 = _probe.plan_for(str(it.get("title") or ""), evidence_url_of(it), str(it.get("evidence") or ""))
            plan = p2.to_dict() if p2 else {}
        if not plan:
            it.setdefault("proof", "unproven")
            continue
        if done:
            res = run_obj.steps[int(done.split(":")[1])]
            try:
                got = json.loads(res.observation)
            except ValueError:
                got = {}
            if not isinstance(got, dict):
                got = {}
            it["prove"] = "\n".join(f"{k}: {v}" for k, v in plan.items() if k in ("method", "path", "param", "payload", "signal"))
            it["proof"] = "confirmed" if got.get("proof") else _GRADES.get(str(got.get("result") or ""), "unproven")
            it["grade"] = got.get("grade") or ""
            it["reproduce"] = got.get("reproduce") or it.get("reproduce") or []
            # A probe that found nothing at all outranks a "confirmed" claim for a negative/error result.
            _downgrade(it, str(got.get("result") or ""), got.get("grade"))
            continue
        text = "\n".join(f"{k}: {v}" for k, v in plan.items() if k in ("method", "path", "param", "payload", "signal"))
        step = Step(n=len(run_obj.steps) + 1, thought=f"auto-probe {plan['weakness']} for: {str(it.get('title'))[:90]}",
                    tool="probe")
        step.args = {**{"title": str(it.get("title") or plan["weakness"]), "url": evidence_url_of(it)}, "proposal": text}
        try:
            res = await registry.call("probe", step.args)
            step.observation, step.ok = _observation(res), True
        except Exception as e:  # noqa: BLE001 - an unprovable issue is still reported
            step.observation, step.ok = f"tool error: {type(e).__name__}: {str(e)[:300]}", False
        run_obj.steps.append(step)
        _save(run_obj)
        if not step.ok or not isinstance(res, dict):
            it["proof"] = "unproven"
            it["severity"] = "suspected"
            continue
        grade = res.get("grade")
        verdict = res.get("result") or "unproven"
        it["prove"] = text
        it["grade"] = grade or ""
        it["proof"] = "confirmed" if res.get("proof") else _GRADES.get(verdict, "unproven")
        it["reproduce"] = res.get("reproduce") or it.get("reproduce") or []
        claimed = str(it.get("severity") or "info")
        if grade in _PROVED:
            if _SEV_RANK.get(grade, 9) < _SEV_RANK.get(claimed, 9):
                it["severity"] = grade
        elif grade == "suspected":
            if _SEV_RANK.get(claimed, 9) < _SEV_RANK["suspected"]:
                it["severity"] = "suspected"
        else:
            _downgrade(it, verdict, grade)


def _downgrade(it: dict, verdict: str, grade: str | None) -> None:
    """Not reproduced: never above `suspected`. Suspected: never above `suspected` either."""
    cap = "suspected" if verdict in ("suspected", "not_reproduced", "error") or grade == "suspected" else None
    if cap and _SEV_RANK.get(str(it.get("severity") or "info"), 9) < _SEV_RANK[cap]:
        it["severity"] = cap
        it["evidence"] = f"{it.get('evidence') or ''} (probe says {verdict})".strip()


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "suspected": 3, "low": 4, "info": 5}


async def _checked_report(report: dict, messages: list[dict[str, str]], reply: str) -> dict:
    """Validate the final report; on failure re-ask the model once with the error, then coerce. Always grounded."""
    try:
        return _ground_report(_validate_report(report))
    except ValidationError as e:
        err = str(e)[:1500]
    emit("analyst.thinking", "Final report failed validation; asking the model to correct it", level="warn")
    ask = list(messages) + [
        {"role": "assistant", "content": (reply or "")[:4000]},
        {"role": "user", "content": f"Your report failed validation:\n{err}\n\nReply with only the corrected JSON "
                                    "object {\"done\": true, \"report\": {...}}. fix_status must be \"applied\" or "
                                    "\"proposed\"."},
    ]
    try:
        res = await asyncio.to_thread(llm.chat, ask, task=_TASK_OF.get("planner", "analyst_plan"),
                                      json_mode=True, deadline=llm.deadline_in(120))
        again = _parse(res.content) or {}
        fixed = again.get("report") if isinstance(again.get("report"), dict) else None
        if fixed is not None:
            try:
                return _ground_report(_validate_report(fixed))
            except ValidationError:
                report = fixed
    except Exception:  # noqa: BLE001 - a failed retry falls back to coercion
        log.exception("report correction call failed")
    return _ground_report(_coerce_report(report))


async def _gate(run_obj: AnalystRun, why: str, timeout: float = 1800.0) -> None:
    """Hold at a proof checkpoint until the user answers (or the wait expires, then continue)."""
    from .. import events as ev

    run_obj.waiting_on = why
    ev.pause(run_obj.id, why)
    emit("analyst.checkpoint", f"Waiting for approval: {why}", level="warn", data={"run_id": run_obj.id})
    waited = await ev.checkpoint(timeout)
    if waited and ev.paused():
        emit("analyst.checkpoint", "Checkpoint wait expired; continuing", level="warn", data={"run_id": run_obj.id})
        ev.resume()
    run_obj.waiting_on = None
    emit("analyst.resumed", "Checkpoint answered; the analyst continues", data={"run_id": run_obj.id})


async def run(goal: str, registry, *, run_id: str | None = None, on_step=None,
              max_steps_override: int | None = None, pause_after_proof: bool = False) -> AnalystRun:
    """Drive the analyst loop to completion. `registry` is an AnalystTools instance."""
    run_obj = AnalystRun(id=run_id or new_id("arn"), goal=goal)
    budget = max(1, min(24, max_steps_override or max_steps()))
    deadline = time.monotonic() + float(__import__("os").environ.get("TIRITH_ANALYST_SECONDS", "600"))
    seen: set[str] = set()
    history: list[dict[str, str]] = []
    original_mode = get_store().get_mode()
    audit("analyst.start", target=run_obj.id, details={"goal": goal[:300], "max_steps": budget})
    emit("analyst.started", f"Analyst run started: {goal[:120]}", data={"run_id": run_obj.id})

    system = SYSTEM.format(tools=registry.describe())
    history.append({"role": "system", "content": system})
    history.append({"role": "user", "content": f"Goal: {goal}\n\nStart with one tool call."})

    try:
        for n in range(1, budget + 1):
            held = await events.checkpoint()
            if held:
                emit("analyst.checkpoint", "Resumed after the pause", data={"run_id": run_obj.id})
            if time.monotonic() > deadline:  # a pause does not spend the clock: give the step one more
                if not held:
                    run_obj.status, run_obj.error = "budget", "wall-clock budget exceeded"
                    break
                deadline = time.monotonic() + 1.0
            res = await asyncio.to_thread(
                llm.chat, list(history), task=_TASK_OF.get("planner", "analyst_plan"),
                json_mode=True, deadline=llm.deadline_in(120),
                stub_context=_stub_turn(run_obj, registry),
            )
            decision = _parse(res.content)
            if decision is None:
                emit("analyst.thinking", "Model reply was not a JSON decision; asking again", level="warn",
                     data={"run_id": run_obj.id})
                history.append({"role": "assistant", "content": (res.content or "")[:1000]})
                history.append({"role": "user", "content": "That was not one JSON object. Reply with only the JSON object."})
                continue

            thought = str(decision.get("thought") or "")[:600]
            if decision.get("done"):
                run_obj.report = await _checked_report(decision["report"], history, res.content) if isinstance(
                    decision.get("report"), dict) else {"summary": str(decision.get("report") or thought)}
                await proof_gate(run_obj, registry)
                run_obj.status = "done"
                emit("analyst.finished", f"Analyst finished: {str(run_obj.report.get('summary'))[:200]}",
                     level="success", data={"run_id": run_obj.id, "report": run_obj.report})
                break

            action = decision.get("action") or {}
            tool = str(action.get("tool") or "").strip()
            args = action.get("args") if isinstance(action.get("args"), dict) else {}
            # `mode` joins the key: `fix` in observe is refused and decides nothing about the same fix in assisted.
            key = f"{tool}:{get_store().get_mode().mode}:{json.dumps(args, sort_keys=True, default=str)}"
            step = Step(n=n, thought=thought, tool=tool, args=args)
            t0 = time.monotonic()
            emit("analyst.thinking", thought or f"calling {tool}", data={"run_id": run_obj.id, "step": n, "tool": tool})

            if not tool or tool not in registry.names():
                step.ok = False
                step.observation = f"unknown tool {tool!r}; available: {', '.join(registry.names())}"
            elif key in seen:
                step.ok = False
                step.observation = "refused: you already made this exact call; choose a different action or finish"
            else:
                emit("analyst.action", f"{tool} {_observation(args)[:160]}", data={"run_id": run_obj.id, "step": n,
                                                                                  "tool": tool, "args": args})
                try:
                    result = await registry.call(tool, args)
                    step.observation = _observation(result)
                    seen.add(key)  # only a call that actually ran counts: a refused one may be retried
                except Exception as e:  # noqa: BLE001 - a tool failure is an observation, not a crash
                    step.ok = False
                    step.observation = f"tool error: {type(e).__name__}: {str(e)[:400]}"
                    # A refusal is a decision about the plan itself, so the model must not repeat the same call
                    # unchanged (live: fix -> "switch mode" -> same fix -> fix -> "assisted never merges" -> fix).
                    if type(e).__name__ == "FixRefused":
                        seen.add(key)
                emit("analyst.observation", step.observation[:200],
                     level="success" if step.ok else "warn",
                     data={"run_id": run_obj.id, "step": n, "tool": tool, "ok": step.ok})
            step.ms = int((time.monotonic() - t0) * 1000)
            run_obj.steps.append(step)
            _save(run_obj)
            if on_step:
                try:
                    on_step(run_obj)
                except Exception:  # noqa: BLE001
                    pass
            history.append({"role": "assistant", "content": json.dumps(
                {"thought": thought, "action": {"tool": tool, "args": args}})})
            history.append({"role": "user", "content": f"Observation from {tool or 'unknown'}:\n{step.observation}"})
            if pause_after_proof and not run_obj.waiting_on and step.ok and step.tool in ("reproduce", "probe"):
                await _gate(run_obj, f"first reproduction done ({step.tool}); approve the rest, or switch to a fix")
        else:
            if pause_after_proof and not run_obj.waiting_on:
                await _gate(run_obj, "step budget reached; confirm whether more is needed")
            run_obj.status = "budget"
            run_obj.error = f"step budget of {budget} reached without finishing"
            # Out of steps is not an excuse for an empty answer: ask once more, report-only and
            # with no tool allowed, so a user still gets what was learned.
            run_obj.report = await _forced_report(run_obj)
            await proof_gate(run_obj, registry)
            emit("analyst.finished", run_obj.error, level="warn",
                 data={"run_id": run_obj.id, "report": run_obj.report})
    except llm.LLMError as e:
        run_obj.status, run_obj.error = "error", f"model unavailable: {e}"
        emit("analyst.finished", run_obj.error, level="error", data={"run_id": run_obj.id})
    except Exception as e:  # noqa: BLE001
        run_obj.status, run_obj.error = "error", f"{type(e).__name__}: {e}"
        emit("analyst.finished", run_obj.error, level="error", data={"run_id": run_obj.id})
    finally:
        # A run that lifted the mode for its fixes puts the server back where the owner left it.
        try:
            now = get_store().get_mode()
            if now.transient and now.mode != original_mode.mode:
                emit("mode.changed", f"Remediation mode: {now.mode} -> {original_mode.mode} (run {run_obj.id})",
                     data=original_mode.model_dump())
                get_store().set_mode(original_mode)
        except Exception:  # noqa: BLE001 - the mode must never fail a run
            log.exception("restoring the mode failed")
        run_obj.finished_at = now_iso()
        try:
            run_obj.report_path = build_report(run_obj)
        except Exception:  # noqa: BLE001 - a missing report must not fail the run
            log.exception("building the analysis report failed")
        _save(run_obj)
        audit("analyst.finished", target=run_obj.id,
              details={"status": run_obj.status, "steps": len(run_obj.steps), "error": run_obj.error})
        try:
            get_store().set_kv("analyst:last", run_obj.id)
        except Exception:  # noqa: BLE001
            pass
    return run_obj