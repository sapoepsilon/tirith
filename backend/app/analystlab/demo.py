"""The analyst-lab demo as four explicit stages, each independently callable from the API.

  start    register asset+finding, ensure both lab variants are booted and verified, capture the
           fixed-code baseline (low identity is denied), then run the model-planned loop on the
           VULNERABLE variant only.
  get      the recorded run/state (memory, then the artifact on disk).
  apply    stage the demo fix on a new branch and open a PR for the demo asset (assisted/observe:
           `fix.propose_fix`; refused by remediation in observe mode). Explicit opt-in only.
  check    deterministic recheck: the SAME request, as the SAME identity, against the patched
           container; plus the same request on the vulnerable container for contrast.
  reset    stop both demo lab copies (artifacts keep their history) and forget in-memory state.

Live model output (`analyst.*`, `mode: "live"`) is kept structurally apart from deterministic results
(`baseline`, `regression_check`), which never involve the model.
"""

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import asdict, dataclass, field

from .. import config
from ..audit import audit
from ..models import new_id, now_iso
from ..store import get_store
from . import http, lab as labmod, loop, regression

LOW = regression.LOW_USER
# The deterministic check always runs the finding's own request (same path + `?as=`), whatever the
# model discovered: the comparison must not depend on the model's choices.
CHECK_PATH = regression.DEFAULT_PATH
# The goal names the outcome the owner wants ("does a low-privilege caller reach the protected page or the
# flag?") and the budget, never a route, parameter or payload: discovery is the model's job.
GOAL = (
    "This is a small, deliberately vulnerable training web app with dummy data. A synthetic low-privilege "
    "identity (you always act as `demo-low`) should not be able to read protected material. Explore the app "
    "from its own responses and determine, with at most {budget} read-only GET requests, whether it does, and "
    "what exactly you observed. Report only what the responses show."
)

_lock = threading.Lock()
_runs: dict[str, "Scenario"] = {}
_tasks: set = set()  # asyncio keeps only weak refs to tasks; hold them until done


@dataclass
class Scenario:
    id: str
    goal: str
    status: str = "running"  # running | done | budget | error | attacked | checked
    mode: str = "live"
    model: str | None = None
    baseline: dict | None = None
    analyst: dict | None = None
    analyst_evidence: list[dict] = field(default_factory=list)
    regression_check: dict | None = None
    regression_vulnerable: dict | None = None
    classes: dict = field(default_factory=lambda: {"app_authorization_bypass": None, "host_or_shell_compromise": None})
    fix: dict | None = None
    handles: dict = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    stage: str = "start"

    def to_dict(self) -> dict:
        return asdict(self)


def _dir():
    d = config.EVIDENCE_DIR / "analystlab"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write(sc: Scenario) -> None:
    try:
        p = _dir() / f"{sc.id}.json"
        p.write_text(json.dumps(sc.to_dict(), indent=2, ensure_ascii=False))
        sc.artifacts["scenario"] = str(p)
        md = _dir() / f"{sc.id}.md"
        md.write_text(_markdown(sc))
        sc.artifacts["report"] = str(md)
        get_store().set_kv("analystlab:last_run", json.dumps({"id": sc.id, "status": sc.status, "stage": sc.stage}))
    except OSError:
        pass


def _markdown(sc: Scenario) -> str:
    L = [f"# Analyst-lab scenario {sc.id}", "",
         f"Goal: {sc.goal}", "",
         f"Status: **{sc.status}** · stage `{sc.stage}` · mode `{sc.mode}` · model `{sc.model or '-'}`", ""]
    if sc.handles:
        L += ["## Lab handles (verified)", ""]
        for k, v in sc.handles.items():
            L.append(f"- `{k}`: {v}" if isinstance(v, str) else
                     f"- `{k}`: variant {v.get('variant')}, container `{v.get('container')}`, network "
                     f"`{v.get('network')}`, image `{v.get('image')}`")
        L.append("")
    L += ["## Deterministic (fixed code, no model)", ""]
    if sc.baseline:
        b = sc.baseline
        L.append(f"- Baseline: `{b.get('request')}` as `{b.get('identity')}` -> HTTP {b.get('status')}, "
                 f"flag {'present' if b.get('flag') else 'absent'} ({b.get('note', '')})")
    if sc.regression_check:
        r = sc.regression_check
        L.append(f"- Patched recheck: `{r.get('request')}` as `demo-low` -> HTTP {r.get('status')}, "
                 f"flag {'present' if r.get('flag') else 'absent'}; baseline "
                 f"`{r.get('baseline', {}).get('request')}` -> HTTP {r.get('baseline', {}).get('status')} "
                 f"(verdict {r.get('result')})")
    if sc.regression_vulnerable:
        v = sc.regression_vulnerable
        L.append(f"- Vulnerable contrast: `{v.get('request')}` as `demo-low` -> HTTP {v.get('status')}, "
                 f"flag {'present' if v.get('flag') else 'absent'} (verdict {v.get('result')})")
    if sc.fix:
        L.append(f"- Fix: {sc.fix.get('status')} {sc.fix.get('pr_url') or ''} {sc.fix.get('error') or ''}")
    L.append("")
    a = sc.analyst or {}
    L += ["## Model-planned run (live model output)", "",
          f"- status `{a.get('status')}` · model `{a.get('model')}` · verdict `{a.get('verdict')}`", ""]
    if a.get("report"):
        rep = a["report"]
        L += [f"Summary: {rep.get('summary')}", ""]
        for e in rep.get("evidence") or []:
            L.append(f"- `{e.get('request', '?')}` -> {e.get('status', '?')}: {e.get('note', '')}")
        if rep.get("limitations"):
            L += ["", "Limitations:"] + [f"- {x}" for x in rep["limitations"]]
        L.append("")
    if sc.analyst_evidence:
        L += ["### Findings recorded from model-selected requests", ""]
        for ev in sc.analyst_evidence:
            L.append(f"- `{ev.get('request')}` (handle `{ev.get('handle')}`) -> HTTP {ev.get('status')}: "
                     f"{ev.get('note')}")
        L.append("")
    L += ["## Classification", "",
          f"- App authorization bypass: {json.dumps(sc.classes.get('app_authorization_bypass'))}",
          f"- Host/shell compromise: {json.dumps(sc.classes.get('host_or_shell_compromise'))}", ""]
    if sc.blockers:
        L += ["## Blockers / not done", ""] + [f"- {b}" for b in sc.blockers] + [""]
    if a.get("transcript_path"):
        L += [f"Full analyst transcript: `{a['transcript_path']}`", ""]
    return "\n".join(L) + "\n"


def _baseline(ref: labmod.LabRef) -> dict:
    r = http.get(ref, regression.DEFAULT_PATH.split("?")[0], as_user=LOW, label="demo baseline")
    flag = regression.FLAG_MARKER in r.body
    note = ("HTTP 403 for demo-low on its own page: baseline denied" if r.status == 403 else
            "Unexpected: low identity already reads the flag" if flag else f"HTTP {r.status} without the flag")
    audit("analystlab.baseline", target=f"{ref.handle}", actor="system",
          details={"identity": LOW, "status": r.status, "flag_present": flag})
    return {"request": f"GET {regression.DEFAULT_PATH.split('?')[0]}", "identity": LOW, "status": r.status,
            "flag": flag, "note": note, "elapsed_ms": r.elapsed_ms}


def _model_chat(messages, **kw):
    from ..remediation import llm

    if llm.provider() == "stub":
        # The stub provider cannot plan: say so instead of driving the loop with canned text.
        raise llm.LLMError("TIRITH_LLM_PROVIDER=stub cannot plan analyst actions; use the live model or dry_run")
    return llm.chat(messages, **kw)


def start(*, max_steps: int | None = None, dry_run: bool = False) -> Scenario:
    """Reserve the run atomically and return before Docker builds or model requests begin."""
    with _lock:
        if any(sc.status == "running" for sc in _runs.values()):
            raise labmod.HandleError("an analyst-lab scenario is already running")
        sc = Scenario(id=new_id("labdemo"), goal=GOAL.format(budget=max_steps or 10),
                      mode="dry" if dry_run else "live", stage="preparing")
        _runs[sc.id] = sc
        _write(sc)
    threading.Thread(target=_prepare, args=(sc, max_steps), name=f"analystlab-{sc.id}", daemon=True).start()
    return sc


def _prepare(sc: Scenario, max_steps: int | None) -> None:
    try:
        if sc.mode == "dry":
            sc.status, sc.stage = "done", "dry"
            sc.blockers.append("Dry run: no containers, model calls or HTTP requests executed.")
            sc.finished_at = now_iso()
            _write(sc)
            return
        asset = regression.ensure_demo_asset()
        finding = regression.ensure_demo_finding()
        sc.artifacts["finding"] = finding.id
        audit("analystlab.start", target=sc.id, actor="api", details={"finding": finding.id})
        for variant, handle in (("vulnerable", "docker-lab"), ("patched", "docker-lab-patched")):
            ref = labmod.for_asset(asset.id, variant) or labmod.boot_or_native(variant, asset_id=asset.id)
            sc.handles[handle] = ref.to_dict()
        sc.baseline = _baseline(labmod.resolve("docker-lab"))
        if sc.baseline["status"] != 403 or sc.baseline["flag"]:
            raise labmod.HandleError("the low-privilege baseline must deny access without returning the flag")
        sc.stage = "assessing"
        _write(sc)
        asyncio.run(_analyst_phase(sc, max_steps))
    except Exception as exc:
        sc.status = "error"
        sc.blockers.append(f"{type(exc).__name__}: {exc}")
        sc.finished_at = now_iso()
        _write(sc)


async def _analyst_phase(sc: Scenario, max_steps: int | None) -> None:
    budget = max_steps or 10
    try:
        run = await loop.run(GOAL.format(budget=budget), max_steps=max_steps, chat=_model_chat,
                             allowed_handles=("docker-lab",))
        sc.analyst = run.to_dict()
        sc.model = run.model
        sc.analyst_evidence = _evidence_from_run(run)
        # A model verdict is a model claim; "attacked" is only granted by check() from observations.
        sc.status = "done" if run.status == "done" else run.status
        if run.error:
            sc.blockers.append(f"analyst: {run.error}")
        sc.artifacts["analyst"] = run.transcript_path or ""
        sc.classes["app_authorization_bypass"] = {
            "deterministic": "pending: POST /api/analystlab/runs/{id}/check",
            "model_observed": next((e for e in sc.analyst_evidence if e.get("flag")), None),
            "model_verdict": (run.report or {}).get("verdict"),
        }
    except Exception as e:  # noqa: BLE001 - surfaced in the artifact, never hidden
        sc.blockers.append(f"{type(e).__name__}: {e}")
        sc.status = "error"
    finally:
        sc.finished_at = now_iso()
        _write(sc)



def _evidence_from_run(run: loop.LabRun) -> list[dict]:
    """Model-selected requests that returned the dummy flag, with the exact request and status."""
    out = []
    for s in run.steps or []:
        if not s.ok or s.tool != "http.get":
            continue
        q = s.args.get("query") or {}
        req = s.args.get("path", "") + (("?" + "&".join(f"{k}={v}" for k, v in q.items())) if q else "")
        body = s.observation or ""
        status = 0
        try:
            status = int(json.loads(body).get("response", {}).get("status") or 0)
        except (ValueError, TypeError):
            pass
        out.append({"request": f"GET {req}", "as_user": LOW, "status": status,
                    "handle": s.args.get("handle"), "flag": regression.FLAG_CONSTANT in body and status == 200,
                    "note": s.thought[:240]})
    return out


def check(scenario_id: str) -> Scenario:
    """Deterministic recheck: same request, same identity, against the patched and vulnerable labs."""
    sc = _get(scenario_id)
    if sc.status == "running":
        raise labmod.HandleError("the assessment is still running")
    if sc.mode != "live" or not sc.baseline or sc.baseline.get("status") != 403:
        raise labmod.HandleError("a live assessment with a denied baseline is required")
    selected = next((e for e in sc.analyst_evidence if e.get("status") == 200
                     and e.get("flag") and e.get("as_user") == LOW), None)
    if not selected:
        raise labmod.HandleError("no model-selected request returned the dummy flag; comparison would not prove a fix")
    request = selected["request"].removeprefix("GET ")
    sc.stage = "check"
    finding = get_store().get_finding(sc.artifacts.get("finding") or "") or regression.ensure_demo_finding()
    try:
        patched = labmod.resolve("docker-lab-patched")
        sc.regression_check = _recheck(patched, finding, request, label="patched")
    except labmod.HandleError as e:
        sc.blockers.append(f"patched recheck not run: {e}")
    try:
        vuln = labmod.resolve("docker-lab")
        sc.regression_vulnerable = _recheck(vuln, finding, request, label="vulnerable")
    except labmod.HandleError as e:
        sc.blockers.append(f"vulnerable contrast not run: {e}")
    if sc.regression_check and sc.regression_vulnerable:
        sc.classes["app_authorization_bypass"] = {
            "observed_on_vulnerable": sc.regression_vulnerable["result"],
            "observed_on_patched": sc.regression_check["result"],
            "same_request": sc.regression_check["request"],
            "deterministic": True,
        }
        sc.status = "checked" if (sc.regression_vulnerable["result"] == "confirmed" and sc.regression_check["result"] == "not_reproduced") else "partial"
    else:
        sc.status = "partial"
    sc.classes["host_or_shell_compromise"] = {
        "observed": "not tested; unavailable by design",
        "detail": "tools execute one read-only GET at the copy's loopback port; no shell, file, process or host tool",
    }
    sc.finished_at = now_iso()
    _write(sc)
    return sc


def _recheck(ref: labmod.LabRef, finding, request: str, *, label: str) -> dict:
    """Replay ONE exact request (`/path?query`, as demo-low) plus the identity's own baseline.

    The exact query is preserved: the "result" fields are the replay of the selected request as the
    low identity, and `baseline` is the same path with no query. Nothing here depends on the model."""
    from .regression import validate as validate_check

    v = validate_check(finding.id, ref, observed_path=request)
    exact = regression.exchange(ref, LOW, request)
    base = regression.exchange(ref, LOW, request.split("?")[0])
    return {"label": label, "variant": ref.variant, "handle": ref.handle, "container": ref.container,
            "request": exact.request, "status": exact.response.status, "flag": exact.flag,
            "baseline": {"request": base.request, "status": base.response.status, "flag": base.flag},
            "result": v.result, "validation_id": v.id,
            "verdict_note": next((e.content for e in v.evidence if e.label == "verdict"), "")}


def _get(scenario_id: str) -> Scenario:
    sc = _runs.get(scenario_id)
    if sc is not None:
        return sc
    p = _dir() / f"{scenario_id}.json"
    if not p.is_file():
        raise FileNotFoundError(scenario_id)
    data = json.loads(p.read_text())
    sc = Scenario(**{k: v for k, v in data.items() if k in Scenario.__dataclass_fields__})
    _runs[scenario_id] = sc
    return sc


def get(scenario_id: str) -> dict:
    return _get(scenario_id).to_dict()


def reset() -> dict:
    with _lock:
        if any(sc.status == "running" for sc in _runs.values()):
            raise labmod.HandleError("finish the active lab assessment before resetting")
        removed = labmod.reset_all()
    audit("analystlab.reset", target="analyst-lab", actor="api", details={"removed": removed})
    return {"removed": removed, "handles": labmod.status()}


__all__ = ["GOAL", "Scenario", "check", "get", "reset", "start"]