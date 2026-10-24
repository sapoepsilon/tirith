"""Explain one finding: finding + surrounding code -> {summary, root_cause, exploitability, fix_plan}.

Streams the model's reasoning as `ai.thinking` events and the result as `ai.summary`.
"""

from __future__ import annotations

from pathlib import Path

from . import core, llm
from .context import code_context, finding_brief, stub_ctx
from .core import Finding

SYSTEM = (
    "You are Tirith, a defensive application-security engineer. You explain scanner findings to the "
    "developer who owns the code. Be concrete and brief; reference the actual code. Never include "
    "secret values. You produce text only; you never run commands. Reply with ONLY a JSON object "
    'with string fields: "summary" (1-2 sentences), "root_cause", "exploitability" (who can reach it '
    'and what they gain; say so if it looks unreachable or a false positive), "fix_plan" (the '
    "minimal change, as steps)."
)

KEYS = ("summary", "root_cause", "exploitability", "fix_plan")


def build_messages(f: Finding, code: str) -> list[dict[str, str]]:
    user = finding_brief(f) + "\n\nCode context (>> marks the flagged line):\n```\n" + (code or "(not available)") + "\n```"
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]


def explain_finding(f: Finding, src_root: Path | None = None) -> dict[str, str]:
    core.audit("remediation.explain", target=f"finding:{f.id}", details={"rule_id": f.rule_id, "tool": f.tool})
    core.emit("ai.thinking", f"Analyzing {f.title}", finding_id=f.id, data={"phase": "start"})
    code = code_context(src_root, f)
    streamer = llm.ThinkingStreamer(
        lambda text: core.emit("ai.thinking", text, finding_id=f.id, data={"phase": "reasoning"})
    )
    try:
        data, res = llm.chat_json(
            build_messages(f, code), task="explain", on_reasoning=streamer, stub_context=stub_ctx(f),
            deadline=llm.deadline_in(),
        )
    except (llm.LLMError, ValueError) as e:
        streamer.flush()
        core.emit("ai.summary", f"Explanation failed: {e}", level="error", finding_id=f.id)
        core.audit("remediation.explain.error", target=f"finding:{f.id}", allowed=True, details={"error": str(e)[:300]})
        raise
    streamer.flush()
    out = {k: _as_text(data.get(k)) if isinstance(data, dict) else "" for k in KEYS}
    if not out["summary"]:
        out["summary"] = f.title
    core.update_finding(f.id, ai_summary=out["summary"])
    core.emit("ai.summary", out["summary"], level="success", finding_id=f.id, data={**out, "model": res.model})
    return out


def _as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return "\n".join(f"{i + 1}. {x}" for i, x in enumerate(v))
    if isinstance(v, dict):
        return "; ".join(f"{k}: {x}" for k, x in v.items())
    return str(v).strip()
