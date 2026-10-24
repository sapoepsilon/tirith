"""OpenAI-compatible chat client (self-hosted DeepSeek by default).

The model only ever returns text/JSON. Nothing it says is executed: callers parse the
JSON into fixed data structures (verdicts, diffs) and run their own fixed code paths.

Env:
  TIRITH_LLM_BASE_URL   default http://192.168.50.160:8010/v1
  TIRITH_LLM_API_KEY    bearer token, read lazily, never logged
  TIRITH_LLM_MODEL      default: first id from GET /models
  TIRITH_LLM_PROVIDER   "openai" (default) | "stub" (deterministic canned outputs, no network)
                        The stub cannot plan by itself; the analyst loop passes `stub_context`
                        ({turn, tool, args}) so a stub run still exercises a tool and finishes.
  TIRITH_LLM_MAX_TOKENS default 16384 (reasoning models think at length)
  TIRITH_LLM_TIMEOUT    seconds, default 600 (per HTTP operation)
  TIRITH_LLM_DEADLINE   overall seconds for one explain/validate/fix LLM step incl. queueing, default 900
  TIRITH_LLM_CONCURRENCY max simultaneous requests to the server, default 1 (the DeepSeek box serves one at
                        a time: callers queue on a semaphore instead of hammering it)
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

log = logging.getLogger("tirith.llm")

DEFAULT_BASE_URL = "http://192.168.50.160:8010/v1"

Chunk = Callable[[str], None]


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    content: str
    reasoning: str = ""
    model: str = ""
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)

    def json(self) -> Any:
        return extract_json(self.content)


# --------------------------------------------------------------------------- config
def provider() -> str:
    return os.environ.get("TIRITH_LLM_PROVIDER", "openai").strip().lower()


def base_url() -> str:
    return os.environ.get("TIRITH_LLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _api_key() -> str | None:
    k = os.environ.get("TIRITH_LLM_API_KEY")
    return k.strip() if k else None


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    k = _api_key()
    if k:
        h["Authorization"] = f"Bearer {k}"
    return h


def _scrub(text: str) -> str:
    k = _api_key()
    return text.replace(k, "***") if k and text else text


def default_deadline_s() -> float:
    return float(os.environ.get("TIRITH_LLM_DEADLINE", "900"))


def deadline_in(seconds: float | None = None) -> float:
    """Absolute time.monotonic() deadline `seconds` (default TIRITH_LLM_DEADLINE) from now."""
    return time.monotonic() + (default_deadline_s() if seconds is None else seconds)


_sem_lock = threading.Lock()
_sem: threading.BoundedSemaphore | None = None
_sem_size = 0


def _semaphore() -> threading.BoundedSemaphore:
    global _sem, _sem_size
    n = max(1, int(os.environ.get("TIRITH_LLM_CONCURRENCY", "1")))
    with _sem_lock:
        if _sem is None or _sem_size != n:
            _sem, _sem_size = threading.BoundedSemaphore(n), n
        return _sem


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    left = deadline - time.monotonic()
    if left <= 0:
        raise LLMError("LLM deadline exceeded")
    return left


def max_tokens_default() -> int:
    return int(os.environ.get("TIRITH_LLM_MAX_TOKENS", "16384"))


def _timeout() -> httpx.Timeout:
    t = float(os.environ.get("TIRITH_LLM_TIMEOUT", "600"))
    return httpx.Timeout(t, connect=10.0)


_model_cache: dict[str, str] = {}
_model_lock = threading.Lock()


def resolve_model() -> str:
    m = os.environ.get("TIRITH_LLM_MODEL")
    if m:
        return m.strip()
    if provider() == "stub":
        return "tirith-stub"
    url = base_url()
    with _model_lock:
        if url in _model_cache:
            return _model_cache[url]
        try:
            r = httpx.get(f"{url}/models", headers=_headers(), timeout=httpx.Timeout(15.0))
        except httpx.HTTPError as e:
            raise LLMError(f"cannot list models at {url}: {type(e).__name__}") from None
        if r.status_code != 200:
            raise LLMError(f"GET {url}/models -> HTTP {r.status_code}: {_scrub(r.text[:200])}")
        data = r.json().get("data") or []
        if not data:
            raise LLMError(f"no models served at {url}")
        _model_cache[url] = data[0]["id"]
        return _model_cache[url]


def reset_model_cache() -> None:
    with _model_lock:
        _model_cache.clear()


# --------------------------------------------------------------------------- parsing helpers
_THINK_RE = re.compile(r"<think>(.*?)</think>", re.S)


def split_think(content: str) -> tuple[str, str]:
    """Some servers inline reasoning as <think>...</think> in content. Returns (content, reasoning)."""
    if "<think>" not in content and "</think>" not in content:
        return content, ""
    reasoning = "\n".join(m.strip() for m in _THINK_RE.findall(content))
    rest = _THINK_RE.sub("", content)
    if "</think>" in rest:  # opening tag was in the prompt template
        head, _, rest = rest.partition("</think>")
        reasoning = (reasoning + "\n" + head).strip()
    if "<think>" in rest:  # unclosed: the model ran out of tokens (or was cut off) while still reasoning
        rest, _, tail = rest.partition("<think>")
        reasoning = (reasoning + "\n" + tail).strip()
    return rest.strip(), reasoning.strip()


def extract_json(text: str) -> Any:
    """Parse the first JSON object/array in text (tolerates ```json fences and prose)."""
    if text is None:
        raise ValueError("empty response")
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    candidates = [fence.group(1).strip()] if fence else []
    candidates.append(t)
    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            pass
        start = min([i for i in (c.find("{"), c.find("[")) if i >= 0], default=-1)
        if start < 0:
            continue
        depth, in_str, esc = 0, False, False
        opener = c[start]
        closer = "}" if opener == "{" else "]"
        for i in range(start, len(c)):
            ch = c[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(c[start : i + 1])
                    except json.JSONDecodeError:
                        break
    raise ValueError("no JSON object found in model output")


# --------------------------------------------------------------------------- chat
def chat(
    messages: list[dict[str, str]],
    *,
    task: str = "generic",
    max_tokens: int | None = None,
    temperature: float = 0.1,
    json_mode: bool = False,
    stream: bool = True,
    on_reasoning: Chunk | None = None,
    on_content: Chunk | None = None,
    stub_context: dict[str, Any] | None = None,
    deadline: float | None = None,
) -> LLMResult:
    """One chat completion. `task` + `stub_context` drive the stub provider.

    `deadline` is an absolute time.monotonic() value covering queueing + the whole response.
    Requests are serialized through a semaphore (TIRITH_LLM_CONCURRENCY, default 1)."""
    if provider() == "stub":
        return _stub_chat(task, stub_context or {}, on_reasoning, on_content)
    sem = _semaphore()
    wait = _remaining(deadline)
    if not sem.acquire(timeout=wait):
        raise LLMError("LLM busy: timed out waiting in the request queue")
    try:
        return _chat_locked(messages, max_tokens=max_tokens, temperature=temperature, json_mode=json_mode,
                            stream=stream, on_reasoning=on_reasoning, on_content=on_content, deadline=deadline)
    finally:
        sem.release()


def _chat_locked(messages, *, max_tokens, temperature, json_mode, stream, on_reasoning, on_content, deadline) -> LLMResult:
    _remaining(deadline)

    body: dict[str, Any] = {
        "model": resolve_model(),
        "messages": messages,
        "max_tokens": max_tokens or max_tokens_default(),
        "temperature": temperature,
        "stream": stream,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    url = f"{base_url()}/chat/completions"
    last: Exception | None = None
    for attempt in range(2):
        try:
            res = _stream(url, body, on_reasoning, on_content, deadline) if stream else _once(url, body, deadline)
            break
        except LLMError as e:
            # Server may not support response_format / streaming: degrade once.
            last = e
            if json_mode and "response_format" in body and ("400" in str(e) or "422" in str(e)):
                body.pop("response_format")
                continue
            raise
        except httpx.HTTPError as e:
            last = e
            if attempt == 0 and (deadline is None or deadline - time.monotonic() > 5):
                time.sleep(1.5)
                continue
            raise LLMError(f"LLM request failed: {type(e).__name__}: {_scrub(str(e))[:200]}") from None
    else:  # pragma: no cover
        raise LLMError(str(last))
    content, inline_reasoning = split_think(res.content)
    if inline_reasoning:
        res.reasoning = (res.reasoning + "\n" + inline_reasoning).strip()
        res.content = content
    return res


def _timeout_for(deadline: float | None) -> httpx.Timeout:
    t = _timeout()
    left = _remaining(deadline)
    if left is None:
        return t
    return httpx.Timeout(min(t.read or left, left), connect=min(10.0, left))


def _once(url: str, body: dict, deadline: float | None = None) -> LLMResult:
    with httpx.Client(timeout=_timeout_for(deadline)) as c:
        r = c.post(url, headers=_headers(), json={**body, "stream": False})
    if r.status_code != 200:
        raise LLMError(f"HTTP {r.status_code}: {_scrub(r.text[:300])}")
    d = r.json()
    ch = (d.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    return LLMResult(
        content=msg.get("content") or "",
        reasoning=msg.get("reasoning_content") or msg.get("reasoning") or "",
        model=d.get("model") or body["model"],
        finish_reason=ch.get("finish_reason"),
        usage=d.get("usage") or {},
    )


def _stream(url: str, body: dict, on_reasoning: Chunk | None, on_content: Chunk | None,
            deadline: float | None = None) -> LLMResult:
    content: list[str] = []
    reasoning: list[str] = []
    model, finish, usage = body["model"], None, {}
    with httpx.Client(timeout=_timeout_for(deadline)) as c:
        with c.stream("POST", url, headers=_headers(), json=body) as r:
            if r.status_code != 200:
                r.read()
                raise LLMError(f"HTTP {r.status_code}: {_scrub(r.text[:300])}")
            ctype = r.headers.get("content-type", "")
            if "text/event-stream" not in ctype:  # server ignored stream=true
                r.read()
                d = r.json()
                ch = (d.get("choices") or [{}])[0]
                msg = ch.get("message") or {}
                rs = msg.get("reasoning_content") or msg.get("reasoning") or ""
                if rs and on_reasoning:
                    on_reasoning(rs)
                return LLMResult(msg.get("content") or "", rs, d.get("model") or model, ch.get("finish_reason"), d.get("usage") or {})
            for line in r.iter_lines():
                if deadline is not None and time.monotonic() > deadline:
                    raise LLMError("LLM deadline exceeded while streaming")
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    d = json.loads(data)
                except json.JSONDecodeError:
                    continue
                model = d.get("model") or model
                if d.get("usage"):
                    usage = d["usage"]
                for ch in d.get("choices") or []:
                    delta = ch.get("delta") or {}
                    rs = delta.get("reasoning_content") or delta.get("reasoning")
                    if rs:
                        reasoning.append(rs)
                        if on_reasoning:
                            on_reasoning(rs)
                    ct = delta.get("content")
                    if ct:
                        content.append(ct)
                        if on_content:
                            on_content(ct)
                    if ch.get("finish_reason"):
                        finish = ch["finish_reason"]
    return LLMResult("".join(content), "".join(reasoning), model, finish, usage)


def _check_output(res: LLMResult) -> None:
    if not (res.content or "").strip():
        why = ("output truncated at max_tokens while still reasoning (raise TIRITH_LLM_MAX_TOKENS)"
               if res.finish_reason == "length" else "model returned no content (reasoning only / unclosed <think>)")
        raise LLMError(why)


def chat_json(messages: list[dict[str, str]], **kw: Any) -> tuple[Any, LLMResult]:
    """chat() and parse JSON; one repair round-trip if the model's JSON is unparseable.

    Empty content (reasoning ate the budget / unclosed <think>) and truncated output
    (finish_reason == "length") raise LLMError instead of producing a half-parsed result."""
    res = chat(messages, json_mode=True, **kw)
    if provider() != "stub":
        _check_output(res)
    try:
        return res.json(), res
    except ValueError:
        if provider() == "stub":
            raise
        if res.finish_reason == "length":
            raise LLMError("model output truncated (finish_reason=length); raise TIRITH_LLM_MAX_TOKENS") from None
    repair = messages + [
        {"role": "assistant", "content": res.content[-6000:]},
        {"role": "user", "content": "That was not valid JSON. Reply with ONLY the JSON object, no prose."},
    ]
    kw.pop("on_reasoning", None)
    res2 = chat(repair, json_mode=True, **kw)
    _check_output(res2)
    if res2.finish_reason == "length":
        try:
            return res2.json(), res2
        except ValueError:
            raise LLMError("model output truncated (finish_reason=length); raise TIRITH_LLM_MAX_TOKENS") from None
    return res2.json(), res2


# --------------------------------------------------------------------------- throttled event streaming
class ThinkingStreamer:
    """Buffers reasoning tokens and flushes them as ai.thinking events (~every 400 chars / 2 s)."""

    def __init__(self, sink: Callable[[str], None], min_chars: int = 400, min_interval: float = 2.0, max_events: int = 40):
        self.sink, self.min_chars, self.min_interval, self.max_events = sink, min_chars, min_interval, max_events
        self.buf: list[str] = []
        self.size = 0
        self.last = time.monotonic()
        self.sent = 0

    def __call__(self, chunk: str) -> None:
        self.buf.append(chunk)
        self.size += len(chunk)
        if self.size >= self.min_chars and time.monotonic() - self.last >= self.min_interval:
            self.flush()

    def flush(self) -> None:
        if not self.buf or self.sent >= self.max_events:
            self.buf, self.size = [], 0
            return
        text = "".join(self.buf).strip()
        self.buf, self.size = [], 0
        self.last = time.monotonic()
        if text:
            self.sent += 1
            self.sink(text[-1500:])


# --------------------------------------------------------------------------- stub provider
def _stub_chat(task: str, ctx: dict[str, Any], on_reasoning: Chunk | None, on_content: Chunk | None) -> LLMResult:
    reasoning_parts = [
        f"Looking at the {ctx.get('category', 'finding')} finding {ctx.get('rule_id', '')}. ",
        "Tracing where the data comes from and where it ends up. ",
        "Checking for sanitization on the path. ",
    ]
    for p in reasoning_parts:
        if on_reasoning:
            on_reasoning(p)
    out = json.dumps(_stub_payload(task, ctx))
    if on_content:
        on_content(out)
    return LLMResult(content=out, reasoning="".join(reasoning_parts), model="tirith-stub", finish_reason="stop")


def _stub_payload(task: str, ctx: dict[str, Any]) -> dict[str, Any]:
    title = ctx.get("title") or ctx.get("rule_id") or "finding"
    if task == "analyst_plan":
        # Two turns then a report: enough for the loop to run once through a real tool and finish.
        turn = int(ctx.get("turn") or 0)
        if turn == 0 and ctx.get("tool"):
            return {"thought": "[stub] look at the first in-scope asset", "action": {"tool": ctx["tool"], "args": ctx.get("args") or {}}}
        if turn == 1 and ctx.get("tool"):
            return {"thought": "[stub] enough for a stub plan", "done": True,
                    "report": {"summary": "[stub] one tool call was made; see the steps.", "notable": [], "next_steps": ["run with the live model"]}}
        return {"thought": "[stub] done", "done": True, "report": {"summary": "[stub] no action claimed.", "notable": [], "next_steps": []}}
    if task == "explain":
        return {
            "summary": f"[stub] {title} in {ctx.get('file') or 'the project'}.",
            "root_cause": f"[stub] {ctx.get('cwe') or 'Weakness'} at line {ctx.get('line')}.",
            "exploitability": "[stub] Reachable by an unauthenticated user via the affected route.",
            "fix_plan": "[stub] Apply the minimal change suggested by the scanner and re-verify.",
        }
    if task == "triage_sast":
        return {
            "verdict": "true_positive",
            "confidence": 0.8,
            "source": "HTTP request parameter",
            "sink": (ctx.get("snippet") or "").splitlines()[0][:200] if ctx.get("snippet") else "unknown",
            "sanitizers": [],
            "reasoning": "[stub] User-controlled input reaches the sink without sanitization.",
        }
    if task == "fix":
        snippet = (ctx.get("snippet") or "").splitlines()
        first = next((ln for ln in snippet if ln.strip()), "")
        edits = []
        if first and ctx.get("file"):
            edits.append({"file": ctx["file"], "find": first, "replace": first + "  # tirith: reviewed"})
        return {"explanation": "[stub] annotate the flagged line", "diff": "", "edits": edits}
    return {"text": f"[stub] {task}"}
