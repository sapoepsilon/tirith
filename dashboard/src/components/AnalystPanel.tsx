"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { Brain, Crosshair, Globe, Image as ImageIcon, Loader2, Play, ShieldAlert, SquareTerminal, Wrench } from "lucide-react";
import { API_BASE, LONG_TIMEOUT_MS } from "@/lib/config";
import { PanelHeader } from "@/components/ui";
import type { AnalystRun, AnalystStep } from "@/lib/types";

const SHOT_RE = /([A-Za-z0-9._-]+\.png)/;

function shotName(step: AnalystStep): string | null {
  const m = SHOT_RE.exec(step.observation || "");
  return m ? m[1] : null;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
    signal: AbortSignal.timeout(LONG_TIMEOUT_MS),
  });
  const text = await res.text();
  if (!res.ok) {
    let detail = text;
    try {
      const j = JSON.parse(text) as { detail?: unknown };
      if (typeof j.detail === "string") detail = j.detail;
    } catch {
      /* not JSON */
    }
    throw new Error(detail.slice(0, 300) || `${res.status} ${res.statusText}`);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

const TOOL_ICON: Record<string, typeof Wrench> = {
  discover: Crosshair,
  scan: ShieldAlert,
  evidence: ImageIcon,
  asset: Globe,
  findings: SquareTerminal,
  posture: SquareTerminal,
  reproduce: ShieldAlert,
  validate: ShieldAlert,
  fix: Wrench,
};

const STATUS_STYLE: Record<string, string> = {
  running: "text-accent",
  done: "text-ok",
  budget: "text-sev-medium",
  error: "text-sev-critical",
};

export function AnalystPanel({ height = 560 }: { height?: number }) {
  const [goal, setGoal] = useState("Assess 192.168.50.132 and 192.168.50.160; what would an attacker see first?");
  const [steps, setSteps] = useState(8);
  const [run, setRun] = useState<AnalystRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (poll.current) clearInterval(poll.current);
    poll.current = null;
  }, []);

  const watch = useCallback(
    (id: string) => {
      stopPolling();
      poll.current = setInterval(async () => {
        try {
          const r = await call<AnalystRun>(`/analyst/runs/${encodeURIComponent(id)}`);
          setRun(r);
          if (r.status !== "running") stopPolling();
        } catch {
          stopPolling();
        }
      }, 2000);
    },
    [stopPolling],
  );

  useEffect(() => () => stopPolling(), [stopPolling]);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await call<AnalystRun>("/analyst/runs", {
        method: "POST",
        body: JSON.stringify({ goal, max_steps: steps }),
      });
      setRun(r);
      watch(r.id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const running = run?.status === "running";

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-night-900/70">
      <PanelHeader icon={Brain} title="Autonomous analyst" sub={run ? `${run.status} · ${run.steps.length} steps` : "model-planned"} />
      <div className="border-b border-line px-4 py-3">
        <textarea
          value={goal}
          onChange={(e) => setGoal(e.target.value)}
          rows={2}
          className="w-full resize-none rounded-lg border border-line bg-night-950 px-3 py-2 text-[12.5px] text-mithril outline-none placeholder:text-faint focus:border-accent/50"
          placeholder="What should the analyst assess? Name in-scope hosts or URLs."
        />
        <div className="mt-2 flex items-center gap-3">
          <label className="flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-widest text-muted">
            steps
            <input
              type="number"
              min={1}
              max={24}
              value={steps}
              onChange={(e) => setSteps(Number(e.target.value))}
              className="w-12 rounded border border-line bg-night-950 px-1.5 py-0.5 text-center text-mithril"
            />
          </label>
          <button
            onClick={() => void start()}
            disabled={busy || running}
            className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-[12px] font-medium text-accent transition hover:bg-accent/20 disabled:opacity-50"
          >
            {busy || running ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5" />}
            {running ? "Analyst working…" : "Run analyst"}
          </button>
          {run && (
            <span className={clsx("font-mono text-[10.5px]", STATUS_STYLE[run.status] ?? "text-muted")}>
              {run.id} · {run.status}
              {run.waiting_on ? ` · waiting: ${run.waiting_on.slice(0, 80)}` : ""}
              {run.error ? ` · ${run.error.slice(0, 120)}` : ""}
            </span>
          )}
        </div>
        {error && <div className="mt-2 font-mono text-[11px] text-sev-critical">{error}</div>}
      </div>

      <div className="overflow-y-auto px-4 py-3" style={{ maxHeight: height }}>
        {!run && <p className="font-mono text-[11.5px] text-muted">The analyst plans its own steps, calls the scanners, records evidence and writes a report.</p>}
        {run?.report?.summary && (
          <div className="mb-3 rounded-lg border border-ok/30 bg-ok/5 p-3">
            <div className="mb-1 font-mono text-[9.5px] uppercase tracking-widest text-ok">report</div>
            <p className="text-[12.5px] leading-relaxed text-mithril">{run.report.summary}</p>
            {Array.isArray(run.report.issues) && run.report.issues.length > 0 && (
              <ul className="mt-2 space-y-2">
                {run.report.issues.map((it, i) => (
                  <li key={i} className="rounded border border-line bg-night-950/50 p-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono text-[9px] uppercase text-mithril-dim">{it.severity ?? "?"}</span>
                      <span
                        className={clsx(
                          "rounded px-1 font-mono text-[9px] uppercase",
                          it.proof === "confirmed"
                            ? "bg-ok/15 text-ok"
                            : it.proof === "suspected"
                              ? "bg-sev-medium/15 text-sev-medium"
                              : "bg-night-800 text-faint",
                        )}
                      >
                        {it.proof === "confirmed" ? "reproduced" : (it.proof ?? "unproven").replace("_", " ")}
                      </span>
                    </div>
                    <p className="mt-1 text-[12px] text-mithril">{it.title}</p>
                    {it.where && <code className="text-[10.5px] text-accent">{it.where}</code>}
                    {it.evidence && <p className="mt-1 text-[11px] text-muted">{it.evidence}</p>}
                    {Array.isArray(it.reproduce) && it.reproduce.length > 0 && (
                      <ol className="mt-1 list-decimal space-y-0.5 pl-4 font-mono text-[10.5px] text-mithril-dim">
                        {it.reproduce.map((r, j) => (
                          <li key={j}>{r}</li>
                        ))}
                      </ol>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {Array.isArray(run.report.next_steps) && run.report.next_steps.length > 0 && (
              <ul className="mt-2 list-disc space-y-0.5 pl-5 text-[11.5px] text-mithril-dim">
                {run.report.next_steps.slice(0, 6).map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        <ol className="space-y-2">
          {run?.steps.map((s) => {
            const Icon = TOOL_ICON[s.tool ?? ""] ?? SquareTerminal;
            const shot = s.tool === "evidence" ? shotName(s) : null;
            return (
              <li key={s.n} className={clsx("rounded-lg border p-2.5", s.ok ? "border-line bg-night-850/60" : "border-sev-medium/30 bg-sev-medium/5")}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-faint">{s.n}</span>
                  <Icon className="size-3 text-accent" strokeWidth={1.75} />
                  <span className="font-mono text-[11px] text-mithril">{s.tool ?? "?"}</span>
                  {!s.ok && <span className="rounded bg-sev-medium/15 px-1 font-mono text-[9px] uppercase text-sev-medium">refused</span>}
                  {typeof s.ms === "number" && <span className="ml-auto font-mono text-[9.5px] text-faint">{s.ms} ms</span>}
                </div>
                <p className="mt-1 text-[12px] leading-snug text-mithril-dim">{s.thought}</p>
                {s.observation && (
                  <pre className="mt-1.5 max-h-24 overflow-auto whitespace-pre-wrap break-words rounded bg-night-950/70 p-2 font-mono text-[10.5px] text-muted">
                    {s.observation.slice(0, 700)}
                  </pre>
                )}
                {shot && (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img
                    src={`/tirith/shots/${encodeURIComponent(shot)}`}
                    alt={`evidence for ${s.args?.url ?? ""}`}
                    className="mt-2 max-h-44 rounded border border-line object-top"
                  />
                )}
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}