"use client";

import clsx from "clsx";
import { Check, GitMerge } from "lucide-react";
import { useTirith } from "@/lib/store";
import type { Finding, Fix } from "@/lib/types";
import { FixChip, PanelHeader, SEV_COLOR } from "./ui";

const STAGES = ["detected", "confirmed", "patched", "shipped", "verified"] as const;

function stageOf(f: Finding, fx?: Fix): number {
  if (f.status === "fixed" || fx?.status === "verified") return 4;
  if (fx && (fx.status === "pr_opened" || fx.status === "applied")) return 3;
  if (fx && fx.diff) return 2;
  if (f.validation?.result === "confirmed" || f.status === "validated") return 1;
  return 0;
}

export function RemediationTracker({ className }: { className?: string }) {
  const { snap, select } = useTirith();
  const items = snap.findings
    .filter((f) => f.fix_id || f.status === "validated")
    .map((f) => ({ f, fx: f.fix_id ? snap.fixes[f.fix_id] : undefined }))
    .map((x) => ({ ...x, stage: stageOf(x.f, x.fx) }))
    .sort((a, b) => b.stage - a.stage);
  const total = snap.findings.filter((f) => f.status !== "not_reproduced").length;
  const fixed = snap.findings.filter((f) => f.status === "fixed").length;
  const pct = total ? Math.round((fixed / total) * 100) : 0;

  const stageCounts = STAGES.map((_, i) => snap.findings.filter((f) => stageOf(f, f.fix_id ? snap.fixes[f.fix_id] : undefined) >= i).length);

  return (
    <section className={clsx("panel flex min-h-0 flex-col", className)}>
      <PanelHeader icon={GitMerge} title="Remediation progress" sub={`${fixed}/${total} resolved`} />
      <div className="px-4 pt-3">
        <div className="flex items-end justify-between">
          <span className="text-[26px] leading-none font-semibold tabular-nums text-mithril">{pct}%</span>
          <span className="font-mono text-[10px] text-muted">validated findings → verified fixes</span>
        </div>
        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-night-700">
          <div
            className="h-full rounded-full bg-gradient-to-r from-accent-dim to-ok shadow-[0_0_12px_rgba(74,222,155,0.5)] transition-all duration-1000"
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="mt-3 grid grid-cols-5 gap-1">
          {STAGES.map((s, i) => (
            <div key={s} className="text-center">
              <div className="text-[15px] font-semibold tabular-nums text-mithril">{stageCounts[i]}</div>
              <div className="font-mono text-[9px] tracking-wider text-muted uppercase">{s}</div>
            </div>
          ))}
        </div>
      </div>
      <ul className="mt-3 min-h-0 flex-1 overflow-y-auto border-t border-line px-2 py-1.5">
        {items.length === 0 && <li className="py-6 text-center font-mono text-[11px] text-muted">nothing in flight</li>}
        {items.map(({ f, fx, stage }) => (
          <li
            key={f.id}
            onClick={() => select(f.id)}
            className="animate-fade-in cursor-pointer rounded-md px-2 py-1.5 hover:bg-night-800/70"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="flex min-w-0 items-center gap-1.5">
                <span className="size-1.5 shrink-0 rounded-full" style={{ background: SEV_COLOR[f.severity] }} />
                <span className="truncate text-[11.5px] text-mithril">{f.title}</span>
              </span>
              {fx && <FixChip s={fx.status} />}
            </div>
            <div className="mt-1.5 flex items-center pl-3">
              {STAGES.map((s, i) => {
                const done = i <= stage;
                const active = i === stage + 1 && f.status === "fixing";
                const blocked = fx?.status === "escalated" && i === stage + 1;
                return (
                  <div key={s} className="flex flex-1 items-center last:flex-none">
                    <span
                      title={s}
                      className={clsx(
                        "flex size-3.5 items-center justify-center rounded-full border transition-colors duration-500",
                        done ? "border-ok bg-ok/20" : active ? "animate-pulse-soft border-accent" : blocked ? "border-sev-high" : "border-line-strong",
                      )}
                    >
                      {done && <Check className="size-2 text-ok" strokeWidth={3} />}
                    </span>
                    {i < STAGES.length - 1 && (
                      <span className={clsx("mx-0.5 h-px flex-1 transition-colors duration-500", i < stage ? "bg-ok/60" : "bg-line-strong")} />
                    )}
                  </div>
                );
              })}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
