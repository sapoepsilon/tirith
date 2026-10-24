"use client";

import { ChevronRight, ListChecks, Wrench } from "lucide-react";
import { useTirith } from "@/lib/store";
import { PanelHeader, SEV_COLOR, SeverityChip } from "./ui";

/** "Top 3 fixes": the posture's plain-language actions (CONTRACT v1.4), shown above the gauge. */
export function TopActions() {
  const { snap, select } = useTirith();
  const actions = snap.posture?.top_actions;
  if (!actions) return null; // older backend / demo data without the field

  const known = new Set(snap.findings.map((f) => f.id));
  return (
    <section className="panel">
      <PanelHeader
        icon={ListChecks}
        title="Top 3 fixes"
        sub={actions.length ? "start here: these move your grade the most" : undefined}
      />
      {actions.length === 0 ? (
        <p className="px-4 py-3 text-[12.5px] text-mithril-dim">Nothing open needs action right now.</p>
      ) : (
        <ol className="grid grid-cols-1 gap-3 p-3 md:grid-cols-3">
          {actions.map((a, i) => {
            const first = a.finding_ids.find((id) => known.has(id));
            return (
              <li
                key={`${i}-${a.finding_ids[0]}`}
                className="flex min-w-0 flex-col gap-2 rounded-md border border-line bg-night-900/60 p-3"
                style={{ borderLeft: `3px solid ${SEV_COLOR[a.severity]}` }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-muted">#{i + 1}</span>
                  <SeverityChip s={a.severity} compact />
                </div>
                <div className="text-[13.5px] leading-snug font-semibold text-mithril [overflow-wrap:anywhere]">{a.action}</div>
                <p className="text-[12px] leading-snug text-mithril-dim [overflow-wrap:anywhere]">{a.why}</p>
                <div className="mt-auto flex items-center justify-between gap-2 pt-1">
                  <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-muted">
                    {a.fixable && <Wrench className="size-3 text-accent" strokeWidth={1.75} />}
                    {a.fixable ? "Tirith can fix this" : "manual fix"}
                    {a.finding_ids.length > 1 && ` · ${a.finding_ids.length} findings`}
                  </span>
                  <button
                    type="button"
                    disabled={!first}
                    onClick={() => first && select(first)}
                    className="inline-flex items-center gap-0.5 rounded border border-line px-2 py-0.5 font-mono text-[10.5px] text-accent transition-colors hover:bg-night-800 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {a.fixable ? "Review fix" : "Details"}
                    <ChevronRight className="size-3" />
                  </button>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
