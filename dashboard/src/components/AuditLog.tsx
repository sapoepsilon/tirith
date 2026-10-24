"use client";

import clsx from "clsx";
import { ScrollText } from "lucide-react";
import { useTirith } from "@/lib/store";
import type { AuditEntry } from "@/lib/types";
import { PanelHeader, fmtTime } from "./ui";

const str = (v: unknown) => (v == null ? "" : typeof v === "string" ? v : JSON.stringify(v));

/** Backend shape (CONTRACT): {id, ts, actor, action, target, allowed: bool, details}. Older/mock rows may carry result/decision. */
function resultOf(a: AuditEntry) {
  if (typeof a.allowed === "boolean") return a.allowed ? "allowed" : "denied";
  return str(a.result ?? a.decision ?? (a as { outcome?: unknown }).outcome);
}

export function AuditLog({ limit, className }: { limit?: number; className?: string }) {
  const { snap } = useTirith();
  const rows = limit ? snap.audit.slice(0, limit) : snap.audit;
  return (
    <section className={clsx("panel flex min-h-0 flex-col", className)}>
      <PanelHeader icon={ScrollText} title="Audit log" sub={`${snap.audit.length} entries · append-only`} />
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left font-mono text-[11px]">
          <thead className="sticky top-0 bg-night-850">
            <tr className="text-[9.5px] tracking-[0.14em] text-faint uppercase">
              <th className="py-2 pr-2 pl-4 font-normal">time</th>
              <th className="px-2 font-normal">actor</th>
              <th className="px-2 font-normal">action</th>
              <th className="px-2 font-normal">target</th>
              <th className="px-2 font-normal">decision</th>
              <th className="pr-4 pl-2 font-normal">details</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a, i) => {
              const r = resultOf(a).toLowerCase();
              const denied = /deny|denied|false|blocked|reject/.test(r);
              return (
                <tr key={String(a.id ?? i)} className="animate-fade-in border-t border-line/70">
                  <td className="py-1.5 pr-2 pl-4 whitespace-nowrap text-faint">{fmtTime(str(a.ts ?? (a as { created_at?: string }).created_at))}</td>
                  <td className="px-2 whitespace-nowrap text-mithril-dim">{str(a.actor) || "—"}</td>
                  <td className="px-2 whitespace-nowrap text-accent">{str(a.action ?? (a as { event?: unknown }).event) || "—"}</td>
                  <td className="max-w-[240px] truncate px-2 text-mithril-dim">{str(a.target) || "—"}</td>
                  <td className="px-2 whitespace-nowrap">
                    {r ? (
                      <span className={clsx("rounded border px-1.5 py-px text-[9.5px] uppercase", denied ? "border-sev-high/50 text-sev-high" : "border-ok/40 text-ok")}>
                        {resultOf(a)}
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="max-w-[420px] truncate pr-4 pl-2 text-muted" title={str(a.details)}>
                    {str(a.details) || "—"}
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="py-10 text-center text-muted">
                  no audited actions yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
