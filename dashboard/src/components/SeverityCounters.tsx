"use client";

import clsx from "clsx";
import { ScanLine } from "lucide-react";
import { useTirith } from "@/lib/store";
import { SEVERITIES, emptyCounts, isClosed, isLab, type ToolName } from "@/lib/types";
import { PanelHeader, SEV_COLOR, ago, useNow } from "./ui";

const TOOLS: { id: ToolName; label: string; kind: string }[] = [
  { id: "semgrep", label: "Semgrep", kind: "SAST" },
  { id: "gitleaks", label: "Gitleaks", kind: "secrets" },
  { id: "trivy", label: "Trivy", kind: "deps" },
  { id: "zap", label: "ZAP", kind: "DAST · lab" },
];

export function SeverityCounters() {
  const { snap } = useTirith();
  const now = useNow(1000);
  const counts = emptyCounts();
  const total = emptyCounts();
  const lab = emptyCounts();
  for (const f of snap.findings) {
    total[f.severity]++;
    if (!isClosed(f)) {
      counts[f.severity]++;
      if (isLab(f)) lab[f.severity]++;
    }
  }
  const scan = snap.scans[0];
  const max = Math.max(1, ...SEVERITIES.map((s) => total[s]));

  return (
    <section className="panel flex h-full flex-col">
      <PanelHeader
        icon={ScanLine}
        title="Exposure"
        sub={scan ? `${scan.id} · ${scan.status}${scan.started_at ? ` · ${ago(scan.started_at, now)}` : ""}` : "no scans yet"}
      />
      <div className="grid grid-cols-5 gap-2 px-4 pt-3">
        {SEVERITIES.map((s) => (
          <div key={s} className="relative overflow-hidden rounded-lg border border-line bg-night-900/70 px-3 py-2.5">
            <div
              className="absolute inset-x-0 top-0 h-[2px]"
              style={{ background: SEV_COLOR[s], boxShadow: counts[s] ? `0 0 12px ${SEV_COLOR[s]}` : undefined, opacity: counts[s] ? 1 : 0.25 }}
            />
            <div className="font-mono text-[9.5px] uppercase tracking-[0.16em]" style={{ color: SEV_COLOR[s] }}>
              {s}
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span key={counts[s]} className="animate-fade-in text-[28px] leading-none font-semibold tabular-nums text-mithril">
                {counts[s]}
              </span>
              {total[s] > counts[s] && (
                <span className="font-mono text-[10px] text-ok">−{total[s] - counts[s]}</span>
              )}
            </div>
            <div className="mt-0.5 h-3 font-mono text-[9.5px] text-faint" title="open findings in lab sub-apps (de-prioritized)">
              {lab[s] ? `${counts[s] - lab[s]} app · ${lab[s]} lab` : ""}
            </div>
            <div className="mt-2 h-1 overflow-hidden rounded-full bg-night-700">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${(counts[s] / max) * 100}%`, background: SEV_COLOR[s] }}
              />
            </div>
          </div>
        ))}
      </div>
      <Breakdown />
      <div className="mt-auto grid grid-cols-4 gap-2 px-4 pt-3 pb-4">
        {TOOLS.map((t) => {
          const st = scan?.tools?.[t.id] ?? "pending";
          const n = snap.findings.filter((f) => f.tool === t.id).length;
          return (
            <div
              key={t.id}
              className={clsx(
                "relative overflow-hidden rounded-md border px-2.5 py-2 transition-colors duration-500",
                st === "running" ? "border-accent/50 bg-accent/5" : "border-line bg-night-900/50",
              )}
            >
              {st === "running" && (
                <div className="absolute inset-0 animate-scan bg-gradient-to-r from-transparent via-accent/10 to-transparent" />
              )}
              <div className="relative flex items-center justify-between">
                <span className="text-[12px] text-mithril">{t.label}</span>
                <span
                  className={clsx(
                    "font-mono text-[9.5px] uppercase tracking-wider",
                    st === "running" && "animate-pulse-soft text-accent",
                    st === "done" && "text-ok",
                    st === "failed" && "text-sev-critical",
                    (st === "pending" || st === "skipped") && "text-faint",
                  )}
                >
                  {st}
                </span>
              </div>
              <div className="relative mt-0.5 flex justify-between font-mono text-[10px] text-muted">
                <span>{t.kind}</span>
                <span className="tabular-nums">{n} hits</span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

const CATS = [
  { id: "sast", label: "code", color: "#7fe3ff" },
  { id: "secret", label: "secrets", color: "#c4a7ff" },
  { id: "dependency", label: "deps", color: "#5b9dff" },
  { id: "dast", label: "runtime", color: "#9be8b4" },
  { id: "config", label: "config", color: "#a3afc2" },
] as const;

function Breakdown() {
  const { snap } = useTirith();
  const n = snap.findings.length;
  const fixes = Object.values(snap.fixes);
  const stats = [
    { k: "confirmed", v: snap.findings.filter((f) => f.validation?.result === "confirmed").length, c: "var(--color-sev-critical)" },
    { k: "not reproduced", v: snap.findings.filter((f) => f.validation?.result === "not_reproduced").length, c: "var(--color-muted)" },
    { k: "PRs opened", v: fixes.filter((f) => f.pr_url).length, c: "var(--color-accent)" },
    { k: "auto-applied", v: fixes.filter((f) => f.status === "applied").length, c: "var(--color-ok)" },
    { k: "escalated", v: fixes.filter((f) => f.status === "escalated").length, c: "var(--color-sev-high)" },
  ];
  return (
    <div className="px-4 pt-4">
      <div className="mb-1.5 flex items-center justify-between font-mono text-[9.5px] tracking-[0.16em] text-faint uppercase">
        <span>surface mix</span>
        <span className="tabular-nums">{n} total</span>
      </div>
      <div className="flex h-2 gap-px overflow-hidden rounded-full bg-night-700">
        {CATS.map((c) => {
          const v = snap.findings.filter((f) => f.category === c.id).length;
          return v ? (
            <div key={c.id} className="h-full transition-all duration-700" style={{ width: `${(v / n) * 100}%`, background: c.color, opacity: 0.8 }} />
          ) : null;
        })}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-muted">
        {CATS.map((c) => (
          <span key={c.id} className="inline-flex items-center gap-1">
            <span className="size-1.5 rounded-sm" style={{ background: c.color }} />
            {c.label} <span className="text-mithril-dim tabular-nums">{snap.findings.filter((f) => f.category === c.id).length}</span>
          </span>
        ))}
      </div>
      <div className="mt-3 grid grid-cols-5 divide-x divide-line rounded-md border border-line bg-night-900/50">
        {stats.map((s) => (
          <div key={s.k} className="px-2.5 py-1.5">
            <div className="text-[17px] leading-tight font-semibold tabular-nums" style={{ color: s.v ? s.c : "var(--color-faint)" }}>
              {s.v}
            </div>
            <div className="truncate font-mono text-[9px] tracking-wider text-muted uppercase">{s.k}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
