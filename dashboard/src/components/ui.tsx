"use client";

import clsx from "clsx";
import {
  Activity,
  Ban,
  Bot,
  BrainCircuit,
  CheckCircle2,
  FlaskConical,
  GitPullRequest,
  Play,
  Radar,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  SquareTerminal,
  TrendingUp,
  Undo2,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { FindingStatus, FixStatus, Severity, TirithEvent } from "@/lib/types";

export const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)",
  info: "var(--color-sev-info)",
};

export function TirithGlyph({ size = 28, className }: { size?: number; className?: string }) {
  // Generic watchtower with a four-point star above it.
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className={className} aria-hidden>
      <defs>
        <linearGradient id="tg-tower" x1="16" y1="10" x2="16" y2="31" gradientUnits="userSpaceOnUse">
          <stop stopColor="#e4e9f1" />
          <stop offset="1" stopColor="#64728a" />
        </linearGradient>
        <radialGradient id="tg-star" cx="16" cy="6" r="6" gradientUnits="userSpaceOnUse">
          <stop stopColor="#ffffff" />
          <stop offset="1" stopColor="#7fe3ff" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx="16" cy="6" r="6" fill="url(#tg-star)" opacity="0.55" />
      <path d="M16 1.2 L17.1 4.9 L20.8 6 L17.1 7.1 L16 10.8 L14.9 7.1 L11.2 6 L14.9 4.9 Z" fill="#7fe3ff" />
      <path d="M13.2 12.5 H18.8 L19.6 14.2 H12.4 Z" fill="url(#tg-tower)" />
      <path d="M13.6 14.2 H18.4 L20.4 30.5 H11.6 Z" fill="url(#tg-tower)" opacity="0.9" />
      <rect x="15.2" y="17" width="1.6" height="3" rx="0.4" fill="#7fe3ff" />
      <path d="M9 30.5 H23" stroke="#3c4a60" strokeWidth="1" strokeLinecap="round" />
    </svg>
  );
}

export function SeverityChip({ s, compact }: { s: Severity; compact?: boolean }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-[5px] border font-mono uppercase tracking-wider",
        compact ? "px-1.5 py-px text-[9.5px]" : "px-2 py-0.5 text-[10px]",
      )}
      style={{
        color: SEV_COLOR[s],
        borderColor: `color-mix(in srgb, ${SEV_COLOR[s]} 35%, transparent)`,
        background: `color-mix(in srgb, ${SEV_COLOR[s]} 10%, transparent)`,
      }}
    >
      <span className="size-1.5 rounded-full" style={{ background: SEV_COLOR[s], boxShadow: `0 0 6px ${SEV_COLOR[s]}` }} />
      {s}
    </span>
  );
}

const STATUS_STYLE: Record<FindingStatus, { c: string; label: string }> = {
  open: { c: "var(--color-mithril-dim)", label: "open" },
  validated: { c: "var(--color-sev-critical)", label: "confirmed" },
  not_reproduced: { c: "var(--color-muted)", label: "not reproduced" },
  fixing: { c: "var(--color-accent)", label: "fixing" },
  fixed: { c: "var(--color-ok)", label: "fixed" },
};

export function StatusChip({ s }: { s: FindingStatus }) {
  const st = STATUS_STYLE[s] ?? STATUS_STYLE.open;
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[10.5px]" style={{ color: st.c }}>
      <span
        className={clsx("size-1.5 rounded-full", s === "fixing" && "animate-pulse-soft")}
        style={{ background: st.c }}
      />
      {st.label}
    </span>
  );
}

const FIX_STYLE: Record<FixStatus, string> = {
  proposed: "var(--color-mithril-dim)",
  pr_opened: "var(--color-accent)",
  verified: "var(--color-ok)",
  applied: "var(--color-ok)",
  rolled_back: "var(--color-sev-medium)",
  failed: "var(--color-sev-critical)",
  escalated: "var(--color-sev-high)",
};

export function FixChip({ s }: { s: FixStatus }) {
  return (
    <span
      className="rounded border px-1.5 py-px font-mono text-[10px] uppercase tracking-wider"
      style={{ color: FIX_STYLE[s], borderColor: `color-mix(in srgb, ${FIX_STYLE[s]} 35%, transparent)` }}
    >
      {s.replace("_", " ")}
    </span>
  );
}

export function PanelHeader({
  icon: Icon,
  title,
  right,
  sub,
}: {
  icon: LucideIcon;
  title: string;
  right?: React.ReactNode;
  sub?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
      <div className="flex min-w-0 items-center gap-2">
        <Icon className="size-3.5 shrink-0 text-accent" strokeWidth={1.75} />
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-mithril-dim">{title}</h2>
        {sub && <span className="truncate font-mono text-[10.5px] text-muted">{sub}</span>}
      </div>
      {right}
    </div>
  );
}

export const EVENT_META: Record<string, { icon: LucideIcon; color: string; label: string }> = {
  "scan.started": { icon: Radar, color: "var(--color-accent)", label: "scan" },
  "scan.finished": { icon: ScanLine, color: "var(--color-accent)", label: "scan" },
  "tool.started": { icon: Play, color: "var(--color-mithril-dim)", label: "tool" },
  "tool.finished": { icon: SquareTerminal, color: "var(--color-mithril-dim)", label: "tool" },
  "finding.new": { icon: ShieldAlert, color: "var(--color-sev-high)", label: "finding" },
  "validation.started": { icon: FlaskConical, color: "var(--color-accent)", label: "lab" },
  "validation.step": { icon: Activity, color: "var(--color-muted)", label: "lab" },
  "validation.result": { icon: FlaskConical, color: "var(--color-sev-critical)", label: "lab" },
  "ai.thinking": { icon: BrainCircuit, color: "#b9a6ff", label: "ai" },
  "ai.summary": { icon: Sparkles, color: "#b9a6ff", label: "ai" },
  "fix.started": { icon: Wrench, color: "var(--color-accent)", label: "fix" },
  "fix.patch": { icon: Bot, color: "var(--color-accent)", label: "fix" },
  "fix.pr_opened": { icon: GitPullRequest, color: "var(--color-ok)", label: "pr" },
  "fix.verified": { icon: ShieldCheck, color: "var(--color-ok)", label: "verified" },
  "fix.applied": { icon: CheckCircle2, color: "var(--color-ok)", label: "applied" },
  "fix.rolled_back": { icon: Undo2, color: "var(--color-sev-medium)", label: "rollback" },
  "posture.updated": { icon: TrendingUp, color: "var(--color-accent)", label: "posture" },
  "policy.denied": { icon: Ban, color: "var(--color-sev-high)", label: "policy" },
  "mode.changed": { icon: SlidersHorizontal, color: "var(--color-mithril-dim)", label: "mode" },
};

export function eventColor(e: TirithEvent): string {
  if (e.type === "finding.new") {
    const sev = (e.data as { severity?: Severity } | undefined)?.severity;
    if (sev) return SEV_COLOR[sev];
  }
  if (e.type === "validation.result") {
    const r = (e.data as { result?: string } | undefined)?.result;
    return r === "confirmed" ? "var(--color-sev-critical)" : "var(--color-ok)";
  }
  if (e.level === "error") return "var(--color-sev-critical)";
  return (EVENT_META[e.type] ?? EVENT_META["mode.changed"]).color;
}

export function fmtTime(ts?: string) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** Re-render every `ms` so relative timestamps tick. */
export function useNow(ms = 1000) {
  const [n, setN] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setN(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return n;
}

export function ago(ts: string | null | undefined, now: number) {
  if (!ts) return "—";
  const s = Math.max(0, Math.round((now - new Date(ts).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
