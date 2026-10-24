"use client";

import clsx from "clsx";
import { ListFilter, Search, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { useTirith } from "@/lib/store";
import { SEVERITIES, byPriority, isLab, type Category, type Finding, type FindingStatus, type Severity } from "@/lib/types";
import { FixChip, PanelHeader, SEV_COLOR, SeverityChip, StatusChip } from "./ui";

const STATUSES: (FindingStatus | "all")[] = ["all", "open", "validated", "not_reproduced", "fixing", "fixed"];
const CATEGORIES: (Category | "all")[] = ["all", "sast", "secret", "dependency", "dast", "config"];
type Scope = "all" | "main" | "lab";
const SCOPES: { id: Scope; label: string }[] = [
  { id: "all", label: "scope: all" },
  { id: "main", label: "scope: main app" },
  { id: "lab", label: "scope: lab sub-apps" },
];
const inScope = (f: Finding, s: Scope) => (s === "all" ? true : s === "lab" ? isLab(f) : !isLab(f));

export function FindingsTable({ limit }: { limit?: number }) {
  const { snap, select, selectedId } = useTirith();
  const [sev, setSev] = useState<Set<Severity>>(new Set());
  const [status, setStatus] = useState<FindingStatus | "all">("all");
  const [cat, setCat] = useState<Category | "all">("all");
  const [scope, setScope] = useState<Scope>("all");
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return snap.findings
      .filter((f) => (sev.size ? sev.has(f.severity) : true))
      .filter((f) => (status === "all" ? true : f.status === status))
      .filter((f) => (cat === "all" ? true : f.category === cat))
      .filter((f) => inScope(f, scope))
      .filter((f) =>
        needle
          ? [f.title, f.file, f.rule_id, f.cwe, f.cve, f.package, f.tool].some((x) => x?.toLowerCase().includes(needle))
          : true,
      )
      .sort(byPriority);
  }, [snap.findings, sev, status, cat, scope, q]);

  const shown = limit ? rows.slice(0, limit) : rows;
  const toggleSev = (s: Severity) =>
    setSev((cur) => {
      const n = new Set(cur);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n;
    });

  return (
    <section className="panel flex flex-col">
      <PanelHeader
        icon={ShieldAlert}
        title="Findings"
        sub={`${rows.length} of ${snap.findings.length}`}
        right={
          limit && rows.length > limit ? (
            <Link href="/findings" className="font-mono text-[10.5px] text-accent hover:underline">
              view all →
            </Link>
          ) : null
        }
      />
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2">
        <ListFilter className="size-3.5 text-muted" />
        {SEVERITIES.map((s) => {
          const on = sev.has(s);
          return (
            <button
              key={s}
              onClick={() => toggleSev(s)}
              className={clsx(
                "rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider transition",
                on ? "" : "border-line text-muted hover:text-mithril-dim",
              )}
              style={
                on
                  ? { color: SEV_COLOR[s], borderColor: SEV_COLOR[s], background: `color-mix(in srgb, ${SEV_COLOR[s]} 12%, transparent)` }
                  : undefined
              }
            >
              {s}
            </button>
          );
        })}
        <span className="mx-1 h-4 w-px bg-line" />
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value as FindingStatus | "all")}
          className="rounded border border-line bg-night-900 px-1.5 py-0.5 font-mono text-[10.5px] text-mithril-dim outline-none focus:border-accent/50"
          aria-label="Status filter"
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              status: {s.replace("_", " ")}
            </option>
          ))}
        </select>
        <select
          value={cat}
          onChange={(e) => setCat(e.target.value as Category | "all")}
          className="rounded border border-line bg-night-900 px-1.5 py-0.5 font-mono text-[10.5px] text-mithril-dim outline-none focus:border-accent/50"
          aria-label="Category filter"
        >
          {CATEGORIES.map((s) => (
            <option key={s} value={s}>
              category: {s}
            </option>
          ))}
        </select>
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as Scope)}
          className="rounded border border-line bg-night-900 px-1.5 py-0.5 font-mono text-[10.5px] text-mithril-dim outline-none focus:border-accent/50"
          aria-label="Scope filter"
        >
          {SCOPES.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
            </option>
          ))}
        </select>
        <label className="ml-auto flex items-center gap-1.5 rounded border border-line bg-night-900 px-2 py-0.5 focus-within:border-accent/50">
          <Search className="size-3 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search rule, file, CVE…"
            className="w-44 bg-transparent font-mono text-[11px] text-mithril outline-none placeholder:text-faint"
          />
        </label>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-faint">
              <th className="py-2 pr-2 pl-4 font-normal">severity</th>
              <th className="px-2 font-normal">finding</th>
              <th className="px-2 font-normal">source</th>
              <th className="px-2 font-normal">ref</th>
              <th className="px-2 font-normal">status</th>
              <th className="px-2 font-normal">fix</th>
              <th className="px-2 text-right font-normal">conf.</th>
              <th className="pr-4 pl-2 text-right font-normal" title="severity × confidence × reachability × validation">prio</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => {
              const fx = f.fix_id ? snap.fixes[f.fix_id] : undefined;
              return (
                <tr
                  key={f.id}
                  onClick={() => select(f.id)}
                  className={clsx(
                    "animate-fade-in cursor-pointer border-t border-line/70 transition-colors hover:bg-night-800/60",
                    selectedId === f.id && "bg-night-800/80",
                  )}
                >
                  <td className="py-2 pr-2 pl-4">
                    <SeverityChip s={f.severity} compact />
                  </td>
                  <td className="max-w-[360px] px-2">
                    <div className={clsx("truncate text-[12.5px]", f.status === "fixed" ? "text-mithril-dim" : "text-mithril")}>{f.title}</div>
                    <div className="truncate font-mono text-[10.5px] text-muted">
                      {isLab(f) && (
                        <span className="mr-1.5 rounded border border-line px-1 text-[9px] uppercase tracking-wider text-faint" title={f.component}>
                          lab
                        </span>
                      )}
                      {f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : (f.url ?? "—")}
                    </div>
                  </td>
                  <td className="px-2 font-mono text-[10.5px] whitespace-nowrap text-mithril-dim">
                    {f.tool}
                    <span className="text-faint"> · {f.category}</span>
                  </td>
                  <td className="px-2 font-mono text-[10.5px] whitespace-nowrap text-muted">{f.cve ?? f.cwe ?? "—"}</td>
                  <td className="px-2 whitespace-nowrap">
                    <StatusChip s={f.status} />
                  </td>
                  <td className="px-2 whitespace-nowrap">{fx ? <FixChip s={fx.status} /> : <span className="text-faint">—</span>}</td>
                  <td className="px-2 text-right font-mono text-[10.5px] text-mithril-dim tabular-nums">
                    {Math.round(f.confidence * 100)}%
                  </td>
                  <td className="pr-4 pl-2 text-right font-mono text-[10.5px] text-mithril tabular-nums">
                    {f.priority != null ? Math.round(f.priority) : "—"}
                  </td>
                </tr>
              );
            })}
            {shown.length === 0 && (
              <tr>
                <td colSpan={8} className="py-10 text-center font-mono text-[11px] text-muted">
                  {snap.findings.length ? "no findings match these filters" : "no findings yet — start a scan"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
