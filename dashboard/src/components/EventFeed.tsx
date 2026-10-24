"use client";

import clsx from "clsx";
import { Radio } from "lucide-react";
import { useMemo, useState } from "react";
import { useTirith } from "@/lib/store";
import { EVENT_META, PanelHeader, eventColor, fmtTime } from "./ui";

const FILTERS = [
  { id: "all", label: "all" },
  { id: "scan", label: "scan", match: ["scan.", "tool.", "finding."] },
  { id: "lab", label: "lab", match: ["validation."] },
  { id: "ai", label: "ai", match: ["ai."] },
  { id: "fix", label: "fix", match: ["fix.", "posture.", "policy.", "mode."] },
] as const;

export function EventFeed({ className, limit = 120 }: { className?: string; limit?: number }) {
  const { events, conn, select } = useTirith();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["id"]>("all");
  const shown = useMemo(() => {
    const f = FILTERS.find((x) => x.id === filter);
    const list = f && "match" in f ? events.filter((e) => f.match.some((m) => e.type.startsWith(m))) : events;
    return list.slice(-limit).reverse();
  }, [events, filter, limit]);

  return (
    <section className={clsx("panel flex min-h-0 flex-col", className)}>
      <PanelHeader
        icon={Radio}
        title="Live event stream"
        sub={
          <span className="inline-flex items-center gap-1.5">
            <span className={clsx("size-1.5 rounded-full", conn === "reconnecting" || conn === "probing" ? "bg-muted" : "animate-pulse-soft bg-accent")} />
            {events.length} events
          </span>
        }
        right={
          <div className="flex gap-0.5">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={clsx(
                  "rounded px-1.5 py-0.5 font-mono text-[10px] transition",
                  filter === f.id ? "bg-night-700 text-accent" : "text-muted hover:text-mithril-dim",
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
        }
      />
      <ol className="min-h-0 flex-1 overflow-y-auto px-2 py-1.5">
        {shown.length === 0 && (
          <li className="px-3 py-10 text-center font-mono text-[11px] text-muted">
            {conn === "reconnecting" ? "waiting for /ws/events…" : "no events yet"}
          </li>
        )}
        {shown.map((e, i) => {
          const meta = EVENT_META[e.type] ?? EVENT_META["mode.changed"];
          const color = eventColor(e);
          const Icon = meta.icon;
          return (
            <li
              key={`${e.ts}-${e.type}-${events.length - i}`}
              onClick={() => e.finding_id && select(e.finding_id)}
              className={clsx(
                "group grid grid-cols-[52px_22px_1fr] items-start gap-2 rounded-md px-2 py-1.5",
                i === 0 && "animate-slide-in",
                e.finding_id && "cursor-pointer hover:bg-night-800/70",
              )}
            >
              <time className="pt-0.5 font-mono text-[10px] text-faint tabular-nums">{fmtTime(e.ts)}</time>
              <span
                className="mt-px flex size-[20px] items-center justify-center rounded-md border"
                style={{ color, borderColor: `color-mix(in srgb, ${color} 30%, transparent)`, background: `color-mix(in srgb, ${color} 8%, transparent)` }}
              >
                <Icon className={clsx("size-3", e.type === "ai.thinking" && "animate-pulse-soft")} strokeWidth={2} />
              </span>
              <div className="min-w-0">
                <span className="mr-1.5 font-mono text-[9.5px] uppercase tracking-wider" style={{ color }}>
                  {e.type}
                </span>
                <span className={clsx("text-[12px] leading-snug", e.type === "validation.step" ? "text-muted" : "text-mithril-dim")}>
                  {e.message}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
