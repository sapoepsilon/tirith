"use client";

import clsx from "clsx";
import { BrainCircuit, Sparkles } from "lucide-react";
import { useTirith } from "@/lib/store";
import { PanelHeader, fmtTime } from "./ui";

export function AiTimeline({ className, limit = 14 }: { className?: string; limit?: number }) {
  const { events, select } = useTirith();
  const ai = events.filter((e) => e.type === "ai.thinking" || e.type === "ai.summary");
  const shown = ai.slice(-limit).reverse();
  const thinkingNow = ai.length > 0 && ai[ai.length - 1].type === "ai.thinking";

  return (
    <section className={clsx("panel flex min-h-0 flex-col", className)}>
      <PanelHeader
        icon={BrainCircuit}
        title="AI agent activity"
        sub="text-only · DeepSeek"
        right={
          thinkingNow ? (
            <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-[#b9a6ff]">
              <span className="size-1.5 animate-pulse-soft rounded-full bg-[#b9a6ff]" />
              thinking
            </span>
          ) : (
            <span className="font-mono text-[10px] text-faint">idle</span>
          )
        }
      />
      <ol className="relative min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {shown.length === 0 && <li className="py-6 text-center font-mono text-[11px] text-muted">agent idle</li>}
        {shown.map((e, i) => {
          const thinking = e.type === "ai.thinking";
          return (
            <li
              key={`${e.ts}-${ai.length - i}`}
              onClick={() => e.finding_id && select(e.finding_id)}
              className={clsx("relative pb-3 pl-6", i === 0 && "animate-fade-in", e.finding_id && "cursor-pointer")}
            >
              {i < shown.length - 1 && <span className="absolute top-4 bottom-0 left-[7px] w-px bg-line" />}
              <span
                className={clsx(
                  "absolute top-[3px] left-0 flex size-[15px] items-center justify-center rounded-full border",
                  thinking ? "border-[#b9a6ff]/40 bg-night-900" : "border-[#b9a6ff]/60 bg-[#b9a6ff]/15",
                )}
              >
                {thinking ? (
                  <span className={clsx("size-1.5 rounded-full bg-[#b9a6ff]", i === 0 && thinkingNow && "animate-pulse-soft")} />
                ) : (
                  <Sparkles className="size-2.5 text-[#cbbcff]" />
                )}
              </span>
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-[9.5px] tracking-wider text-[#b9a6ff] uppercase">{thinking ? "thinking" : "summary"}</span>
                <time className="font-mono text-[9.5px] text-faint">{fmtTime(e.ts)}</time>
              </div>
              <p className={clsx("mt-0.5 text-[12px] leading-snug", thinking ? "text-muted italic" : "text-mithril-dim")}>{e.message}</p>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
