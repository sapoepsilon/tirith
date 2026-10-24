"use client";

import { Gauge } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { gradeColor, gradeFor } from "@/lib/posture";
import { useTirith } from "@/lib/store";
import { PanelHeader } from "./ui";

function useTween(target: number, ms = 900) {
  const [v, setV] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      const e = 1 - Math.pow(1 - p, 3);
      const cur = a + (target - a) * e;
      setV(cur);
      from.current = cur;
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

const R = 70;
const SWEEP = 240;
const polar = (deg: number) => {
  const rad = ((deg - 90) * Math.PI) / 180;
  return [90 + R * Math.cos(rad), 90 + R * Math.sin(rad)];
};
const arc = (from: number, to: number) => {
  const [x1, y1] = polar(from);
  const [x2, y2] = polar(to);
  return `M ${x1} ${y1} A ${R} ${R} 0 ${to - from > 180 ? 1 : 0} 1 ${x2} ${y2}`;
};

function Sparkline({ points }: { points: { ts: string; score: number }[] }) {
  if (points.length < 2) return <div className="h-12" />;
  const W = 260;
  const H = 48;
  const xs = points.map((_, i) => (i / (points.length - 1)) * (W - 8) + 4);
  const ys = points.map((p) => H - 6 - (p.score / 100) * (H - 12));
  const d = xs.map((x, i) => `${i ? "L" : "M"}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ");
  const area = `${d} L${xs[xs.length - 1]},${H} L${xs[0]},${H} Z`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-12 w-full" preserveAspectRatio="none">
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#7fe3ff" stopOpacity="0.28" />
          <stop offset="1" stopColor="#7fe3ff" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[25, 50, 75].map((g) => (
        <line key={g} x1="0" x2={W} y1={H - 6 - (g / 100) * (H - 12)} y2={H - 6 - (g / 100) * (H - 12)} stroke="#1a2538" strokeDasharray="2 3" />
      ))}
      <path d={area} fill="url(#spark-fill)" />
      <path d={d} fill="none" stroke="#7fe3ff" strokeWidth="1.5" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      {xs.map((x, i) => (
        <circle key={i} cx={x} cy={ys[i]} r={i === xs.length - 1 ? 2.8 : 1.5} fill={i === xs.length - 1 ? "#fff" : "#7fe3ff"} />
      ))}
    </svg>
  );
}

export function PostureGauge() {
  const { snap } = useTirith();
  const p = snap.posture;
  const score = p?.score ?? 0;
  const v = useTween(score);
  const grade = p?.grade ?? gradeFor(score);
  const color = gradeColor(gradeFor(Math.round(v)));
  const hist = p?.history ?? [];
  const before = hist[0]?.score;
  const delta = before !== undefined ? score - before : 0;

  return (
    <section className="panel flex h-full flex-col">
      <PanelHeader icon={Gauge} title="Security posture" />
      <div className="flex flex-1 flex-col items-center px-4 pt-2 pb-3">
        <div className="relative">
          <svg viewBox="0 0 180 160" className="h-[170px] w-[190px]">
            <defs>
              <filter id="gauge-glow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="3" />
              </filter>
            </defs>
            {Array.from({ length: 25 }).map((_, i) => {
              const deg = -SWEEP / 2 + (i / 24) * SWEEP;
              const rad = ((deg - 90) * Math.PI) / 180;
              const r1 = R + 9;
              const r2 = R + (i % 6 === 0 ? 14 : 11);
              return (
                <line
                  key={i}
                  x1={90 + r1 * Math.cos(rad)}
                  y1={90 + r1 * Math.sin(rad)}
                  x2={90 + r2 * Math.cos(rad)}
                  y2={90 + r2 * Math.sin(rad)}
                  stroke={i % 6 === 0 ? "#3c4a60" : "#1f2b40"}
                  strokeWidth="1"
                />
              );
            })}
            <path d={arc(-SWEEP / 2, SWEEP / 2)} stroke="#151f31" strokeWidth="9" fill="none" strokeLinecap="round" />
            {v > 0.5 && (
              <>
                <path
                  d={arc(-SWEEP / 2, -SWEEP / 2 + (SWEEP * v) / 100)}
                  stroke={color}
                  strokeWidth="9"
                  fill="none"
                  strokeLinecap="round"
                  opacity="0.45"
                  filter="url(#gauge-glow)"
                />
                <path
                  d={arc(-SWEEP / 2, -SWEEP / 2 + (SWEEP * v) / 100)}
                  stroke={color}
                  strokeWidth="6"
                  fill="none"
                  strokeLinecap="round"
                />
              </>
            )}
          </svg>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pb-3">
            <div className="text-[52px] leading-none font-semibold tracking-tight tabular-nums" style={{ color: "var(--color-mithril)" }}>
              {Math.round(v)}
            </div>
            <div className="mt-1 flex items-center gap-2">
              <span
                className="rounded border px-1.5 font-mono text-[13px] font-semibold"
                style={{ color: gradeColor(grade), borderColor: `color-mix(in srgb, ${gradeColor(grade)} 45%, transparent)` }}
              >
                {grade}
              </span>
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted">/ 100</span>
            </div>
          </div>
        </div>
        <div className="-mt-2 w-full">
          <div className="mb-1 flex items-baseline justify-between font-mono text-[10.5px] text-muted">
            <span>history</span>
            {before !== undefined && (
              <span>
                <span className="text-mithril-dim">{before}</span>
                <span className="mx-1">→</span>
                <span className="text-mithril">{score}</span>
                <span className="ml-2" style={{ color: delta > 0 ? "var(--color-ok)" : delta < 0 ? "var(--color-sev-critical)" : undefined }}>
                  {delta > 0 ? "▲" : delta < 0 ? "▼" : "•"} {Math.abs(delta)}
                </span>
              </span>
            )}
          </div>
          <Sparkline points={hist} />
          <div className="mt-2 grid grid-cols-2 gap-2 font-mono text-[11px]">
            <div className="rounded-md border border-line bg-night-900/60 px-2 py-1.5">
              <div className="text-[9.5px] uppercase tracking-widest text-muted">open</div>
              <div className="text-mithril tabular-nums">{p?.open ?? 0}</div>
            </div>
            <div className="rounded-md border border-line bg-night-900/60 px-2 py-1.5">
              <div className="text-[9.5px] uppercase tracking-widest text-muted">fixed</div>
              <div className="text-ok tabular-nums">{p?.fixed ?? 0}</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
