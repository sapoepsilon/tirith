"use client";

import clsx from "clsx";
import { Eye, FolderGit2, Hand, Radar, RotateCcw, Zap } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { TirithProvider, useTirith } from "@/lib/store";
import type { Mode } from "@/lib/types";
import { FindingDrawer } from "./FindingDrawer";
import { TirithGlyph } from "./ui";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/analyst", label: "Analyst" },
  { href: "/findings", label: "Findings" },
  { href: "/activity", label: "Activity" },
  { href: "/audit", label: "Audit log" },
];

const MODES: { id: Mode; label: string; icon: typeof Eye; hint: string }[] = [
  { id: "observe", label: "Observe", icon: Eye, hint: "Report only" },
  { id: "assisted", label: "Assisted", icon: Hand, hint: "Patch → PR → verify, human merges" },
  { id: "autonomous", label: "Autonomous", icon: Zap, hint: "Auto-apply allowlisted categories, rollback on failure" },
];

function ConnBadge() {
  const { conn, demoReason, replay } = useTirith();
  if (conn === "demo")
    return (
      <div className="flex items-center gap-1.5">
        <span
          title={demoReason ?? undefined}
          className="inline-flex items-center gap-1.5 rounded-md border border-sev-medium/40 bg-sev-medium/10 px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-sev-medium"
        >
          <span className="size-1.5 animate-pulse-soft rounded-full bg-sev-medium" />
          Demo data
        </span>
        <button
          onClick={replay}
          title="Replay demo from the start"
          className="rounded-md border border-line p-1 text-muted transition hover:border-line-strong hover:text-mithril"
        >
          <RotateCcw className="size-3" />
        </button>
      </div>
    );
  const live = conn === "live";
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em]",
        live ? "border-ok/40 bg-ok/10 text-ok" : "border-line text-muted",
      )}
    >
      <span className={clsx("size-1.5 rounded-full", live ? "bg-ok" : "animate-pulse-soft bg-muted")} />
      {conn === "probing" ? "Connecting" : live ? "Live" : "Reconnecting"}
    </span>
  );
}

function ModeSelector() {
  const { snap, setMode } = useTirith();
  const cur = snap.mode.mode;
  return (
    <div className="flex items-center rounded-lg border border-line bg-night-900/80 p-0.5" role="radiogroup" aria-label="Remediation mode">
      {MODES.map((m) => {
        const active = m.id === cur;
        return (
          <button
            key={m.id}
            role="radio"
            aria-checked={active}
            title={m.hint}
            onClick={() => !active && void setMode(m.id)}
            className={clsx(
              "relative flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11.5px] font-medium transition-all duration-300",
              active
                ? "bg-night-700 text-mithril shadow-[inset_0_0_0_1px_rgba(127,227,255,0.35),0_0_14px_-4px_rgba(127,227,255,0.6)]"
                : "text-muted hover:text-mithril-dim",
            )}
          >
            <m.icon className={clsx("size-3", active && "text-accent")} strokeWidth={2} />
            {m.label}
          </button>
        );
      })}
    </div>
  );
}

function Header() {
  const path = usePathname();
  const { snap, startScan, demo } = useTirith();
  const asset = snap.assets[0];
  const scan = snap.scans[0];
  const running = scan?.status === "running" || scan?.status === "queued";
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-night-950/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1680px] flex-wrap items-center gap-x-6 gap-y-2 px-5 py-2.5">
        <Link href="/" className="flex items-center gap-2.5">
          <TirithGlyph size={30} />
          <div className="leading-none">
            <div className="text-[17px] font-semibold tracking-[0.32em] text-mithril">TIRITH</div>
            <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.22em] text-muted">security command center</div>
          </div>
        </Link>

        <nav className="flex items-center gap-0.5">
          {NAV.map((n) => {
            const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
            return (
              <Link
                key={n.href}
                href={n.href}
                className={clsx(
                  "relative rounded-md px-3 py-1.5 text-[12.5px] transition",
                  active ? "text-mithril" : "text-muted hover:text-mithril-dim",
                )}
              >
                {n.label}
                {active && <span className="absolute inset-x-3 -bottom-[11px] h-px bg-accent shadow-[0_0_8px_var(--color-accent)]" />}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex flex-wrap items-center gap-3">
          {asset && (
            <span className="hidden items-center gap-1.5 rounded-md border border-line bg-night-900/60 px-2 py-1 font-mono text-[11px] text-mithril-dim xl:inline-flex">
              <FolderGit2 className="size-3 text-muted" />
              {asset.ref}
            </span>
          )}
          <ConnBadge />
          <ModeSelector />
          <button
            onClick={() => void startScan()}
            disabled={running && !demo}
            className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-[12px] font-medium text-accent transition hover:bg-accent/20 disabled:opacity-50"
          >
            <Radar className={clsx("size-3.5", running && "animate-spin [animation-duration:2.5s]")} />
            {running ? "Scanning" : demo ? "Replay scan" : "Run scan"}
          </button>
        </div>
      </div>
    </header>
  );
}

function Toasts() {
  const { toasts } = useTirith();
  return (
    <div className="pointer-events-none fixed bottom-4 left-4 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={clsx(
            "panel animate-fade-in px-3 py-2 font-mono text-[11.5px]",
            t.level === "error" ? "text-sev-critical" : t.level === "success" ? "text-ok" : "text-mithril-dim",
          )}
        >
          {t.text}
        </div>
      ))}
    </div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <TirithProvider>
      <Header />
      <main className="mx-auto max-w-[1680px] px-5 py-5">{children}</main>
      <FindingDrawer />
      <Toasts />
    </TirithProvider>
  );
}
