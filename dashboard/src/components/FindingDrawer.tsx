"use client";

import clsx from "clsx";
import {
  BookOpenText,
  CheckCircle2,
  ExternalLink,
  FileCode2,
  FlaskConical,
  GitBranch,
  GitPullRequest,
  Loader2,
  Sparkles,
  Undo2,
  Wrench,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo } from "react";
import { useTirith, type ActionName } from "@/lib/store";
import type { EvidenceBlock } from "@/lib/types";
import { CodeBlock, DiffView } from "./Code";
import { EVENT_META, FixChip, SEV_COLOR, SeverityChip, StatusChip, eventColor, fmtTime } from "./ui";

function Section({ icon: Icon, title, children, right }: { icon: LucideIcon; title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="border-t border-line px-5 py-4">
      <div className="mb-2.5 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-[10.5px] font-semibold tracking-[0.16em] text-mithril-dim uppercase">
          <Icon className="size-3.5 text-accent" strokeWidth={1.75} />
          {title}
        </h3>
        {right}
      </div>
      {children}
    </section>
  );
}

const EV_KIND: Record<EvidenceBlock["kind"], string> = {
  request: "var(--color-accent)",
  response: "var(--color-sev-low)",
  log: "var(--color-sev-medium)",
  note: "var(--color-mithril-dim)",
};

function ActionButton({
  name,
  label,
  icon: Icon,
  onClick,
  disabled,
  busy,
  primary,
  title,
}: {
  name: ActionName;
  label: string;
  icon: LucideIcon;
  onClick: (n: ActionName) => void;
  disabled?: boolean;
  busy?: boolean;
  primary?: boolean;
  title?: string;
}) {
  return (
    <button
      onClick={() => onClick(name)}
      title={title}
      disabled={disabled || busy}
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[11.5px] font-medium transition disabled:cursor-not-allowed disabled:opacity-35",
        primary
          ? "border-accent/50 bg-accent/15 text-accent hover:bg-accent/25"
          : "border-line-strong bg-night-800 text-mithril-dim hover:border-faint hover:text-mithril",
      )}
    >
      {busy ? <Loader2 className="size-3.5 animate-spin" /> : <Icon className="size-3.5" />}
      {label}
    </button>
  );
}

export function FindingDrawer() {
  const { snap, selectedId, select, act, isPending, explanations, events } = useTirith();
  const f = snap.findings.find((x) => x.id === selectedId);
  const fx = f?.fix_id ? snap.fixes[f.fix_id] : undefined;
  const ex = f ? explanations[f.id] : undefined;
  const busy = (n: ActionName) => !!f && isPending(f.id, n);
  const mode = snap.mode.mode;

  const trail = useMemo(() => (f ? events.filter((e) => e.finding_id === f.id) : []), [events, f]);
  const startedAt = trail.findLastIndex((e) => e.type === "validation.started");
  const validating =
    (startedAt >= 0 && !trail.slice(startedAt).some((e) => e.type === "validation.result")) ||
    // A stored validation without a finish time is still running (e.g. after a reload mid-run, events gone).
    (!!f?.validation && !f.validation.finished_at && startedAt < 0);
  const liveSteps = useMemo(() => {
    const start = trail.findLastIndex((e) => e.type === "validation.started");
    return start >= 0 ? trail.slice(start).filter((e) => e.type === "validation.step") : [];
  }, [trail]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && select(null);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [select]);

  if (!f) return null;

  const run = (n: ActionName) => void act(n, f.id);
  const canApply = !!fx && ["proposed", "pr_opened", "verified", "escalated"].includes(fx.status) && mode !== "observe";
  const canRollback = !!fx && ["applied", "verified"].includes(fx.status);
  const fixLabel = mode === "autonomous" ? "Auto-fix" : "Fix → PR";
  const observe = mode === "observe";

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <button aria-label="Close" onClick={() => select(null)} className="absolute inset-0 bg-night-950/60 backdrop-blur-[2px]" />
      <aside className="drawer-in relative flex h-full w-full max-w-[680px] flex-col overflow-y-auto border-l border-line-strong bg-night-900 shadow-[-30px_0_60px_-30px_rgba(0,0,0,0.9)]">
        <div className="sticky top-0 z-10 border-b border-line bg-night-900/95 px-5 pt-4 pb-3 backdrop-blur">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityChip s={f.severity} />
                <StatusChip s={f.status} />
                {fx && <FixChip s={fx.status} />}
              </div>
              <h2 className="mt-2 text-[17px] leading-snug font-semibold text-mithril">{f.title}</h2>
              <div className="mt-1 font-mono text-[10.5px] text-muted">
                {f.id} · {f.tool} · {f.rule_id}
              </div>
            </div>
            <button onClick={() => select(null)} className="rounded-md border border-line p-1.5 text-muted hover:text-mithril">
              <X className="size-4" />
            </button>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <ActionButton name="explain" label="Explain" icon={BookOpenText} onClick={run} busy={busy("explain")} />
            <ActionButton
              name="validate"
              label="Validate in lab"
              icon={FlaskConical}
              onClick={run}
              busy={busy("validate") || validating}
              disabled={f.status === "fixed"}
            />
            <ActionButton
              name="fix"
              label={fixLabel}
              icon={Wrench}
              onClick={run}
              busy={busy("fix") || f.status === "fixing"}
              disabled={
                observe ||
                f.status === "fixed" ||
                (!!fx && fx.status !== "rolled_back" && fx.status !== "failed" && fx.status !== "escalated")
              }
              title={observe ? "Observe mode is report-only; switch to Assisted or Autonomous to fix" : undefined}
              primary
            />
            <ActionButton name="apply" label="Apply" icon={CheckCircle2} onClick={run} busy={busy("apply")} disabled={!canApply} />
            <ActionButton name="rollback" label="Rollback" icon={Undo2} onClick={run} busy={busy("rollback")} disabled={!canRollback} />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-px bg-line font-mono text-[10.5px]">
          {[
            ["category", f.category],
            ["weakness", f.cwe ?? "—"],
            ["cve", f.cve ?? "—"],
            ["package", f.package ? `${f.package} ${f.installed_version ?? ""}${f.fixed_version ? ` → ${f.fixed_version}` : ""}` : "—"],
            ["confidence", `${Math.round(f.confidence * 100)}%`],
            ["priority", f.priority != null ? `${Math.round(f.priority)} / 100${f.component && f.component !== "main" ? ` · ${f.component}` : ""}` : "—"],
          ].map(([k, v]) => (
            <div key={k} className="bg-night-900 px-5 py-2">
              <div className="text-[9px] tracking-widest text-faint uppercase">{k}</div>
              <div className="mt-0.5 truncate text-mithril-dim">{v}</div>
            </div>
          ))}
        </div>

        <Section icon={BookOpenText} title="Description">
          <p className="whitespace-pre-line text-[13px] leading-relaxed text-mithril-dim">
            {f.advisories?.length ? f.description.split("\n- ")[0] : f.description}
          </p>
          {f.advisories && f.advisories.length > 0 && (
            <div className="mt-3 max-h-56 overflow-auto rounded border border-line">
              <table className="w-full text-left font-mono text-[10.5px]">
                <tbody>
                  {f.advisories.map((a) => (
                    <tr key={a.id} className="border-t border-line/60 first:border-t-0">
                      <td className="py-1 pr-2 pl-2.5 whitespace-nowrap" style={{ color: SEV_COLOR[a.severity] }}>
                        {a.severity}
                      </td>
                      <td className="px-2 whitespace-nowrap text-mithril-dim">
                        {a.url ? (
                          <a href={a.url} target="_blank" rel="noreferrer" className="hover:text-accent hover:underline">
                            {a.id}
                          </a>
                        ) : (
                          a.id
                        )}
                      </td>
                      <td className="max-w-[260px] truncate px-2 text-muted" title={a.title}>
                        {a.title}
                      </td>
                      <td className="pr-2.5 pl-2 text-right whitespace-nowrap text-faint">{a.fixed_version ?? "no fix"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        {(f.snippet || f.file) && (
          <Section
            icon={FileCode2}
            title="Location"
            right={
              <span className="font-mono text-[10.5px] text-accent">
                {f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.url}
              </span>
            }
          >
            {f.snippet && <CodeBlock code={f.snippet} startLine={f.line} highlightLine={f.line} />}
          </Section>
        )}

        <Section icon={Sparkles} title="AI analysis" right={<span className="font-mono text-[9.5px] text-faint">text only · no tool access</span>}>
          {f.ai_summary ? (
            <p className="rounded-md border border-[#b9a6ff]/20 bg-[#b9a6ff]/[0.05] px-3 py-2.5 text-[12.5px] leading-relaxed text-mithril">{f.ai_summary}</p>
          ) : (
            <p className="font-mono text-[11px] text-muted">triage pending…</p>
          )}
          {ex && (
            <dl className="animate-fade-in mt-3 space-y-2.5 text-[12.5px]">
              {(
                [
                  ["Root cause", ex.root_cause],
                  ["Exploitability", ex.exploitability],
                  ["Fix plan", ex.fix_plan],
                ] as const
              ).map(([k, v]) => (
                <div key={k}>
                  <dt className="font-mono text-[9.5px] tracking-widest text-faint uppercase">{k}</dt>
                  <dd className="mt-0.5 leading-relaxed text-mithril-dim">{v}</dd>
                </div>
              ))}
            </dl>
          )}
        </Section>

        <Section
          icon={FlaskConical}
          title="Lab validation"
          right={
            f.validation && (
              <span
                className={clsx(
                  "rounded border px-1.5 py-px font-mono text-[10px] tracking-wider uppercase",
                  f.validation.result === "confirmed" ? "border-sev-critical/50 text-sev-critical" : "border-ok/40 text-ok",
                  (f.validation.result === "unsupported" || f.validation.result === "error") && "border-line text-muted",
                )}
              >
                {f.validation.result.replace("_", " ")} · {Math.round(f.validation.confidence * 100)}%
              </span>
            )
          }
        >
          {validating && (
            <ol className="mb-3 space-y-1 font-mono text-[11px]">
              {liveSteps.map((s, i) => (
                <li key={i} className="animate-slide-in flex gap-2 text-mithril-dim">
                  <span className="text-accent">›</span>
                  {s.message}
                </li>
              ))}
              <li className="flex items-center gap-2 text-accent">
                <Loader2 className="size-3 animate-spin" /> running in tirith-lab (isolated, no egress)…
              </li>
            </ol>
          )}
          {f.validation ? (
            <div className="space-y-2">
              <div className="font-mono text-[10.5px] text-muted">
                template <span className="text-mithril-dim">{f.validation.check}</span> · {fmtTime(f.validation.finished_at ?? undefined)}
              </div>
              {f.validation.evidence.map((ev, i) => (
                <div key={i} className="overflow-hidden rounded-md border border-line">
                  <div className="flex items-center gap-2 border-b border-line bg-night-850 px-3 py-1">
                    <span className="font-mono text-[9.5px] tracking-widest uppercase" style={{ color: EV_KIND[ev.kind] }}>
                      {ev.kind}
                    </span>
                    <span className="text-[11px] text-mithril-dim">{ev.label}</span>
                  </div>
                  <pre className="overflow-x-auto bg-night-950/80 px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-mithril-dim">
                    {ev.content}
                  </pre>
                </div>
              ))}
            </div>
          ) : (
            !validating && <p className="font-mono text-[11px] text-muted">not validated yet — run a fixed, read-only template against the lab target.</p>
          )}
        </Section>

        <Section
          icon={Wrench}
          title="Remediation"
          right={
            fx?.pr_url && (
              <a
                href={fx.pr_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 font-mono text-[10.5px] text-accent hover:underline"
              >
                <GitPullRequest className="size-3" />
                PR #{fx.pr_url.split("/").pop()}
                <ExternalLink className="size-3" />
              </a>
            )
          }
        >
          {fx ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3 font-mono text-[10.5px] text-muted">
                <FixChip s={fx.status} />
                <span>mode {fx.mode}</span>
                {fx.branch && (
                  <span className="inline-flex items-center gap-1">
                    <GitBranch className="size-3" />
                    {fx.branch}
                  </span>
                )}
              </div>
              {fx.verification && (
                <div className="rounded-md border border-ok/25 bg-ok/[0.05] px-3 py-2 font-mono text-[11px] text-mithril-dim">
                  {fx.verification.validation_result && (
                    <span className={fx.verification.validation_result === "fixed" ? "text-ok" : "text-sev-critical"}>
                      verification (rescan + lab boot): {fx.verification.validation_result}
                    </span>
                  )}
                  {fx.verification.details && <div className="mt-1 text-muted">{fx.verification.details}</div>}
                </div>
              )}
              {fx.diff ? <DiffView diff={fx.diff} /> : <p className="font-mono text-[11px] text-muted">patch generating…</p>}
            </div>
          ) : (
            <p className="font-mono text-[11px] text-muted">
              no fix yet · current mode <span className="text-mithril-dim">{mode}</span>
            </p>
          )}
        </Section>

        <Section icon={GitPullRequest} title="Finding timeline">
          <ol className="space-y-1.5">
            {trail.length === 0 && <li className="font-mono text-[11px] text-muted">no events recorded in this session</li>}
            {trail.slice(-30).map((e, i) => {
              const M = EVENT_META[e.type] ?? EVENT_META["mode.changed"];
              return (
                <li key={i} className="flex gap-2 text-[11.5px]">
                  <time className="w-14 shrink-0 font-mono text-[10px] text-faint">{fmtTime(e.ts)}</time>
                  <M.icon className="mt-0.5 size-3 shrink-0" style={{ color: eventColor(e) }} />
                  <span className="text-mithril-dim">{e.message}</span>
                </li>
              );
            })}
          </ol>
        </Section>
      </aside>
    </div>
  );
}
