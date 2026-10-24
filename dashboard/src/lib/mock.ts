import type { DataSource } from "./api";
import { DEFAULT_DIFF, DIFFS, MOCK_ASSET, SEEDS, VALIDATIONS } from "./mock-catalog";
import { gradeFor } from "./posture";
import type {
  AuditEntry,
  Counts,
  Explanation,
  Finding,
  Fix,
  Mode,
  ModeState,
  Scan,
  Snapshot,
  TirithEvent,
  ToolName,
} from "./types";
import { emptyCounts } from "./types";

/**
 * In-browser replay of a realistic Tirith run:
 * scan → findings → AI triage → lab validation → fix PR → verified → autonomous bump → posture rises.
 * Loops forever so the dashboard is always alive. User actions (validate/fix/…) also work against it.
 */

const WEIGHT: Counts = { critical: 12, high: 6, medium: 3, low: 1, info: 0 };

/** Mirror of the backend's v1.1 component tagging + priority (backend/app/focus.py) for demo data. */
const SUB_APP = /^(dockerized_labs\/[^/]+|challenge\/labs\/[^/]+|challenge)\//;
const SEV_W: Record<string, number> = { critical: 1, high: 0.7, medium: 0.4, low: 0.15, info: 0.03 };
function withPriority(f: Finding): Finding {
  const m = f.file?.match(SUB_APP);
  const component = m ? `lab:${m[1]}` : "main";
  if (f.status === "fixed" || f.status === "not_reproduced") return { ...f, component, priority: 0 };
  const v = f.validation;
  const conf = v?.result === "confirmed" ? v.confidence : f.confidence;
  const reach = (m ? 0.3 : 1) * (f.category === "dependency" ? (v?.result === "confirmed" ? 1 : 0.8) : 1);
  const validated = v ? (v.result === "confirmed" ? 1 : 0.6) : 0.7;
  const priority = Math.round(1000 * (SEV_W[f.severity] ?? 0.03) * conf * reach * validated) / 10;
  return { ...f, component, tags: m ? ["lab-subapp"] : [], priority };
}
const now = () => new Date().toISOString();
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

class Cancelled extends Error {}

export class MockEngine implements DataSource {
  kind = "mock" as const;
  private listeners = new Set<(e: TirithEvent) => void>();
  private events: TirithEvent[] = [];
  private run = 0;
  private scan!: Scan;
  private findings = new Map<string, Finding>();
  private fixes: Record<string, Fix> = {};
  private history: { ts: string; score: number }[] = [];
  private mode: ModeState = { mode: "assisted", autonomous_categories: ["dependency_bump", "config_hardening"] };
  private audit: AuditEntry[] = [];
  private started = false;
  private seq = 0;

  constructor() {
    this.reset();
  }

  // ---------------------------------------------------------------- state
  private reset() {
    this.findings.clear();
    this.fixes = {};
    this.events = [];
    this.audit = [];
    const t = Date.now();
    // Prior history so the sparkline shows "before" context.
    this.history = [
      { ts: new Date(t - 86400000 * 6).toISOString(), score: 52 },
      { ts: new Date(t - 86400000 * 4).toISOString(), score: 49 },
      { ts: new Date(t - 86400000 * 2).toISOString(), score: 46 },
    ];
    this.scan = {
      id: `scn_${(t % 100000).toString(36)}`,
      asset_id: MOCK_ASSET.id,
      status: "queued",
      tools: { semgrep: "pending", gitleaks: "pending", trivy: "pending", zap: "pending" },
      counts: emptyCounts(),
      started_at: null,
      finished_at: null,
    };
    this.mode = { mode: "assisted", autonomous_categories: ["dependency_bump", "config_hardening"] };
  }

  private score(): number {
    let penalty = 0;
    for (const f of this.findings.values()) {
      if (f.status === "fixed") continue;
      const w = WEIGHT[f.severity];
      penalty += f.status === "not_reproduced" ? w * 0.25 : w;
    }
    return Math.max(0, Math.min(100, Math.round(100 - penalty)));
  }

  private counts(): Counts {
    const c = emptyCounts();
    for (const f of this.findings.values()) if (f.status !== "fixed") c[f.severity]++;
    return c;
  }

  private emit(e: Omit<TirithEvent, "ts">) {
    const ev: TirithEvent = { ts: now(), ...e };
    this.events.push(ev);
    if (this.events.length > 500) this.events.shift();
    this.listeners.forEach((l) => l(ev));
  }

  private log(actor: string, action: string, target: string, result: string, details?: string) {
    this.audit.unshift({ id: ++this.seq, ts: now(), actor, action, target, result, details });
  }

  private pushPosture(reason: string) {
    const score = this.score();
    const prev = this.history[this.history.length - 1]?.score ?? score;
    this.history.push({ ts: now(), score });
    this.emit({
      type: "posture.updated",
      level: score > prev ? "success" : "info",
      message: `Posture ${prev} → ${score} (${gradeFor(score)}) · ${reason}`,
      data: { score, previous: prev, grade: gradeFor(score) },
    });
  }

  // -------------------------------------------------------------- scenario
  private sleep(ms: number, run: number) {
    return new Promise<void>((resolve, reject) =>
      setTimeout(() => (run === this.run ? resolve() : reject(new Cancelled())), ms),
    );
  }

  private async scenario(run: number) {
    const s = (ms: number) => this.sleep(ms, run);
    const scan = this.scan;
    await s(900);
    scan.status = "running";
    scan.started_at = now();
    this.log("dashboard", "scan.create", MOCK_ASSET.ref, "allowed", "scope: github_repo in allowlist");
    this.emit({ type: "scan.started", level: "info", message: `Scan started on ${MOCK_ASSET.ref}`, scan_id: scan.id });

    const byTool: Record<ToolName, string[]> = { semgrep: [], gitleaks: [], trivy: [], zap: [] };
    for (const seed of SEEDS) byTool[seed.tool as ToolName].push(seed.id);

    const runTool = async (tool: ToolName, delay: number, gap: number) => {
      await s(delay);
      scan.tools[tool] = "running";
      this.emit({
        type: "tool.started",
        level: "info",
        message: tool === "zap" ? "zap baseline started against lab target pygoat.lab:8000" : `${tool} started`,
        scan_id: scan.id,
        data: { tool },
      });
      for (const id of byTool[tool]) {
        await s(gap);
        this.addFinding(id);
      }
      await s(gap * 0.6);
      scan.tools[tool] = "done";
      this.emit({
        type: "tool.finished",
        level: "info",
        message: `${tool} finished · ${byTool[tool].length} findings`,
        scan_id: scan.id,
        data: { tool, findings: byTool[tool].length },
      });
    };

    await Promise.all([runTool("semgrep", 400, 1100), runTool("gitleaks", 700, 1600), runTool("trivy", 1000, 1500)]);
    this.emit({ type: "ai.thinking", level: "info", message: "Deploying target into isolated lab network for DAST…", scan_id: scan.id });
    await runTool("zap", 600, 900);

    scan.status = "done";
    scan.finished_at = now();
    scan.counts = this.counts();
    const c = scan.counts;
    this.emit({
      type: "scan.finished",
      level: "warn",
      message: `Scan complete · ${this.findings.size} findings (${c.critical} critical, ${c.high} high)`,
      scan_id: scan.id,
      data: { counts: c },
    });
    this.pushPosture("baseline after scan");

    await s(1200);
    this.emit({ type: "ai.thinking", level: "info", message: `Triaging ${this.findings.size} findings: ranking by reachability, exploitability and blast radius…` });
    await s(2200);
    let summarised = 0;
    for (const f of this.findings.values()) {
      this.emit({
        type: "ai.summary",
        level: "info",
        message: `${f.title}: ${f.ai_summary}`,
        finding_id: f.id,
        data: { severity: f.severity },
      });
      if (++summarised >= 6) break;
      await s(500);
    }

    await s(1200);
    await this.runValidation("fnd_sqli_lab", run);
    await s(800);
    await this.runValidation("fnd_path_traversal", run);
    await s(800);
    await this.runValidation("fnd_xss_lab", run);

    await s(1200);
    await this.runFix("fnd_sqli_lab", run, "assisted");

    await s(1600);
    this.setModeInternal("autonomous", "dashboard");
    await s(1200);
    await this.runFix("fnd_dep_werkzeug", run, "autonomous");
    await s(900);
    await this.runFix("fnd_dep_pyyaml", run, "autonomous");
    await s(900);
    await this.runFix("fnd_debug_mode", run, "autonomous");
    await s(900);
    await this.runFix("fnd_xss_lab", run, "autonomous");
    await s(1200);
    await this.runFix("fnd_secret_django", run, "assisted");
    await s(900);
    await this.runFix("fnd_zap_cookie", run, "autonomous");
    await s(900);
    const all = [...this.findings.values()];
    const fixed = all.filter((f) => f.status === "fixed").length;
    const notRepro = all.filter((f) => f.status === "not_reproduced").length;
    const escalated = Object.values(this.fixes).filter((x) => x.status === "escalated").length;
    const open = all.length - fixed - notRepro;
    this.emit({
      type: "ai.summary",
      level: "success",
      message: `Run complete: ${fixed} fixed, ${notRepro} not reproduced, ${escalated} escalated for human review, ${open} still open. Posture ${this.history[3]?.score} → ${this.score()}.`,
    });
  }

  private addFinding(id: string) {
    const seed = SEEDS.find((x) => x.id === id)!;
    const f: Finding = {
      ...clone(seed),
      ai_summary: null,
      scan_id: this.scan.id,
      asset_id: MOCK_ASSET.id,
      status: "open",
      validation: null,
      fix_id: null,
    };
    this.findings.set(id, f);
    this.scan.counts = this.counts();
    this.emit({
      type: "finding.new",
      level: f.severity === "critical" || f.severity === "high" ? "warn" : "info",
      message: `[${f.severity.toUpperCase()}] ${f.title}${f.file ? ` — ${f.file}${f.line ? `:${f.line}` : ""}` : ""}`,
      scan_id: this.scan.id,
      finding_id: id,
      data: { severity: f.severity, tool: f.tool },
    });
    // AI summary lands slightly later, like a real triage pass.
    setTimeout(() => {
      const cur = this.findings.get(id);
      if (cur) cur.ai_summary = seed.ai_summary;
    }, 2500);
  }

  private async runValidation(id: string, run: number) {
    const s = (ms: number) => this.sleep(ms, run);
    const f = this.findings.get(id);
    if (!f) return;
    const tpl = VALIDATIONS[id];
    if (!tpl) {
      this.emit({
        type: "validation.result",
        level: "warn",
        message: `No fixed validation template for ${f.cwe ?? f.rule_id} — marked unsupported`,
        finding_id: id,
        data: { result: "unsupported" },
      });
      f.validation = {
        id: `val_${id}`,
        finding_id: id,
        check: "none",
        result: "unsupported",
        confidence: 0,
        evidence: [{ kind: "note", label: "Unsupported", content: "No template exists for this weakness class." }],
        started_at: now(),
        finished_at: now(),
      };
      return;
    }
    this.log("tirith", "validation.run", id, "allowed", `template ${tpl.check} · target tirith-lab only`);
    this.emit({
      type: "validation.started",
      level: "info",
      message: `Validating ${f.title} with template ${tpl.check}`,
      finding_id: id,
      data: { check: tpl.check },
    });
    const started = now();
    for (const step of tpl.steps) {
      await s(850);
      this.emit({ type: "validation.step", level: "info", message: step, finding_id: id, data: { check: tpl.check } });
    }
    await s(900);
    const confirmed = id !== "fnd_path_traversal";
    f.validation = {
      id: `val_${id}`,
      finding_id: id,
      check: tpl.check,
      result: confirmed ? "confirmed" : "not_reproduced",
      confidence: confirmed ? 0.96 : 0.82,
      evidence: tpl.evidence,
      started_at: started,
      finished_at: now(),
    };
    f.status = confirmed ? "validated" : "not_reproduced";
    this.emit({
      type: "validation.result",
      level: confirmed ? "error" : "success",
      message: confirmed ? `CONFIRMED exploitable: ${f.title}` : `Not reproduced in lab: ${f.title}`,
      finding_id: id,
      data: { result: f.validation.result, confidence: f.validation.confidence },
    });
    if (!confirmed) this.pushPosture("path traversal not reproduced");
  }

  private async runFix(id: string, run: number, mode: Mode) {
    const s = (ms: number) => this.sleep(ms, run);
    const f = this.findings.get(id);
    if (!f || f.status === "fixed") return;
    const fixId = `fix_${id.replace(/^fnd_/, "")}`;
    const category =
      f.category === "dependency" ? "dependency_bump" : f.category === "config" || f.category === "dast" ? "config_hardening" : f.category;
    const branch = `tirith/fix-${id.replace(/^fnd_/, "").replace(/_/g, "-")}`;
    const fix: Fix = {
      id: fixId,
      finding_id: id,
      mode,
      status: "proposed",
      diff: DIFFS[id] ?? DEFAULT_DIFF(f),
      branch,
      pr_url: null,
      verification: null,
      created_at: now(),
    };
    this.fixes[fixId] = fix;
    f.fix_id = fixId;
    f.status = "fixing";
    this.emit({ type: "ai.thinking", level: "info", message: `Drafting minimal patch for ${f.rule_id}…`, finding_id: id, fix_id: fixId });
    this.emit({ type: "fix.started", level: "info", message: `Remediation started: ${f.title}`, finding_id: id, fix_id: fixId, data: { mode } });
    await s(1600);
    const lines = fix.diff.split("\n");
    const add = lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length;
    const del = lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length;
    this.emit({
      type: "fix.patch",
      level: "info",
      message: `Patch ready · ${f.file ?? "config"} (+${add} −${del})`,
      finding_id: id,
      fix_id: fixId,
      data: { additions: add, deletions: del },
    });

    const autonomousAllowed = mode === "autonomous" && this.mode.autonomous_categories.includes(category);

    if (mode === "autonomous" && !autonomousAllowed) {
      await s(700);
      fix.status = "escalated";
      f.status = f.validation?.result === "confirmed" ? "validated" : "open";
      this.log("tirith", "fix.apply", fixId, "denied", `category '${category}' not in autonomous_categories`);
      this.emit({
        type: "policy.denied",
        level: "warn",
        message: `Auto-apply blocked: category '${category}' is not in the autonomous allowlist — escalated to human`,
        finding_id: id,
        fix_id: fixId,
        data: { category },
      });
      return;
    }

    if (autonomousAllowed) {
      await s(1100);
      fix.status = "applied";
      this.log("tirith", "fix.apply", fixId, "allowed", `autonomous · ${category}`);
      this.emit({ type: "fix.applied", level: "success", message: `Auto-applied ${category} on ${branch}`, finding_id: id, fix_id: fixId });
    } else {
      await s(1300);
      const pr = 1 + Object.values(this.fixes).filter((x) => x.pr_url).length;
      // Demo only: a reserved, never-resolving host (RFC 6761 .invalid) so no link points at a real PR.
      fix.pr_url = `https://demo-pr.invalid/${MOCK_ASSET.ref}/pull/${pr}`;
      fix.status = "pr_opened";
      this.log("tirith", "github.pr.create", `${MOCK_ASSET.ref}#${pr}`, "allowed", `branch ${branch}`);
      this.emit({
        type: "fix.pr_opened",
        level: "success",
        message: `Pull request #${pr} opened: ${f.title}`,
        finding_id: id,
        fix_id: fixId,
        data: { pr_url: fix.pr_url, branch },
      });
    }

    await s(1500);
    // Same shape as the backend: (a) rescan of the changed files + (b) lab rebuild/boot; no project test suite.
    fix.verification = {
      tests_passed: null,
      validation_result: "fixed",
      details: `(a) ${f.tool} rescan of ${f.file ?? "changed files"}: rule no longer reported · (b) patched app rebuilt and booted in the isolated lab`,
    };
    if (fix.status !== "applied") fix.status = "verified";
    f.status = "fixed";
    this.emit({
      type: "fix.verified",
      level: "success",
      message: `Verified: ${fix.verification.details}`,
      finding_id: id,
      fix_id: fixId,
    });
    this.scan.counts = this.counts();
    this.pushPosture(`${f.title} remediated`);
  }

  private setModeInternal(mode: Mode, actor: string) {
    const prev = this.mode.mode;
    this.mode = { ...this.mode, mode };
    this.log(actor, "mode.set", mode, "allowed", `${prev} → ${mode}`);
    this.emit({
      type: "mode.changed",
      level: "info",
      message: `Mode ${prev} → ${mode}${mode === "autonomous" ? ` · allowlist: ${this.mode.autonomous_categories.join(", ")}` : ""}`,
      data: { mode, previous: prev },
    });
  }

  private loop() {
    const run = ++this.run;
    this.scenario(run)
      .then(() => this.sleep(40000, run))
      .then(() => {
        this.reset();
        this.emit({ type: "mode.changed", level: "info", message: "Demo replay restarting", data: { mode: "assisted", reset: true } });
        this.loop();
      })
      .catch((e) => {
        if (!(e instanceof Cancelled)) console.error(e);
      });
  }

  /** Restart the scripted replay from the beginning. */
  replay() {
    this.run++;
    this.reset();
    this.listeners.forEach((l) =>
      l({ ts: now(), type: "mode.changed", level: "info", message: "Demo replay restarted", data: { reset: true } }),
    );
    this.loop();
  }

  // ------------------------------------------------------------ DataSource
  async snapshot(): Promise<Snapshot> {
    const score = this.score();
    const counts = this.counts();
    const all = [...this.findings.values()];
    return clone({
      assets: [MOCK_ASSET],
      scans: [this.scan],
      findings: all.map(withPriority),
      fixes: this.fixes,
      posture: {
        asset_id: MOCK_ASSET.id,
        score: this.findings.size ? score : this.history[this.history.length - 1].score,
        grade: gradeFor(this.findings.size ? score : this.history[this.history.length - 1].score),
        counts,
        open: all.filter((f) => f.status !== "fixed").length,
        fixed: all.filter((f) => f.status === "fixed").length,
        history: this.history,
      },
      mode: this.mode,
      audit: this.audit,
    });
  }

  async recentEvents() {
    return [...this.events];
  }

  subscribe(onEvent: (e: TirithEvent) => void, onStatus: (s: "open" | "closed") => void) {
    this.listeners.add(onEvent);
    onStatus("open");
    if (!this.started) {
      this.started = true;
      this.loop();
    }
    return () => {
      this.listeners.delete(onEvent);
    };
  }

  async explain(id: string): Promise<Explanation> {
    const f = this.findings.get(id);
    await new Promise((r) => setTimeout(r, 900));
    this.emit({ type: "ai.thinking", level: "info", message: `Explaining ${f?.title ?? id}…`, finding_id: id });
    await new Promise((r) => setTimeout(r, 700));
    const ex: Explanation = {
      summary: f?.ai_summary ?? f?.description ?? "No summary available.",
      root_cause: f
        ? `${f.cwe ?? f.rule_id}: ${f.description}`
        : "Unknown",
      exploitability:
        f?.validation?.result === "confirmed"
          ? `Confirmed in the isolated lab with template ${f.validation.check} (confidence ${f.validation.confidence}).`
          : "Not yet validated dynamically; static confidence " + (f?.confidence ?? 0).toFixed(2) + ".",
      fix_plan: f && DIFFS[id] ? "Apply the minimal patch shown below, then rescan the changed files and boot the patched app in the lab." : "Escalate to a human owner.",
    };
    this.emit({ type: "ai.summary", level: "info", message: `${f?.title ?? id}: ${ex.summary}`, finding_id: id });
    return ex;
  }

  async validate(id: string) {
    void this.runValidation(id, this.run).catch(() => {});
    return { started: true };
  }

  async fix(id: string, mode?: Mode) {
    const m = mode ?? this.mode.mode;
    if (m === "observe") {
      // Mirror the backend: observe mode is report-only and the fix endpoint answers 403.
      this.log("operator", "fix.create", id, "denied", "observe mode: remediation disabled");
      this.emit({ type: "policy.denied", level: "warn", message: "Fix refused: observe mode is report-only", finding_id: id });
      throw new Error("403 — observe mode: remediation is disabled (report only)");
    }
    void this.runFix(id, this.run, m).catch(() => {});
    await new Promise((r) => setTimeout(r, 50));
    const f = this.findings.get(id);
    return clone(this.fixes[f?.fix_id ?? ""] ?? ({} as Fix));
  }

  async apply(fixId: string) {
    const fix = this.fixes[fixId];
    if (!fix) throw new Error("unknown fix");
    fix.status = "applied";
    const f = this.findings.get(fix.finding_id);
    if (f) f.status = "fixed";
    this.log("operator", "fix.apply", fixId, "allowed", "manual approval");
    this.emit({ type: "fix.applied", level: "success", message: `Applied ${fixId} (operator approval)`, fix_id: fixId, finding_id: fix.finding_id });
    this.pushPosture("operator applied fix");
    return fix;
  }

  async rollback(fixId: string) {
    const fix = this.fixes[fixId];
    if (!fix) throw new Error("unknown fix");
    fix.status = "rolled_back";
    const f = this.findings.get(fix.finding_id);
    if (f) f.status = f.validation?.result === "confirmed" ? "validated" : "open";
    this.log("operator", "fix.rollback", fixId, "allowed", "manual rollback");
    this.emit({ type: "fix.rolled_back", level: "warn", message: `Rolled back ${fixId}`, fix_id: fixId, finding_id: fix.finding_id });
    this.pushPosture("fix rolled back");
    return fix;
  }

  async setMode(m: ModeState) {
    this.setModeInternal(m.mode, "operator");
    return this.mode;
  }

  async startScan() {
    this.replay();
    return clone(this.scan);
  }
}

let singleton: MockEngine | null = null;
export const mockSource = () => (singleton ??= new MockEngine());
