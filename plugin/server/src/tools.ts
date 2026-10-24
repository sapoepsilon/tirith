import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import { backend, BackendError } from "./backend.js";
import {
  countsLine,
  diffMeta,
  fullFinding,
  publicAsset,
  slimFinding,
  slimFix,
  slimIssue,
  slimPosture,
  slimScan,
  slimValidation,
  sortFindings,
  truncate,
  untrusted,
  UNTRUSTED_NOTE,
} from "./shape.js";
import { WIDGET_URI } from "./widget.js";
import type { Finding, Fix, Scan } from "./types.js";

const SCAN_WAIT_MS = Number(process.env.TIRITH_SCAN_WAIT_MS ?? 45_000);
const FIX_WAIT_MS = Number(process.env.TIRITH_FIX_WAIT_MS ?? 40_000);
const POLL_MS = Number(process.env.TIRITH_POLL_MS ?? 2_000);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- annotation presets (explicit booleans on every tool, per OpenAI plugin guidelines) ---
const READ: ToolAnnotations = { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true };
const ann = (a: { readOnly: boolean; destructive: boolean; openWorld: boolean; idempotent?: boolean; title: string }): ToolAnnotations => ({
  title: a.title,
  readOnlyHint: a.readOnly,
  destructiveHint: a.destructive,
  openWorldHint: a.openWorld,
  ...(a.idempotent === undefined ? {} : { idempotentHint: a.idempotent }),
});

const OPEN_STATUSES = "open,validated,fixing";

const widgetMeta = (invoking: string, invoked: string) => ({
  ui: { resourceUri: WIDGET_URI },
  "openai/outputTemplate": WIDGET_URI,
  "openai/toolInvocation/invoking": invoking,
  "openai/toolInvocation/invoked": invoked,
});
const statusMeta = (invoking: string, invoked: string) => ({
  "openai/toolInvocation/invoking": invoking,
  "openai/toolInvocation/invoked": invoked,
});

function ok(text: string, structuredContent: Record<string, unknown>, meta?: Record<string, unknown>): CallToolResult {
  return { content: [{ type: "text", text }], structuredContent, ...(meta ? { _meta: meta } : {}) };
}

function fail(err: unknown): CallToolResult {
  const msg = err instanceof BackendError ? err.message : `Unexpected error: ${(err as Error)?.message ?? String(err)}`;
  return { isError: true, content: [{ type: "text", text: msg }] };
}

const wrap =
  <A>(fn: (args: A) => Promise<CallToolResult>) =>
  async (args: A): Promise<CallToolResult> => {
    try {
      return await fn(args);
    } catch (err) {
      return fail(err);
    }
  };

const id = (what: string) => z.string().min(1).describe(`${what} ID returned by an earlier Tirith tool call.`);
const severity = z.enum(["critical", "high", "medium", "low", "info"]);

async function postureView(asset_id?: string, extra: Record<string, unknown> = {}) {
  const [posture, findings, assets, mode] = await Promise.all([
    backend.getPosture(asset_id),
    backend.listFindings({ asset_id, status: OPEN_STATUSES, limit: 8 }),
    backend.listAssets().catch(() => []),
    backend.getMode().catch(() => null),
  ]);
  const asset = asset_id ? assets.find((a) => a.id === asset_id) : undefined;
  return {
    view: "posture" as const,
    asset: asset ? publicAsset(asset) : null,
    posture: slimPosture(posture),
    mode: mode?.mode ?? null,
    top_findings: sortFindings(findings).slice(0, 8).map(slimFinding),
    note: UNTRUSTED_NOTE,
    ...extra,
  };
}

async function findingView(finding_id: string) {
  const f = await backend.getFinding(finding_id);
  const fix = f.fix_id ? await backend.getFix(f.fix_id).catch(() => null) : null;
  return { view: { view: "finding" as const, finding: fullFinding(f), fix: slimFix(fix), note: UNTRUSTED_NOTE }, fix };
}

function findingText(f: Finding): string {
  const loc = f.file ? ` at ${f.file}${f.line ? `:${f.line}` : ""}` : f.url ? ` at ${f.url}` : f.package ? ` in ${f.package}@${f.installed_version ?? "?"}` : "";
  const where = f.component?.startsWith("lab:") ? " [lab sub-app]" : "";
  const prio = f.priority != null ? `, priority ${Math.round(f.priority)}` : "";
  return `[${f.severity.toUpperCase()}] ${truncate(f.title, 200)}${loc}${where} (id ${f.id}, ${f.status}${prio})`;
}

export function registerTools(server: McpServer) {
  // ---------------- assets ----------------
  server.registerTool(
    "tirith_list_assets",
    {
      title: "List assets",
      description:
        "List the code repositories, local paths and web apps registered with Tirith for security assessment. Use this first when the user says 'scan my repo' or refers to 'my app' so you can find the asset ID.",
      inputSchema: {},
      annotations: { ...READ, title: "List assets" },
      _meta: statusMeta("Loading assets…", "Assets loaded"),
    },
    wrap(async () => {
      const assets = await backend.listAssets();
      const rows = assets.map(publicAsset);
      const text = rows.length
        ? `${rows.length} asset(s):\n${rows.map((a) => `- ${a.name} (${a.kind}: ${a.ref}) id=${a.id}`).join("\n")}`
        : "No assets registered yet. Use tirith_add_asset to register a GitHub repo, local path or URL.";
      return ok(text, { assets: rows });
    }),
  );

  server.registerTool(
    "tirith_add_asset",
    {
      title: "Add asset",
      description:
        "Register an asset for Tirith to assess: a GitHub repository ('owner/name'), an absolute local path, or a web app base URL. Only assets allowed by the Tirith scope policy can be added. Call tirith_list_assets first to avoid duplicates. If the asset already exists it is returned, and any focus/exclude/sub_apps you pass REPLACE its saved profile (which changes finding priorities), so only pass them when the user asks to change the profile.",
      inputSchema: {
        kind: z.enum(["github_repo", "local_path", "url"]).describe("github_repo for 'owner/name', local_path for an absolute path, url for a running web app."),
        ref: z.string().min(1).describe("'owner/name' for github_repo, absolute path for local_path, base URL for url."),
        name: z.string().min(1).max(80).optional().describe("Friendly display name. Defaults to the ref."),
        focus: z.array(z.string().min(1)).optional().describe("Optional path globs of the main app (e.g. 'app/**'); findings elsewhere rank lower."),
        exclude: z.array(z.string().min(1)).optional().describe("Optional path globs to ignore entirely (e.g. 'docs/**')."),
        sub_apps: z.array(z.string().min(1)).optional().describe("Optional directory globs of separate lower-priority sub-apps (e.g. 'labs/*')."),
      },
      // destructive: on an existing asset, profile globs overwrite the saved ones.
      annotations: ann({ title: "Add asset", readOnly: false, destructive: true, openWorld: true, idempotent: true }),
      _meta: statusMeta("Registering asset…", "Asset registered"),
    },
    wrap(async ({ kind, ref, name, focus, exclude, sub_apps }: { kind: string; ref: string; name?: string; focus?: string[]; exclude?: string[]; sub_apps?: string[] }) => {
      const a = await backend.addAsset({ kind, ref, name: name ?? ref.split("/").filter(Boolean).pop() ?? ref, focus, exclude, sub_apps });
      const pa = publicAsset(a);
      return ok(`Registered ${pa.name} (${pa.kind}: ${pa.ref}) id=${pa.id}. Next: tirith_start_scan.`, { asset: pa });
    }),
  );

  // ---------------- scans ----------------
  server.registerTool(
    "tirith_start_scan",
    {
      title: "Start security scan",
      description:
        "Run a security scan of an asset (SAST with Semgrep, secret detection with Gitleaks, dependency CVEs with Trivy, and a passive DAST baseline with ZAP: for URLs, and for repos with a Dockerfile against their isolated lab copy, signed in as a lab test user). Use for 'scan my repo', 'check my app for vulnerabilities', 'run a security assessment'. Waits up to ~45 seconds; if the scan is still running, returns the scan ID so you can follow up with tirith_scan_status. Requires an asset_id from tirith_list_assets or tirith_add_asset.",
      inputSchema: {
        asset_id: id("Asset"),
        tools: z
          .array(z.enum(["semgrep", "gitleaks", "trivy", "zap"]))
          .optional()
          .describe("Optional subset of scanners. Omit to run all scanners applicable to the asset."),
      },
      annotations: ann({ title: "Start security scan", readOnly: false, destructive: false, openWorld: true, idempotent: false }),
      _meta: statusMeta("Scanning…", "Scan finished"),
    },
    wrap(async ({ asset_id, tools }: { asset_id: string; tools?: string[] }) => {
      let scan: Scan = await backend.startScan(asset_id, tools);
      const stillRunning = (why = "") =>
        ok(
          `Scan ${scan.id} is still running${why} (tools: ${fmtTools(scan.tools)}). Call tirith_scan_status with scan_id ${scan.id} in a moment.`,
          { view: "scan", scan: { ...slimScan(scan), status: scan.status === "queued" ? "queued" : "running" } },
        );
      const deadline = Date.now() + SCAN_WAIT_MS;
      while ((scan.status === "queued" || scan.status === "running") && Date.now() < deadline) {
        await sleep(POLL_MS);
        try {
          scan = await backend.getScan(scan.id);
        } catch {
          // Transient backend error while polling: never lose the scan id.
          return stillRunning("; status check failed temporarily");
        }
      }
      if (scan.status === "queued" || scan.status === "running") return stillRunning();
      if (scan.status === "failed") {
        return ok(`Scan ${scan.id} failed (tools: ${fmtTools(scan.tools)}).`, { view: "scan", scan: slimScan(scan) });
      }
      let view: Awaited<ReturnType<typeof postureView>>;
      let top: Finding[];
      try {
        [view, top] = await Promise.all([
          postureView(asset_id, { scan: slimScan(scan) }),
          backend.listFindings({ scan_id: scan.id, status: OPEN_STATUSES, limit: 5 }).then(sortFindings),
        ]);
      } catch {
        return ok(`Scan ${scan.id} done: ${countsLine(scan.counts)}. Posture could not be loaded right now; call tirith_get_posture.`, {
          view: "scan",
          scan: slimScan(scan),
        });
      }
      return ok(
        `Scan ${scan.id} done: ${countsLine(scan.counts)}. Posture ${view.posture.score}/100 (grade ${view.posture.grade}).` +
          (top.length ? `\nTop open findings:\n${untrusted(top.map(findingText).join("\n"))}` : "\nNo open findings."),
        view,
      );
    }),
  );

  server.registerTool(
    "tirith_scan_status",
    {
      title: "Scan status",
      description: "Check progress of a running or finished Tirith scan: overall status, per-scanner status and severity counts.",
      inputSchema: { scan_id: id("Scan") },
      annotations: { ...READ, title: "Scan status" },
      _meta: statusMeta("Checking scan…", "Scan status loaded"),
    },
    wrap(async ({ scan_id }: { scan_id: string }) => {
      const s = await backend.getScan(scan_id);
      return ok(`Scan ${s.id}: ${s.status}. Tools: ${fmtTools(s.tools)}. Counts: ${countsLine(s.counts)}.`, { scan: slimScan(s) });
    }),
  );

  // ---------------- findings ----------------
  server.registerTool(
    "tirith_list_findings",
    {
      title: "List findings",
      description:
        "List security findings, sorted by priority (severity x confidence x reachability x validation; open first), optionally filtered by asset, scan, severity, status or component. Dependency CVEs are grouped one finding per package. Findings in lab sub-apps (intentionally vulnerable training labs) rank lower. Without asset_id it lists ALL assets; without status it also lists closed (fixed / not_reproduced) findings, which posture does not count. Posture counts = this asset's findings with status open, validated or fixing. Use to answer 'what are my vulnerabilities', or to pick 'the top issue' before calling tirith_fix_finding.",
      inputSchema: {
        asset_id: z.string().optional().describe("Filter by asset ID."),
        scan_id: z.string().optional().describe("Filter by scan ID."),
        severity: severity.optional().describe("Only this severity."),
        status: z.enum(["open", "validated", "not_reproduced", "fixing", "fixed"]).optional().describe("Only this status."),
        component: z.enum(["main", "lab", "periphery"]).optional().describe("Only the main app, only lab sub-apps, or only code outside the main app's focus."),
        limit: z.number().int().min(1).max(100).optional().describe("Max results (default 20)."),
      },
      annotations: { ...READ, title: "List findings" },
      _meta: statusMeta("Loading findings…", "Findings loaded"),
    },
    wrap(async (a: { asset_id?: string; scan_id?: string; severity?: string; status?: string; component?: string; limit?: number }) => {
      const limit = a.limit ?? 20;
      // Filters and limit go to the backend (which sorts by priority); ask for one extra row to know if there are more.
      const got = sortFindings(
        await backend.listFindings({ asset_id: a.asset_id, scan_id: a.scan_id, severity: a.severity, status: a.status, component: a.component, limit: limit + 1 }),
      );
      const rows = got.slice(0, limit);
      const more = got.length > limit;
      // State the scope so a listing is never read against a posture for a different asset / status set.
      const scope = `${a.asset_id ? `asset ${a.asset_id}` : "ALL assets"}, ${a.status ? `status ${a.status}` : "all statuses incl. closed"}`;
      const text = rows.length
        ? `${rows.length} finding(s) [${scope}]${more ? ` (more available; narrow the filters or raise limit)` : ""}:\n${untrusted(rows.map(findingText).join("\n"))}`
        : `No findings match [${scope}].`;
      return ok(text, { returned: rows.length, has_more: more, findings: rows.map(slimFinding), note: UNTRUSTED_NOTE });
    }),
  );

  registerAppTool(
    server,
    "tirith_get_finding",
    {
      title: "Show finding",
      description:
        "Show full details of one finding in the Tirith finding view: description, code location and snippet, CWE/CVE, AI summary, lab validation evidence and any fix/PR. Use when the user asks about a specific finding or 'show me that issue'.",
      inputSchema: { finding_id: id("Finding") },
      annotations: { ...READ, title: "Show finding" },
      _meta: widgetMeta("Loading finding…", "Finding loaded"),
    },
    wrap(async ({ finding_id }: { finding_id: string }) => {
      const { view: v, fix } = await findingView(finding_id);
      const f = v.finding as Record<string, unknown>;
      const meta = [
        `Finding ${f.id}: severity ${String(f.severity).toUpperCase()}, status ${f.status}.`,
        f.cwe || f.cve ? `Refs: ${[f.cwe, f.cve].filter(Boolean).join(", ")}` : "",
        v.finding.validation ? `Validation: ${(v.finding.validation as { result: string }).result}` : "Not validated yet (tirith_validate_finding).",
        v.fix ? `Fix: ${v.fix.status}${v.fix.pr_url ? ` — ${v.fix.pr_url}` : ""}${fix?.diff ? " (diff shown in the finding view)" : ""}` : "",
      ].filter(Boolean);
      const repoText = [
        `Title: ${f.title}`,
        f.file ? `Location: ${f.file}${f.line ? `:${f.line}` : ""}` : f.url ? `URL: ${f.url}` : "",
        f.description ? `Description: ${f.description}` : "",
        f.ai_summary ? `AI summary: ${f.ai_summary}` : "",
      ].filter(Boolean);
      return ok(`${meta.join("\n")}\n${untrusted(repoText.join("\n"))}`, v, diffMeta(fix));
    }),
  );

  server.registerTool(
    "tirith_explain_finding",
    {
      title: "Explain finding",
      description:
        "Get an AI explanation of a finding: plain-language summary, root cause, how exploitable it is, and a fix plan. Use for 'what does this mean', 'how bad is this', 'how would I fix it'. Calls Tirith's language model and stores the summary on the finding; the code is not changed. To actually test exploitability, use tirith_validate_finding.",
      inputSchema: { finding_id: id("Finding") },
      annotations: ann({ title: "Explain finding", readOnly: false, destructive: false, openWorld: false, idempotent: false }),
      _meta: statusMeta("Analyzing finding…", "Analysis ready"),
    },
    wrap(async ({ finding_id }: { finding_id: string }) => {
      const e = await backend.explainFinding(finding_id);
      const cap = (x: unknown) => truncate(String(x ?? ""), 2000);
      const ex = { summary: cap(e.summary), root_cause: cap(e.root_cause), exploitability: cap(e.exploitability), fix_plan: cap(e.fix_plan) };
      return ok(
        `AI analysis of finding ${finding_id} (generated from repository content):\n` +
          untrusted(`Summary: ${ex.summary}\n\nRoot cause: ${ex.root_cause}\n\nExploitability: ${ex.exploitability}\n\nFix plan: ${ex.fix_plan}`),
        { finding_id, ...ex, note: UNTRUSTED_NOTE },
      );
    }),
  );

  server.registerTool(
    "tirith_validate_finding",
    {
      title: "Validate in lab",
      description:
        "Check whether a finding is really exploitable by running Tirith's fixed, non-destructive validation check for its weakness class (for example CWE-89 SQL injection) against an isolated lab copy of the app with dummy data and no internet access. Never touches production. Use for 'is this exploitable', 'is this real', 'prove it'. Returns confirmed / not_reproduced / unsupported with evidence.",
      inputSchema: { finding_id: id("Finding") },
      annotations: ann({ title: "Validate in lab", readOnly: false, destructive: false, openWorld: false, idempotent: false }),
      _meta: statusMeta("Validating in isolated lab…", "Validation complete"),
    },
    wrap(async ({ finding_id }: { finding_id: string }) => {
      const v = await backend.validateFinding(finding_id);
      const sv = slimValidation(v);
      const ev = (sv?.evidence ?? []).map((e) => `- ${e.kind} · ${e.label}: ${truncate(e.content, 300)}`);
      return ok(
        `Validation ${v.check}: ${v.result} (confidence ${Math.round((v.confidence ?? 0) * 100)}%).` +
          (ev.length ? `\nEvidence (${ev.length}${sv?.evidence_total ? ` of ${sv.evidence_total}` : ""}):\n${untrusted(ev.join("\n"))}` : ""),
        { finding_id, validation: sv, note: UNTRUSTED_NOTE },
      );
    }),
  );

  // ---------------- remediation ----------------
  server.registerTool(
    "tirith_fix_finding",
    {
      title: "Fix finding (open PR)",
      description:
        "Generate a patch for a finding using the operator-configured remediation mode. In assisted mode Tirith pushes it to a new branch and opens a GitHub pull request that a human reviews and merges. In autonomous mode, fixes in the operator's allowed categories (e.g. dependency bumps) may be applied/merged automatically after verification, with rollback on failure; other fixes are escalated. In observe mode the request is refused by policy (403) and nothing is generated. Verification = rescan of the changed files with the same scanner rule + booting the patched app in the isolated lab (the project's own tests are not run). Only call when the user explicitly asks to fix a specific finding ('fix this', 'open a PR fixing the top issue': call tirith_list_findings first and pick the top open finding).",
      inputSchema: {
        finding_id: id("Finding"),
        apply: z
          .boolean()
          .optional()
          .describe("Also merge the verified fix (autonomous mode + dependency bump only; otherwise it stays a PR)."),
      },
      // destructive: in autonomous mode the fix may be merged into the target without a human.
      annotations: ann({ title: "Fix finding (open PR)", readOnly: false, destructive: true, openWorld: true, idempotent: false }),
      _meta: statusMeta("Writing patch and opening PR…", "Fix ready"),
    },
    wrap(async ({ finding_id, apply }: { finding_id: string; apply?: boolean }) => {
      let fix: Fix = await backend.fixFinding(finding_id);
      const deadline = Date.now() + FIX_WAIT_MS;
      while (fix.status === "proposed" && fix.mode !== "observe" && Date.now() < deadline) {
        await sleep(POLL_MS);
        try {
          fix = await backend.getFix(fix.id);
        } catch {
          // Transient backend error while polling: never lose the fix id.
          return ok(`Fix ${fix.id} for finding ${fix.finding_id} is still running (status check failed temporarily). Call tirith_get_fix with fix_id ${fix.id} in a moment.`, {
            fix: slimFix(fix),
          });
        }
      }
      if (apply && (fix.status === "pr_opened" || fix.status === "verified" || fix.status === "escalated")) {
        fix = await backend.applyFix(fix.id);
      }
      return ok(fixText(fix), { fix: slimFix(fix) }, diffMeta(fix));
    }),
  );

  server.registerTool(
    "tirith_get_fix",
    {
      title: "Fix status",
      description: "Check the status of a fix: proposed, PR opened (with link), verified, applied, rolled back, failed or escalated, plus verification results.",
      inputSchema: { fix_id: id("Fix") },
      annotations: { ...READ, title: "Fix status" },
      _meta: statusMeta("Checking fix…", "Fix status loaded"),
    },
    wrap(async ({ fix_id }: { fix_id: string }) => {
      const fix = await backend.getFix(fix_id);
      return ok(fixText(fix), { fix: slimFix(fix) }, diffMeta(fix));
    }),
  );

  server.registerTool(
    "tirith_apply_fix",
    {
      title: "Apply fix",
      description:
        "Apply a proposed or verified fix to the asset (approval step). Changes the target code. Only call when the user explicitly asks to apply or approve a specific fix. Can be undone with tirith_rollback_fix.",
      inputSchema: { fix_id: id("Fix") },
      annotations: ann({ title: "Apply fix", readOnly: false, destructive: true, openWorld: true, idempotent: false }),
      _meta: statusMeta("Applying fix…", "Fix applied"),
    },
    wrap(async ({ fix_id }: { fix_id: string }) => {
      const fix = await backend.applyFix(fix_id);
      return ok(fixText(fix), { fix: slimFix(fix) });
    }),
  );

  server.registerTool(
    "tirith_rollback_fix",
    {
      title: "Roll back fix",
      description: "Revert a previously applied fix. Only call when the user explicitly asks to roll back or undo a specific fix.",
      inputSchema: { fix_id: id("Fix") },
      annotations: ann({ title: "Roll back fix", readOnly: false, destructive: true, openWorld: true, idempotent: false }),
      _meta: statusMeta("Rolling back…", "Rolled back"),
    },
    wrap(async ({ fix_id }: { fix_id: string }) => {
      const fix = await backend.rollbackFix(fix_id);
      return ok(fixText(fix), { fix: slimFix(fix) });
    }),
  );

  // ---------------- posture & policy ----------------
  registerAppTool(
    server,
    "tirith_get_posture",
    {
      title: "Security posture",
      description:
        "Show the security posture dashboard: the top 3 plain-language fixes first (top_actions: what to do and why, with finding IDs and whether Tirith can fix it), then 0-100 score, letter grade, open findings by severity, fixed count, trend and the top open findings. Use for 'show my security status', 'how secure is my app', 'how am I doing', 'what should I do / fix first', 'security overview'. Omit asset_id for all assets.",
      inputSchema: { asset_id: z.string().optional().describe("Asset ID; omit for overall posture.") },
      annotations: { ...READ, title: "Security posture" },
      _meta: widgetMeta("Loading posture…", "Posture ready"),
    },
    wrap(async ({ asset_id }: { asset_id?: string }) => {
      const v = await postureView(asset_id);
      const tops = v.top_findings.slice(0, 5).map((f) => `- [${String(f.severity).toUpperCase()}] ${f.title} (id ${f.id})`);
      const actions = v.posture.top_actions.map(
        (a, i) =>
          `${i + 1}. [${a.severity.toUpperCase()}] ${a.title}\n   Why: ${a.why}\n   Do: ${a.action}\n   ` +
          `${a.fixable ? "Tirith can open a fix PR (tirith_fix_finding)" : "Needs a manual fix"}; findings: ${a.finding_ids.slice(0, 5).join(", ")}` +
          (a.finding_ids.length > 5 ? ` (+${a.finding_ids.length - 5} more)` : ""),
      );
      return ok(
        (actions.length ? `Top ${actions.length} fixes (lead with these):\n${untrusted(actions.join("\n"))}\n` : "") +
          `Posture${v.asset ? ` for ${v.asset.name}` : ""}: ${v.posture.score}/100, grade ${v.posture.grade}. Open: ${v.posture.open} (${countsLine(v.posture.counts)}); fixed: ${v.posture.fixed}. Mode: ${v.mode ?? "unknown"}.` +
          (v.posture.main_counts && v.posture.lab_open
            ? `\nMain app: ${countsLine(v.posture.main_counts)}. Lab sub-apps (training labs, de-prioritized): ${v.posture.lab_open} open.`
            : "") +
          (tops.length ? `\nTop open findings:\n${untrusted(tops.join("\n"))}` : ""),
        v,
      );
    }),
  );

  server.registerTool(
    "tirith_get_mode",
    {
      title: "Remediation mode",
      description:
        "Show the remediation mode: 'observe' (report only; nothing is changed), 'assisted' (patch + PR, a human merges) or 'autonomous' (auto-apply only the listed categories, verify, roll back on failure, escalate the rest). Use tirith_set_mode to change it.",
      inputSchema: {},
      annotations: { ...READ, title: "Remediation mode" },
      _meta: statusMeta("Reading mode…", "Mode loaded"),
    },
    wrap(async () => {
      const m = await backend.getMode();
      return ok(
        `Remediation mode: ${m.mode}${m.mode === "autonomous" ? ` (auto-apply: ${m.autonomous_categories.join(", ") || "none"})` : ""}.`,
        { mode: m.mode, autonomous_categories: m.autonomous_categories },
      );
    }),
  );

  server.registerTool(
    "tirith_set_mode",
    {
      title: "Switch remediation mode",
      description:
        "Change the remediation mode for this and later runs. observe = report only; assisted = fixes open a pull request for review; autonomous = dependency bumps are also applied and verified automatically (refused with 403 when the operator disabled autonomous on the server). Call it when the user asks to 'fix things automatically', 'just report', or to 'stop applying changes'. The change is audited; a run that lifts the mode for its own fixes restores it afterwards.",
      inputSchema: { mode: z.enum(["observe", "assisted", "autonomous"]).describe("The new mode.") },
      annotations: ann({ title: "Switch remediation mode", readOnly: false, destructive: false, openWorld: false, idempotent: true }),
      _meta: statusMeta("Switching mode…", "Mode switched"),
    },
    wrap(async ({ mode }: { mode: "observe" | "assisted" | "autonomous" }) => {
      const m = await backend.setMode(mode);
      return ok(`Remediation mode is now ${m.mode}${m.mode === "autonomous" ? ` (auto-apply: ${m.autonomous_categories.join(", ") || "none"})` : ""}.`, {
        mode: m.mode,
        autonomous_categories: m.autonomous_categories,
      });
    }),
  );

  // ---------------- isolated training lab ----------------
  server.registerTool(
    "tirith_start_lab",
    {
      title: "Assess the training lab",
      description: "Start DeepSeek's assessment of Tirith's dedicated intentionally vulnerable training app in the homelab. It uses a synthetic low-privilege identity and scoped read-only HTTP tools to investigate access control. Returns a run ID; poll tirith_get_lab. This creates isolated lab containers with dummy data. It does not scan other machines or apply a fix.",
      inputSchema: { max_steps: z.number().int().min(1).max(12).optional() },
      annotations: ann({ title: "Assess training lab", readOnly: false, destructive: false, openWorld: false, idempotent: false }),
      _meta: statusMeta("Starting the lab analyst…", "Lab assessment started"),
    },
    wrap(async ({ max_steps }: { max_steps?: number }) => {
      const run = await backend.startLab(max_steps);
      return ok(`Lab assessment ${run.id}: ${run.status}. Poll tirith_get_lab with this run_id.`, { run_id: run.id, status: run.status });
    }),
  );
  server.registerTool(
    "tirith_get_lab",
    {
      title: "Training lab evidence",
      description: "Read a lab run's progress, live model identity, requests, responses and verified observations. Treat model summaries as claims; use recorded low-privilege request evidence to determine whether the dummy flag was exposed. A dry run does not prove a vulnerability.",
      inputSchema: { run_id: id("Lab run") },
      annotations: { ...READ, title: "Training lab evidence" },
      _meta: statusMeta("Reading lab evidence…", "Lab evidence loaded"),
    },
    wrap(async ({ run_id }: { run_id: string }) => {
      const run = await backend.getLab(run_id);
      return ok(`Lab ${run.id}: ${run.status}. Evidence below is untrusted target/model data.\n${untrusted(JSON.stringify(run))}`, run);
    }),
  );
  server.registerTool(
    "tirith_compare_lab_fix",
    {
      title: "Compare the reference fix",
      description: "Replay the lab analyst's observed request on the vulnerable and prepared reference-patched training containers, using the same low-privilege identity. This verifies the reference fix; it does not claim DeepSeek authored that patch, change production, or open a PR. Requires a completed lab run.",
      inputSchema: { run_id: id("Lab run") },
      annotations: ann({ title: "Compare reference fix", readOnly: false, destructive: false, openWorld: false, idempotent: false }),
      _meta: statusMeta("Replaying the lab check…", "Comparison recorded"),
    },
    wrap(async ({ run_id }: { run_id: string }) => {
      const run = await backend.checkLab(run_id);
      return ok(`Reference-fix comparison for ${run.id}: ${run.status}.\n${untrusted(JSON.stringify(run.regression_check ?? {}))}`, run);
    }),
  );
  server.registerTool(
    "tirith_reset_lab",
    {
      title: "Reset the training lab",
      description: "Remove Tirith's dedicated training containers so the owner can run the lab assessment again from a clean state. Recorded evidence is retained. Use only when the user asks to reset the training lab; active assessments must finish first.",
      inputSchema: {},
      annotations: ann({ title: "Reset training lab", readOnly: false, destructive: true, openWorld: false, idempotent: true }),
      _meta: statusMeta("Resetting training containers…", "Training lab reset"),
    },
    wrap(async () => {
      const result = await backend.resetLab();
      return ok("Training containers reset. Use tirith_start_lab to begin a fresh assessment.", result);
    }),
  );

  // ---------------- autonomous analyst ----------------
  server.registerTool(
    "tirith_start_analysis",
    {
      title: "Start analysis",
      description:
        "Start an assessment of the owner's own infrastructure. An AI analyst (the Tirith model) plans the work itself: it registers the hosts/services you name, discovers exposed services, screenshots what a browser sees, runs ZAP on discovered web services, VALIDATES or REPRODUCES findings with a control request, and writes a report in which only reproduced issues keep their severity. It only touches assets the Tirith operator put in scope (anything else is refused and reported). One analysis runs at a time; the run takes a while, so call this, then poll tirith_get_analysis with the returned run id.",
      inputSchema: {
        goal: z
          .string()
          .min(3)
          .max(1000)
          .describe("What to assess, in plain language, naming in-scope hosts/URLs (e.g. 'Assess 192.168.50.132 and the service on :8010; what would an attacker see first?')."),
        max_steps: z
          .number()
          .int()
          .min(1)
          .max(24)
          .optional()
          .describe("Cap on analyst tool calls (default server setting, usually 8)."),
        mode: z
          .enum(["auto", "approve"])
          .optional()
          .describe("auto (default) runs straight through to the report. approve pauses after the first reproduction and at the step cap, so the user answers before anything else happens."),
        charge: z
          .enum(["observe", "assisted", "autonomous"])
          .optional()
          .describe("Remediation mode for this run only (restored afterwards). observe = report only."),
      },
      annotations: ann({ title: "Start analysis", readOnly: false, destructive: false, openWorld: true, idempotent: false }),
      _meta: statusMeta("Starting the analyst…", "Analysis started"),
    },
    wrap(async ({ goal, max_steps, mode, charge }: { goal: string; max_steps?: number; mode?: string; charge?: string }) => {
      const run = await backend.startAnalyst(goal, max_steps, charge, mode);
      return ok(`Analysis ${run.id} started (${run.status}). Poll tirith_get_analysis with run_id ${run.id} for progress and the report.`, {
        run_id: run.id,
        status: run.status,
      });
    }),
  );

  server.registerTool(
    "tirith_get_analysis",
    {
      title: "Analysis progress",
      description:
        "Progress and result of an autonomous analysis: status, each step the analyst took (its reasoning, tool, arguments and what it observed), and the final report with summary, notable findings and recommended next steps.",
      inputSchema: { run_id: id("Analysis run") },
      annotations: { ...READ, title: "Analysis progress" },
      _meta: statusMeta("Reading analysis…", "Analysis loaded"),
    },
    wrap(async ({ run_id }: { run_id: string }) => {
      const run = await backend.getAnalyst(run_id);
      const lines = [`Analysis ${run.id}: ${run.status}${run.error ? ` (${run.error})` : ""}. ${run.steps.length} step(s).`];
      for (const s of run.steps) {
        lines.push(`${s.n}. ${s.tool ?? "?"}${s.ok ? "" : " [refused/failed]"} — ${s.thought}`);
      }
      if (run.report?.summary) lines.push(`Summary: ${run.report.summary}`);
      const issues = (run.report?.issues ?? []).map(slimIssue);
      if (issues.length) {
        lines.push(
          `Issues (proof first):\n${untrusted(
            issues
              .map(
                (i) =>
                  `[${String(i.severity ?? "?").toUpperCase()}] ${i.proof ?? "unproven"}${i.grade ? ` (${i.grade})` : ""}: ` +
                  `${i.title}${i.where ? ` at ${i.where}` : ""}${i.reproduce?.length ? `\n   reproduce: ${i.reproduce.join(" → ")}` : ""}`,
              )
              .join("\n"),
          )}`,
        );
      }
      const next = run.report?.next_steps;
      if (Array.isArray(next) && next.length) lines.push(`Next steps: ${next.join("; ")}`);
      if (run.waiting_on) {
        lines.push(
          `PAUSED at a checkpoint (${untrusted(String(run.waiting_on))}). Nothing proceeds until tirith_resume_analysis when the user says go / stop / change something.`,
        );
      } else if (run.status === "running") {
        lines.push("Still running; check again in a moment.");
      }
      return ok(lines.join("\n"), {
        run_id: run.id,
        status: run.status,
        ...(run.waiting_on ? { waiting_on: run.waiting_on } : {}),
        report: run.report,
        issues,
        steps: run.steps.map((s) => ({ n: s.n, tool: s.tool, thought: s.thought, ok: s.ok })),
      });
    }),
  );

  server.registerTool(
    "tirith_pause_analysis",
    {
      title: "Pause the analysis",
      description:
        "Hold the running analysis at its next checkpoint so the user can see what was found and decide (approve a fix, change the scope, stop). The current step finishes; nothing new starts until tirith_resume_analysis. Use it for the approval gate after the reproduction step, or when the user says stop / hold on / wait.",
      inputSchema: { run_id: id("Analysis run"), reason: z.string().max(200).optional().describe("What is being approved, in a few words.") },
      annotations: ann({ title: "Pause the analysis", readOnly: false, destructive: false, openWorld: false, idempotent: true }),
      _meta: statusMeta("Pausing…", "Paused"),
    },
    wrap(async ({ run_id, reason }: { run_id: string; reason?: string }) => {
      const res = await backend.pauseAnalyst(run_id, reason);
      return ok(`Analysis ${run_id} will hold at its next checkpoint${res.waiting_on ? ` (${res.waiting_on})` : ""}.`, res);
    }),
  );

  server.registerTool(
    "tirith_resume_analysis",
    {
      title: "Resume the analysis",
      description:
        "Let a paused analysis take its next step. Call it when the user has answered the checkpoint ('go ahead', 'yes fix it', 'skip that'). Only works while the run is actually waiting.",
      inputSchema: { run_id: id("Analysis run") },
      annotations: ann({ title: "Resume the analysis", readOnly: false, destructive: false, openWorld: false, idempotent: false }),
      _meta: statusMeta("Resuming…", "Resumed"),
    },
    wrap(async ({ run_id }: { run_id: string }) => {
      const res = await backend.resumeAnalyst(run_id);
      return ok(`Analysis ${run_id} resumed${res.was_waiting_on ? ` (was waiting on ${res.was_waiting_on})` : ""}.`, res);
    }),
  );

  server.registerTool(
    "tirith_render_report",
    {
      title: "Report as a web page",
      description:
        "Turn a finished analysis into two HTML reports the user can open in a browser. 'as-found' lists only issues that were confirmed with evidence, each with the steps to reproduce it. 'as-fixed' lists the same issues and what was actually changed, with anything not yet applied clearly marked proposed. Read-only for the infrastructure: it only formats results that already exist.",
      inputSchema: {
        run_id: id("Analysis run"),
        variant: z
          .enum(["both", "as-found", "as-fixed"])
          .optional()
          .describe("Which report to build. Default 'both'."),
      },
      annotations: ann({ title: "Report as a web page", readOnly: true, destructive: false, openWorld: false, idempotent: true }),
      _meta: statusMeta("Building report…", "Report ready"),
    },
    wrap(async ({ run_id, variant }: { run_id: string; variant?: "both" | "as-found" | "as-fixed" }) => {
      const res = await backend.renderReport(run_id, variant ?? "both");
      const dashboard = process.env.TIRITH_DASHBOARD_PUBLIC_URL?.replace(/\/+$/, "");
      if (dashboard) {
        for (const file of Object.values(res.files)) {
          if (file.url.startsWith("/reports/")) file.url = new URL(file.url, dashboard).href;
        }
      }
      const lines = [`Report for analysis ${res.run_id} is ready.`];
      for (const [name, f] of Object.entries(res.files)) {
        lines.push(`- ${name}: ${f.url} (file ${f.path})`);
      }
      if (!dashboard && Object.values(res.files).some((f) => f.url)) {
        lines.push(
          "The URLs are paths on the Tirith dashboard; prepend the dashboard base URL (for example http://192.168.50.161:3000) and the dashboard login.",
        );
      }
      return ok(lines.join("\n"), res);
    }),
  );
}

function fmtTools(t: Record<string, string> | undefined): string {
  return Object.entries(t ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(", ") || "n/a";
}

function fixText(fix: Fix): string {
  const parts = [`Fix ${fix.id} for finding ${fix.finding_id}: ${fix.status} (${fix.mode} mode).`];
  if (fix.pr_url) parts.push(`Pull request: ${fix.pr_url}`);
  if (fix.branch) parts.push(`Branch: ${fix.branch}`);
  const v = fix.verification;
  if (v && v.validation_result) {
    parts.push(`Verification (rescan + lab boot): ${v.validation_result}.${v.details ? ` ${truncate(v.details, 500)}` : ""}`);
  }
  if (fix.status === "proposed" && fix.mode !== "observe") parts.push(`Still in progress; check again with tirith_get_fix (fix_id ${fix.id}).`);
  if (fix.diff) parts.push("The patch diff is shown to the user in the Tirith finding view (tirith_get_finding).");
  return parts.join("\n");
}
