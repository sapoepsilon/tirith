export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type Counts = Record<Severity, number>;
export type Mode = "observe" | "assisted" | "autonomous";
export type ToolName = "semgrep" | "gitleaks" | "trivy" | "zap";
export type ToolStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface Asset {
  id: string;
  kind: "github_repo" | "local_path" | "url";
  ref: string;
  name: string;
  created_at: string;
}

export interface Scan {
  id: string;
  asset_id: string;
  status: "queued" | "running" | "done" | "failed";
  tools: Partial<Record<ToolName, ToolStatus>>;
  counts: Counts;
  started_at: string | null;
  finished_at: string | null;
}

export interface EvidenceBlock {
  kind: "request" | "response" | "log" | "note";
  label: string;
  content: string;
}

export interface Validation {
  id: string;
  finding_id: string;
  check: string;
  result: "confirmed" | "not_reproduced" | "unsupported" | "error";
  confidence: number;
  evidence: EvidenceBlock[];
  started_at: string | null;
  finished_at: string | null;
}

export type FindingStatus = "open" | "validated" | "not_reproduced" | "fixing" | "fixed";
export type Category = "sast" | "secret" | "dependency" | "dast" | "config";

export interface Finding {
  id: string;
  scan_id: string;
  asset_id: string;
  fingerprint: string;
  tool: ToolName | string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  file: string | null;
  line: number | null;
  snippet: string | null;
  cwe: string | null;
  cve: string | null;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  url: string | null;
  status: FindingStatus;
  confidence: number;
  ai_summary: string | null;
  validation: Validation | null;
  fix_id: string | null;
  /** v1.1 (optional so older payloads/mock data still type-check) */
  advisories?: Advisory[];
  component?: string; // "main" | "periphery" | "lab:<dir>"
  tags?: string[];
  priority?: number; // 0..100; backend default sort key
}

export interface Advisory {
  id: string;
  severity: Severity;
  title?: string;
  fixed_version?: string | null;
  url?: string | null;
  cwe?: string | null;
}

export const isLab = (f: Pick<Finding, "component">) => !!f.component?.startsWith("lab:");
export const isClosed = (f: Pick<Finding, "status">) => f.status === "fixed" || f.status === "not_reproduced";

/** Backend order: open first, then priority desc; falls back to severity, then confidence. */
export function byPriority(a: Finding, b: Finding): number {
  return (
    Number(isClosed(a)) - Number(isClosed(b)) ||
    (b.priority ?? -1) - (a.priority ?? -1) ||
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
    b.confidence - a.confidence
  );
}

export type FixStatus =
  | "proposed"
  | "pr_opened"
  | "verified"
  | "applied"
  | "rolled_back"
  | "failed"
  | "escalated";

export interface Fix {
  id: string;
  finding_id: string;
  mode: Mode;
  status: FixStatus;
  diff: string;
  branch: string | null;
  pr_url: string | null;
  verification: {
    tests_passed: boolean | null;
    validation_result: string | null;
    details: string | null;
  } | null;
  created_at: string;
}

/** Plain-language fix covering one or more open findings (CONTRACT v1.4: Posture.top_actions). */
export interface TopAction {
  title: string;
  why: string;
  action: string;
  /** Best-first; open the first one in the finding drawer. */
  finding_ids: string[];
  severity: Severity;
  /** Tirith's fix flow can attempt at least one of these findings. */
  fixable: boolean;
}

export interface Posture {
  asset_id: string;
  score: number;
  grade: string;
  counts: Counts;
  open: number;
  fixed: number;
  history: { ts: string; score: number }[];
  risk?: number;
  risk_fixed?: number;
  main_counts?: Counts;
  lab_open?: number;
  top_actions?: TopAction[];
}

export interface ModeState {
  mode: Mode;
  autonomous_categories: string[];
}

export interface Explanation {
  summary: string;
  root_cause: string;
  exploitability: string;
  fix_plan: string;
}

export type EventType =
  | "scan.started"
  | "tool.started"
  | "tool.finished"
  | "finding.new"
  | "scan.finished"
  | "validation.started"
  | "validation.step"
  | "validation.result"
  | "ai.thinking"
  | "ai.summary"
  | "fix.started"
  | "fix.patch"
  | "fix.pr_opened"
  | "fix.verified"
  | "fix.applied"
  | "fix.rolled_back"
  | "posture.updated"
  | "policy.denied"
  | "mode.changed";

export interface TirithEvent {
  ts: string;
  type: EventType | string;
  level: "info" | "warn" | "error" | "success";
  message: string;
  scan_id?: string;
  finding_id?: string;
  fix_id?: string;
  data?: Record<string, unknown>;
}

/** Audit entry: not pinned down by the contract, so every field is optional and rendered defensively. */
export interface AuditEntry {
  id?: string | number;
  ts?: string;
  actor?: string;
  action?: string;
  target?: string;
  allowed?: boolean;
  result?: string;
  decision?: string;
  details?: unknown;
  [k: string]: unknown;
}

export interface Snapshot {
  assets: Asset[];
  scans: Scan[];
  findings: Finding[];
  fixes: Record<string, Fix>;
  posture: Posture | null;
  mode: ModeState;
  audit: AuditEntry[];
}

export const emptyCounts = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

/** Autonomous analyst run (backend /api/analyst/runs). */
export type AnalystStatus = "running" | "done" | "budget" | "error";

export interface AnalystStep {
  n: number;
  thought: string;
  tool: string | null;
  args: Record<string, unknown>;
  observation: string;
  ok: boolean;
  at?: string;
  ms?: number;
}

export interface AnalystIssue {
  title?: string;
  severity?: string;
  where?: string;
  evidence?: string;
  prove?: string;
  proof?: "confirmed" | "suspected" | "not_reproduced" | "unproven";
  grade?: string;
  finding_id?: string;
  reproduce?: string[];
  [k: string]: unknown;
}

export interface AnalystReport {
  summary?: string;
  notable?: string[];
  next_steps?: string[];
  issues?: AnalystIssue[];
  [k: string]: unknown;
}

export interface AnalystRun {
  id: string;
  goal: string;
  status: AnalystStatus;
  report: AnalystReport | null;
  report_path?: string | null;
  error?: string | null;
  started_at?: string;
  finished_at?: string | null;
  waiting_on?: string | null;
  steps: AnalystStep[];
}
