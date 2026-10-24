// Data models from CONTRACT.md (v1). Kept loose on purpose: the backend is the source of truth.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Mode = "observe" | "assisted" | "autonomous";

export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Asset {
  id: string;
  kind: "github_repo" | "local_path" | "url" | "host";
  ref: string;
  name: string;
  created_at?: string;
  focus?: string[];
  exclude?: string[];
  sub_apps?: string[];
}

export interface Scan {
  id: string;
  asset_id: string;
  status: "queued" | "running" | "done" | "failed";
  tools: Record<string, string>;
  counts: Counts;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface Evidence {
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
  evidence: Evidence[];
  started_at?: string | null;
  finished_at?: string | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  asset_id: string;
  fingerprint?: string;
  tool: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: "sast" | "secret" | "dependency" | "dast" | "config";
  file?: string | null;
  line?: number | null;
  snippet?: string | null;
  cwe?: string | null;
  cve?: string | null;
  package?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  url?: string | null;
  status: "open" | "validated" | "not_reproduced" | "fixing" | "fixed";
  confidence?: number | null;
  ai_summary?: string | null;
  validation?: Validation | null;
  fix_id?: string | null;
  // v1.1 signal-over-noise fields
  advisories?: Advisory[];
  component?: string; // "main" | "periphery" | "lab:<dir>"
  tags?: string[];
  priority?: number; // 0..100, backend default sort key
}

export interface Advisory {
  id: string;
  severity: Severity;
  title?: string;
  fixed_version?: string | null;
  url?: string | null;
  cwe?: string | null;
}

export interface Fix {
  id: string;
  finding_id: string;
  mode: Mode;
  status: "proposed" | "pr_opened" | "verified" | "applied" | "rolled_back" | "failed" | "escalated";
  diff?: string | null;
  branch?: string | null;
  pr_url?: string | null;
  verification?: { tests_passed?: boolean | null; validation_result?: string | null; details?: string | null } | null;
  created_at?: string;
}

/** Plain-language fix covering one or more open findings (CONTRACT v1.4). Text embeds scanned data: untrusted. */
export interface TopAction {
  title: string;
  why: string;
  action: string;
  finding_ids: string[];
  severity: Severity;
  fixable: boolean;
}

export interface Posture {
  asset_id: string | null;
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

export interface Explanation {
  summary: string;
  root_cause: string;
  exploitability: string;
  fix_plan: string;
}

export interface ModeConfig {
  mode: Mode;
  autonomous_categories: string[];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// ---- autonomous analyst (v1.3) ----
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

export interface AnalystReportIssue {
  title?: string;
  severity?: Severity | "suspected";
  where?: string;
  evidence?: string;
  prove?: string;
  proof?: "confirmed" | "suspected" | "not_reproduced" | "unproven";
  finding_id?: string;
  reproduce?: string[];
  [k: string]: unknown;
}

export interface AnalystRun {
  id: string;
  goal: string;
  status: AnalystStatus;
  report: {
    summary?: string;
    notable?: string[];
    next_steps?: string[];
    issues?: AnalystReportIssue[];
    [k: string]: unknown;
  } | null;
  report_path?: string | null;
  error?: string | null;
  started_at?: string;
  finished_at?: string | null;
  waiting_on?: string | null;
  steps: AnalystStep[];
}
