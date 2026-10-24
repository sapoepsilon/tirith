// Thin REST client for the Tirith backend (CONTRACT.md, prefix /api).
import type { AnalystRun, Asset, Explanation, Finding, Fix, Mode, ModeConfig, Posture, Scan, Validation } from "./types.js";

const BASE = (process.env.TIRITH_BACKEND_URL ?? "http://localhost:8000").replace(/\/+$/, "");
const TIMEOUT_MS = Number(process.env.TIRITH_BACKEND_TIMEOUT_MS ?? 120_000);
// Shared bearer token for the backend API (never logged). Sent on every call when set.
const API_TOKEN = process.env.TIRITH_API_TOKEN?.trim() || undefined;

function headers(hasBody: boolean): Record<string, string> {
  const h: Record<string, string> = { accept: "application/json" };
  if (hasBody) h["content-type"] = "application/json";
  if (API_TOKEN) h.authorization = `Bearer ${API_TOKEN}`;
  return h;
}

export class BackendError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown, query?: Record<string, string | undefined>): Promise<T> {
  const url = new URL(`${BASE}/api${path}`);
  for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== "") url.searchParams.set(k, v);
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: headers(body !== undefined),
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    throw new BackendError(`Tirith backend is unreachable (${(err as Error).name}). Try again shortly.`, 0);
  }
  const text = await res.text();
  if (!res.ok) {
    // Only relay the contract's {detail: string}; never raw (possibly HTML / stack trace) bodies.
    let detail = "";
    try {
      const j = JSON.parse(text);
      if (typeof j?.detail === "string") detail = j.detail.slice(0, 300);
    } catch {
      /* non-JSON body: drop it */
    }
    const suffix = detail ? `: ${detail}` : ".";
    throw new BackendError(
      res.status === 401
        ? "Tirith backend rejected the server's credentials (check TIRITH_API_TOKEN)."
        : res.status === 404
          ? `Not found${suffix}`
          : res.status === 403
            ? `Blocked by Tirith policy${suffix}`
            : `Backend error ${res.status}${suffix}`,
      res.status,
    );
  }
  if (!text) return null as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new BackendError("Tirith backend returned an unreadable response.", res.status);
  }
}

export const backend = {
  listAssets: () => call<Asset[]>("GET", "/assets"),
  addAsset: (a: { kind: string; ref: string; name: string; focus?: string[]; exclude?: string[]; sub_apps?: string[] }) =>
    call<Asset>("POST", "/assets", a),
  startScan: (asset_id: string, tools?: string[]) => call<Scan>("POST", "/scans", tools?.length ? { asset_id, tools } : { asset_id }),
  listScans: (asset_id?: string) => call<Scan[]>("GET", "/scans", undefined, { asset_id }),
  getScan: (id: string) => call<Scan>("GET", `/scans/${encodeURIComponent(id)}`),
  listFindings: (q: { scan_id?: string; asset_id?: string; severity?: string; status?: string; component?: string; limit?: number }) =>
    call<Finding[]>("GET", "/findings", undefined, { ...q, limit: q.limit === undefined ? undefined : String(q.limit) }),
  getFinding: (id: string) => call<Finding>("GET", `/findings/${encodeURIComponent(id)}`),
  explainFinding: (id: string) => call<Explanation>("POST", `/findings/${encodeURIComponent(id)}/explain`, {}),
  validateFinding: (id: string) => call<Validation>("POST", `/findings/${encodeURIComponent(id)}/validate`, {}),
  fixFinding: (id: string, mode?: string) => call<Fix>("POST", `/findings/${encodeURIComponent(id)}/fix`, mode ? { mode } : {}),
  getFix: (id: string) => call<Fix>("GET", `/fixes/${encodeURIComponent(id)}`),
  applyFix: (id: string) => call<Fix>("POST", `/fixes/${encodeURIComponent(id)}/apply`, {}),
  rollbackFix: (id: string) => call<Fix>("POST", `/fixes/${encodeURIComponent(id)}/rollback`, {}),
  getPosture: (asset_id?: string) => call<Posture>("GET", "/posture", undefined, { asset_id }),
  getMode: () => call<ModeConfig>("GET", "/mode"),
  setMode: (m: Mode) => call<ModeConfig>("PATCH", "/mode", { mode: m }),
  health: () => call<unknown>("GET", "/health"),
  startAnalyst: (goal: string, maxSteps?: number, charge?: string, approval?: string) =>
    call<AnalystRun>("POST", "/analyst/runs", {
      goal,
      ...(maxSteps ? { max_steps: maxSteps } : {}),
      ...(charge ? { charge } : {}),
      ...(approval ? { mode: approval } : {}),
    }),
  pauseAnalyst: (id: string, reason?: string) =>
    call<{ run_id: string; waiting_on?: string }>("POST", `/analyst/runs/${encodeURIComponent(id)}/pause`, reason ? { reason } : {}),
  resumeAnalyst: (id: string) => call<{ resumed: boolean; was_waiting_on?: string }>("POST", `/analyst/runs/${encodeURIComponent(id)}/resume`, {}),
  getAnalyst: (id: string) => call<AnalystRun>("GET", `/analyst/runs/${encodeURIComponent(id)}`),
  listAnalysts: () => call<AnalystRun[]>("GET", "/analyst/runs"),
  startLab: (maxSteps?: number) => call<Record<string, unknown>>("POST", "/analystlab/start", { max_steps: maxSteps ?? 10 }),
  getLab: (id: string) => call<Record<string, unknown>>("GET", `/analystlab/runs/${encodeURIComponent(id)}`),
  checkLab: (id: string) => call<Record<string, unknown>>("POST", `/analystlab/runs/${encodeURIComponent(id)}/check`, {}),
  resetLab: () => call<Record<string, unknown>>("POST", "/analystlab/reset", {}),
  renderReport: (id: string, variant: "as-found" | "as-fixed" | "both") =>
    call<{ run_id: string; variant: string; files: Record<string, { path: string; url: string }> }>(
      "POST",
      `/analyst/runs/${encodeURIComponent(id)}/report?variant=${variant}`,
      {},
    ),
};

export const backendUrl = BASE;
export const backendAuthConfigured = Boolean(API_TOKEN);
