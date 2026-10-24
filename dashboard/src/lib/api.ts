import { API_BASE, EVENTS_URL, LONG_TIMEOUT_MS, SHORT_TIMEOUT_MS } from "./config";
import type {
  Asset,
  AuditEntry,
  Explanation,
  Finding,
  Fix,
  Mode,
  ModeState,
  Posture,
  Scan,
  Snapshot,
  TirithEvent,
} from "./types";

/**
 * REST goes through the same-origin route handler (/tirith/api/* -> backend /api/*), which adds the backend
 * bearer token server side. The browser never sees the token or the backend URL.
 */
async function req<T>(path: string, init?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), init?.timeoutMs ?? SHORT_TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: { "content-type": "application/json", ...(init?.headers || {}) },
      cache: "no-store",
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      let detail = text;
      try {
        const j = JSON.parse(text) as { detail?: unknown };
        if (typeof j.detail === "string") detail = j.detail;
      } catch {
        /* not JSON */
      }
      throw new Error(`${res.status}${detail ? ` — ${detail.slice(0, 200)}` : ` ${res.statusText}`}`);
    }
    return (await res.json()) as T;
  } catch (e) {
    if (ctrl.signal.aborted) throw new Error(`timed out after ${Math.round((init?.timeoutMs ?? SHORT_TIMEOUT_MS) / 1000)}s`);
    throw e;
  } finally {
    clearTimeout(t);
  }
}

const post = <T>(path: string, body?: unknown, timeoutMs?: number) =>
  req<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body), timeoutMs });

/** Accept either a bare array or an `{items: [...]}`-style envelope. */
function list<T>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[];
  if (v && typeof v === "object") {
    for (const k of ["items", "results", "data", "entries", "events"]) {
      const inner = (v as Record<string, unknown>)[k];
      if (Array.isArray(inner)) return inner as T[];
    }
  }
  return [];
}

/** Identity used to drop duplicate events (WS replay after a reconnect overlaps what we already have). */
export const eventKey = (e: TirithEvent) =>
  `${e.ts}|${e.type}|${e.finding_id ?? e.fix_id ?? e.scan_id ?? ""}|${e.message}`;

export interface DataSource {
  kind: "live" | "mock";
  /** `prev` lets a source keep the last good value for any sub-request that fails. */
  snapshot(prev?: Snapshot): Promise<Snapshot>;
  recentEvents(): Promise<TirithEvent[]>;
  subscribe(onEvent: (e: TirithEvent) => void, onStatus: (s: "open" | "closed") => void): () => void;
  explain(id: string): Promise<Explanation>;
  validate(id: string): Promise<unknown>;
  fix(id: string, mode?: Mode): Promise<Fix>;
  apply(fixId: string): Promise<unknown>;
  rollback(fixId: string): Promise<unknown>;
  setMode(m: ModeState): Promise<unknown>;
  startScan(assetId: string): Promise<Scan>;
}

export async function backendReachable(timeoutMs = 2500): Promise<boolean> {
  try {
    await req("/health", { timeoutMs });
    return true;
  } catch {
    return false;
  }
}

export function liveSource(): DataSource {
  return {
    kind: "live",
    async snapshot(prev) {
      const keep = <T>(fallback: T) => (): T => fallback;
      const [allAssets, mode, audit, allScans] = await Promise.all([
        req<unknown>("/assets").then(list<Asset>), // no assets -> nothing to show; let the caller keep prev
        req<ModeState>("/mode").catch(keep(prev?.mode ?? { mode: "observe" as Mode, autonomous_categories: [] })),
        req<unknown>("/audit?limit=200").then(list<AuditEntry>).catch(keep(prev?.audit ?? [])),
        req<unknown>("/scans").then(list<Scan>).catch(() => null),
      ]);
      // Focus the asset with the most recent scan (the one being worked on), not simply the first registered.
      const scansForPick = allScans ?? prev?.scans ?? [];
      const latest = [...scansForPick].sort((a, b) => (b.started_at ?? "9").localeCompare(a.started_at ?? "9"))[0];
      const asset = allAssets.find((a) => a.id === latest?.asset_id) ?? allAssets[0];
      const assets = asset ? [asset, ...allAssets.filter((a) => a.id !== asset.id)] : allAssets;
      // Previous per-asset data is only a valid fallback when it belongs to the same asset.
      const same = !!prev && !!asset && prev.assets[0]?.id === asset.id;
      const q = asset ? `?asset_id=${encodeURIComponent(asset.id)}` : "";
      const [scans, findings, posture] = await Promise.all([
        req<unknown>(`/scans${q}`)
          .then(list<Scan>)
          .then((xs) => xs.sort((a, b) => (b.started_at ?? "9").localeCompare(a.started_at ?? "9")))
          .catch(keep(same ? prev!.scans : [])),
        req<unknown>(`/findings${q}`).then(list<Finding>).catch(keep(same ? prev!.findings : [])),
        asset ? req<Posture>(`/posture${q}`).catch(keep(same ? prev!.posture : null)) : Promise.resolve(null),
      ]);
      const fixIds = Array.from(new Set(findings.map((f) => f.fix_id).filter(Boolean))) as string[];
      const fixesArr = await Promise.all(
        fixIds.map((id) => req<Fix>(`/fixes/${encodeURIComponent(id)}`).catch(() => prev?.fixes[id] ?? null)),
      );
      const fixes: Record<string, Fix> = {};
      for (const f of fixesArr) if (f) fixes[f.id] = f;
      return { assets, scans, findings, fixes, posture, mode, audit };
    },
    async recentEvents() {
      return req<unknown>("/events/recent?limit=100").then(list<TirithEvent>).catch(() => []);
    },
    subscribe(onEvent, onStatus) {
      // Same-origin SSE relay of the backend WebSocket (see app/tirith/events/route.ts). Every (re)connect asks
      // for a replay of recent events so nothing emitted during the gap is missed; the store dedupes.
      let es: EventSource | null = null;
      let stopped = false;
      let attempt = 0;
      let timer: ReturnType<typeof setTimeout> | null = null;

      const connect = () => {
        if (stopped) return;
        es = new EventSource(`${EVENTS_URL}?replay=100`);
        es.addEventListener("ready", () => {
          attempt = 0;
          onStatus("open");
        });
        es.addEventListener("unavailable", () => onStatus("closed"));
        es.onmessage = (m) => {
          try {
            const parsed = JSON.parse(m.data);
            if (parsed && typeof parsed === "object" && "type" in parsed) onEvent(parsed as TirithEvent);
          } catch {
            /* ignore malformed frames */
          }
        };
        es.onerror = () => {
          onStatus("closed");
          // CONNECTING = the browser retries by itself; CLOSED (e.g. non-200) = we must reconnect ourselves.
          if (es?.readyState === EventSource.CLOSED && !stopped) {
            es.close();
            attempt++;
            timer = setTimeout(connect, Math.min(10000, 500 * 2 ** Math.min(attempt, 5)));
          }
        };
      };
      connect();
      return () => {
        stopped = true;
        if (timer) clearTimeout(timer);
        es?.close();
      };
    },
    explain: (id) => post<Explanation>(`/findings/${encodeURIComponent(id)}/explain`, undefined, LONG_TIMEOUT_MS),
    validate: (id) => post(`/findings/${encodeURIComponent(id)}/validate`, undefined, LONG_TIMEOUT_MS),
    fix: (id, mode) => post<Fix>(`/findings/${encodeURIComponent(id)}/fix`, mode ? { mode } : {}, LONG_TIMEOUT_MS),
    apply: (id) => post(`/fixes/${encodeURIComponent(id)}/apply`),
    rollback: (id) => post(`/fixes/${encodeURIComponent(id)}/rollback`),
    setMode: (m) => req(`/mode`, { method: "PUT", body: JSON.stringify(m) }),
    startScan: (asset_id) => post<Scan>(`/scans`, { asset_id }),
  };
}
