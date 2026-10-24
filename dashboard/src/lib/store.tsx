"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { backendReachable, eventKey, liveSource, type DataSource } from "./api";
import { FORCE_MOCK } from "./config";
import { mockSource, type MockEngine } from "./mock";
import type { Explanation, Mode, Snapshot, TirithEvent } from "./types";

export type Conn = "probing" | "live" | "reconnecting" | "demo";
export type ActionName = "explain" | "validate" | "fix" | "apply" | "rollback";

interface Toast {
  id: number;
  level: "info" | "error" | "success";
  text: string;
}

interface Store {
  conn: Conn;
  demo: boolean;
  demoReason: string | null;
  snap: Snapshot;
  events: TirithEvent[];
  selectedId: string | null;
  select: (id: string | null) => void;
  explanations: Record<string, Explanation>;
  /** Keyed `${findingId}:${action}`; cleared only after the post-action refresh has landed. */
  pending: Record<string, true | undefined>;
  isPending: (findingId: string, action: ActionName) => boolean;
  act: (name: ActionName, findingId: string) => Promise<void>;
  setMode: (m: Mode) => Promise<void>;
  replay: () => void;
  startScan: () => Promise<void>;
  toasts: Toast[];
  lastEventAt: number;
}

const EMPTY: Snapshot = {
  assets: [],
  scans: [],
  findings: [],
  fixes: {},
  posture: null,
  mode: { mode: "observe", autonomous_categories: [] },
  audit: [],
};

const Ctx = createContext<Store | null>(null);
const MAX_EVENTS = 400;

const pkey = (findingId: string, action: ActionName) => `${findingId}:${action}`;
const PROBE_MS = 10_000;

export function TirithProvider({ children }: { children: React.ReactNode }) {
  const [conn, setConn] = useState<Conn>("probing");
  const [demoReason, setDemoReason] = useState<string | null>(null);
  const [snap, setSnap] = useState<Snapshot>(EMPTY);
  const [events, setEvents] = useState<TirithEvent[]>([]);
  const [selectedId, select] = useState<string | null>(null);
  const [explanations, setExplanations] = useState<Record<string, Explanation>>({});
  const [pending, setPending] = useState<Record<string, true | undefined>>({});
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [lastEventAt, setLastEventAt] = useState(0);
  const src = useRef<DataSource | null>(null);
  const snapRef = useRef<Snapshot>(EMPTY);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Refresh sequencing: every refresh takes a number; a result older than the newest applied one is dropped.
  // Bumping `generation` (source switch) invalidates everything in flight.
  const reqSeq = useRef(0);
  const appliedSeq = useRef(0);
  const generation = useRef(0);
  const seen = useRef<Set<string>>(new Set());

  const toast = useCallback((level: Toast["level"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, level, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);

  const applySnap = useCallback((next: Snapshot) => {
    snapRef.current = next;
    setSnap(next);
  }, []);

  /** Resolves once the snapshot is applied (or dropped as stale / failed). */
  const refresh = useCallback(async () => {
    const s = src.current;
    if (!s) return;
    const gen = generation.current;
    const my = ++reqSeq.current;
    try {
      const next = await s.snapshot(snapRef.current);
      if (gen !== generation.current || my < appliedSeq.current) return; // stale
      appliedSeq.current = my;
      applySnap(next);
    } catch {
      /* transient; keep previous data, next poll/event retries */
    }
  }, [applySnap]);

  const scheduleRefresh = useCallback(
    (ms: number) => {
      if (refreshTimer.current) return;
      refreshTimer.current = setTimeout(() => {
        refreshTimer.current = null;
        void refresh();
      }, ms);
    },
    [refresh],
  );

  const resetEvents = useCallback((list: TirithEvent[]) => {
    const unique: TirithEvent[] = [];
    const keys = new Set<string>();
    for (const e of list) {
      const k = eventKey(e);
      if (keys.has(k)) continue;
      keys.add(k);
      unique.push(e);
    }
    const kept = unique.slice(-MAX_EVENTS);
    seen.current = new Set(kept.map(eventKey));
    setEvents(kept);
  }, []);

  useEffect(() => {
    let stop: (() => void) | null = null;
    let probe: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;
    const gens = generation; // bumped on cleanup to invalidate in-flight work (not a DOM ref)

    /** Wire one source: initial load, polling, then the live subscription. Returns its teardown. */
    const start = async (source: DataSource): Promise<(() => void) | null> => {
      const gen = ++generation.current;
      appliedSeq.current = reqSeq.current;
      src.current = source;
      const isMock = source.kind === "mock";
      setConn(isMock ? "demo" : "reconnecting");

      // Poll first (belt and braces: state stays fresh even if the event stream is down or sparse).
      const poll = setInterval(() => void refresh(), isMock ? 1500 : 5000);
      const [, recent] = await Promise.all([refresh(), source.recentEvents().catch(() => [] as TirithEvent[])]);
      if (cancelled || gen !== generation.current) {
        clearInterval(poll);
        return null;
      }
      resetEvents(recent);

      const unsub = source.subscribe(
        (e) => {
          if (gen !== generation.current) return;
          if (e.data && (e.data as { reset?: boolean }).reset) {
            seen.current = new Set();
            setEvents([]);
            setExplanations({});
          }
          const k = eventKey(e);
          if (seen.current.has(k)) return; // replayed after reconnect
          seen.current.add(k);
          setEvents((prev) => {
            const next = prev.length >= MAX_EVENTS ? prev.slice(-MAX_EVENTS + 1) : prev.slice();
            if (prev.length >= MAX_EVENTS) seen.current.delete(eventKey(prev[0]));
            next.push(e);
            return next;
          });
          setLastEventAt(Date.now());
          scheduleRefresh(isMock ? 120 : 400);
        },
        (st) => {
          if (gen !== generation.current || isMock) return;
          setConn(st === "open" ? "live" : "reconnecting");
          if (st === "open") void refresh();
        },
      );
      return () => {
        clearInterval(poll);
        unsub();
      };
    };

    (async () => {
      if (FORCE_MOCK) {
        setDemoReason("NEXT_PUBLIC_TIRITH_MOCK=1");
        stop = await start(mockSource());
        return;
      }
      if (await backendReachable()) {
        if (!cancelled) stop = await start(liveSource());
        return;
      }
      if (cancelled) return;
      setDemoReason("backend unreachable — replaying scripted demo; retrying every 10 s");
      stop = await start(mockSource());
      // Leave demo mode as soon as the backend answers again.
      let probing = false;
      probe = setInterval(async () => {
        if (probing || cancelled) return;
        probing = true;
        try {
          if (!(await backendReachable()) || cancelled) return;
          if (probe) clearInterval(probe);
          probe = null;
          stop?.();
          setDemoReason(null);
          setExplanations({});
          resetEvents([]);
          stop = await start(liveSource());
          toast("success", "Backend is back — switched to live data");
        } finally {
          probing = false;
        }
      }, PROBE_MS);
    })();

    return () => {
      cancelled = true;
      gens.current++;
      if (probe) clearInterval(probe);
      stop?.();
    };
  }, [refresh, scheduleRefresh, resetEvents, toast]);

  const isPending = useCallback((findingId: string, action: ActionName) => !!pending[pkey(findingId, action)], [pending]);

  const act = useCallback(
    async (name: ActionName, findingId: string) => {
      const s = src.current;
      if (!s) return;
      const key = pkey(findingId, name);
      const current = snapRef.current;
      const finding = current.findings.find((f) => f.id === findingId);
      const mode = current.mode.mode;
      if (name === "fix" && mode === "observe") {
        toast("error", "Observe mode is report-only — switch to Assisted or Autonomous to fix");
        return;
      }
      setPending((p) => ({ ...p, [key]: true }));
      try {
        if (name === "explain") {
          const ex = await s.explain(findingId);
          setExplanations((m) => ({ ...m, [findingId]: ex }));
        } else if (name === "validate") {
          const v = (await s.validate(findingId)) as { result?: string } | null;
          toast(v?.result === "confirmed" ? "error" : "info", v?.result ? `Validation: ${v.result.replace("_", " ")}` : "Validation started in isolated lab");
        } else if (name === "fix") {
          await s.fix(findingId, mode);
          toast("info", `Remediation started (${mode})`);
        } else if (name === "apply" || name === "rollback") {
          const fixId = finding?.fix_id;
          if (!fixId) throw new Error("no fix for this finding yet");
          await (name === "apply" ? s.apply(fixId) : s.rollback(fixId));
          toast("success", name === "apply" ? "Fix applied" : "Fix rolled back");
        }
      } catch (e) {
        toast("error", `${name} failed: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        // Keep the button busy until the UI reflects the action's outcome.
        await refresh();
        setPending((p) => {
          const next = { ...p };
          delete next[key];
          return next;
        });
      }
    },
    [refresh, toast],
  );

  const setMode = useCallback(
    async (m: Mode) => {
      const s = src.current;
      if (!s) return;
      const prev = snapRef.current.mode;
      applySnap({ ...snapRef.current, mode: { ...prev, mode: m } });
      try {
        await s.setMode({ mode: m, autonomous_categories: prev.autonomous_categories });
        void refresh();
      } catch (e) {
        applySnap({ ...snapRef.current, mode: prev });
        toast("error", `Mode change rejected: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
    [applySnap, refresh, toast],
  );

  const replay = useCallback(() => {
    const s = src.current;
    if (s && s.kind === "mock") {
      resetEvents([]);
      setExplanations({});
      (s as MockEngine).replay();
      void refresh();
    }
  }, [refresh, resetEvents]);

  const startScan = useCallback(async () => {
    const s = src.current;
    const asset = snap.assets[0];
    if (!s) return;
    if (s.kind === "mock") return replay();
    if (!asset) return toast("error", "No asset registered yet");
    try {
      await s.startScan(asset.id);
      toast("info", `Scan queued for ${asset.ref}`);
    } catch (e) {
      toast("error", `Scan failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, [snap.assets, replay, toast]);

  const value = useMemo<Store>(
    () => ({
      conn,
      demo: conn === "demo",
      demoReason,
      snap,
      events,
      selectedId,
      select,
      explanations,
      pending,
      isPending,
      act,
      setMode,
      replay,
      startScan,
      toasts,
      lastEventAt,
    }),
    [conn, demoReason, snap, events, selectedId, explanations, pending, isPending, act, setMode, replay, startScan, toasts, lastEventAt],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTirith(): Store {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTirith outside TirithProvider");
  return v;
}
