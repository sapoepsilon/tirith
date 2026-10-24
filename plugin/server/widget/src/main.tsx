import { StrictMode, useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { bridge, type ToolResult } from "./bridge";

// ---------- types (mirror the MCP server's structuredContent; treat as untrusted) ----------
type Sev = "critical" | "high" | "medium" | "low" | "info";
type Counts = Record<Sev, number>;
interface SlimFinding {
  id: string;
  title: string;
  severity: Sev;
  category?: string;
  tool?: string;
  file?: string;
  line?: number;
  cwe?: string;
  cve?: string;
  package?: string;
  status?: string;
  confidence?: number;
}
interface Evidence {
  kind: string;
  label: string;
  content: string;
}
interface FullFinding extends SlimFinding {
  rule_id?: string;
  description?: string;
  snippet?: string;
  installed_version?: string;
  fixed_version?: string;
  url?: string;
  ai_summary?: string;
  validation?: { check?: string; result?: string; confidence?: number; evidence?: Evidence[] } | null;
  fix_id?: string;
}
interface FixView {
  id: string;
  status: string;
  mode?: string;
  branch?: string;
  pr_url?: string;
  diff?: string;
  verification?: { tests_passed?: boolean; validation_result?: string; details?: string };
}
interface PostureData {
  view: "posture";
  asset?: { id: string; name: string; ref: string; kind: string } | null;
  posture: { score: number; grade: string; counts: Counts; open: number; fixed: number; history: number[] };
  mode?: string | null;
  top_findings: SlimFinding[];
  scan?: { id: string; status: string; tools?: Record<string, string>; counts?: Counts };
}
interface FindingData {
  view: "finding";
  finding: FullFinding;
  fix?: FixView | null;
}
interface ScanData {
  view: "scan";
  scan: { id: string; status: string; tools?: Record<string, string>; counts?: Counts };
}
type Data = PostureData | FindingData | ScanData;

const SEVS: Sev[] = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL: Record<Sev, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

function isData(x: unknown): x is Data {
  const v = (x as { view?: unknown } | null)?.view;
  return v === "posture" || v === "finding" || v === "scan";
}

// ---------- host bridge ----------

/** Tool result -> view data. The patch diff is widget-only: it arrives in result _meta, not structuredContent. */
function toData(structured: unknown, meta: Record<string, unknown> | undefined): Data | null {
  if (!isData(structured)) return null;
  const diff = meta?.["tirith/diff"];
  if (structured.view === "finding" && structured.fix && typeof diff === "string" && meta?.["tirith/fixId"] === structured.fix.id) {
    return { ...structured, fix: { ...structured.fix, diff } };
  }
  return structured;
}
const fromResult = (r: ToolResult | undefined) => toData(r?.structuredContent, r?._meta);

// Register before connecting so the first tool-result is never missed; one connection per iframe.
let latest: Data | null = (() => {
  const oa = (window as unknown as { openai?: { toolOutput?: unknown; toolResponseMetadata?: Record<string, unknown> } }).openai;
  return toData(oa?.toolOutput, oa?.toolResponseMetadata);
})();
// Each host tool result is a fresh root view: subscribers reset navigation (back stack).
const subscribers = new Set<(d: Data) => void>();
bridge.onToolResult((p) => {
  const d = fromResult(p);
  if (!d) return;
  latest = d;
  subscribers.forEach((fn) => fn(d));
});
const standalone = window.parent === window;
if (standalone) {
  // Local preview outside a host: open tirith.html#demo or #demo-finding.
  if (location.hash.startsWith("#demo")) latest = demoData(location.hash === "#demo-finding" ? "finding" : "posture");
} else {
  bridge.connect().catch((e) => console.warn("Tirith: host bridge unavailable", e));
}

function demoData(view: "posture" | "finding"): Data {
  const top: SlimFinding[] = [
    { id: "fnd_1", title: "SQL injection in SQL injection lab login", severity: "critical", tool: "semgrep", file: "dockerized_labs/sql_injection_lab/app.py", line: 50, cwe: "CWE-89", status: "validated" },
    { id: "fnd_2", title: "Hard-coded Django SECRET_KEY", severity: "high", tool: "gitleaks", file: "pygoat/settings.py", line: 23, cwe: "CWE-798", status: "open" },
    { id: "fnd_3", title: "Werkzeug 2.1.2: 4 CVEs", severity: "high", tool: "trivy", package: "Werkzeug", cve: "CVE-2024-34069", status: "fixing" },
    { id: "fnd_4", title: "Reflected XSS in FAANG search lab", severity: "medium", tool: "zap", category: "dast", cwe: "CWE-79", status: "open" },
  ];
  if (view === "posture")
    return {
      view: "posture",
      asset: { id: "ast_pygoat", name: "pygoat", ref: "sapoepsilon/tirith-demo-target", kind: "github_repo" },
      posture: { score: 41, grade: "F", counts: { critical: 1, high: 2, medium: 2, low: 1, info: 0 }, open: 6, fixed: 1, history: [100, 38, 33, 41] },
      mode: "assisted",
      top_findings: top,
    };
  return {
    view: "finding",
    finding: {
      ...top[0],
      rule_id: "tainted-sql-string",
      confidence: 0.94,
      description: "`username` and `password` from the login form are interpolated into an f-string SQL query executed with sqlite3.",
      snippet: `sql_query = (\n    f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"\n)`,
      ai_summary: "The /lab endpoint builds SQL with an f-string from form fields, so an attacker can bypass the login or dump the users table.",
      validation: {
        check: "cwe-89-sqli",
        result: "confirmed",
        confidence: 0.97,
        evidence: [
          { kind: "request", label: "Boolean probe (true)", content: "POST /lab  username=admin'--&password=x" },
          { kind: "response", label: "Response (true)", content: "200 OK — Welcome admin" },
          { kind: "log", label: "Verdict", content: "Responses differ: injectable." },
        ],
      },
    },
    fix: {
      id: "fix_1",
      status: "verified",
      pr_url: "https://github.com/sapoepsilon/tirith-demo-target/pull/1",
      verification: { validation_result: "not_reproduced" },
      diff: `-result = c.execute(sql_query).fetchone()\n+result = c.execute(sql_query, (username, password)).fetchone()`,
    },
  };
}

function useHost(onHostResult: () => void) {
  const [data, setData] = useState<Data | null>(latest);
  useEffect(() => {
    const fn = (d: Data) => {
      onHostResult();
      setData(d);
    };
    subscribers.add(fn);
    if (latest) setData(latest);
    return () => {
      subscribers.delete(fn);
    };
  }, [onHostResult]);
  return { data, setData };
}

// ---------- small components ----------
function Glyph({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <path d="M32 6 20 16h24L32 6Z" fill="currentColor" />
      <rect x="22" y="18" width="20" height="7" rx="1.5" fill="currentColor" opacity=".9" />
      <path d="M25 27h14l3 31H22l3-31Z" fill="currentColor" opacity=".75" />
      <rect x="29.5" y="20" width="5" height="3" rx="1" fill="#0b0f17" />
    </svg>
  );
}

function SevBadge({ s }: { s: Sev }) {
  return <span className={`sev sev-${s}`}>{SEV_LABEL[s] ?? s}</span>;
}

function StatusChip({ s }: { s?: string }) {
  if (!s) return null;
  return <span className={`chip chip-${s}`}>{s.replace(/_/g, " ")}</span>;
}

function Gauge({ score, grade }: { score: number; grade: string }) {
  const r = 46;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const tone = score >= 80 ? "var(--ok)" : score >= 60 ? "var(--warn)" : "var(--bad)";
  return (
    <div className="gauge">
      <svg viewBox="0 0 120 120" width="132" height="132" role="img" aria-label={`Posture score ${score} of 100, grade ${grade}`}>
        <circle cx="60" cy="60" r={r} className="gauge-track" />
        <circle
          cx="60"
          cy="60"
          r={r}
          className="gauge-arc"
          style={{ stroke: tone, strokeDasharray: `${c * pct} ${c}` }}
          transform="rotate(-90 60 60)"
        />
      </svg>
      <div className="gauge-center">
        <div className="gauge-score">{Math.round(score)}</div>
        <div className="gauge-grade" style={{ color: tone }}>
          Grade {grade}
        </div>
      </div>
    </div>
  );
}

function Sparkline({ values }: { values: number[] }) {
  if (!values || values.length < 2) return null;
  const w = 120;
  const h = 28;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - (Math.max(0, Math.min(100, v)) / 100) * h}`).join(" ");
  const last = values[values.length - 1];
  const delta = last - values[0];
  return (
    <div className="spark">
      <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} aria-hidden="true">
        <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" />
      </svg>
      <span className={delta >= 0 ? "up" : "down"}>
        {delta >= 0 ? "▲" : "▼"} {Math.abs(Math.round(delta))}
      </span>
    </div>
  );
}

function SevBar({ counts }: { counts: Counts }) {
  const total = SEVS.reduce((a, s) => a + (counts?.[s] ?? 0), 0);
  return (
    <div className="sevbar-wrap">
      <div className="sevbar" aria-hidden="true">
        {total === 0 ? <div className="seg seg-none" style={{ flex: 1 }} /> : SEVS.map((s) => (counts[s] ? <div key={s} className={`seg seg-${s}`} style={{ flex: counts[s] }} /> : null))}
      </div>
      <div className="sevcounts">
        {SEVS.map((s) => (
          <div key={s} className="sevcount">
            <span className={`dot dot-${s}`} />
            <span className="n">{counts?.[s] ?? 0}</span>
            <span className="l">{SEV_LABEL[s]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function loc(f: SlimFinding & { url?: string }) {
  if (f.file) return `${f.file}${f.line ? `:${f.line}` : ""}`;
  if (f.package) return f.package;
  if (f.url) return f.url.replace(/^https?:\/\//, "");
  return f.category ?? "";
}

function Header({ asset, mode }: { asset?: PostureData["asset"]; mode?: string | null }) {
  return (
    <header className="hdr">
      <div className="brand">
        <span className="brand-mark">
          <Glyph />
        </span>
        <span className="brand-name">Tirith</span>
        {asset && <span className="brand-asset">· {asset.name}</span>}
      </div>
      {mode && <span className={`mode mode-${mode}`}>{mode}</span>}
    </header>
  );
}

// ---------- views ----------
function PostureView({ d, onOpen, loadingId }: { d: PostureData; onOpen: (id: string) => void; loadingId: string | null }) {
  const p = d.posture;
  return (
    <>
      <Header asset={d.asset} mode={d.mode} />
      {d.scan && (
        <div className="banner">
          <span className="pulse" /> Scan {d.scan.status} ·{" "}
          {Object.entries(d.scan.tools ?? {})
            .map(([k, v]) => `${k} ${v}`)
            .join(" · ")}
        </div>
      )}
      <section className="hero">
        <Gauge score={p.score} grade={p.grade} />
        <div className="hero-side">
          <div className="kpis">
            <div className="kpi">
              <div className="kpi-n">{p.open}</div>
              <div className="kpi-l">Open</div>
            </div>
            <div className="kpi">
              <div className="kpi-n ok">{p.fixed}</div>
              <div className="kpi-l">Fixed</div>
            </div>
            <div className="kpi">
              <Sparkline values={p.history} />
              <div className="kpi-l">Trend</div>
            </div>
          </div>
          <SevBar counts={p.counts} />
        </div>
      </section>
      <section>
        <div className="sec-title">Top findings</div>
        {d.top_findings.length === 0 ? (
          <div className="empty">No open findings. Nice work.</div>
        ) : (
          <ul className="list">
            {d.top_findings.map((f) => (
              <li key={f.id}>
                <button className="row" onClick={() => onOpen(f.id)} disabled={loadingId !== null}>
                  <SevBadge s={f.severity} />
                  <span className="row-main">
                    <span className="row-title">{f.title}</span>
                    <span className="row-sub">
                      {loc(f)}
                      {f.cwe ? ` · ${f.cwe}` : f.cve ? ` · ${f.cve}` : ""}
                      {f.tool ? ` · ${f.tool}` : ""}
                    </span>
                  </span>
                  <StatusChip s={f.status} />
                  <span className="chev">{loadingId === f.id ? <span className="spin" /> : "›"}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}

function FindingView({ d, onBack, canBack }: { d: FindingData; onBack: () => void; canBack: boolean }) {
  const f = d.finding;
  const fix = d.fix;
  const [openEv, setOpenEv] = useState<number | null>(null);
  const ask = useCallback((text: string) => {
    bridge.sendMessage(text).catch(() => {});
  }, []);
  const v = f.validation;
  return (
    <>
      <header className="hdr">
        <div className="brand">
          {canBack ? (
            <button className="back" onClick={onBack} aria-label="Back to posture">
              ‹
            </button>
          ) : (
            <span className="brand-mark">
              <Glyph />
            </span>
          )}
          <span className="brand-name">Tirith</span>
          <span className="brand-asset">· Finding</span>
        </div>
        <StatusChip s={f.status} />
      </header>

      <section className="fhead">
        <SevBadge s={f.severity} />
        <h1>{f.title}</h1>
        <div className="meta">
          {[loc(f), f.cwe, f.cve, f.tool && `${f.tool}${f.rule_id ? ` · ${f.rule_id}` : ""}`, f.confidence != null && `${Math.round(f.confidence * 100)}% confidence`]
            .filter(Boolean)
            .map((m, i) => (
              <span key={i} className="meta-i">
                {m}
              </span>
            ))}
        </div>
      </section>

      {f.ai_summary && (
        <section className="card ai">
          <div className="card-t">
            <span className="ai-dot" /> AI summary
          </div>
          <p>{f.ai_summary}</p>
        </section>
      )}

      {f.description && (
        <section className="card">
          <div className="card-t">Description</div>
          <p>{f.description}</p>
          {f.package && (
            <p className="mono small">
              {f.package} {f.installed_version} → {f.fixed_version ?? "no fix yet"}
            </p>
          )}
        </section>
      )}

      {f.snippet && (
        <section className="card">
          <div className="card-t">Code</div>
          <pre className="code">{f.snippet}</pre>
        </section>
      )}

      <section className="card">
        <div className="card-t">
          Lab validation
          {v?.result && <span className={`verdict verdict-${v.result}`}>{v.result.replace(/_/g, " ")}</span>}
        </div>
        {!v ? (
          <p className="muted">Not validated yet. Tirith can run a fixed, non-destructive check against an isolated lab copy.</p>
        ) : (
          <>
            <p className="muted small">
              {v.check}
              {v.confidence != null ? ` · ${Math.round(v.confidence * 100)}% confidence` : ""}
            </p>
            <ul className="ev">
              {(v.evidence ?? []).map((e, i) => (
                <li key={i}>
                  <button className="ev-h" onClick={() => setOpenEv(openEv === i ? null : i)} aria-expanded={openEv === i}>
                    <span className={`ev-k ev-${e.kind}`}>{e.kind}</span>
                    <span>{e.label}</span>
                    <span className="chev">{openEv === i ? "–" : "+"}</span>
                  </button>
                  {openEv === i && <pre className="code">{e.content}</pre>}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      {fix && (
        <section className="card">
          <div className="card-t">
            Remediation <span className={`chip chip-${fix.status}`}>{fix.status.replace(/_/g, " ")}</span>
          </div>
          {fix.pr_url && (
            <button className="pr" onClick={() => bridge.openLink(fix.pr_url!).catch(() => window.open(fix.pr_url, "_blank"))}>
              <span className="pr-i">⎇</span>
              <span className="pr-t">{fix.pr_url.replace(/^https:\/\/github\.com\//, "")}</span>
              <span className="chev">↗</span>
            </button>
          )}
          {fix.verification?.validation_result && (
            <p className="small">Verification (rescan + lab boot): {fix.verification.validation_result}</p>
          )}
          {fix.diff && <pre className="code diff">{fix.diff}</pre>}
        </section>
      )}

      <div className="actions">
        <button className="btn" onClick={() => ask(`Explain Tirith finding ${f.id} and how exploitable it is.`)}>
          Explain
        </button>
        <button className="btn" onClick={() => ask(`Validate Tirith finding ${f.id} in the isolated lab.`)}>
          Validate in lab
        </button>
        {!fix && (
          <button className="btn primary" onClick={() => ask(`Open a pull request fixing Tirith finding ${f.id}.`)}>
            Open fix PR
          </button>
        )}
      </div>
    </>
  );
}

function ScanView({ d }: { d: ScanData }) {
  return (
    <>
      <Header />
      <section className="card">
        <div className="card-t">
          Scan <span className={`chip chip-${d.scan.status}`}>{d.scan.status}</span>
        </div>
        <ul className="tools">
          {Object.entries(d.scan.tools ?? {}).map(([k, v]) => (
            <li key={k}>
              <span className="mono">{k}</span>
              <span className={`chip chip-${v}`}>{v}</span>
            </li>
          ))}
        </ul>
        {d.scan.counts && <SevBar counts={d.scan.counts} />}
      </section>
    </>
  );
}

function Root() {
  const [stack, setStack] = useState<Data[]>([]);
  const resetNav = useCallback(() => setStack([]), []);
  const { data, setData } = useHost(resetNav);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const open = useCallback(
    async (id: string) => {
      if (!data) return;
      setLoadingId(id);
      setErr(null);
      try {
        const r = await bridge.callTool("tirith_get_finding", { finding_id: id });
        const next = fromResult(r);
        if (r.isError || !next) throw new Error("Could not load this finding. Try asking in the chat.");
        setStack((s) => [...s, data]);
        setData(next);
      } catch (e) {
        setErr((e as Error).message);
      } finally {
        setLoadingId(null);
      }
    },
    [data, setData],
  );

  const back = useCallback(() => {
    setStack((s) => {
      const prev = s[s.length - 1];
      if (prev) setData(prev);
      return s.slice(0, -1);
    });
  }, [setData]);

  const body = useMemo(() => {
    if (!data)
      return (
        <div className="loading">
          <span className="brand-mark big">
            <Glyph size={28} />
          </span>
          <span>Tirith is watching…</span>
        </div>
      );
    if (data.view === "posture") return <PostureView d={data} onOpen={open} loadingId={loadingId} />;
    if (data.view === "finding") return <FindingView d={data} onBack={back} canBack={stack.length > 0} />;
    return <ScanView d={data} />;
  }, [data, open, back, loadingId, stack.length]);

  return (
    <main className="t">
      {body}
      {err && <div className="err">{err}</div>}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
