// Tiny in-memory implementation of the Tirith backend REST contract (CONTRACT.md) with canned
// PyGoat data, for testing the MCP server while the real FastAPI backend is built.
// Run: MOCK_PORT=8000 TIRITH_API_TOKEN=dev-token npx tsx mock-backend.ts
// When TIRITH_API_TOKEN is set every /api call needs `Authorization: Bearer <token>` (401 otherwise).
// Assets whose ref contains "flaky" make GET /scans/{id} fail with a raw HTML 502 (transient-error test).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";

const PORT = Number(process.env.MOCK_PORT ?? 8000);
const SCAN_MS = Number(process.env.MOCK_SCAN_MS ?? 5000);
const FIX_MS = Number(process.env.MOCK_FIX_MS ?? 3000);
const API_TOKEN = process.env.TIRITH_API_TOKEN?.trim() || undefined;

type Sev = "critical" | "high" | "medium" | "low" | "info";
const now = () => new Date().toISOString();
const sid = (p: string) => `${p}_${randomUUID().slice(0, 8)}`;

const assets: any[] = [
  { id: "ast_pygoat", kind: "github_repo", ref: "sapoepsilon/tirith-demo-target", name: "pygoat", created_at: now() },
  { id: "ast_local", kind: "local_path", ref: "/srv/private/checkouts/pygoat-local", name: "pygoat-local", created_at: now() },
];
const scans: any[] = [];
const findings: any[] = [];
const fixes: any[] = [];
const validations: any[] = [];
const events: any[] = [];
const audit: any[] = [];
let lastFindingsQuery: Record<string, string> = {};
let modeCfg = { mode: "assisted", autonomous_categories: ["dependency_bump"] };
const history: { ts: string; score: number }[] = [{ ts: now(), score: 100 }];

const CANNED = [
  {
    tool: "semgrep", rule_id: "python.flask.security.injection.tainted-sql-string", title: "SQL injection in SQL injection lab login",
    description: "`username` and `password` from the login form are interpolated into an f-string SQL query executed with sqlite3.",
    severity: "critical", category: "sast", file: "dockerized_labs/sql_injection_lab/app.py", line: 50,
    snippet: `sql_query = (\n    f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"\n)`,
    cwe: "CWE-89", confidence: 0.99,
    ai_summary: "The /lab endpoint builds SQL with an f-string from form fields, so an attacker can bypass the login (admin'--) or read the users table.",
  },
  {
    tool: "gitleaks", rule_id: "generic-api-key", title: "Hard-coded Django SECRET_KEY",
    description: "The Django SECRET_KEY is committed in pygoat/settings.py, allowing forged session cookies and signed tokens.",
    severity: "high", category: "secret", file: "pygoat/settings.py", line: 23, snippet: `SECRET_KEY = "lr66%-a!$km5...REDACTED"`,
    cwe: "CWE-798", confidence: 0.88,
    ai_summary: "The signing key for sessions is stored in source control; anyone with repo access can forge sessions. Rotate it and load it from the environment.",
  },
  {
    tool: "semgrep", rule_id: "python.lang.security.deserialization.pickle.avoid-pickle", title: "Insecure deserialization with pickle.loads",
    description: "Base64 data from the `serialized_data` form field is passed straight to `pickle.loads`, allowing arbitrary code execution.",
    severity: "high", category: "sast", file: "dockerized_labs/insec_des_lab/main.py", line: 40,
    snippet: `decoded_data = base64.b64decode(serialized_data)\nuser = pickle.loads(decoded_data)`,
    cwe: "CWE-502", confidence: 0.93,
    ai_summary: "Unauthenticated POST /deserialize unpickles attacker-controlled bytes, which gives remote code execution in the lab container.",
  },
  {
    tool: "trivy", rule_id: "CVE-2024-42005", title: "Django 4.2: 7 CVEs (CVE-2024-42005, CVE-2024-53908, CVE-2023-31047, +4)",
    description: "Django==4.2 is affected by CVE-2024-42005 (SQL injection in QuerySet.values on JSONField), CVE-2024-53908, CVE-2023-31047, CVE-2023-36053, CVE-2023-43665, CVE-2024-24680 and CVE-2024-27351. Upgrading to 4.2.26 resolves all of them.",
    severity: "critical", category: "dependency", file: "requirements.txt", line: 12, cve: "CVE-2024-42005",
    package: "Django", installed_version: "4.2", fixed_version: "4.2.26", confidence: 0.98,
    ai_summary: "Django 4.2 is several patch releases behind in the LTS line. One bump to 4.2.26 clears all seven advisories.",
  },
  {
    tool: "trivy", rule_id: "CVE-2020-14343", title: "PyYAML 5.1: 2 CVEs (CVE-2020-14343, CVE-2020-1747)",
    description: "PyYAML==5.1 is affected by CVE-2020-14343 and CVE-2020-1747, arbitrary code execution through the full loader. Version 6.0.2 resolves both.",
    severity: "critical", category: "dependency", file: "requirements.txt", line: 24, cve: "CVE-2020-14343",
    package: "PyYAML", installed_version: "5.1", fixed_version: "6.0.2", confidence: 0.97,
    ai_summary: "PyYAML 5.1 allows code execution when parsing untrusted YAML. Bumping to 6.0.2 is the fix.",
  },
  {
    tool: "trivy", rule_id: "CVE-2024-34069", title: "Werkzeug 2.1.2: 4 CVEs (CVE-2024-34069, CVE-2023-25577, CVE-2024-49767, +1)",
    description: "Werkzeug==2.1.2 is affected by CVE-2024-34069 (debugger RCE), CVE-2023-25577, CVE-2024-49767 and CVE-2023-23934. Version 3.0.6 resolves all four.",
    severity: "high", category: "dependency", file: "requirements.txt", line: 29, cve: "CVE-2024-34069",
    package: "Werkzeug", installed_version: "2.1.2", fixed_version: "3.0.6", confidence: 0.95,
    ai_summary: "Outdated Werkzeug with a known debugger RCE. Bumping to 3.0.6 is a low-risk dependency upgrade.",
  },
  {
    tool: "zap", rule_id: "40012", title: "Reflected XSS in FAANG search lab",
    description: "The `q` parameter is reflected into the HTML response without encoding.",
    severity: "medium", category: "dast", url: "http://pygoat.lab:5006/lab1?q=%3Cscript%3E", cwe: "CWE-79", confidence: 0.71,
    ai_summary: "Search terms are echoed back unescaped via |safe in dockerized_labs/xss_lab/templates/lab1.html, enabling script injection.",
  },
  {
    tool: "semgrep", rule_id: "python.django.security.audit.django-debug-enabled", title: "Django DEBUG = True",
    description: "settings.py ships with DEBUG = True, exposing detailed error pages.", severity: "medium", category: "config",
    file: "pygoat/settings.py", line: 28, snippet: "DEBUG = True", cwe: "CWE-489", confidence: 0.9,
  },
  {
    tool: "zap", rule_id: "10038", title: "Content-Security-Policy header not set",
    description: "Responses lack a CSP header.", severity: "low", category: "dast", url: "http://pygoat.lab:8000/login/", cwe: "CWE-693", confidence: 0.6,
  },
];

function emit(type: string, message: string, extra: Record<string, unknown> = {}, level = "info") {
  events.push({ ts: now(), type, level, message, ...extra });
  if (events.length > 500) events.shift();
}

function counts(fs: any[]) {
  const c: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of fs) c[f.severity as Sev]++;
  return c;
}

function posture(asset_id?: string) {
  const fs = findings.filter((f) => !asset_id || f.asset_id === asset_id);
  const open = fs.filter((f) => f.status !== "fixed");
  const c = counts(open);
  const score = Math.max(0, Math.min(100, 100 - (c.critical * 25 + c.high * 12 + c.medium * 5 + c.low * 1)));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 55 ? "D" : "F";
  return { asset_id: asset_id ?? null, score, grade, counts: c, open: open.length, fixed: fs.length - open.length, history };
}

function recordPosture() {
  history.push({ ts: now(), score: posture().score });
  emit("posture.updated", `Posture is now ${posture().score}`);
}

function runScan(scan: any) {
  const tools = Object.keys(scan.tools);
  scan.status = "running";
  scan.started_at = now();
  emit("scan.started", `Scan ${scan.id} started`, { scan_id: scan.id });
  tools.forEach((t, i) =>
    setTimeout(() => {
      scan.tools[t] = "running";
      emit("tool.started", `${t} started`, { scan_id: scan.id });
    }, (SCAN_MS / (tools.length + 1)) * i),
  );
  setTimeout(() => {
    for (const c of CANNED) {
      if (!scan.tools[c.tool]) continue;
      const fp = `${c.tool}:${c.rule_id}:${c.file ?? c.url}`;
      const existing = findings.find((f) => f.fingerprint === fp && f.asset_id === scan.asset_id);
      if (existing) {
        existing.scan_id = scan.id;
        continue;
      }
      const f = {
        id: sid("fnd"), scan_id: scan.id, asset_id: scan.asset_id, fingerprint: fp,
        file: null, line: null, snippet: null, cwe: null, cve: null, package: null, installed_version: null, fixed_version: null, url: null,
        ai_summary: null, ...c, status: "open", validation: null, fix_id: null,
      };
      findings.push(f);
      emit("finding.new", f.title, { scan_id: scan.id, finding_id: f.id });
    }
    for (const t of tools) scan.tools[t] = "done";
    scan.counts = counts(findings.filter((f) => f.scan_id === scan.id));
    scan.status = "done";
    scan.finished_at = now();
    emit("scan.finished", `Scan ${scan.id} finished`, { scan_id: scan.id }, "success");
    recordPosture();
  }, SCAN_MS);
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
}
const notFound = (res: ServerResponse, what: string) => send(res, 404, { detail: `${what} not found` });

async function readBody(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const s = Buffer.concat(chunks).toString("utf8");
  return s ? JSON.parse(s) : {};
}

const routes: [string, RegExp, (m: RegExpMatchArray, q: URLSearchParams, body: any, res: ServerResponse) => void][] = [
  ["GET", /^\/api\/health$/, (_m, _q, _b, res) => send(res, 200, { status: "ok", mock: true })],
  ["GET", /^\/api\/assets$/, (_m, _q, _b, res) => send(res, 200, assets)],
  ["POST", /^\/api\/assets$/, (_m, _q, b, res) => {
    if (!["github_repo", "local_path", "url"].includes(b.kind) || !b.ref) return send(res, 422, { detail: "kind and ref required" });
    if (b.kind === "github_repo" && !/^[\w.-]+\/[\w.-]+$/.test(b.ref)) return send(res, 422, { detail: "ref must be owner/name" });
    if (b.ref.includes("forbidden")) return send(res, 403, { detail: `${b.ref} is outside scope.yaml` });
    const a = { id: sid("ast"), kind: b.kind, ref: b.ref, name: b.name ?? b.ref, created_at: now() };
    assets.push(a);
    audit.push({ ts: now(), action: "asset.add", ref: a.ref });
    send(res, 201, a);
  }],
  ["POST", /^\/api\/scans$/, (_m, _q, b, res) => {
    const asset = assets.find((a) => a.id === b.asset_id);
    if (!asset) return notFound(res, "asset");
    const all = asset.kind === "url" ? ["zap"] : ["semgrep", "gitleaks", "trivy", "zap"];
    const tools = (b.tools?.length ? b.tools : all) as string[];
    const scan = {
      id: sid("scn"), asset_id: asset.id, status: "queued",
      tools: Object.fromEntries(["semgrep", "gitleaks", "trivy", "zap"].map((t) => [t, tools.includes(t) ? "pending" : "skipped"]).filter(([, v]) => v !== "skipped")),
      counts: counts([]), started_at: null, finished_at: null,
    };
    scans.push(scan);
    setTimeout(() => runScan(scan), 200);
    send(res, 202, scan);
  }],
  ["GET", /^\/api\/scans$/, (_m, q, _b, res) => send(res, 200, scans.filter((s) => !q.get("asset_id") || s.asset_id === q.get("asset_id")))],
  ["GET", /^\/api\/scans\/([^/]+)$/, (m, _q, _b, res) => {
    const s = scans.find((x) => x.id === m[1]);
    if (s && assets.find((a) => a.id === s.asset_id)?.ref.includes("flaky")) {
      res.writeHead(502, { "content-type": "text/html" }).end("<html><body>502 Bad Gateway nginx /internal/stack trace</body></html>");
      return;
    }
    s ? send(res, 200, s) : notFound(res, "scan");
  }],
  ["GET", /^\/api\/findings$/, (_m, q, _b, res) => {
    const inList = (key: string, v: string) => !q.get(key) || q.get(key)!.split(",").includes(v);
    const SEV: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const closed = (f: any) => (f.status === "fixed" || f.status === "not_reproduced" ? 1 : 0);
    const out = findings
      .filter((f) => inList("scan_id", f.scan_id) && inList("asset_id", f.asset_id) && inList("severity", f.severity) && inList("status", f.status))
      .sort((a, b) => closed(a) - closed(b) || SEV[a.severity] - SEV[b.severity] || b.confidence - a.confidence);
    const limit = Number(q.get("limit") ?? 0);
    lastFindingsQuery = Object.fromEntries(q.entries());
    send(res, 200, limit > 0 ? out.slice(0, limit) : out);
  }],
  ["GET", /^\/api\/_mock\/last-findings-query$/, (_m, _q, _b, res) => send(res, 200, lastFindingsQuery)],
  ["GET", /^\/api\/findings\/([^/]+)$/, (m, _q, _b, res) => {
    const f = findings.find((x) => x.id === m[1]);
    f ? send(res, 200, f) : notFound(res, "finding");
  }],
  ["POST", /^\/api\/findings\/([^/]+)\/explain$/, (m, _q, _b, res) => {
    const f = findings.find((x) => x.id === m[1]);
    if (!f) return notFound(res, "finding");
    f.ai_summary ??= `${f.title}: ${f.description}`;
    emit("ai.summary", `Explained ${f.title}`, { finding_id: f.id });
    send(res, 200, {
      summary: f.ai_summary,
      root_cause: f.category === "sast" ? "Untrusted input reaches a sensitive sink without parameterization or encoding." : f.category === "dependency" ? "A pinned dependency version has a published vulnerability." : "Insecure configuration or committed credential.",
      exploitability: f.severity === "critical" ? "High: reachable unauthenticated over HTTP with a single request." : "Moderate: requires specific conditions.",
      fix_plan: f.fixed_version ? `Upgrade ${f.package} to ${f.fixed_version}.` : "Use parameterized queries / output encoding / environment configuration as appropriate.",
    });
  }],
  ["POST", /^\/api\/findings\/([^/]+)\/validate$/, (m, _q, _b, res) => {
    const f = findings.find((x) => x.id === m[1]);
    if (!f) return notFound(res, "finding");
    const supported = f.cwe === "CWE-89" || f.cwe === "CWE-79";
    const v = {
      id: sid("val"), finding_id: f.id, check: f.cwe === "CWE-89" ? "cwe-89-sqli" : f.cwe === "CWE-79" ? "cwe-79-xss" : "none",
      result: supported ? "confirmed" : "unsupported", confidence: supported ? 0.97 : 0,
      evidence: supported ? [
        { kind: "note", label: "Target", content: "PyGoat SQL injection lab in tirith-lab (internal network, seeded dummy data)" },
        { kind: "request", label: "Boolean probe (true)", content: "POST /lab HTTP/1.1\nHost: pygoat.lab:5012\n\nusername=admin%27--&password=x" },
        { kind: "response", label: "Response (true)", content: "HTTP/1.1 200 OK\n... Welcome admin (login bypassed)" },
        { kind: "request", label: "Boolean probe (false)", content: "POST /lab HTTP/1.1\nHost: pygoat.lab:5012\n\nusername=admin%27%20AND%20%271%27%3D%272&password=x" },
        { kind: "response", label: "Response (false)", content: "HTTP/1.1 200 OK\n... Invalid username or password" },
        { kind: "log", label: "Verdict", content: "Responses differ between true/false predicates: injectable." },
      ] : [{ kind: "note", label: "Unsupported", content: `No fixed validation template for ${f.cwe ?? f.category}.` }],
      started_at: now(), finished_at: now(),
    };
    validations.push(v);
    f.validation = v;
    if (supported) f.status = "validated";
    emit("validation.result", `${v.check}: ${v.result}`, { finding_id: f.id }, supported ? "warn" : "info");
    send(res, 200, v);
  }],
  ["POST", /^\/api\/findings\/([^/]+)\/fix$/, (m, _q, b, res) => {
    const f = findings.find((x) => x.id === m[1]);
    if (!f) return notFound(res, "finding");
    const mode = b.mode ?? modeCfg.mode;
    const diff = f.cwe === "CWE-89"
      ? `--- a/dockerized_labs/sql_injection_lab/app.py\n+++ b/dockerized_labs/sql_injection_lab/app.py\n@@ -50,10 +50,7 @@ def lab():\n-        sql_query = (\n-            f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"\n-        )\n+        sql_query = "SELECT * FROM users WHERE username=? AND password=?"\n \n         try:\n             conn = sqlite3.connect("database.db")\n             c = conn.cursor()\n-            result = c.execute(sql_query).fetchone()\n+            result = c.execute(sql_query, (username, password)).fetchone()\n`
      : f.package ? `--- a/requirements.txt\n+++ b/requirements.txt\n@@ -${f.line ?? 1} +${f.line ?? 1} @@\n-${f.package}==${f.installed_version}\n+${f.package}==${f.fixed_version}\n` : `# manual remediation required for ${f.title}\n`;
    const fix: any = {
      id: sid("fix"), finding_id: f.id, mode, status: "proposed", diff, branch: null, pr_url: null,
      verification: { tests_passed: null, validation_result: null, details: null }, created_at: now(),
    };
    fixes.push(fix);
    f.fix_id = fix.id;
    emit("fix.started", `Fixing ${f.title}`, { finding_id: f.id, fix_id: fix.id });
    if (mode !== "observe") {
      f.status = "fixing";
      setTimeout(() => {
        fix.branch = `tirith/fix-${f.id}`;
        fix.pr_url = `https://github.com/sapoepsilon/tirith-demo-target/pull/${fixes.length}`;
        fix.status = "pr_opened";
        emit("fix.pr_opened", `PR opened: ${fix.pr_url}`, { fix_id: fix.id }, "success");
        setTimeout(() => {
          fix.status = "verified";
          fix.verification = { tests_passed: null, validation_result: "fixed", details: "(a) rescan of changed files: finding gone. (b) patched app boots in the lab." };
          emit("fix.verified", "Fix verified", { fix_id: fix.id }, "success");
        }, FIX_MS);
      }, FIX_MS);
    }
    send(res, 200, fix);
  }],
  ["GET", /^\/api\/fixes\/([^/]+)$/, (m, _q, _b, res) => {
    const x = fixes.find((y) => y.id === m[1]);
    x ? send(res, 200, x) : notFound(res, "fix");
  }],
  ["POST", /^\/api\/fixes\/([^/]+)\/apply$/, (m, _q, _b, res) => {
    const x = fixes.find((y) => y.id === m[1]);
    if (!x) return notFound(res, "fix");
    x.status = "applied";
    const f = findings.find((y) => y.id === x.finding_id);
    if (f) f.status = "fixed";
    emit("fix.applied", "Fix applied", { fix_id: x.id }, "success");
    recordPosture();
    send(res, 200, x);
  }],
  ["POST", /^\/api\/fixes\/([^/]+)\/rollback$/, (m, _q, _b, res) => {
    const x = fixes.find((y) => y.id === m[1]);
    if (!x) return notFound(res, "fix");
    x.status = "rolled_back";
    const f = findings.find((y) => y.id === x.finding_id);
    if (f) f.status = "open";
    emit("fix.rolled_back", "Fix rolled back", { fix_id: x.id }, "warn");
    recordPosture();
    send(res, 200, x);
  }],
  ["GET", /^\/api\/posture$/, (_m, q, _b, res) => send(res, 200, posture(q.get("asset_id") ?? undefined))],
  ["GET", /^\/api\/mode$/, (_m, _q, _b, res) => send(res, 200, modeCfg)],
  ["PUT", /^\/api\/mode$/, (_m, _q, b, res) => {
    if (!["observe", "assisted", "autonomous"].includes(b.mode)) return send(res, 422, { detail: "invalid mode" });
    modeCfg = { mode: b.mode, autonomous_categories: b.autonomous_categories ?? modeCfg.autonomous_categories };
    emit("mode.changed", `Mode set to ${b.mode}`);
    send(res, 200, modeCfg);
  }],
  ["GET", /^\/api\/audit$/, (_m, q, _b, res) => send(res, 200, audit.slice(-Number(q.get("limit") ?? 50)))],
  ["GET", /^\/api\/events\/recent$/, (_m, q, _b, res) => send(res, 200, events.slice(-Number(q.get("limit") ?? 50)))],
];

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  if (API_TOKEN && req.headers.authorization !== `Bearer ${API_TOKEN}`) return send(res, 401, { detail: "missing or invalid bearer token" });
  try {
    const body = req.method === "POST" || req.method === "PUT" ? await readBody(req) : {};
    for (const [method, re, fn] of routes) {
      const m = req.method === method ? url.pathname.match(re) : null;
      if (m) return fn(m, url.searchParams, body, res);
    }
    send(res, 404, { detail: "route not found" });
  } catch (e) {
    send(res, 400, { detail: (e as Error).message });
  }
}).listen(PORT, () => console.log(`Tirith mock backend on http://localhost:${PORT}/api (scan ${SCAN_MS}ms, auth ${API_TOKEN ? "on" : "off"})`));
