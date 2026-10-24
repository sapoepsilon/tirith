// Live end-to-end check: MCP SDK client -> Tirith MCP server -> REAL backend (not the mock).
// Flow: add_asset (local_path PyGoat) -> start_scan -> list_findings -> get_finding -> explain -> validate
//       -> fix (observe mode: must be refused 403 by policy) -> get_posture.
// Usage: MCP_URL=http://localhost:8790/mcp PYGOAT_PATH=/abs/path/targets/pygoat npx tsx scripts/smoke-live.ts
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const MCP_URL = process.env.MCP_URL ?? "http://localhost:8787/mcp";
const PYGOAT = process.env.PYGOAT_PATH ?? path.resolve(here, "../../../targets/pygoat");
const SCAN_TIMEOUT_MS = Number(process.env.SMOKE_SCAN_TIMEOUT_MS ?? 20 * 60_000);

let failures = 0;
const check = (cond: unknown, msg: string) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`);
  if (!cond) failures++;
};
const text = (r: any) => (r.content?.[0]?.text ?? "") as string;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const call = (name: string, args: Record<string, unknown>, timeout = 180_000) =>
  client.callTool({ name, arguments: args }, undefined, { timeout }) as Promise<any>;

const client = new Client({ name: "tirith-smoke-live", version: "0.0.1" });
await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL)));
const { tools } = await client.listTools();
check(tools.length >= 13, `MCP server lists ${tools.length} tools`);

// Policy: the mode is operator config (backend TIRITH mode). This script only runs the fix step in observe mode,
// where it must be refused, so it never opens a PR.
const gm = await call("tirith_get_mode", {});
const observe = /Remediation mode: observe/.test(text(gm));
console.log(`mode: ${text(gm)}${observe ? "" : " (fix step will be skipped; set the backend to observe to test the refusal)"}`);

// 1. add_asset (local path, in scope via scope.yaml local_paths)
const added = await call("tirith_add_asset", { kind: "local_path", ref: PYGOAT, name: "pygoat" });
check(!added.isError, `add_asset: ${text(added)}`);
const assetId: string = added.structuredContent?.asset?.id;
check(/^ast_/.test(assetId ?? ""), `asset id ${assetId}`);

// 2. start_scan (waits ~45 s in the tool, then we poll scan_status)
let t0 = Date.now();
const scan = await call("tirith_start_scan", { asset_id: assetId }, 120_000);
const scanId: string = scan.structuredContent?.scan?.id;
check(!scan.isError && /^scn_/.test(scanId ?? ""), `start_scan -> ${scanId}`);
let status = scan.structuredContent?.scan?.status as string;
while ((status === "queued" || status === "running") && Date.now() - t0 < SCAN_TIMEOUT_MS) {
  await sleep(5000);
  const st = await call("tirith_scan_status", { scan_id: scanId });
  status = st.structuredContent?.scan?.status;
  console.log(`  … ${text(st)}`);
}
check(status === "done", `scan ${scanId} finished: ${status} in ${((Date.now() - t0) / 1000).toFixed(0)}s`);

// 3. list_findings: grouped, prioritized, main app first
const lf = await call("tirith_list_findings", { asset_id: assetId, limit: 10 });
console.log(text(lf));
const rows: any[] = lf.structuredContent?.findings ?? [];
check(rows.length > 0, `findings returned ${rows.length} (has_more ${lf.structuredContent?.has_more})`);
const all = await call("tirith_list_findings", { asset_id: assetId, limit: 100 });
check(!all.structuredContent?.has_more || all.structuredContent.returned === 100, `grouped findings page: ${all.structuredContent?.returned}`);
check(rows.length > 0 && rows.every((f) => typeof f.priority === "number"), "every finding carries a priority");
check(rows.every((f, i) => i === 0 || rows[i - 1].priority >= f.priority), "sorted by priority desc");
check(rows.slice(0, 5).every((f) => !f.component), "top 5 are main-app findings (no lab sub-app on top)");
const deps = all.structuredContent.findings.filter(
  (f: any) => f.category === "dependency",
);
const keys = deps.map((f: any) => `${f.file}|${String(f.package).toLowerCase()}`);
check(new Set(keys).size === keys.length, `dependency findings unique per package+manifest (${deps.length})`);
check(deps.some((f: any) => (f.advisories ?? 0) > 1), "grouped dependency findings list several advisories");
const lab = await call("tirith_list_findings", { asset_id: assetId, component: "lab", limit: 3 });
check((lab.structuredContent?.returned ?? 0) > 0 && lab.structuredContent.findings.every((f: any) => f.component?.startsWith("lab:")),
  `lab sub-app findings still visible (${lab.structuredContent?.returned})`);

const top = rows[0];
const gf = await call("tirith_get_finding", { finding_id: top.id });
check(gf.structuredContent?.view === "finding", `get_finding: ${text(gf).split("\n")[0]}`);

// 4. explain (stub LLM provider on the backend)
t0 = Date.now();
const ex = await call("tirith_explain_finding", { finding_id: top.id });
check(!ex.isError && /Root cause/i.test(text(ex)), `explain_finding (${((Date.now() - t0) / 1000).toFixed(1)}s): ${text(ex).slice(0, 160)}`);

// 5. validate (dependency: advisory range + import reachability evidence)
t0 = Date.now();
const va = await call("tirith_validate_finding", { finding_id: top.id }, 600_000);
const vres = va.structuredContent?.validation?.result;
check(!va.isError && ["confirmed", "not_reproduced", "unsupported"].includes(vres), `validate_finding (${((Date.now() - t0) / 1000).toFixed(1)}s): ${vres}`);
console.log(text(va).slice(0, 800));

// 6. fix in observe mode -> refused by policy (403), nothing pushed
if (observe) {
  const fx = await call("tirith_fix_finding", { finding_id: top.id });
  check(fx.isError === true && /observe|policy|403|refus/i.test(text(fx)), `fix refused in observe mode: ${text(fx).slice(0, 200)}`);
}

// 7. posture
const gp = await call("tirith_get_posture", { asset_id: assetId });
console.log(text(gp));
const p = gp.structuredContent?.posture;
check(gp.structuredContent?.view === "posture" && typeof p?.score === "number" && p.score > 2, `posture ${p?.score}/${p?.grade}`);
check(typeof p?.lab_open === "number" && p.main_counts, `posture splits main app vs lab (lab_open ${p?.lab_open})`);

await client.close();
console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL LIVE CHECKS PASSED");
process.exit(failures ? 1 : 0);
