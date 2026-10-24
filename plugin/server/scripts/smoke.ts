// End-to-end smoke test: MCP SDK client -> Tirith MCP server -> backend (mock or real).
// Usage: MCP_URL=http://localhost:8787/mcp/<secret> BACKEND_URL=http://localhost:8000 TIRITH_API_TOKEN=<token> npx tsx scripts/smoke.ts
// (mock backend: npm run mock with the same TIRITH_API_TOKEN; MCP server: npm start with TIRITH_MCP_PATH_SECRET=<secret>)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const MCP_URL = process.env.MCP_URL ?? "http://localhost:8787/mcp";
const BACKEND_URL = (process.env.BACKEND_URL ?? process.env.TIRITH_BACKEND_URL ?? "http://localhost:8000").replace(/\/+$/, "");
const TOKEN = process.env.TIRITH_API_TOKEN;
const ORIGIN = new URL(MCP_URL).origin;
let failures = 0;
const check = (cond: unknown, msg: string) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`);
  if (!cond) failures++;
};
const text = (r: any) => (r.content?.[0]?.text ?? "") as string;

// --- public routes, secret path, backend auth ---
for (const p of ["/health", "/privacy", "/terms", "/support"]) {
  const r = await fetch(`${ORIGIN}${p}`);
  check(r.status === 200, `GET ${p} -> ${r.status}`);
}
const health = await (await fetch(`${ORIGIN}/health`)).text();
check(!/mcp\//.test(health), `health does not reveal the MCP path: ${health}`);
if (new URL(MCP_URL).pathname !== "/mcp") {
  const plain = await fetch(`${ORIGIN}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
  check(plain.status === 404, `plain /mcp is 404 when a path secret is set (got ${plain.status})`);
}
const noAuth = await fetch(`${BACKEND_URL}/api/assets`);
check(!TOKEN || noAuth.status === 401, `backend without bearer -> ${noAuth.status}`);
const bauth = (p: string) => fetch(`${BACKEND_URL}${p}`, { headers: TOKEN ? { authorization: `Bearer ${TOKEN}` } : {} }).then((r) => r.json());

const client = new Client({ name: "tirith-smoke", version: "0.0.1" });
await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL)));

// --- tools + annotations ---
const { tools } = await client.listTools();
console.log(`tools (${tools.length}): ${tools.map((t) => t.name).join(", ")}`);
const expected = [
  "tirith_list_assets", "tirith_add_asset", "tirith_start_scan", "tirith_scan_status", "tirith_list_findings",
  "tirith_get_finding", "tirith_explain_finding", "tirith_validate_finding", "tirith_fix_finding", "tirith_apply_fix",
  "tirith_rollback_fix", "tirith_get_posture", "tirith_get_mode",
];
for (const n of expected) check(tools.some((t) => t.name === n), `tool ${n} listed`);

const tool = (n: string) => tools.find((t) => t.name === n)!;
check(tool("tirith_fix_finding").annotations?.destructiveHint === true, "fix_finding destructiveHint true");
check(!("mode" in ((tool("tirith_fix_finding").inputSchema as any).properties ?? {})), "fix_finding has no mode override");
check(/403|refused/i.test(tool("tirith_fix_finding").description ?? ""), "fix_finding description: observe mode refused");
check(tool("tirith_add_asset").annotations?.destructiveHint === true, "add_asset destructiveHint true (profile overwrite)");
const exA = tool("tirith_explain_finding").annotations ?? {};
check(exA.readOnlyHint === false && exA.idempotentHint === false, "explain_finding readOnly false, idempotent false");
check(tool("tirith_get_mode").annotations?.readOnlyHint === true, "get_mode read-only");
check(tool("tirith_set_mode").annotations?.readOnlyHint === false, "set_mode is a write tool");
for (const n of ["tirith_start_analysis", "tirith_get_analysis", "tirith_pause_analysis", "tirith_resume_analysis", "tirith_render_report"]) {
  check(tools.some((t) => t.name === n), `analyst tool ${n} listed`);
}
check("apply" in ((tool("tirith_fix_finding").inputSchema as any).properties ?? {}), "fix_finding can apply");
for (const t of tools) {
  const a = t.annotations ?? {};
  check(
    typeof a.readOnlyHint === "boolean" && typeof a.destructiveHint === "boolean" && typeof a.openWorldHint === "boolean",
    `${t.name} annotations ro=${a.readOnlyHint} destr=${a.destructiveHint} open=${a.openWorldHint}`,
  );
}
const widgetTools = tools.filter((t) => (t._meta as any)?.ui?.resourceUri);
console.log(`widget-linked tools: ${widgetTools.map((t) => `${t.name} -> ${(t._meta as any).ui.resourceUri}`).join(", ")}`);
check(
  widgetTools.length === 2 && widgetTools.every((t) => ["tirith_get_finding", "tirith_get_posture"].includes(t.name)),
  "only render tools (get_finding, get_posture) link the widget",
);
check(widgetTools.every((t) => (t._meta as any)["openai/outputTemplate"] === (t._meta as any).ui.resourceUri), "openai/outputTemplate alias matches");

// --- widget resource ---
const { resources } = await client.listResources();
console.log(`resources: ${resources.map((r) => `${r.uri} (${r.mimeType})`).join(", ")}`);
const uri = (widgetTools[0]?._meta as any)?.ui?.resourceUri;
const rr = await client.readResource({ uri });
const c0: any = rr.contents[0];
check(c0.mimeType === "text/html;profile=mcp-app", `widget mime ${c0.mimeType}`);
check(typeof c0.text === "string" && c0.text.includes('<div id="root">') && c0.text.length > 10_000, `widget html ${c0.text?.length} bytes`);
check(Array.isArray(c0._meta?.ui?.csp?.connectDomains), `widget csp ${JSON.stringify(c0._meta?.ui?.csp)}`);

// --- flow ---
const la = await client.callTool({ name: "tirith_list_assets", arguments: {} });
console.log(text(la));
const assetId = (la.structuredContent as any).assets[0].id;
check(!JSON.stringify(la).includes("/srv/private"), "local_path asset does not expose the absolute server path");
check((la.structuredContent as any).assets.some((a: any) => a.ref === "local:pygoat-local"), "local_path shown as local:<basename>");

const added = await client.callTool({ name: "tirith_add_asset", arguments: { kind: "url", ref: "http://pygoat.lab:8000", name: "pygoat (lab)" } });
check(!added.isError, `add_asset: ${text(added)}`);
const denied = await client.callTool({ name: "tirith_add_asset", arguments: { kind: "github_repo", ref: "someone/forbidden-repo" } });
check(denied.isError && /scope/i.test(text(denied)), `out-of-scope asset rejected: ${text(denied)}`);

const t0 = Date.now();
const scan = await client.callTool({ name: "tirith_start_scan", arguments: { asset_id: assetId } }, undefined, { timeout: 90_000 });
console.log(`start_scan (${((Date.now() - t0) / 1000).toFixed(1)}s):\n${text(scan)}`);
const sc: any = scan.structuredContent;
check(sc?.view === "posture" && sc.scan?.status === "done", "start_scan returns posture view after completion");
check(text(scan).includes("<untrusted-data"), "start_scan frames finding titles as untrusted data");
check(!JSON.stringify(sc).includes("fingerprint") && !JSON.stringify(sc).includes("started_at"), "no fingerprints/timestamps in scan result");

const st = await client.callTool({ name: "tirith_scan_status", arguments: { scan_id: sc.scan.id } });
check(/done/.test(text(st)), `scan_status: ${text(st)}`);

const lf = await client.callTool({ name: "tirith_list_findings", arguments: { asset_id: assetId, limit: 3, status: "open" } });
console.log(text(lf));
const top = (lf.structuredContent as any).findings[0];
check(top?.severity === "critical", "list_findings sorted most severe first");
const lq = await bauth("/api/_mock/last-findings-query");
check(lq.limit === "4" && lq.status === "open" && lq.asset_id === assetId, `limit/status filters passed to backend: ${JSON.stringify(lq)}`);
check((lf.structuredContent as any).has_more === true && (lf.structuredContent as any).findings.length === 3, "list_findings reports has_more");
check(/<untrusted-data[\s\S]*<\/untrusted-data>/.test(text(lf)), "list_findings frames repository text as untrusted");

const gf = await client.callTool({ name: "tirith_get_finding", arguments: { finding_id: top.id } });
check((gf.structuredContent as any)?.view === "finding", `get_finding view: ${text(gf).split("\n")[0]}`);
check(text(gf).includes("<untrusted-data") && !!(gf.structuredContent as any)?.note, "get_finding frames description as untrusted");

const ex = await client.callTool({ name: "tirith_explain_finding", arguments: { finding_id: top.id } });
check(/Root cause/.test(text(ex)), "explain_finding returns root cause");

const va = await client.callTool({ name: "tirith_validate_finding", arguments: { finding_id: top.id } });
console.log(text(va));
check((va.structuredContent as any)?.validation?.result === "confirmed", "validate_finding confirmed");
check(((va.structuredContent as any)?.validation?.evidence?.length ?? 99) <= 8, "validation evidence capped at 8");

const fx = await client.callTool({ name: "tirith_fix_finding", arguments: { finding_id: top.id } }, undefined, { timeout: 90_000 });
console.log(text(fx));
const fix: any = (fx.structuredContent as any)?.fix;
check(fix?.pr_url?.startsWith("https://github.com/"), `fix_finding opened PR ${fix?.pr_url}`);
check(!text(fx).includes("+++ ") && !JSON.stringify(fx.structuredContent).includes("+++ "), "diff not in model-visible output");
check(typeof (fx._meta as any)?.["tirith/diff"] === "string", "diff delivered in widget-only _meta");
const gf2 = await client.callTool({ name: "tirith_get_finding", arguments: { finding_id: top.id } });
check(typeof (gf2._meta as any)?.["tirith/diff"] === "string" && !text(gf2).includes("+++ "), "get_finding: diff only in _meta");

const gx = await client.callTool({ name: "tirith_get_fix", arguments: { fix_id: fix.id } });
check(!gx.isError, `get_fix: ${text(gx).split("\n")[0]}`);

const ap = await client.callTool({ name: "tirith_apply_fix", arguments: { fix_id: fix.id } });
check(/applied/.test(text(ap)), `apply_fix: ${text(ap).split("\n")[0]}`);
const rb = await client.callTool({ name: "tirith_rollback_fix", arguments: { fix_id: fix.id } });
check(/rolled_back/.test(text(rb)), `rollback_fix: ${text(rb).split("\n")[0]}`);

const gp = await client.callTool({ name: "tirith_get_posture", arguments: { asset_id: assetId } });
console.log(text(gp));
const gpc: any = gp.structuredContent;
check(gpc?.view === "posture" && typeof gpc.posture.score === "number" && gpc.top_findings.length > 0, "get_posture view");

const gm = await client.callTool({ name: "tirith_get_mode", arguments: {} });
check(/assisted/.test(text(gm)), `get_mode: ${text(gm)}`);

// Transient backend error during scan polling: the scan id must survive; raw HTML error bodies never relayed.
const flaky = await client.callTool({ name: "tirith_add_asset", arguments: { kind: "github_repo", ref: "sapoepsilon/flaky-repo" } });
const flakyId = (flaky.structuredContent as any)?.asset?.id;
const fs = await client.callTool({ name: "tirith_start_scan", arguments: { asset_id: flakyId } }, undefined, { timeout: 90_000 });
const fsId = (fs.structuredContent as any)?.scan?.id;
check(!fs.isError && fsId && text(fs).includes(fsId) && /still running/.test(text(fs)), `flaky poll keeps scan id: ${text(fs)}`);
const fst = await client.callTool({ name: "tirith_scan_status", arguments: { scan_id: fsId } });
check(fst.isError === true && !/nginx|<html|stack/i.test(text(fst)), `non-JSON error body not relayed: ${text(fst)}`);

const nf = await client.callTool({ name: "tirith_get_finding", arguments: { finding_id: "nope" } });
check(nf.isError === true, `missing finding -> isError: ${text(nf)}`);

await client.close();
console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
