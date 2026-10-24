import http from "node:http";
import https from "node:https";
import { LONG_CALL, LONG_TIMEOUT_MS, SHORT_TIMEOUT_MS, backendAuthHeaders, backendUrl } from "@/lib/server-config";

/**
 * Same-origin REST proxy: /tirith/api/<path> -> <TIRITH_BACKEND_INTERNAL_URL>/api/<path>.
 * The bearer token is added here, server side; the browser's own Authorization (dashboard basic auth) and
 * cookies are never forwarded. node:http instead of fetch so long calls are not cut by undici's 300 s
 * headers timeout.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const FORWARD_REQ = ["content-type", "accept"];
const FORWARD_RES = ["content-type", "cache-control"];

type Ctx = { params: Promise<{ path: string[] }> };

function json(status: number, detail: string) {
  return Response.json({ detail }, { status, headers: { "cache-control": "no-store" } });
}

async function proxy(req: Request, { params }: Ctx): Promise<Response> {
  const { path } = await params;
  if (!path?.length || path.some((s) => !s || s === "." || s === ".." || s.includes("/") || s.includes("\\"))) {
    return json(400, "bad path");
  }
  const rel = path.map(encodeURIComponent).join("/");
  const target = new URL(`${backendUrl()}/api/${rel}${new URL(req.url).search}`);
  const timeoutMs = LONG_CALL.test(path.join("/")) ? LONG_TIMEOUT_MS : SHORT_TIMEOUT_MS;

  const headers: Record<string, string> = { ...backendAuthHeaders() };
  for (const h of FORWARD_REQ) {
    const v = req.headers.get(h);
    if (v) headers[h] = v;
  }
  const body = req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.from(await req.arrayBuffer());
  if (body) headers["content-length"] = String(body.length);

  const lib = target.protocol === "https:" ? https : http;
  return new Promise<Response>((resolve) => {
    let done = false;
    const finish = (r: Response) => {
      if (!done) {
        done = true;
        resolve(r);
      }
    };
    const out = lib.request(target, { method: req.method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const h = new Headers({ "cache-control": "no-store" });
        for (const k of FORWARD_RES) {
          const v = res.headers[k];
          if (typeof v === "string") h.set(k, v);
        }
        const status = res.statusCode ?? 502;
        const nullBody = status === 204 || status === 304 || req.method === "HEAD";
        finish(new Response(nullBody ? null : Buffer.concat(chunks), { status, headers: h }));
      });
      res.on("error", () => finish(json(502, "backend response aborted")));
    });
    out.setTimeout(timeoutMs, () => {
      out.destroy();
      finish(json(504, `backend did not answer within ${Math.round(timeoutMs / 1000)}s`));
    });
    out.on("error", (e) => finish(json(502, `backend unreachable: ${(e as NodeJS.ErrnoException).code ?? e.message}`)));
    // Browser went away: stop waiting on the backend.
    req.signal.addEventListener("abort", () => out.destroy());
    out.end(body);
  });
}

export { proxy as GET, proxy as POST, proxy as PUT, proxy as PATCH, proxy as DELETE };
