import fs from "node:fs";
import path from "node:path";
import { EVIDENCE_DIR } from "@/lib/evidence";

/**
 * Serves a rendered HTML report (and the screenshots it references) for an analyst run.
 * Files live in the backend's evidence volume under `reports/<run-id>/`, mounted read-only here.
 * Only `as-found.html`, `as-fixed.html` and `shots/<generated>.png` are reachable.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ path: string[] }> };

const RUN = /^arn_[A-Za-z0-9]{6,40}$/;
const PAGE = /^(as-found|as-fixed)\.html$/;
const SHOT = /^[A-Za-z0-9._-]{1,180}\.png$/;

export async function GET(_req: Request, { params }: Ctx): Promise<Response> {
  const seg = (await params).path ?? [];
  if (seg.length < 2 || seg.length > 3 || seg.some((s) => s.includes(".."))) {
    return Response.json({ detail: "bad path" }, { status: 400 });
  }
  const [runId] = seg;
  if (!RUN.test(runId)) return Response.json({ detail: "bad run id" }, { status: 400 });
  const base = path.join(EVIDENCE_DIR, "reports", runId);

  // /reports/<run>/as-found.html  or  /reports/<run>/shots/<name>.png
  const isPage = seg.length === 2 && PAGE.test(seg[1]);
  const isShot = seg.length === 3 && seg[1] === "shots" && SHOT.test(seg[2]);
  if (!isPage && !isShot) return Response.json({ detail: "not found" }, { status: 404 });

  const file = isPage ? path.join(base, seg[1]) : path.join(base, "shots", seg[2]);
  const type = isPage ? "text/html; charset=utf-8" : "image/png";

  if (!fs.existsSync(file)) return Response.json({ detail: "not found" }, { status: 404 });
  const raw = fs.readFileSync(file);
  const body = isPage ? Buffer.from(maskSecretValues(raw.toString("utf8"))) : raw;
  return new Response(new Uint8Array(body), {
    headers: {
      "content-type": type,
      "cache-control": "private, max-age=60",
      // The page carries its own inline <style> and its screenshots are siblings under the same origin.
      // `img-src 'self'` alone did not resolve them (they arrive as basic-auth subresources), so name the
      // host explicitly and keep everything else shut.
      "content-security-policy": isPage
        ? "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'"
        : "default-src 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

/**
 * The report renders reproduction steps verbatim, and those can carry a credential (a login body, an
 * API token in a query string). This is the last place before the page reaches a browser, so find the
 * runs' own audit log (same evidence volume) and knock any live secret value out of the rendered text.
 * Absent audit files simply mean nothing is masked.
 */
const SECRET_KEY = /token|secret|passw|apikey|api_key|authorization|license/i;
const AUDIT_KEYS = new Set([...["token", "secret", "password", "passwd", "apikey", "api_key", "authorization", "license"]]);

function maskSecretValues(html: string): string {
  const found = new Set<string>();
  let runs: string[] = [];
  try {
    runs = fs.readdirSync(EVIDENCE_DIR).filter((f) => f.startsWith("audit"));
  } catch {
    /* no volume */
  }
  for (const name of runs.slice(0, 20)) {
    let text = "";
    try {
      text = fs.readFileSync(path.join(EVIDENCE_DIR, name), "utf8");
    } catch {
      continue;
    }
    for (const raw of text.split(/\n|,(?=\s*")/)) {
      const m = /"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"\s]{8,})"/g;
      for (let hit = m.exec(raw); hit; hit = m.exec(raw)) {
        const [, key, value] = hit;
        if (AUDIT_KEYS.has(key.toLowerCase()) || SECRET_KEY.test(key)) found.add(value);
      }
    }
  }
  if (!found.size) return html;
  let out = html;
  for (const value of [...found].sort((a, b) => b.length - a.length).slice(0, 200)) {
    if (/^[A-Za-z0-9._~-]+$/.test(value)) out = out.split(value).join("***");
  }
  return out;
}