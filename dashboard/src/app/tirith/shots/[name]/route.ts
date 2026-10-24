import fs from "node:fs";
import path from "node:path";
import { EVIDENCE_DIR } from "@/lib/evidence";

/**
 * Serves a captured screenshot to the dashboard. The PNG lives in the backend's evidence volume
 * (mounted read-only into the dashboard at TIRITH_EVIDENCE_DIR); the backend only exposes its path.
 * Only a bare, generated file name is accepted, so this cannot read outside the shots directory.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ name: string }> };

const NAME = /^[A-Za-z0-9._-]{1,180}\.png$/;

export async function GET(_req: Request, { params }: Ctx): Promise<Response> {
  const { name } = await params;
  if (!NAME.test(name) || name.includes("..")) {
    return Response.json({ detail: "bad shot name" }, { status: 400 });
  }
  const file = path.join(EVIDENCE_DIR, "shots", name);
  if (!fs.existsSync(file)) {
    return Response.json({ detail: "shot not found" }, { status: 404 });
  }
  const body = fs.readFileSync(file);
  return new Response(new Uint8Array(body), {
    headers: {
      "content-type": "image/png",
      "cache-control": "private, max-age=3600",
      "content-security-policy": "default-src 'none'",
    },
  });
}