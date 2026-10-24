import { createHash, timingSafeEqual } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";

/**
 * HTTP basic auth for the whole dashboard (pages, REST proxy, SSE).
 * TIRITH_DASH_USER / TIRITH_DASH_PASSWORD; when either is unset the dashboard is open (single-operator installs
 * behind a tunnel). Set both to put it behind a prompt again; clearing either turns the prompt off.
 */
export const config = {
  runtime: "nodejs",
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

const digest = (s: string) => createHash("sha256").update(s, "utf8").digest();

/** Constant-time: compares fixed-length digests, and always checks both fields. */
function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(digest(a), digest(b));
}

function challenge() {
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "www-authenticate": 'Basic realm="Tirith", charset="UTF-8"', "cache-control": "no-store" },
  });
}

export function middleware(req: NextRequest) {
  const user = process.env.TIRITH_DASH_USER;
  const pass = process.env.TIRITH_DASH_PASSWORD;
  if (!user || !pass) return NextResponse.next();
  const h = req.headers.get("authorization") ?? "";
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(h.trim());
  if (!m) return challenge();
  let decoded: string;
  try {
    decoded = Buffer.from(m[1], "base64").toString("utf8");
  } catch {
    return challenge();
  }
  const i = decoded.indexOf(":");
  if (i < 0) return challenge();
  const okUser = safeEqual(decoded.slice(0, i), user);
  const okPass = safeEqual(decoded.slice(i + 1), pass);
  return okUser && okPass ? NextResponse.next() : challenge();
}
