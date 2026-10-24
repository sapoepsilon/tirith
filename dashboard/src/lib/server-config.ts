/**
 * Server-only settings. Never import this from a client component: TIRITH_API_TOKEN must not reach the browser.
 * Read lazily (per request) so `next start` picks up runtime env, not build-time values.
 */

export function backendUrl(): string {
  const raw = process.env.TIRITH_BACKEND_INTERNAL_URL || "http://localhost:8000";
  return raw.replace(/\/+$/, "");
}

export function backendWsUrl(path: string): string {
  return backendUrl().replace(/^http/, "ws") + path;
}

/** Headers added to every backend call. Empty when no token is configured (backend in open/dev mode). */
export function backendAuthHeaders(): Record<string, string> {
  const token = process.env.TIRITH_API_TOKEN;
  return token ? { authorization: `Bearer ${token}` } : {};
}

/** Long-running LLM / lab calls: explain, validate, fix. */
export const LONG_CALL = /^findings\/[^/]+\/(explain|validate|fix)$/;
export const LONG_TIMEOUT_MS = 620_000;
export const SHORT_TIMEOUT_MS = 15_000;
