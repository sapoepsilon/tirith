/** Client-visible settings only. Backend URL and token are server-only (see server-config.ts). */
export const FORCE_MOCK = process.env.NEXT_PUBLIC_TIRITH_MOCK === "1";

/** Same-origin endpoints served by the Next.js route handlers. */
export const API_BASE = "/tirith/api";
export const EVENTS_URL = "/tirith/events";

/** explain / validate / fix wait on the LLM and the lab; the proxy allows 620 s, the browser a bit more. */
export const LONG_TIMEOUT_MS = 625_000;
export const SHORT_TIMEOUT_MS = 15_000;
