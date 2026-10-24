import { backendAuthHeaders, backendWsUrl } from "@/lib/server-config";

/**
 * Live events as Server-Sent Events. The server opens the backend WebSocket (bearer token attached here) and
 * relays each JSON message as an SSE `data:` frame, so the browser only ever talks same-origin HTTP(S):
 * no ws:// mixed content behind TLS tunnels, no token in the browser.
 *
 * ?replay=N (0..500) asks the backend to resend the last N events first; the client dedupes.
 * Frames: `event: ready` once the backend socket is open, default `message` events, `: ping` heartbeats.
 * When the backend socket closes the stream ends and EventSource reconnects after `retry` ms.
 */
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const HEARTBEAT_MS = 15_000;

export async function GET(req: Request): Promise<Response> {
  const n = Number(new URL(req.url).searchParams.get("replay") ?? "0");
  const replay = Number.isFinite(n) ? Math.max(0, Math.min(500, Math.floor(n))) : 0;
  const enc = new TextEncoder();

  let cleanup = () => {};
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let closed = false;
      const send = (s: string) => {
        if (closed) return;
        try {
          controller.enqueue(enc.encode(s));
        } catch {
          close();
        }
      };
      let ws: WebSocket | null = null;
      const hb = setInterval(() => send(": ping\n\n"), HEARTBEAT_MS);
      const close = () => {
        if (closed) return;
        closed = true;
        clearInterval(hb);
        try {
          ws?.close();
        } catch {
          /* already closed */
        }
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      cleanup = close;
      req.signal.addEventListener("abort", close);

      send("retry: 2000\n\n");
      try {
        // Node's WebSocket (undici) accepts extra handshake headers.
        ws = new WebSocket(backendWsUrl(`/api/ws/events${replay ? `?replay=${replay}` : ""}`), {
          headers: backendAuthHeaders(),
        } as unknown as string[]);
      } catch {
        send("event: unavailable\ndata: {}\n\n");
        close();
        return;
      }
      ws.onopen = () => send("event: ready\ndata: {}\n\n");
      ws.onmessage = (m) => {
        if (typeof m.data !== "string") return;
        // One SSE data line per message: JSON never contains raw newlines after re-serialising.
        try {
          send(`data: ${JSON.stringify(JSON.parse(m.data))}\n\n`);
        } catch {
          /* ignore non-JSON frames */
        }
      };
      ws.onerror = () => {
        send("event: unavailable\ndata: {}\n\n");
        close();
      };
      ws.onclose = () => close();
    },
    cancel() {
      cleanup();
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
