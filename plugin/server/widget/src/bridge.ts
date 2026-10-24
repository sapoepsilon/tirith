// Minimal MCP Apps host bridge (JSON-RPC 2.0 over postMessage), per the MCP Apps spec / OpenAI docs.
// Hand-rolled instead of bundling @modelcontextprotocol/ext-apps' App class to keep the widget small
// (the App class pulls in zod, ~450 KiB minified).

const PROTOCOL_VERSION = "2026-01-26";

type Json = Record<string, unknown>;
export interface ToolResult {
  structuredContent?: unknown;
  content?: { type: string; text?: string }[];
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

let nextId = 1;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();
const resultListeners = new Set<(r: ToolResult) => void>();

function post(msg: Json) {
  window.parent.postMessage({ jsonrpc: "2.0", ...msg }, "*");
}

function request<T = unknown>(method: string, params: Json = {}, timeoutMs = 60_000): Promise<T> {
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`${method} timed out`));
    }, timeoutMs);
    pending.set(id, {
      resolve: (v) => {
        clearTimeout(t);
        resolve(v as T);
      },
      reject: (e) => {
        clearTimeout(t);
        reject(e);
      },
    });
    post({ id, method, params });
  });
}

function notify(method: string, params: Json = {}) {
  post({ method, params });
}

window.addEventListener(
  "message",
  (event) => {
    if (event.source !== window.parent) return;
    const m = event.data as Json | null;
    if (!m || m.jsonrpc !== "2.0") return;
    if ((typeof m.id === "number" || typeof m.id === "string") && !m.method) {
      const p = pending.get(m.id as number);
      if (!p) return;
      pending.delete(m.id as number);
      if (m.error) p.reject(m.error);
      else p.resolve(m.result);
      return;
    }
    if (m.method === "ui/notifications/tool-result") {
      resultListeners.forEach((fn) => fn((m.params ?? {}) as ToolResult));
      return;
    }
    if (typeof m.id === "number" && typeof m.method === "string") {
      // Host -> view request we don't implement (e.g. ui/resource-teardown): acknowledge.
      post({ id: m.id, result: {} });
    }
  },
  { passive: true },
);

let ready: Promise<void> | null = null;

export const bridge = {
  connect(): Promise<void> {
    ready ??= request("ui/initialize", {
      appInfo: { name: "tirith-console", version: "1.0.0" },
      appCapabilities: {},
      protocolVersion: PROTOCOL_VERSION,
    }).then(() => {
      notify("ui/notifications/initialized", {});
      startAutoResize();
    });
    return ready;
  },
  onToolResult(fn: (r: ToolResult) => void) {
    resultListeners.add(fn);
    return () => resultListeners.delete(fn);
  },
  async callTool(name: string, args: Json): Promise<ToolResult> {
    await ready;
    return request<ToolResult>("tools/call", { name, arguments: args }, 120_000);
  },
  async sendMessage(text: string) {
    await ready;
    return request("ui/message", { role: "user", content: [{ type: "text", text }] });
  },
  async openLink(url: string) {
    await ready;
    return request("ui/open-link", { url });
  },
};

function startAutoResize() {
  let last = 0;
  const send = () => {
    const h = Math.ceil(document.documentElement.getBoundingClientRect().height);
    if (h !== last) {
      last = h;
      notify("ui/notifications/size-changed", { height: h });
    }
  };
  new ResizeObserver(send).observe(document.documentElement);
  send();
}
