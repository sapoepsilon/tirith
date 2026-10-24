// Deployment config shared by the HTTP server and the widget resource.

/** Secret path segment: MCP is served at /mcp/<secret> when set (plain /mcp then 404s). */
export const MCP_PATH_SECRET = process.env.TIRITH_MCP_PATH_SECRET?.trim() || undefined;
export const MCP_PATH = MCP_PATH_SECRET ? `/mcp/${encodeURIComponent(MCP_PATH_SECRET)}` : "/mcp";

/** Public origin (https://host) derived from TIRITH_MCP_PUBLIC_URL, e.g. https://tirith.example.com/mcp/<secret>. */
export const PUBLIC_ORIGIN: string | undefined = (() => {
  const raw = process.env.TIRITH_MCP_PUBLIC_URL?.trim();
  if (!raw) return undefined;
  try {
    return new URL(raw).origin;
  } catch {
    console.warn("TIRITH_MCP_PUBLIC_URL is not a valid URL; ignoring it.");
    return undefined;
  }
})();
