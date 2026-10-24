import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAppResource, RESOURCE_MIME_TYPE } from "@modelcontextprotocol/ext-apps/server";
import { PUBLIC_ORIGIN } from "./config.js";

// Bump the version suffix on breaking widget changes: hosts cache by URI.
export const WIDGET_URI = "ui://tirith/console-v1.html";

const here = dirname(fileURLToPath(import.meta.url));
const candidates = [resolve(here, "../dist/widget/tirith.html"), resolve(here, "../../dist/widget/tirith.html")];

let cached: string | null = null;
function widgetHtml(): string {
  if (cached && process.env.NODE_ENV === "production") return cached;
  const path = candidates.find((p) => existsSync(p));
  if (!path) return "<!doctype html><p style='font-family:system-ui'>Tirith widget not built. Run <code>npm run build:widget</code>.</p>";
  cached = readFileSync(path, "utf8");
  return cached;
}

export function registerWidget(server: McpServer) {
  // e.g. https://tirith.example.com; defaults to the origin of TIRITH_MCP_PUBLIC_URL (required for submission).
  const domain = process.env.TIRITH_WIDGET_DOMAIN?.trim() || PUBLIC_ORIGIN;
  const uiMeta = {
    prefersBorder: true,
    // Fully self-contained bundle: no network, no external assets, no nested frames.
    csp: { connectDomains: [] as string[], resourceDomains: [] as string[] },
    ...(domain ? { domain } : {}),
  };
  registerAppResource(
    server,
    "tirith-console",
    WIDGET_URI,
    { description: "Tirith security console: posture score, severity counts, top findings and finding detail.", _meta: { ui: uiMeta } },
    async () => ({
      contents: [
        {
          uri: WIDGET_URI,
          mimeType: RESOURCE_MIME_TYPE,
          text: widgetHtml(),
          _meta: {
            ui: uiMeta,
            "openai/widgetDescription": "Tirith security console showing posture, severity counts and findings.",
            "openai/widgetPrefersBorder": true,
            "openai/widgetCSP": { connect_domains: [], resource_domains: [] },
            ...(domain ? { "openai/widgetDomain": domain } : {}),
          },
        },
      ],
    }),
  );
}
