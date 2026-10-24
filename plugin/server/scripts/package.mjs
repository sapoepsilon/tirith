// Build plugin/dist/tirith-plugin.zip: plugin.json, mcp.json, skills/, assets/ at the ZIP root.
// TIRITH_MCP_PUBLIC_URL=https://<host>/mcp[/<secret>] sets the MCP server URL in mcp.json and the base of the
// website/privacy/terms/support URLs in plugin.json (pages served by the MCP server). Required: the placeholder fails.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const pluginRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const outDir = join(pluginRoot, "dist");
const zipPath = join(outDir, "tirith-plugin.zip");

const fail = (msg) => {
  console.error(`package: ${msg}`);
  process.exit(1);
};
const readJson = (p) => {
  try {
    return JSON.parse(readFileSync(join(pluginRoot, p), "utf8"));
  } catch (e) {
    fail(`${p}: ${e.message}`);
  }
};

const manifest = readJson("plugin.json");
const mcp = readJson("mcp.json");

if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(manifest.name ?? "")) fail("plugin.json name must be kebab-case");
for (const k of ["version", "description"]) if (!manifest[k]) fail(`plugin.json missing ${k}`);

// Every ./ path referenced by the OpenAI extension must exist in the package.
const iface = manifest.extensions?.["com.openai"]?.interface ?? {};
const refs = [iface.composerIcon, iface.composerIconDark, iface.logo, iface.logoDark, ...(iface.screenshots ?? [])].filter(Boolean);
for (const r of refs) {
  if (!r.startsWith("./")) fail(`path must start with ./: ${r}`);
  if (!existsSync(join(pluginRoot, r))) fail(`referenced file missing: ${r}`);
}

// Skills: each needs SKILL.md with name + description frontmatter.
const skillMd = readFileSync(join(pluginRoot, "skills/tirith/SKILL.md"), "utf8");
if (!/^---\n[\s\S]*?\bname:\s*\S[\s\S]*?\bdescription:\s*\S[\s\S]*?\n---/.test(skillMd)) fail("skills/tirith/SKILL.md frontmatter needs name and description");

// --- OpenAI listing limits ---
if (typeof iface.shortDescription !== "string" || !iface.shortDescription.trim()) fail("interface.shortDescription is required");
if (iface.shortDescription.length > 30) fail(`interface.shortDescription is ${iface.shortDescription.length} chars (max 30)`);
if (!Array.isArray(iface.defaultPrompt) || iface.defaultPrompt.length === 0) fail("interface.defaultPrompt needs 1-3 entries");
if (iface.defaultPrompt.length > 3) fail(`interface.defaultPrompt has ${iface.defaultPrompt.length} entries (max 3)`);
const cmds = iface.commands ?? [];
if (!Array.isArray(cmds) || cmds.length > 10) fail("interface.commands must be an array of at most 10");
for (const c of cmds) {
  if (!/^[a-z][a-z0-9-]{1,20}$/.test(c.name ?? "")) fail(`command name must be lowercase kebab, got ${c.name}`);
  if (!c.description?.trim() || c.description.length > 60) fail(`command ${c.name} needs a description of 1-60 chars`);
  if (!c.prompt?.trim() || c.prompt.length > 400) fail(`command ${c.name} needs a prompt of 1-400 chars`);
  if (new Set(cmds.map((x) => x.name)).size !== cmds.length) fail("command names must be unique");
}
const hex = /^#([0-9a-f]{6})$/i.exec(iface.brandColor ?? "");
if (!hex) fail(`interface.brandColor must be #RRGGBB, got ${iface.brandColor}`);
const lum = (h) => {
  const ch = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
};
const contrast = 1.05 / (lum(hex[1]) + 0.05);
if (contrast < 2) fail(`interface.brandColor ${iface.brandColor} contrast on white is ${contrast.toFixed(2)}:1 (min 2:1)`);

// --- public URLs ---
const PLACEHOLDER = /(^|\.)example\.com$/i;
const publicUrl = process.env.TIRITH_MCP_PUBLIC_URL?.trim();
if (!publicUrl) fail("TIRITH_MCP_PUBLIC_URL is not set (e.g. https://tirith.yourdomain/mcp/<secret>); refusing to package the placeholder URL");
let origin;
try {
  origin = new URL(publicUrl).origin;
} catch {
  fail(`TIRITH_MCP_PUBLIC_URL is not a valid URL: ${publicUrl}`);
}
for (const s of Object.values(mcp.mcpServers ?? {})) {
  s.url = publicUrl;
  if (!/^https:\/\/[^/]+\/mcp(\/[^/?#]+)?$/.test(s.url)) fail(`MCP url must be https://<host>/mcp or https://<host>/mcp/<secret>, got ${s.url}`);
  if (PLACEHOLDER.test(new URL(s.url).hostname)) fail(`MCP url is still the placeholder host: ${s.url}`);
}
iface.websiteURL = `${origin}/`;
iface.privacyPolicyURL = `${origin}/privacy`;
iface.termsOfServiceURL = `${origin}/terms`;
iface.supportURL = `${origin}/support`;
for (const k of ["websiteURL", "privacyPolicyURL", "termsOfServiceURL", "supportURL"]) {
  if (!iface[k].startsWith("https://")) fail(`interface.${k} must be https: ${iface[k]}`);
}

const stage = mkdtempSync(join(tmpdir(), "tirith-plugin-"));
try {
  writeFileSync(join(stage, "plugin.json"), JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(stage, "mcp.json"), JSON.stringify(mcp, null, 2) + "\n");
  cpSync(join(pluginRoot, "skills"), join(stage, "skills"), { recursive: true });
  cpSync(join(pluginRoot, "assets"), join(stage, "assets"), { recursive: true });
  mkdirSync(outDir, { recursive: true });
  rmSync(zipPath, { force: true });
  execFileSync("zip", ["-r", "-X", "-q", zipPath, "plugin.json", "mcp.json", "skills", "assets", "-x", "*.DS_Store"], { cwd: stage, stdio: "inherit" });
} finally {
  rmSync(stage, { recursive: true, force: true });
}
console.log(`package: ${zipPath}`);
