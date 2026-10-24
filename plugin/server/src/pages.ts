// Static public pages linked from plugin.json (privacy, terms, support). Served by the MCP server.

const STYLE = `body{font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;max-width:720px;margin:0 auto;padding:32px 16px;color:#111827;background:#fff}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.1rem;margin-top:28px}p.sub{color:#4b5563;margin:0 0 24px}a{color:#0D9488}
nav{margin-bottom:24px;font-size:.9rem}nav a{margin-right:16px}
@media (prefers-color-scheme:dark){body{background:#0b0f17;color:#e5e7eb}p.sub{color:#9ca3af}a{color:#5EEAD4}}`;

const NAV = `<nav><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/support">Support</a></nav>`;

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tirith · ${title}</title><style>${STYLE}</style></head><body>${NAV}<h1>${title}</h1><p class="sub">Tirith security assessment plugin</p>${body}</body></html>`;
}

export const PAGES: Record<string, string> = {
  "/privacy": page(
    "Privacy policy",
    `<h2>What Tirith processes</h2>
<p>Tirith scans only the repositories, local paths and web apps that its operator has placed in its allow-listed scope. It stores scan findings, validation evidence, fix diffs and an audit log of every action on the operator's own server.</p>
<h2>What the plugin sends to ChatGPT</h2>
<p>Tool results contain finding summaries (titles, severities, file locations, short descriptions and evidence excerpts) so the assistant can answer your questions. Secret values found by the scanners are never intentionally returned; leaked credentials are reported by location so you can rotate them.</p>
<h2>Third parties</h2>
<p>Findings may be summarized by the operator's configured language model, and fix pull requests are opened on GitHub repositories in scope. Tirith does not sell or share data with anyone else and does not use it for advertising.</p>
<h2>Retention and deletion</h2>
<p>Data stays on the operator's server until the operator deletes it. Contact support to request deletion.</p>`,
  ),
  "/terms": page(
    "Terms of use",
    `<h2>Defensive use only</h2>
<p>Use Tirith only on code and applications you own or are authorized to test. Tirith refuses targets outside its configured scope and runs exploit checks only against an isolated lab copy with dummy data.</p>
<h2>No warranty</h2>
<p>Tirith is provided "as is". Scanner results and AI-generated explanations and patches can be wrong; review every pull request before merging. You are responsible for changes you merge or apply.</p>
<h2>Availability</h2>
<p>The service may change or be unavailable at any time.</p>`,
  ),
  "/support": page(
    "Support",
    `<p>For help, bug reports or data deletion requests, open an issue at <a href="https://github.com/sapoepsilon/tirith-demo-target/issues">github.com/sapoepsilon/tirith-demo-target/issues</a>.</p>
<h2>Common problems</h2>
<p><strong>"Blocked by Tirith policy"</strong>: the asset or action is outside the operator's scope, or the server is in observe mode (fixes are refused). Ask the operator to adjust the scope or mode.</p>
<p><strong>"Scan still running"</strong>: large repositories take a few minutes. Ask the assistant to check the scan status again with the scan ID it gave you.</p>`,
  ),
};
