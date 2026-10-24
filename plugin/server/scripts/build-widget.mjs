// Bundle the React widget into one self-contained HTML file: dist/widget/tirith.html
import { build } from "esbuild";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "dist/widget");
mkdirSync(out, { recursive: true });

const result = await build({
  entryPoints: [resolve(root, "widget/src/main.tsx")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  jsx: "automatic",
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "none",
  // preact/compat keeps the single-file widget small (~40 KiB vs ~230 KiB with react-dom).
  alias: { react: "preact/compat", "react-dom/client": "preact/compat/client", "react-dom": "preact/compat", "react/jsx-runtime": "preact/jsx-runtime" },
  write: false,
});

// Never let bundled code close the inline <script> early.
const js = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script").replace(/<!--/g, "<\\!--");
const css = readFileSync(resolve(root, "widget/src/styles.css"), "utf8");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Tirith</title>
<style>${css}</style>
</head>
<body>
<div id="root"></div>
<script type="module">${js}</script>
</body>
</html>
`;
writeFileSync(resolve(out, "tirith.html"), html);
console.log(`widget: dist/widget/tirith.html (${(html.length / 1024).toFixed(1)} KiB)`);
