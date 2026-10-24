"use client";

import clsx from "clsx";
import { Fragment } from "react";

const KW = new Set(
  "def return if else elif for in while import from as class try except finally with raise None True False and or not lambda yield pass break continue async await is".split(
    " ",
  ),
);
const BUILTIN = new Set("print len str int dict list open request render_template send_file os db hashlib".split(" "));

const TOKEN =
  /(#[^\n]*)|([rbfu]{0,2}"(?:\\.|[^"\\])*"?|[rbfu]{0,2}'(?:\\.|[^'\\])*'?)|(\{\{|\}\}|\{%|%\})|(\b\d+(?:\.\d+)*\b)|([A-Za-z_][\w]*)|(<\/?[a-zA-Z][\w-]*|\/?>)|([^\w\s]+)|(\s+)/g;

/** Tiny dependency-free highlighter tuned for Python / Jinja / requirements / HTTP snippets. */
export function highlight(line: string) {
  const out: React.ReactNode[] = [];
  let m: RegExpExecArray | null;
  let i = 0;
  let last = 0;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(line))) {
    if (m.index > last) out.push(<Fragment key={i++}>{line.slice(last, m.index)}</Fragment>);
    last = m.index + m[0].length;
    const [t, comment, str, tpl, num, ident, tag, punct] = m;
    let cls = "";
    if (comment) cls = "text-faint italic";
    else if (str) cls = "text-[#9be8b4]";
    else if (tpl) cls = "text-[#f0a6ff]";
    else if (num) cls = "text-[#f2c94c]";
    else if (ident) {
      if (KW.has(ident)) cls = "text-[#c4a7ff]";
      else if (BUILTIN.has(ident)) cls = "text-accent";
      else if (/^[A-Z][A-Z0-9_]+$/.test(ident)) cls = "text-[#ffb27a]";
      else if (line[m.index + t.length] === "(") cls = "text-[#8ec5ff]";
      else cls = "text-mithril";
    } else if (tag) cls = "text-[#ff9db0]";
    else if (punct) cls = "text-mithril-dim";
    out.push(
      cls ? (
        <span key={i++} className={cls}>
          {t}
        </span>
      ) : (
        <Fragment key={i++}>{t}</Fragment>
      ),
    );
    if (t.length === 0) TOKEN.lastIndex++;
  }
  if (last < line.length) out.push(<Fragment key={i++}>{line.slice(last)}</Fragment>);
  return out;
}

export function CodeBlock({ code, startLine, highlightLine }: { code: string; startLine?: number | null; highlightLine?: number | null }) {
  const lines = code.replace(/\n$/, "").split("\n");
  const start = startLine ?? 1;
  return (
    <pre className="overflow-x-auto rounded-md border border-line bg-night-950/80 py-2 font-mono text-[11.5px] leading-[1.6]">
      {lines.map((l, i) => {
        const n = start + i;
        const hot = highlightLine === n;
        return (
          <div key={i} className={clsx("flex", hot && "bg-sev-critical/10 shadow-[inset_2px_0_0_var(--color-sev-critical)]")}>
            {startLine != null && <span className="w-10 shrink-0 pr-3 text-right text-faint select-none">{n}</span>}
            <code className="pr-4 pl-3 whitespace-pre">{highlight(l)}</code>
          </div>
        );
      })}
    </pre>
  );
}

export function DiffView({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, "").split("\n");
  let oldN = 0;
  let newN = 0;
  return (
    <pre className="overflow-x-auto rounded-md border border-line bg-night-950/80 py-1 font-mono text-[11.5px] leading-[1.6]">
      {lines.map((l, i) => {
        if (l.startsWith("---") || l.startsWith("+++")) {
          return (
            <div key={i} className="px-3 text-mithril-dim">
              <span className={l.startsWith("---") ? "text-sev-critical/80" : "text-ok/80"}>{l.slice(0, 3)}</span>
              {l.slice(3)}
            </div>
          );
        }
        if (l.startsWith("@@")) {
          const m = /@@ -(\d+)(?:,\d+)? \+(\d+)/.exec(l);
          if (m) {
            oldN = Number(m[1]);
            newN = Number(m[2]);
          }
          return (
            <div key={i} className="my-0.5 bg-accent/5 px-3 text-accent/80">
              {l}
            </div>
          );
        }
        const kind = l[0] === "+" ? "add" : l[0] === "-" ? "del" : "ctx";
        const o = kind === "add" ? "" : oldN++;
        const n = kind === "del" ? "" : newN++;
        return (
          <div
            key={i}
            className={clsx(
              "flex",
              kind === "add" && "bg-ok/[0.09] shadow-[inset_2px_0_0_var(--color-ok)]",
              kind === "del" && "bg-sev-critical/[0.09] shadow-[inset_2px_0_0_var(--color-sev-critical)]",
            )}
          >
            <span className="w-9 shrink-0 pr-2 text-right text-faint select-none">{o}</span>
            <span className="w-9 shrink-0 pr-2 text-right text-faint select-none">{n}</span>
            <span className={clsx("w-4 shrink-0 select-none", kind === "add" ? "text-ok" : kind === "del" ? "text-sev-critical" : "text-faint")}>
              {kind === "add" ? "+" : kind === "del" ? "−" : " "}
            </span>
            <code className="pr-4 whitespace-pre">{highlight(l.slice(1))}</code>
          </div>
        );
      })}
    </pre>
  );
}
