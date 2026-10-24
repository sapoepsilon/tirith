"use client";

import clsx from "clsx";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { FolderGit2, GitPullRequest, Network, ShieldCheck, Wrench } from "lucide-react";
import { useEffect, useMemo } from "react";
import { useTirith } from "@/lib/store";
import type { Finding, Fix, ToolName, ToolStatus } from "@/lib/types";
import { byPriority, isLab } from "@/lib/types";
import { FixChip, PanelHeader, SEV_COLOR } from "./ui";

const TOOLS: { id: ToolName; label: string; kind: string }[] = [
  { id: "semgrep", label: "semgrep", kind: "SAST" },
  { id: "gitleaks", label: "gitleaks", kind: "secrets" },
  { id: "trivy", label: "trivy", kind: "dependencies" },
  { id: "zap", label: "zap", kind: "DAST · tirith-lab" },
];

type AssetData = { name: string; ref: string; kind: string; scanning: boolean };
type ScannerData = { label: string; kind: string; status: ToolStatus; hits: number };
type FindingData = { f: Finding };
type FixData = { fix: Fix };
type MoreData = { hidden: number; lab: number };

/** Max finding nodes drawn; the rest collapse into one "+N more" node per scanner. */
const MAX_NODES = 10;

function AssetNode({ data }: NodeProps<Node<AssetData>>) {
  return (
    <div
      className={clsx(
        "h-full w-full rounded-lg border bg-night-850 px-3 py-2.5 transition-shadow duration-700",
        data.scanning ? "border-accent/60 shadow-[0_0_24px_-6px_rgba(127,227,255,0.55)]" : "border-line-strong",
      )}
    >
      <div className="flex items-center gap-2">
        <FolderGit2 className="size-4 text-accent" />
        <span className="truncate text-[12.5px] font-medium text-mithril">{data.name}</span>
      </div>
      <div className="mt-1 truncate font-mono text-[10px] text-muted">{data.ref}</div>
      <div className="mt-1.5 font-mono text-[9px] uppercase tracking-widest text-faint">{data.kind.replace("_", " ")}</div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function ScannerNode({ data }: NodeProps<Node<ScannerData>>) {
  const running = data.status === "running";
  const done = data.status === "done";
  return (
    <div
      className={clsx(
        "relative h-full w-full overflow-hidden rounded-md border bg-night-850 px-2.5 py-2 transition-all duration-500",
        running ? "border-accent/60 shadow-[0_0_18px_-6px_rgba(127,227,255,0.6)]" : done ? "border-line-strong" : "border-line opacity-60",
      )}
    >
      {running && <div className="absolute inset-0 animate-scan bg-gradient-to-r from-transparent via-accent/15 to-transparent" />}
      <Handle type="target" position={Position.Left} />
      <div className="relative flex items-center justify-between">
        <span className="font-mono text-[11.5px] text-mithril">{data.label}</span>
        <span
          className={clsx(
            "size-1.5 rounded-full",
            running ? "animate-pulse-soft bg-accent" : done ? "bg-ok" : data.status === "failed" ? "bg-sev-critical" : "bg-faint",
          )}
        />
      </div>
      <div className="relative mt-0.5 flex justify-between font-mono text-[9.5px] text-muted">
        <span>{data.kind}</span>
        <span>{data.hits}</span>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function FindingNode({ data }: NodeProps<Node<FindingData>>) {
  const f = data.f;
  const c = SEV_COLOR[f.severity];
  const fixed = f.status === "fixed";
  return (
    <div
      className={clsx(
        "animate-fade-in h-full w-full cursor-pointer rounded-md border bg-night-850 py-1.5 pr-2 pl-2.5 transition-all duration-500 hover:bg-night-800",
        fixed && "opacity-70",
      )}
      style={{
        borderColor: fixed ? "color-mix(in srgb, var(--color-ok) 40%, transparent)" : `color-mix(in srgb, ${c} 35%, transparent)`,
        boxShadow: f.status === "validated" ? `0 0 16px -6px ${c}` : undefined,
      }}
    >
      <Handle type="target" position={Position.Left} />
      <div className="flex items-center gap-1.5">
        <span className="size-1.5 shrink-0 rounded-full" style={{ background: fixed ? "var(--color-ok)" : c }} />
        <span className={clsx("truncate text-[11px]", fixed ? "text-mithril-dim line-through decoration-faint" : "text-mithril")}>
          {f.title}
        </span>
      </div>
      <div className="mt-0.5 flex justify-between gap-2 pl-3 font-mono text-[9.5px] text-muted">
        <span className="truncate">{f.cwe ?? f.cve ?? f.rule_id}</span>
        <span
          className={clsx(
            f.status === "validated" && "text-sev-critical",
            f.status === "fixed" && "text-ok",
            f.status === "fixing" && "animate-pulse-soft text-accent",
          )}
        >
          {f.status === "validated" ? "confirmed" : f.status.replace("_", " ")}
        </span>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function FixNode({ data }: NodeProps<Node<FixData>>) {
  const fx = data.fix;
  const Icon = fx.pr_url ? GitPullRequest : fx.status === "verified" || fx.status === "applied" ? ShieldCheck : Wrench;
  return (
    <div className="animate-fade-in flex h-full w-full items-center gap-2 rounded-md border border-line-strong bg-night-850 px-2 py-1.5">
      <Handle type="target" position={Position.Left} />
      <Icon className="size-3.5 shrink-0 text-accent" />
      <div className="min-w-0">
        <FixChip s={fx.status} />
        <div className="mt-0.5 truncate font-mono text-[9px] text-muted">{fx.pr_url ? `#${fx.pr_url.split("/").pop()}` : fx.mode}</div>
      </div>
    </div>
  );
}

function MoreNode({ data }: NodeProps<Node<MoreData>>) {
  return (
    <div className="flex h-full w-full flex-col justify-center rounded-md border border-dashed border-line-strong bg-night-900/60 px-2.5 font-mono text-[10px] text-muted">
      <Handle type="target" position={Position.Left} />
      <span className="text-mithril-dim">+{data.hidden} more</span>
      {data.lab > 0 && <span className="text-[9px] text-faint">{data.lab} in lab sub-apps</span>}
    </div>
  );
}

const nodeTypes = { asset: AssetNode, scanner: ScannerNode, finding: FindingNode, fix: FixNode, more: MoreNode };

const ROW = 50;
const toolIdx = (t: string) => TOOLS.findIndex((x) => x.id === t);

type Row = { kind: "finding"; f: Finding } | { kind: "more"; tool: string; hidden: number; lab: number };

function useGraph() {
  const { snap } = useTirith();
  return useMemo(() => {
    const asset = snap.assets[0];
    const scan = snap.scans[0];
    const all = [...snap.findings].sort(byPriority);
    // Draw the highest-priority findings (plus anything with a fix); collapse the rest per scanner.
    const keep = new Set<string>();
    for (const f of all) if (f.fix_id && snap.fixes[f.fix_id]) keep.add(f.id);
    for (const f of all) {
      if (keep.size >= MAX_NODES) break;
      keep.add(f.id);
    }
    const findings = all.filter((f) => keep.has(f.id)).sort((a, b) => toolIdx(a.tool) - toolIdx(b.tool) || byPriority(a, b));
    const rows: Row[] = [];
    for (const t of TOOLS) {
      for (const f of findings) if (f.tool === t.id) rows.push({ kind: "finding", f });
      const hidden = all.filter((f) => f.tool === t.id && !keep.has(f.id));
      if (hidden.length) rows.push({ kind: "more", tool: t.id, hidden: hidden.length, lab: hidden.filter(isLab).length });
    }
    const nodes: Node[] = [];
    const edges: Edge[] = [];

    // Finding rows first so scanners can be centred on their group.
    const fy = new Map<string, number>();
    rows.forEach((r, i) => fy.set(r.kind === "finding" ? r.f.id : `more-${r.tool}`, i * ROW));
    const totalH = Math.max(rows.length - 1, 3) * ROW;

    // Scanner y = mean of its rows, then enforce minimum spacing.
    let scannerY = TOOLS.map((t, i) => {
      const ys = rows
        .filter((r) => (r.kind === "finding" ? r.f.tool : r.tool) === t.id)
        .map((r) => fy.get(r.kind === "finding" ? r.f.id : `more-${r.tool}`)!);
      return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : (i / 3) * totalH;
    });
    const GAP = 70;
    for (let i = 1; i < scannerY.length; i++) scannerY[i] = Math.max(scannerY[i], scannerY[i - 1] + GAP);
    if (!rows.length) scannerY = TOOLS.map((_, i) => i * GAP * 1.2);
    const midY = (scannerY[0] + scannerY[scannerY.length - 1]) / 2;

    if (asset) {
      nodes.push({
        id: "asset",
        type: "asset",
        position: { x: 0, y: midY - 20 },
        data: { name: asset.name, ref: asset.ref, kind: asset.kind, scanning: scan?.status === "running" },
        width: 190,
        height: 80,
        draggable: false,
      });
    }
    TOOLS.forEach((t, i) => {
      const status = (scan?.tools?.[t.id] ?? "pending") as ToolStatus;
      nodes.push({
        id: `tool-${t.id}`,
        type: "scanner",
        position: { x: 270, y: scannerY[i] - 6 },
        data: { label: t.label, kind: t.kind, status, hits: all.filter((f) => f.tool === t.id).length },
        width: 150,
        height: 48,
        draggable: false,
      });
      if (asset)
        edges.push({
          id: `e-asset-${t.id}`,
          source: "asset",
          target: `tool-${t.id}`,
          animated: status === "running",
          style: status === "done" ? { stroke: "#2f4466" } : undefined,
        });
    });
    for (const r of rows) {
      if (r.kind !== "more") continue;
      const id = `more-${r.tool}`;
      nodes.push({ id, type: "more", position: { x: 500, y: fy.get(id)! }, data: { hidden: r.hidden, lab: r.lab }, width: 230, height: 38, draggable: false });
      edges.push({ id: `e-${r.tool}-${id}`, source: `tool-${r.tool}`, target: id, style: { stroke: "#2f4466", strokeDasharray: "4 4" } });
    }
    for (const f of findings) {
      const y = fy.get(f.id)!;
      nodes.push({ id: f.id, type: "finding", position: { x: 500, y }, data: { f }, width: 230, height: 42, draggable: false });
      edges.push({
        id: `e-${f.tool}-${f.id}`,
        source: `tool-${f.tool}`,
        target: f.id,
        animated: f.status === "fixing",
        style: {
          stroke: f.status === "fixed" ? "var(--color-ok)" : SEV_COLOR[f.severity],
          strokeOpacity: f.status === "fixed" ? 0.35 : 0.45,
        },
      });
      const fx = f.fix_id ? snap.fixes[f.fix_id] : undefined;
      if (fx) {
        nodes.push({ id: `fix-${fx.id}`, type: "fix", position: { x: 780, y: y + 1 }, data: { fix: fx }, width: 150, height: 40, draggable: false });
        edges.push({
          id: `e-fix-${fx.id}`,
          source: f.id,
          target: `fix-${fx.id}`,
          animated: fx.status === "proposed" || fx.status === "pr_opened",
          style: { stroke: fx.status === "escalated" ? "var(--color-sev-high)" : "var(--color-ok)", strokeOpacity: 0.5 },
        });
      }
    }
    return { nodes, edges, key: `${rows.length}:${Object.keys(snap.fixes).length}` };
  }, [snap]);
}

function Graph() {
  const { nodes, edges, key } = useGraph();
  const { select } = useTirith();
  const rf = useReactFlow();
  useEffect(() => {
    const t = setTimeout(() => void rf.fitView({ duration: 600, padding: 0.12, maxZoom: 1.05 }), 60);
    return () => clearTimeout(t);
  }, [key, rf]);
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.12, maxZoom: 1.05 }}
      minZoom={0.3}
      maxZoom={1.6}
      nodesConnectable={false}
      elementsSelectable={false}
      proOptions={{ hideAttribution: true }}
      onNodeClick={(_, n) => n.type === "finding" && select(n.id)}
      panOnScroll={false}
      zoomOnScroll={false}
      preventScrolling={false}
    >
      <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#1d2a40" />
      <Controls showInteractive={false} position="bottom-right" />
    </ReactFlow>
  );
}

export function Topology({ height = 440 }: { height?: number }) {
  const { snap } = useTirith();
  return (
    <section className="panel flex flex-col">
      <PanelHeader
        icon={Network}
        title="Attack-surface topology"
        sub="asset → scanners → findings → fixes"
        right={
          <span className="font-mono text-[10px] text-muted">
            top {Math.min(MAX_NODES, snap.findings.length)} of {snap.findings.length} by priority · click a finding
          </span>
        }
      />
      <div style={{ height }} className="relative">
        <ReactFlowProvider>
          <Graph />
        </ReactFlowProvider>
      </div>
    </section>
  );
}
