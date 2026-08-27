"use client";
import { Shield, Bug, Target, ArrowRight, Zap } from "lucide-react";

type Node = { id: string; type: string; template_id?: string; severity?: string; host?: string; label?: string };
type Link = { source: string; target: string; label?: string };

export function AttackPathGraph({ nodes, links }: { nodes: Node[]; links: Link[] }) {
  if (!nodes?.length) {
    return <p className="text-sm text-[var(--muted-foreground)]">No attack paths detected — no chaining rules matched.</p>;
  }

  // Build ordered chain: follow links source->target
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const ordered: Node[] = [];
  const linkMap = new Map(links.map((l) => [l.source, l]));

  // Find start node (no incoming)
  const targets = new Set(links.map((l) => l.target));
  let current: string | undefined = nodes.find((n) => !targets.has(n.id))?.id || nodes[0]?.id;
  const visited = new Set<string>();
  while (current && !visited.has(current) && nodeMap.has(current)) {
    visited.add(current);
    ordered.push(nodeMap.get(current)!);
    const nextLink = linkMap.get(current);
    current = nextLink?.target;
  }
  // Add any remaining nodes not in chain
  for (const n of nodes) if (!visited.has(n.id)) ordered.push(n);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
        <Zap className="h-4 w-4 text-[var(--primary)]" /> Interactive chain — Source → Chained Finding → Impact
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {ordered.map((node, idx) => (
          <div key={node.id} className="flex items-center gap-2">
            <div className={`flex flex-col items-center gap-1 rounded-lg border px-3 py-2 min-w-[140px] text-center ${node.type === "impact" ? "bg-red-500/10 border-red-500/30 text-red-300" : node.type === "finding" ? "bg-[var(--card)] border-[var(--primary)]/30 cyber-glow" : "bg-[var(--muted)]"}`}>
              <div className="flex items-center gap-1 text-xs font-medium">
                {node.type === "finding" ? <Bug className="h-3 w-3" /> : node.type === "impact" ? <Target className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
                {node.template_id || node.label || node.id.slice(0, 8)}
              </div>
              <div className="text-[10px] text-[var(--muted-foreground)] truncate max-w-[120px]">{node.host || node.id}</div>
              {node.severity && <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${node.severity === "CRITICAL" ? "bg-red-900 text-red-200" : node.severity === "HIGH" ? "bg-red-600 text-white" : "bg-amber-600 text-white"}`}>{node.severity}</span>}
            </div>
            {idx < ordered.length - 1 && (
              <div className="flex flex-col items-center">
                <ArrowRight className="h-4 w-4 text-[var(--primary)]" />
                <span className="text-[9px] text-[var(--muted-foreground)]">{links.find((l) => l.source === node.id)?.label || "chains"}</span>
              </div>
            )}
          </div>
        ))}
      </div>
      <div className="text-xs text-[var(--muted-foreground)]">Fetched via <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/projects/{"{id}"}/engagements/{"{id}"}/attack-paths</code></div>
    </div>
  );
}
