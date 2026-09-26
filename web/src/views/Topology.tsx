import { useMemo, useState } from "react";
import { Search, Network, Info } from "lucide-react";
import { useTopology } from "@/lib/api";

/**
 * AS adjacency derived from observed AS paths.
 *
 * Layout: deterministic ring by origin weight (largest origins centred on the
 * upper arc) rather than a physics simulation — a NOC needs a stable picture it
 * can compare between refreshes, not nodes drifting on every poll.
 */
export default function Topology() {
  const { data, isLoading, error } = useTopology();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<number | null>(null);

  const layout = useMemo(() => {
    const nodes = data?.nodes ?? [];
    const edges = data?.edges ?? [];
    if (nodes.length === 0) return { nodes: [], edges: [] };
    const width = 1000;
    const height = 620;
    const cx = width / 2;
    const cy = height / 2;
    const sorted = [...nodes].sort((a, b) => b.origin_count - a.origin_count);
    const placed = sorted.map((node, i) => {
      const rank = i / Math.max(sorted.length, 1);
      const ring = i < 8 ? 0 : i < 32 ? 1 : 2;
      const radius = ring === 0 ? 0 : ring === 1 ? 190 : 280;
      const countInRing = ring === 0 ? 1 : ring === 1 ? 24 : sorted.length - 32;
      const indexInRing = ring === 0 ? 0 : ring === 1 ? i - 8 : i - 32;
      const angle = (indexInRing / Math.max(countInRing, 1)) * Math.PI * 2 - Math.PI / 2 + rank * 0.4;
      return {
        ...node,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        r: Math.max(3, Math.min(14, 3 + Math.sqrt(node.origin_count) / 3)),
      };
    });
    const byAsn = new Map(placed.map((n) => [n.asn, n]));
    const drawn = edges
      .map((e) => {
        const from = byAsn.get(e.from);
        const to = byAsn.get(e.to);
        return from && to ? { ...e, from, to } : null;
      })
      .filter((e): e is NonNullable<typeof e> => e !== null)
      .slice(0, 400);
    return { nodes: placed, edges: drawn };
  }, [data]);

  const matches = query
    ? layout.nodes.filter((n) => String(n.asn).includes(query.replace(/^AS/i, "")))
    : [];

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-4 border-b border-border bg-surface px-5 py-2.5">
        <label className="flex items-center gap-2 rounded-md border border-border bg-bg px-2.5 py-1.5">
          <Search className="size-3.5 text-muted" aria-hidden="true" />
          <span className="sr-only">Find ASN</span>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="find ASN…"
            className="w-40 bg-transparent text-[12px] outline-none placeholder:text-muted/70"
          />
        </label>
        {matches.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {matches.slice(0, 6).map((m) => (
              <button
                key={m.asn}
                type="button"
                onClick={() => setSelected(m.asn)}
                className="rounded-md border border-border bg-bg px-2 py-1 font-mono text-[11px] hover:border-accent/50"
              >
                AS{m.asn}
              </button>
            ))}
          </div>
        )}
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-muted">
          <Network className="size-3.5" aria-hidden="true" />
          {layout.nodes.length} origins · {layout.edges.length} adjacencies
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        {isLoading && <Centered>Loading topology from the graph…</Centered>}
        {error && <Centered>Graph unavailable — {String((error as Error).message)}</Centered>}
        {!isLoading && !error && layout.nodes.length === 0 && (
          <Centered>
            No adjacency yet. The graph sink needs to be enabled and receiving updates before topology
            can be derived.
          </Centered>
        )}
        {layout.nodes.length > 0 && (
          <svg viewBox="0 0 1000 620" className="h-full w-full" role="img" aria-label="Observed AS adjacency graph">
            <g>
              {layout.edges.map((e, i) => {
                const dim = selected !== null && e.from.asn !== selected && e.to.asn !== selected;
                return (
                  <line
                    key={`${e.from.asn}-${e.to.asn}-${i}`}
                    x1={e.from.x}
                    y1={e.from.y}
                    x2={e.to.x}
                    y2={e.to.y}
                    stroke="var(--color-accent)"
                    strokeOpacity={dim ? 0.03 : Math.min(0.5, 0.08 + e.count / 60)}
                    strokeWidth={Math.min(2.5, 0.5 + e.count / 20)}
                  />
                );
              })}
            </g>
            <g>
              {layout.nodes.map((n) => {
                const isSel = selected === n.asn;
                const dim = selected !== null && !isSel;
                return (
                  <g key={n.asn} transform={`translate(${n.x} ${n.y})`}>
                    <circle
                      r={n.r}
                      fill={isSel ? "var(--color-accent)" : "var(--color-surface-2)"}
                      stroke={isSel ? "var(--color-accent)" : "var(--color-border)"}
                      strokeWidth={1.5}
                      opacity={dim ? 0.35 : 1}
                    />
                    {(n.r > 8 || isSel) && (
                      <text
                        y={-n.r - 3}
                        textAnchor="middle"
                        fontSize={9}
                        fill={isSel ? "var(--color-accent)" : "var(--color-muted)"}
                        className="font-mono"
                      >
                        AS{n.asn}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>
        )}
      </div>

      <div className="flex items-start gap-2 border-t border-border bg-surface px-5 py-2 text-[11px] text-muted">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        Adjacency is observed from AS paths in the graph; node size reflects how many distinct prefixes an
        origin announced. Directional provider/customer classification is applied at detection time, not drawn
        here.
      </div>
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="grid h-full place-items-center px-6 text-center text-[12px] text-muted">{children}</div>;
}
