import { clsx } from "clsx";
import { useMemo, useState } from "react";
import { ArrowUpDown, Search, ShieldCheck } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef } from "react";
import type { Alert, Severity } from "@/lib/types";
import { ALL_KINDS, KIND_LABEL, SEVERITY_ORDER, SEVERITY_STYLE, formatRelative, shortPath } from "@/lib/format";
import { useFilters } from "@/lib/store";
import { useAlertHistory } from "@/lib/api";

type SortKey = "timestamp" | "severity" | "prefix" | "kind";

export default function Alerts({ alerts }: { alerts: Alert[] }) {
  const { severities, kinds, ownedOnly, query, toggleSeverity, toggleKind, setOwnedOnly, setQuery } = useFilters();
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [asc, setAsc] = useState(false);
  const { data: history } = useAlertHistory({ limit: 300 });

  // Prefer the graph-backed history when the live buffer is thin (fresh load,
  // or a quiet feed) so the table is useful immediately after navigation.
  const source = alerts.length > 0 ? alerts : history?.alerts ?? [];

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = source.filter((a) => {
      if (severities[a.severity] === false) return false;
      const activeKinds = Object.entries(kinds).filter(([, on]) => on).map(([k]) => k);
      if (activeKinds.length > 0 && !activeKinds.includes(a.kind)) return false;
      if (ownedOnly && !a.is_owned) return false;
      if (needle) {
        const haystack = `${a.prefix} ${a.origin_as ?? ""} ${a.as_path} ${a.kind} ${a.reasons.join(" ")}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
    const dir = asc ? 1 : -1;
    return filtered.sort((a, b) => {
      if (sortKey === "timestamp") return dir * a.timestamp.localeCompare(b.timestamp);
      if (sortKey === "severity") {
        return dir * (SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)) * -1;
      }
      if (sortKey === "prefix") return dir * a.prefix.localeCompare(b.prefix);
      return dir * a.kind.localeCompare(b.kind);
    });
  }, [source, severities, kinds, ownedOnly, query, sortKey, asc]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 44,
    overscan: 12,
  });

  const header = (key: SortKey, label: string, className?: string) => (
    <button
      type="button"
      onClick={() => {
        if (sortKey === key) setAsc((v) => !v);
        else {
          setSortKey(key);
          setAsc(false);
        }
      }}
      className={clsx(
        "flex items-center gap-1 text-left text-[11px] font-semibold uppercase tracking-wide text-muted hover:text-text",
        className,
      )}
      aria-sort={sortKey === key ? (asc ? "ascending" : "descending") : "none"}
    >
      {label}
      <ArrowUpDown className={clsx("size-3", sortKey === key ? "opacity-100" : "opacity-40")} aria-hidden="true" />
    </button>
  );

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-4 border-b border-border bg-surface px-5 py-2.5">
        <label className="flex items-center gap-2 rounded-md border border-border bg-bg px-2.5 py-1.5">
          <Search className="size-3.5 text-muted" aria-hidden="true" />
          <span className="sr-only">Filter alerts</span>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="prefix, ASN, reason…"
            className="w-56 bg-transparent text-[12px] outline-none placeholder:text-muted/70"
          />
        </label>

        <fieldset className="flex items-center gap-1">
          <legend className="sr-only">Severity</legend>
          {SEVERITY_ORDER.map((s) => (
            <FilterChip
              key={s}
              active={severities[s] !== false}
              onClick={() => toggleSeverity(s)}
              className={SEVERITY_STYLE[s as Severity].text}
            >
              {SEVERITY_STYLE[s as Severity].label}
            </FilterChip>
          ))}
        </fieldset>

        <details className="relative">
          <summary className="cursor-pointer rounded-md border border-border bg-bg px-2.5 py-1.5 text-[12px] text-muted hover:text-text">
            Categories
            {Object.values(kinds).some(Boolean) && (
              <span className="ml-2 rounded-full bg-accent/20 px-1.5 text-[10px] text-accent">
                {Object.values(kinds).filter(Boolean).length}
              </span>
            )}
          </summary>
          <div className="absolute z-20 mt-1 max-h-72 w-60 overflow-auto rounded-md border border-border bg-surface-2 p-2 shadow-xl">
            {ALL_KINDS.map((k) => (
              <label key={k} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-[12px] hover:bg-surface">
                <input
                  type="checkbox"
                  checked={Boolean(kinds[k])}
                  onChange={() => toggleKind(k)}
                  className="accent-[var(--color-accent)]"
                />
                {KIND_LABEL[k]}
              </label>
            ))}
          </div>
        </details>

        <label className="flex cursor-pointer items-center gap-2 text-[12px] text-muted">
          <input
            type="checkbox"
            checked={ownedOnly}
            onChange={(e) => setOwnedOnly(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          Owned space only
        </label>

        <span className="ml-auto font-mono text-[11px] text-muted">
          {rows.length} of {source.length} alerts
        </span>
      </div>

      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
        <div className="sticky top-0 z-10 grid grid-cols-[9rem_7rem_5rem_1fr_7rem_6rem_5rem] gap-3 border-b border-border bg-surface px-5 py-2">
          {header("timestamp", "Time")}
          {header("severity", "Severity")}
          {header("kind", "Type")}
          {header("prefix", "Detail")}
          <span className="text-[11px] font-semibold uppercase tracking-wide text-muted">Path</span>
          <span className="text-[11px] font-semibold uppercase tracking-wide text-muted">Origin</span>
          <span className="text-[11px] font-semibold uppercase tracking-wide text-muted">Source</span>
        </div>

        {rows.length === 0 ? (
          <EmptyState />
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((item) => {
              const alert = rows[item.index];
              const style = SEVERITY_STYLE[alert.severity];
              const evidence = formatEvidence(alert);
              return (
                <div
                  key={alert.alert_id}
                  style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${item.start}px)` }}
                  className="grid grid-cols-[9rem_7rem_5rem_1fr_7rem_6rem_5rem] items-center gap-3 border-b border-border/60 px-5 py-2.5 hover:bg-surface/60"
                >
                  <span className="font-mono text-[11px] text-muted" title={alert.timestamp}>
                    {formatRelative(alert.timestamp)}
                  </span>
                  <span
                    className={clsx("inline-flex w-fit items-center rounded px-1.5 py-0.5 text-[11px] font-semibold ring-1", style.bg, style.text, style.ring)}
                  >
                    {style.label}
                  </span>
                  <span className="truncate text-[12px]" title={KIND_LABEL[alert.kind]}>
                    {KIND_LABEL[alert.kind]}
                  </span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-2">
                      <span className="font-mono text-[12px]">{alert.prefix}</span>
                      {alert.is_owned && (
                        <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-medium text-accent ring-1 ring-accent/30">
                          owned
                        </span>
                      )}
                    </span>
                    <span className="block truncate text-[11px] text-muted" title={alert.reasons.join("; ")}>
                      {alert.reasons[0]}
                      {evidence && <span className="ml-1 text-muted/70">· {evidence}</span>}
                    </span>
                  </span>
                  <span className="truncate font-mono text-[11px] text-muted" title={alert.as_path}>
                    {shortPath(alert.as_path, 3)}
                  </span>
                  <span className="font-mono text-[11px]">AS{alert.origin_as ?? "—"}</span>
                  <span className="truncate font-mono text-[10px] text-muted" title={alert.collector}>
                    {alert.collector}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function formatEvidence(alert: Alert): string {
  const ev = alert.evidence ?? {};
  if (typeof ev.offending_pair === "object" && Array.isArray(ev.offending_pair)) {
    return `AS${ev.offending_pair[0]} → AS${ev.offending_pair[1]}`;
  }
  if (typeof ev.zscore === "number") return `z=${ev.zscore}`;
  if (typeof ev.prepend_count === "number") return `${ev.prepend_count}× prepend`;
  if (typeof ev.parent === "string") return `parent ${ev.parent}`;
  if (typeof ev.rpki_source === "string") return `via ${ev.rpki_source}`;
  if (typeof ev.last_seen === "string") return `last seen ${formatRelative(ev.last_seen)}`;
  return "";
}

function FilterChip({
  active,
  onClick,
  children,
  className,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={clsx(
        "rounded-md border px-2 py-1 text-[11px] font-medium transition-colors",
        active ? clsx("border-border bg-surface-2", className) : "border-transparent text-muted hover:text-text",
      )}
    >
      {children}
    </button>
  );
}

function EmptyState() {
  return (
    <div className="grid place-items-center px-6 py-24 text-center">
      <ShieldCheck className="size-8 text-ok" aria-hidden="true" />
      <p className="mt-3 text-[13px] font-medium">No alerts match the current filters</p>
      <p className="mt-1 max-w-md text-[12px] text-muted">
        Detection is baselined on owned space, RPKI, and AS relationships, so an empty table means no
        unauthorised routing was observed — not that monitoring is off.
      </p>
    </div>
  );
}
