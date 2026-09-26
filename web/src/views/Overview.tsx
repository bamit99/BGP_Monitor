import { clsx } from "clsx";
import { AlertTriangle, Database, Gauge, Radar, ShieldAlert, Timer, Waves } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Alert, Health } from "@/lib/types";
import { KIND_LABEL, SEVERITY_ORDER, SEVERITY_STYLE } from "@/lib/format";

/** Rolling samples for the throughput sparkline. Client-side only: the API is
 *  polled every 3s, so 40 points is a ~2 minute window at no extra cost. */
function useSeries(value: number | undefined, key: string, window = 40) {
  const [series, setSeries] = useState<{ t: number; v: number }[]>([]);
  const lastRef = useRef<number | null>(null);
  useEffect(() => {
    if (value === undefined || lastRef.current === null) {
      lastRef.current = value ?? null;
      return;
    }
    if (value === lastRef.current) return;
    lastRef.current = value;
    setSeries((prev) => [...prev, { t: Date.now(), v: value }].slice(-window));
  }, [value, window, key]);
  return series;
}

export default function Overview({ alerts, health }: { alerts: Alert[]; health?: Health }) {
  const ups = useSeries(health?.metrics.updates_per_second, "ups");
  const alertsSeries = useSeries(health?.metrics.alerts_total, "alerts");

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of alerts) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
    return counts;
  }, [alerts]);

  const kindCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of alerts) counts[a.kind] = (counts[a.kind] ?? 0) + 1;
    return Object.entries(counts)
      .map(([kind, count]) => ({ kind, label: KIND_LABEL[kind as keyof typeof KIND_LABEL] ?? kind, count }))
      .sort((a, b) => b.count - a.count);
  }, [alerts]);

  const critical = alerts.filter((a) => a.severity === "CRITICAL");

  return (
    <div className="h-full overflow-auto">
      <div className="grid gap-4 p-5">
        <section aria-label="Key metrics" className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-6">
          <Metric
            icon={Waves}
            label="Ingest rate"
            value={health ? `${health.metrics.updates_per_second.toFixed(0)}` : "—"}
            unit="upd/s"
            tone="accent"
            series={ups}
          />
          <Metric
            icon={ShieldAlert}
            label="Alerts"
            value={health ? String(health.metrics.alerts_total) : "—"}
            unit={health ? `${health.metrics.suppressed_total} suppressed` : ""}
            tone={critical.length > 0 ? "critical" : "ok"}
            series={alertsSeries}
          />
          <Metric
            icon={Radar}
            label="RPKI prefixes"
            value={health ? `${(health.rpki.indexed_prefixes / 1000).toFixed(0)}k` : "—"}
            unit={health ? `${health.rpki.transport} · ${health.rpki.set_age_s ?? "—"}s old` : ""}
            tone="ok"
          />
          <Metric
            icon={Gauge}
            label="Detect latency"
            value={health ? `${health.metrics.mean_detect_us.toFixed(0)}` : "—"}
            unit="µs/update"
            tone="muted"
          />
          <Metric
            icon={Timer}
            label="Queue depth"
            value={health ? String(health.queue_depth) : "—"}
            unit={health ? `dropped ${health.feed.dropped ?? 0}` : ""}
            tone={health && health.queue_depth > 10000 ? "high" : "muted"}
          />
          <Metric
            icon={Database}
            label="Graph writes"
            value={health ? `${(health.sink.updates_written / 1000).toFixed(0)}k` : "—"}
            unit={health ? `${health.sink.alerts_written} alerts` : ""}
            tone={health?.sink.enabled ? "ok" : "high"}
          />
        </section>

        <div className="grid gap-4 xl:grid-cols-3">
          <Panel title="Throughput" subtitle="updates per second, live" className="xl:col-span-2">
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={ups} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                  <defs>
                    <linearGradient id="upsFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--color-accent)" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="var(--color-accent)" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" hide />
                  <YAxis stroke="var(--color-muted)" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip unit="upd/s" />} />
                  <Area
                    type="monotone"
                    dataKey="v"
                    stroke="var(--color-accent)"
                    strokeWidth={2}
                    fill="url(#upsFill)"
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel title="Severity mix" subtitle="current buffer">
            <ul className="space-y-2">
              {SEVERITY_ORDER.map((s) => {
                const count = severityCounts[s] ?? 0;
                const total = alerts.length || 1;
                const pct = (count / total) * 100;
                return (
                  <li key={s} className="flex items-center gap-3">
                    <span className={clsx("w-16 text-[11px] font-semibold", SEVERITY_STYLE[s].text)}>
                      {SEVERITY_STYLE[s].label}
                    </span>
                    <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                      <span
                        className="block h-full rounded-full"
                        style={{ width: `${pct}%`, background: `var(--color-${s.toLowerCase()})` }}
                      />
                    </span>
                    <span className="w-10 text-right font-mono text-[11px] text-muted">{count}</span>
                  </li>
                );
              })}
            </ul>
            <div className="mt-4 border-t border-border pt-3">
              <p className="text-[11px] uppercase tracking-wide text-muted">Pipeline</p>
              <dl className="mt-2 space-y-1.5 text-[12px]">
                <Row label="Prefixes tracked" value={health?.detection.prefixes_tracked ?? "—"} />
                <Row label="AS relationships" value={health?.detection.as_relationships_loaded?.toLocaleString() ?? "—"} />
                <Row label="Collectors" value={health?.collectors.length ?? "—"} />
                <Row label="WS clients" value={health?.subscribers ?? "—"} />
              </dl>
            </div>
          </Panel>
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          <Panel title="Alert categories" subtitle="current buffer" className="xl:col-span-2">
            <div className="h-56">
              {kindCounts.length === 0 ? (
                <div className="grid h-full place-items-center text-[12px] text-muted">
                  No alerts in the buffer — detection is active, nothing unauthorised observed.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={kindCounts} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 96 }}>
                    <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" stroke="var(--color-muted)" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis
                      type="category"
                      dataKey="label"
                      stroke="var(--color-muted)"
                      fontSize={11}
                      width={120}
                      tickLine={false}
                      axisLine={false}
                    />
                    <Tooltip content={<ChartTooltip unit="alerts" />} />
                    <Bar dataKey="count" radius={[0, 3, 3, 0]} isAnimationActive={false}>
                      {kindCounts.map((entry) => (
                        <Cell
                          key={entry.kind}
                          fill={entry.kind.startsWith("HIJACK") || entry.kind === "VISIBILITY_LOSS" ? "var(--color-critical)" : "var(--color-accent)"}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </Panel>

          <Panel
            title="Priority queue"
            subtitle="highest severity first"
            action={<AlertTriangle className="size-3.5 text-critical" aria-hidden="true" />}
          >
            {alerts.length === 0 ? (
              <p className="py-8 text-center text-[12px] text-muted">Nothing to triage.</p>
            ) : (
              <ul className="divide-y divide-border/60">
                {alerts.slice(0, 8).map((a) => (
                  <li key={a.alert_id} className="flex items-start gap-3 py-2">
                    <span
                      className={clsx(
                        "mt-0.5 rounded px-1.5 py-0.5 text-[10px] font-semibold ring-1",
                        SEVERITY_STYLE[a.severity].bg,
                        SEVERITY_STYLE[a.severity].text,
                        SEVERITY_STYLE[a.severity].ring,
                      )}
                    >
                      {SEVERITY_STYLE[a.severity].label}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[12px]">{a.prefix}</span>
                      <span className="block truncate text-[11px] text-muted" title={a.reasons.join("; ")}>
                        {KIND_LABEL[a.kind]} · {a.reasons[0]}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  unit,
  tone,
  series,
}: {
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean | "true" | "false" }>;
  label: string;
  value: string;
  unit?: string;
  tone: "accent" | "ok" | "high" | "critical" | "muted";
  series?: { t: number; v: number }[];
}) {
  const toneVar = { accent: "var(--color-accent)", ok: "var(--color-ok)", high: "var(--color-high)", critical: "var(--color-critical)", muted: "var(--color-muted)" }[tone];
  return (
    <div className="relative overflow-hidden rounded-[var(--radius-panel)] border border-border bg-surface p-3">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-muted">
        <Icon className="size-3.5" aria-hidden="true" />
        {label}
      </div>
      <div className="mt-1.5 flex items-baseline gap-1.5">
        <span className="font-mono text-xl font-semibold" style={{ color: toneVar }}>
          {value}
        </span>
        {unit && <span className="text-[11px] text-muted">{unit}</span>}
      </div>
      {series && series.length > 1 && (
        <svg className="mt-2 h-6 w-full" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true">
          <path
            d={sparkPath(series.map((p) => p.v))}
            fill="none"
            stroke={toneVar}
            strokeWidth={1.5}
            vectorEffect="non-scaling-stroke"
          />
        </svg>
      )}
    </div>
  );
}

function sparkPath(values: number[]): string {
  const max = Math.max(...values, 1);
  const step = 100 / Math.max(values.length - 1, 1);
  return values
    .map((v, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(2)},${(24 - (v / max) * 22).toFixed(2)}`)
    .join(" ");
}

function Panel({
  title,
  subtitle,
  className,
  action,
  children,
}: {
  title: string;
  subtitle?: string;
  className?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className={clsx("rounded-[var(--radius-panel)] border border-border bg-surface p-4", className)}>
      <header className="mb-3 flex items-center gap-2">
        <h2 className="text-[12px] font-semibold">{title}</h2>
        {subtitle && <span className="text-[11px] text-muted">{subtitle}</span>}
        <span className="ml-auto">{action}</span>
      </header>
      {children}
    </section>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between">
      <dt className="text-muted">{label}</dt>
      <dd className="font-mono">{value}</dd>
    </div>
  );
}

function ChartTooltip({ active, payload, unit }: { active?: boolean; payload?: { value: number }[]; unit: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-[11px] shadow-xl">
      <span className="font-mono font-semibold">{payload[0].value.toLocaleString()}</span>{" "}
      <span className="text-muted">{unit}</span>
    </div>
  );
}
