import { NavLink, Route, Routes } from "react-router-dom";
import { Activity, Globe, Radar, ShieldAlert } from "lucide-react";
import { clsx } from "clsx";
import { useAlertStream } from "@/lib/useAlertStream";
import { useHealth } from "@/lib/api";
import Overview from "@/views/Overview";
import Alerts from "@/views/Alerts";
import Rpki from "@/views/Rpki";
import Scope from "@/views/Scope";

const NAV = [
  { to: "/", label: "Overview", icon: Activity, end: true },
  { to: "/alerts", label: "Alerts", icon: ShieldAlert, end: false },
  { to: "/scope", label: "Scope", icon: Globe, end: false },
  { to: "/rpki", label: "RPKI", icon: Radar, end: false },
];

export default function App() {
  const { alerts, status: streamStatus } = useAlertStream();
  const { data: health } = useHealth(3000);

  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL").length;

  return (
    <div className="flex h-full flex-col bg-bg text-text">
      <header className="flex items-center gap-6 border-b border-border bg-surface px-5 py-3">
        <div className="flex items-center gap-2.5">
          <span className="grid size-7 place-items-center rounded-md bg-accent/15 ring-1 ring-accent/40">
            <Radar className="size-4 text-accent" aria-hidden="true" />
          </span>
          <div className="leading-tight">
            <h1 className="text-[13px] font-semibold tracking-tight">BGP Monitor</h1>
            <p className="text-[11px] text-muted">Routing Security Console</p>
          </div>
        </div>

        <nav aria-label="Sections" className="flex items-center gap-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-2 rounded-md px-3 py-1.5 text-[12px] font-medium transition-colors",
                  isActive ? "bg-surface-2 text-text" : "text-muted hover:bg-surface-2/60 hover:text-text",
                )
              }
            >
              <Icon className="size-3.5" aria-hidden="true" />
              {label}
              {label === "Alerts" && criticalCount > 0 && (
                <span className="rounded-full bg-critical/20 px-1.5 text-[10px] font-semibold text-critical ring-1 ring-critical/40">
                  {criticalCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-4 text-[11px]">
          <StatusDot
            ok={streamStatus === "open"}
            label={streamStatus === "open" ? "Live" : streamStatus === "connecting" ? "Connecting" : "Offline"}
          />
          <StatusDot ok={Boolean(health?.sink.enabled)} label={health?.sink.enabled ? "Graph" : "No graph"} />
          <StatusDot
            ok={Boolean(health && health.rpki.indexed_prefixes > 0)}
            label={health ? `RPKI ${(health.rpki.indexed_prefixes / 1000).toFixed(0)}k` : "RPKI —"}
          />
          <span className="font-mono text-muted">
            {health ? `${health.metrics.updates_per_second.toFixed(0)} upd/s` : "—"}
          </span>
        </div>
      </header>

      <main className="min-h-0 flex-1 overflow-hidden">
        <Routes>
          <Route path="/" element={<Overview alerts={alerts} health={health} />} />
          <Route path="/alerts" element={<Alerts alerts={alerts} />} />
          <Route path="/scope" element={<Scope />} />
          <Route path="/rpki" element={<Rpki />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}

function NotFound() {
  return (
    <div className="grid h-full place-items-center px-6 text-center">
      <div className="max-w-md space-y-2">
        <h2 className="text-sm font-semibold">No such view</h2>
        <p className="text-[12px] text-muted">
          The global AS topology map was removed: it drew 400 origins with no pan, zoom or
          drill-down, which was not a usable picture. For ad-hoc graph exploration, the Neo4j
          browser is at <span className="font-mono">http://localhost:7474</span>.
        </p>
      </div>
    </div>
  );
}

function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-muted">
      <span
        aria-hidden="true"
        className={clsx("size-1.5 rounded-full", ok ? "bg-ok" : "bg-critical")}
      />
      {label}
    </span>
  );
}
