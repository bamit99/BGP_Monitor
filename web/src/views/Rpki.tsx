import { useState } from "react";
import { clsx } from "clsx";
import { BadgeCheck, BadgeX, HelpCircle, Radar, Search } from "lucide-react";
import { useHealth, useRpkiCheck } from "@/lib/api";

/**
 * RPKI inspector.
 *
 * Deliberately honest about coverage: NOT_FOUND means "no ROA covers this
 * prefix", which is not a routing fault, so it is presented as neutral rather
 * than as a warning. Only INVALID is a finding.
 */
export default function Rpki() {
  const { data: health } = useHealth(5000);
  const [prefix, setPrefix] = useState("1.1.1.0/24");
  const [origin, setOrigin] = useState("13335");
  const parsedOrigin = Number.parseInt(origin.replace(/^AS/i, ""), 10);
  const { data, isFetching, error } = useRpkiCheck(prefix, Number.isNaN(parsedOrigin) ? null : parsedOrigin);

  const state = data?.state;
  const verdictStyle =
    state === "VALID"
      ? { icon: BadgeCheck, cls: "text-ok", bg: "bg-ok/10", ring: "ring-ok/30", label: "Valid" }
      : state === "INVALID"
        ? { icon: BadgeX, cls: "text-critical", bg: "bg-critical/10", ring: "ring-critical/30", label: "Invalid" }
        : { icon: HelpCircle, cls: "text-muted", bg: "bg-surface-2", ring: "ring-border", label: "No ROA coverage" };

  const VerdictIcon = verdictStyle.icon;

  return (
    <div className="h-full overflow-auto p-5">
      <div className="mx-auto grid max-w-4xl gap-4">
        <section className="rounded-[var(--radius-panel)] border border-border bg-surface p-4">
          <header className="mb-3 flex items-center gap-2">
            <Radar className="size-4 text-accent" aria-hidden="true" />
            <h2 className="text-[13px] font-semibold">RPKI validation</h2>
            <span className="text-[11px] text-muted">
              local validator over RTR · {health?.rpki.indexed_prefixes.toLocaleString() ?? "—"} prefixes indexed
            </span>
          </header>

          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
            }}
          >
            <label className="flex flex-col gap-1">
              <span className="text-[11px] uppercase tracking-wide text-muted">Prefix</span>
              <input
                value={prefix}
                onChange={(e) => setPrefix(e.target.value.trim())}
                className="w-56 rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-[12px] outline-none focus:border-accent/60"
                placeholder="203.0.113.0/24"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[11px] uppercase tracking-wide text-muted">Origin AS</span>
              <input
                value={origin}
                onChange={(e) => setOrigin(e.target.value.trim())}
                className="w-32 rounded-md border border-border bg-bg px-2.5 py-1.5 font-mono text-[12px] outline-none focus:border-accent/60"
                placeholder="64496"
              />
            </label>
            <span className="ml-auto flex items-center gap-1.5 text-[11px] text-muted">
              <Search className="size-3.5" aria-hidden="true" />
              {isFetching ? "Validating…" : "Queries the local VRP set"}
            </span>
          </form>

          <div className="mt-4">
            {error && <p className="text-[12px] text-critical">Lookup failed: {String((error as Error).message)}</p>}
            {data && (
              <div className={clsx("rounded-md p-4 ring-1", verdictStyle.bg, verdictStyle.ring)}>
                <div className="flex items-center gap-2">
                  <VerdictIcon className={clsx("size-5", verdictStyle.cls)} aria-hidden="true" />
                  <span className={clsx("text-[14px] font-semibold", verdictStyle.cls)}>{verdictStyle.label}</span>
                  <span className="font-mono text-[12px] text-muted">
                    {data.prefix} · AS{data.origin_as}
                  </span>
                  <span className="ml-auto rounded bg-surface-2 px-2 py-0.5 text-[10px] text-muted">
                    via {data.source}
                  </span>
                </div>
                <p className="mt-2 text-[12px] text-muted">{data.reason}</p>

                {data.matched.length > 0 && (
                  <div className="mt-3">
                    <p className="text-[11px] uppercase tracking-wide text-muted">Matching VRPs</p>
                    <ul className="mt-1 flex flex-wrap gap-1.5">
                      {data.matched.map((m) => (
                        <li key={`${m.asn}-${m.max_length}`} className="rounded bg-surface-2 px-2 py-0.5 font-mono text-[11px]">
                          AS{m.asn} maxLength {m.max_length}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {data.offending.length > 0 && (
                  <div className="mt-3">
                    <p className="text-[11px] uppercase tracking-wide text-muted">Why it is invalid</p>
                    <ul className="mt-1 space-y-1">
                      {data.offending.map((o, i) => (
                        <li key={i} className="text-[12px]">
                          <span className="font-mono">AS{o.asn}</span> maxLength {o.max_length} — {o.why}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        <section className="rounded-[var(--radius-panel)] border border-border bg-surface p-4">
          <h2 className="text-[13px] font-semibold">Validator status</h2>
          <dl className="mt-3 grid grid-cols-2 gap-3 text-[12px] sm:grid-cols-4">
            <Stat label="Transport" value={health?.rpki.transport ?? "—"} />
            <Stat label="Prefixes" value={health?.rpki.indexed_prefixes.toLocaleString() ?? "—"} />
            <Stat label="Set age" value={health?.rpki.set_age_s != null ? `${health.rpki.set_age_s}s` : "—"} />
            <Stat label="ASPA objects" value={String(health?.rpki.aspa_objects ?? 0)} />
          </dl>
          {health?.rpki.last_error && (
            <p className="mt-3 text-[11px] text-high">Last sync error: {health.rpki.last_error}</p>
          )}
          <p className="mt-3 text-[11px] text-muted">
            ASPA objects are not yet published in the global RPKI, so ASPA-based checks stay inert until an
            operator supplies objects; the console reports that state rather than implying coverage.
          </p>
        </section>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-bg px-3 py-2">
      <dt className="text-[10px] uppercase tracking-wide text-muted">{label}</dt>
      <dd className="mt-0.5 font-mono text-[13px]">{value}</dd>
    </div>
  );
}
