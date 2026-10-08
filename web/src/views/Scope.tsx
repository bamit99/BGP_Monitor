import { useState } from "react";
import { clsx } from "clsx";
import { Globe, Network, Search, ShieldCheck, ShieldX, HelpCircle, Loader2 } from "lucide-react";
import { useScopeSearch } from "@/lib/api";

/**
 * Scope / telecom lookup.
 *
 * Search by ASN (AS8220) or by operator name ("Colt"). Results come from
 * RIPEstat announced-prefixes and PeeringDB name search, with each prefix
 * cross-checked against the local RPKI validator.
 */
export default function Scope() {
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");
  const { data, isFetching, error } = useScopeSearch(submitted);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = query.trim();
    if (trimmed) setSubmitted(trimmed);
  };

  return (
    <div className="h-full overflow-auto p-5">
      <div className="mx-auto grid max-w-6xl gap-4">
        <section className="rounded-[var(--radius-panel)] border border-border bg-surface p-4">
          <header className="mb-3 flex items-center gap-2">
            <Globe className="size-4 text-accent" aria-hidden="true" />
            <h2 className="text-[13px] font-semibold">Telecom scope lookup</h2>
            <span className="text-[11px] text-muted">RIPEstat + PeeringDB, local RPKI cross-check</span>
          </header>

          <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
            <label className="flex flex-1 flex-col gap-1">
              <span className="text-[11px] uppercase tracking-wide text-muted">ASN or operator name</span>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="AS8220 or Colt"
                className="w-full min-w-[16rem] rounded-md border border-border bg-bg px-2.5 py-1.5 text-[12px] outline-none focus:border-accent/60"
              />
            </label>
            <button
              type="submit"
              disabled={isFetching || !query.trim()}
              className={clsx(
                "flex items-center gap-2 rounded-md px-4 py-1.5 text-[12px] font-medium transition-colors",
                isFetching || !query.trim()
                  ? "cursor-not-allowed bg-surface-2 text-muted"
                  : "bg-accent/15 text-accent hover:bg-accent/25",
              )}
            >
              {isFetching ? <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <Search className="size-3.5" aria-hidden="true" />}
              Search
            </button>
          </form>

          {error && (
            <p className="mt-3 text-[12px] text-critical">
              Lookup failed: {String((error as Error).message)}
            </p>
          )}
        </section>

        {data && data.asns.length === 0 && submitted && (
          <section className="rounded-[var(--radius-panel)] border border-border bg-surface p-6 text-center text-muted">
            <Network className="mx-auto size-8" aria-hidden="true" />
            <p className="mt-3 text-[13px] font-medium">No ASN found</p>
            <p className="mt-1 text-[12px]">Try an exact ASN like AS13335 or a shorter operator name.</p>
          </section>
        )}

        {data?.asns.map((asn) => (
          <section key={asn.asn} className="rounded-[var(--radius-panel)] border border-border bg-surface p-4">
            <header className="mb-3 flex items-center gap-3">
              <div className="grid size-8 place-items-center rounded-md bg-accent/15 text-accent">
                <Network className="size-4" aria-hidden="true" />
              </div>
              <div className="leading-tight">
                <h3 className="text-[13px] font-semibold">
                  {asn.name} · AS{asn.asn}
                </h3>
                {asn.country && <span className="text-[11px] text-muted">{asn.country}</span>}
              </div>
              <span className="ml-auto rounded bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-muted">
                {asn.prefixes.length} prefixes
              </span>
            </header>

            {asn.prefixes.length === 0 ? (
              <p className="py-6 text-center text-[12px] text-muted">No announced prefixes returned by RIPEstat.</p>
            ) : (
              <div className="max-h-[28rem] overflow-auto rounded-md border border-border bg-bg">
                <table className="w-full text-left text-[12px]">
                  <thead className="sticky top-0 z-10 bg-surface-2 text-[11px] uppercase tracking-wide text-muted">
                    <tr>
                      <th className="px-3 py-2 font-medium">Prefix</th>
                      <th className="px-3 py-2 font-medium">Origin AS</th>
                      <th className="px-3 py-2 font-medium">RPKI</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {asn.prefixes.map((p, i) => (
                      <tr key={`${p.prefix}-${i}`} className="hover:bg-surface/60">
                        <td className="px-3 py-2 font-mono">{p.prefix}</td>
                        <td className="px-3 py-2 font-mono">{p.origin_as ?? "—"}</td>
                        <td className="px-3 py-2">
                          <RPKIBadge state={p.rpki_state} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        ))}
      </div>
    </div>
  );
}

function RPKIBadge({ state }: { state: string | null }) {
  if (state === "VALID") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-ok/10 px-1.5 py-0.5 text-[11px] text-ok ring-1 ring-ok/30">
        <ShieldCheck className="size-3" aria-hidden="true" /> Valid
      </span>
    );
  }
  if (state === "INVALID") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-critical/10 px-1.5 py-0.5 text-[11px] text-critical ring-1 ring-critical/30">
        <ShieldX className="size-3" aria-hidden="true" /> Invalid
      </span>
    );
  }
  if (state === "NOT_FOUND" || state == null) {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted ring-1 ring-border">
        <HelpCircle className="size-3" aria-hidden="true" /> No ROA
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted ring-1 ring-border">
      <HelpCircle className="size-3" aria-hidden="true" /> {state}
    </span>
  );
}
