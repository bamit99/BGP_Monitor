import type { Severity, Kind } from "./types";

/** Severity presentation. Colour is never the only signal: every chip also
 *  carries its label, and rows expose severity via an accessible name. */
export const SEVERITY_STYLE: Record<Severity, { text: string; bg: string; ring: string; label: string }> = {
  CRITICAL: { text: "text-critical", bg: "bg-critical/12", ring: "ring-critical/40", label: "Critical" },
  HIGH: { text: "text-high", bg: "bg-high/12", ring: "ring-high/40", label: "High" },
  MEDIUM: { text: "text-medium", bg: "bg-medium/12", ring: "ring-medium/40", label: "Medium" },
  LOW: { text: "text-low", bg: "bg-low/12", ring: "ring-low/40", label: "Low" },
  INFO: { text: "text-info", bg: "bg-info/12", ring: "ring-info/40", label: "Info" },
};

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export const KIND_LABEL: Record<Kind, string> = {
  HIJACK_ORIGIN: "Origin hijack",
  HIJACK_SUB_PREFIX: "Sub-prefix hijack",
  ROUTE_LEAK: "Route leak",
  RPKI_INVALID: "RPKI invalid",
  RPKI_ASPAS: "ASPA violation",
  BOGON_ASN: "Bogon ASN",
  BOGON_PREFIX: "Bogon prefix",
  PREPEND: "Path prepending",
  LONG_PATH: "Abnormal path length",
  VISIBILITY_LOSS: "Visibility loss",
  NEW_PREFIX: "New prefix",
  MOAS_NEW_ORIGIN: "New MOAS origin",
  RPKI_ROA_CHANGE: "ROA change",
};

export const ALL_KINDS = Object.keys(KIND_LABEL) as Kind[];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(s);
}

export function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const delta = Date.now() - then;
  const s = Math.max(0, Math.round(delta / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function shortPath(asPath: string, max = 6): string {
  if (!asPath) return "—";
  const parts = asPath.split(",");
  if (parts.length <= max) return parts.join(" → ");
  return `${parts.slice(0, 3).join(" → ")} … ${parts.slice(-2).join(" → ")}`;
}
