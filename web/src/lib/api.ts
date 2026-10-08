import { useQuery } from "@tanstack/react-query";
import type { AlertResponse, Health, RPKIResult, ScopeSearchResponse, Topology } from "./types";

/**
 * Build-time only: a Vite env var is inlined into the bundle at `vite build`.
 * A runtime token would need a settings input and a secret store, which is
 * part of the enterprise deployment work in ROADMAP.md.
 */
export const apiToken = (): string => import.meta.env.VITE_API_TOKEN ?? "";

export function apiHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = apiToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/**
 * The most likely 401 by far is a token configured on the server but not baked
 * into the bundle. Say so, rather than showing a bare 401 the operator will
 * read as a broken dashboard.
 */
function describeFailure(res: Response, url: string): string {
  if (res.status === 401 && !apiToken()) {
    return (
      `401 for ${url}: the server has BGPMON_API_TOKEN set but this dashboard was built ` +
      `without VITE_API_TOKEN. Set VITE_API_TOKEN in web/.env to the same value and ` +
      `rebuild (npm run build), or clear BGPMON_API_TOKEN on the server.`
    );
  }
  return `${res.status} ${res.statusText} for ${url}`;
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) throw new Error(describeFailure(res, url));
  return (await res.json()) as T;
}

export function useHealth(intervalMs = 2000) {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => getJSON<Health>("/api/health"),
    refetchInterval: intervalMs,
    staleTime: intervalMs / 2,
  });
}

export function useTopology(intervalMs = 15000) {
  return useQuery({
    queryKey: ["topology"],
    queryFn: () => getJSON<Topology>("/api/topology?limit=400"),
    refetchInterval: intervalMs,
  });
}

export function useAlertHistory(params: { kind?: string; severity?: string; limit?: number }) {
  const search = new URLSearchParams();
  search.set("limit", String(params.limit ?? 300));
  if (params.kind) search.set("kind", params.kind);
  if (params.severity) search.set("severity", params.severity);
  return useQuery({
    queryKey: ["alert-history", params.kind ?? "", params.severity ?? "", params.limit ?? 300],
    queryFn: () => getJSON<AlertResponse>(`/api/alerts?${search.toString()}`),
    refetchInterval: 10000,
  });
}

export function useRpkiCheck(prefix: string, originAs: number | null) {
  return useQuery({
    queryKey: ["rpki", prefix, originAs],
    queryFn: () => getJSON<RPKIResult>(`/api/rpki/${prefix}/${originAs}`),
    enabled: Boolean(prefix) && originAs !== null && originAs > 0,
    retry: false,
  });
}

export function useScopeSearch(query: string) {
  return useQuery({
    queryKey: ["scope", query],
    queryFn: () => getJSON<ScopeSearchResponse>(`/api/scope/search?q=${encodeURIComponent(query)}`),
    enabled: Boolean(query),
    retry: 1,
  });
}
