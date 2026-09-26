import { useQuery } from "@tanstack/react-query";
import type { AlertResponse, Health, RPKIResult, Topology } from "./types";

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
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
