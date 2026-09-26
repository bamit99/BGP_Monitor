export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Kind =
  | "HIJACK_ORIGIN"
  | "HIJACK_SUB_PREFIX"
  | "ROUTE_LEAK"
  | "RPKI_INVALID"
  | "RPKI_ASPAS"
  | "BOGON_ASN"
  | "BOGON_PREFIX"
  | "PREPEND"
  | "LONG_PATH"
  | "VISIBILITY_LOSS"
  | "NEW_PREFIX"
  | "MOAS_NEW_ORIGIN"
  | "RPKI_ROA_CHANGE";

export interface Alert {
  alert_id: string;
  timestamp: string;
  kind: Kind;
  severity: Severity;
  confidence: number;
  prefix: string;
  origin_as: number | null;
  expected_origins: number[];
  as_path: string;
  peer_as: string;
  collector: string;
  is_owned: boolean;
  reasons: string[];
  evidence: Record<string, unknown>;
}

export interface AlertResponse {
  source: "memory" | "graph";
  count: number;
  alerts: Alert[];
}

export interface Health {
  status: string;
  collectors: string[];
  feed: Record<string, number>;
  queue_depth: number;
  rpki: {
    indexed_prefixes: number;
    aspa_objects: number;
    set_age_s: number | null;
    transport: string;
    failures: number;
    last_error: string | null;
    remote_degraded: boolean;
  };
  detection: {
    prefixes_tracked: number;
    owned_prefixes: number;
    critical_prefixes: number;
    as_relationships_loaded: number;
    alerts_by_kind: Record<string, number>;
  };
  gate: Record<string, number>;
  sink: {
    enabled: boolean;
    uri: string;
    updates_written: number;
    alerts_written: number;
    failed_batches: number;
    pending_updates: number;
    pending_alerts: number;
    last_error: string | null;
  };
  metrics: {
    uptime_s: number;
    updates_total: number;
    updates_by_type: Record<string, number>;
    updates_per_second: number;
    alerts_total: number;
    alerts_by_kind: Record<string, number>;
    alerts_by_severity: Record<string, number>;
    suppressed_total: number;
    mean_detect_us: number;
    prometheus_enabled: boolean;
  };
  subscribers: number;
}

export interface TopologyNode {
  asn: number;
  origin_count: number;
}

export interface TopologyEdge {
  from: number;
  to: number;
  count: number;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export interface RPKIResult {
  prefix: string;
  origin_as: number;
  state: "VALID" | "INVALID" | "NOT_FOUND";
  reason: string;
  source: string;
  matched: { asn: number; max_length: number }[];
  offending: { asn: number; max_length: number; why: string }[];
}
