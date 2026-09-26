"""Neo4j sink: batched, retrying, and linking alerts to the update that caused them.

Batch writes replace the previous one-transaction-per-announcement pattern.
`update_id` and `alert_id` now come from a single shared helper, so the
TRIGGERED_BY edge actually resolves instead of silently matching nothing.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from bgpmon.config import SinkSettings
from bgpmon.models import Alert, Update

logger = logging.getLogger(__name__)

try:
    from neo4j import GraphDatabase
    _HAVE_NEO4J = True
except Exception:  # noqa: BLE001
    _HAVE_NEO4J = False
    logger.warning("neo4j driver unavailable; graph sink disabled")


SCHEMA_STATEMENTS = (
    "CREATE CONSTRAINT bgpupdate_id IF NOT EXISTS FOR (u:BGPUpdate) REQUIRE u.update_id IS UNIQUE",
    "CREATE CONSTRAINT prefix_key IF NOT EXISTS FOR (p:Prefix) REQUIRE p.prefix IS UNIQUE",
    "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:SecurityAlert) REQUIRE a.alert_id IS UNIQUE",
    "CREATE INDEX bgpupdate_ts IF NOT EXISTS FOR (u:BGPUpdate) ON (u.timestamp)",
    "CREATE INDEX bgpupdate_prefix IF NOT EXISTS FOR (u:BGPUpdate) ON (u.prefix)",
    "CREATE INDEX alert_ts IF NOT EXISTS FOR (a:SecurityAlert) ON (a.timestamp)",
    "CREATE INDEX alert_prefix IF NOT EXISTS FOR (a:SecurityAlert) ON (a.prefix)",
    "CREATE INDEX alert_severity IF NOT EXISTS FOR (a:SecurityAlert) ON (a.severity)",
)

_UPSERT_STREAM = """
UNWIND $rows AS row
MERGE (u:BGPUpdate {update_id: row.update_id})
SET u.timestamp = row.timestamp,
    u.collector = row.collector,
    u.peer = row.peer,
    u.peer_as = row.peer_as,
    u.prefix = row.prefix,
    u.as_path = row.as_path,
    u.origin_as = row.origin_as,
    u.next_hop = row.next_hop,
    u.update_type = row.update_type
WITH u, row
MERGE (p:Prefix {prefix: row.prefix})
MERGE (u)-[:AFFECTS]->(p)
MERGE (c:Collector {id: row.collector})
MERGE (c)-[:REPORTED]->(u)
"""

_UPSERT_ALERT = """
UNWIND $rows AS row
MERGE (a:SecurityAlert {alert_id: row.alert_id})
SET a.timestamp = row.timestamp,
    a.kind = row.kind,
    a.severity = row.severity,
    a.confidence = row.confidence,
    a.prefix = row.prefix,
    a.prefix_key = row.prefix_key,
    a.origin_as = row.origin_as,
    a.expected_origins = row.expected_origins,
    a.as_path = row.as_path,
    a.peer_as = row.peer_as,
    a.collector = row.collector,
    a.reasons = row.reasons,
    a.evidence = row.evidence,
    a.is_owned = row.is_owned,
    a.update_id = row.update_id
WITH a, row
MERGE (p:Prefix {prefix: row.prefix})
MERGE (a)-[:AFFECTS]->(p)
WITH a, row
OPTIONAL MATCH (u:BGPUpdate {update_id: row.update_id})
FOREACH (_ IN CASE WHEN u IS NULL THEN [] ELSE [1] END | MERGE (a)-[:TRIGGERED_BY]->(u))
"""


class GraphSink:
    """Write-behind Neo4j sink. Never blocks the detection loop on I/O."""

    def __init__(self, settings: SinkSettings, metrics=None) -> None:
        self.settings = settings
        self.metrics = metrics
        self._driver = None
        self._lock = threading.Lock()
        self._updates: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.enabled = False
        self.last_error: Optional[str] = None
        self.written_updates = 0
        self.written_alerts = 0
        self.failed_batches = 0
        # Adjacency aggregates kept in memory; see topology().
        self._edge_counts: Counter = Counter()
        self._origin_counts: Counter = Counter()
        self._aggregate_cap = 20_000

    # ---- lifecycle ----------------------------------------------------
    def start(self) -> bool:
        if not (self.settings.neo4j_enabled and _HAVE_NEO4J and self.settings.neo4j_password):
            logger.info("Graph sink disabled (enabled=%s driver=%s)", self.settings.neo4j_enabled, _HAVE_NEO4J)
            return False
        try:
            self._driver = GraphDatabase.driver(
                self.settings.neo4j_uri,
                auth=(self.settings.neo4j_user, self.settings.neo4j_password),
                max_connection_pool_size=32,
            )
            self._driver.verify_connectivity()
            self._init_schema()
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            logger.error("Neo4j connection failed: %s", exc)
            self._driver = None
            return False
        self.enabled = True
        self._thread = threading.Thread(target=self._loop, name="neo4j-sink", daemon=True)
        self._thread.start()
        logger.info("Graph sink online at %s", self.settings.neo4j_uri)
        return True

    def stop(self, drain: bool = True) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if drain:
            self.flush()
        if self._driver:
            self._driver.close()
            self._driver = None

    def _init_schema(self) -> None:
        with self._driver.session() as session:
            for statement in SCHEMA_STATEMENTS:
                try:
                    session.run(statement)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Schema statement failed (%s): %s", statement.split()[2], exc)

    # ---- producing ----------------------------------------------------
    def submit_update(self, update: Update) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._updates.append({
                "update_id": update.update_id,
                "timestamp": update.timestamp,
                "collector": update.collector,
                "peer": update.peer,
                "peer_as": update.peer_as,
                "prefix": update.prefix,
                "as_path": update.as_path,
                "origin_as": update.origin_as,
                "next_hop": update.next_hop,
                "update_type": update.update_type,
            })
            # Aggregate adjacency here rather than deriving it from raw history
            # on every dashboard load: ORDER BY timestamp cannot be index-backed
            # while filtering on as_path, so the query scanned every BGPUpdate
            # node (measured 23-28s). These counters are O(1) per update.
            if update.as_path_list:
                path = update.as_path_list
                if update.origin_as is not None:
                    self._origin_counts[update.origin_as] += 1
                for i in range(len(path) - 1):
                    if path[i] != path[i + 1]:
                        self._edge_counts[(path[i], path[i + 1])] += 1

    def _trim_aggregates(self) -> None:
        """Keep the largest contributors so the map cannot grow without bound on
        a long-running full-table feed."""
        if len(self._edge_counts) <= self._aggregate_cap:
            return
        top = dict(sorted(self._edge_counts.items(), key=lambda kv: -kv[1])[: self._aggregate_cap // 2])
        self._edge_counts = Counter(top)
        if len(self._origin_counts) > self._aggregate_cap:
            top_o = dict(sorted(self._origin_counts.items(), key=lambda kv: -kv[1])[: self._aggregate_cap // 2])
            self._origin_counts = Counter(top_o)

    def submit_alert(self, alert: Alert) -> None:
        if not self.enabled:
            return
        payload = alert.to_dict()
        payload["evidence"] = json.dumps(payload.get("evidence") or {})
        payload["prefix_key"] = payload["prefix"]
        with self._lock:
            self._alerts.append(payload)

    # ---- writing ------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.wait(self.settings.flush_interval_s):
            self.flush()

    def flush(self) -> None:
        if not self.enabled or self._driver is None:
            return
        with self._lock:
            updates, self._updates = self._updates, []
            alerts, self._alerts = self._alerts, []
        with self._lock:
            self._trim_aggregates()
        if updates:
            self._write(_UPSERT_STREAM, updates, "updates")
        if alerts:
            self._write(_UPSERT_ALERT, alerts, "alerts")

    def _write(self, query: str, rows: Sequence[Dict[str, Any]], label: str) -> None:
        started = time.perf_counter()
        for attempt in range(1, self.settings.max_retries + 1):
            try:
                with self._driver.session() as session:
                    for i in range(0, len(rows), self.settings.batch_size):
                        session.execute_write(lambda tx, chunk=rows[i:i + self.settings.batch_size]:
                                              tx.run(query, rows=chunk).consume())
                elapsed = time.perf_counter() - started
                if label == "updates":
                    self.written_updates += len(rows)
                else:
                    self.written_alerts += len(rows)
                if self.metrics is not None:
                    self.metrics.record_sink(label, "ok", elapsed, len(rows))
                logger.debug("Sink wrote %d %s in %.3fs", len(rows), label, elapsed)
                return
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)
                if attempt == self.settings.max_retries:
                    self.failed_batches += 1
                    if self.metrics is not None:
                        self.metrics.record_sink(label, "error", time.perf_counter() - started, len(rows))
                    logger.error("Sink write failed for %d %s after %d attempts: %s",
                                 len(rows), label, attempt, exc)
                    return
                time.sleep(0.5 * attempt)

    # ---- queries used by the API --------------------------------------
    def recent_alerts(self, limit: int = 200, min_severity: Optional[str] = None,
                      kind: Optional[str] = None, prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.enabled or self._driver is None:
            return []
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        query = """
        MATCH (a:SecurityAlert)
        WHERE ($min_sev IS NULL OR a.severity IN $allowed)
          AND ($kind IS NULL OR a.kind = $kind)
          AND ($prefix IS NULL OR a.prefix STARTS WITH $prefix)
        RETURN a ORDER BY a.timestamp DESC LIMIT $limit
        """
        allowed = []
        if min_severity:
            allowed = [s for s, v in order.items() if v >= order.get(min_severity.upper(), 0)]
        try:
            with self._driver.session() as session:
                result = session.run(query, min_sev=min_severity, allowed=allowed,
                                     kind=kind, prefix=prefix, limit=limit)
                out = []
                for record in result:
                    node = dict(record["a"])
                    if isinstance(node.get("evidence"), str):
                        try:
                            node["evidence"] = json.loads(node["evidence"])
                        except json.JSONDecodeError:
                            pass
                    out.append(node)
                return out
        except Exception as exc:  # noqa: BLE001
            logger.error("recent_alerts query failed: %s", exc)
            return []

    def prefix_history(self, prefix: str, limit: int = 50) -> List[Dict[str, Any]]:
        if not self.enabled or self._driver is None:
            return []
        try:
            with self._driver.session() as session:
                result = session.run("""
                    MATCH (u:BGPUpdate {prefix: $prefix})
                    RETURN u.update_id AS update_id, u.timestamp AS timestamp, u.collector AS collector,
                           u.as_path AS as_path, u.origin_as AS origin_as, u.update_type AS update_type
                    ORDER BY u.timestamp DESC LIMIT $limit
                """, prefix=prefix, limit=limit)
                return [dict(r) for r in result]
        except Exception as exc:  # noqa: BLE001
            logger.error("prefix_history query failed: %s", exc)
            return []

    def topology(self, limit: int = 300) -> Dict[str, Any]:
        """Observed AS adjacency for the graph view.

        Served from in-process counters (populated as updates are produced).
        The Neo4j path is a fallback for a freshly restarted process, and is
        restricted to a recent time window so it can use the timestamp index.
        """
        with self._lock:
            edges = self._edge_counts.most_common(limit * 3)
            origins = self._origin_counts.most_common(limit)
        if edges or origins:
            return {
                "nodes": [{"asn": asn, "origin_count": count} for asn, count in origins],
                "edges": [{"from": a, "to": b, "count": count} for (a, b), count in edges[: limit * 2]],
                "source": "live",
            }
        return self._topology_from_graph(limit)

    def _topology_from_graph(self, limit: int) -> Dict[str, Any]:
        if not self.enabled or self._driver is None:
            return {"nodes": [], "edges": [], "source": "empty"}
        try:
            with self._driver.session() as session:
                since = datetime.now(timezone.utc) - timedelta(minutes=15)
                result = session.run("""
                    MATCH (u:BGPUpdate)
                    WHERE u.timestamp > $since AND u.as_path IS NOT NULL AND u.as_path <> ''
                    WITH u ORDER BY u.timestamp DESC LIMIT $limit
                    RETURN u.as_path AS as_path
                """, since=since, limit=limit)
                edges = {}
                origins = {}
                for record in result:
                    asns = [int(x) for x in (record["as_path"] or "").split(",") if x.isdigit()]
                    for i in range(len(asns) - 1):
                        if asns[i] != asns[i + 1]:
                            edges[(asns[i], asns[i + 1])] = edges.get((asns[i], asns[i + 1]), 0) + 1
                    if asns:
                        origins[asns[-1]] = origins.get(asns[-1], 0) + 1
                nodes = [{"asn": asn, "origin_count": count} for asn, count in
                         sorted(origins.items(), key=lambda x: -x[1])[:200]]
                return {
                    "nodes": nodes,
                    "edges": [{"from": a, "to": b, "count": c} for (a, b), c in
                              sorted(edges.items(), key=lambda x: -x[1])[:500]],
                    "source": "graph",
                }
        except Exception as exc:  # noqa: BLE001
            logger.error("topology query failed: %s", exc)
            return {"nodes": [], "edges": []}

    def stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "uri": self.settings.neo4j_uri,
            "updates_written": self.written_updates,
            "alerts_written": self.written_alerts,
            "failed_batches": self.failed_batches,
            "pending_updates": len(self._updates),
            "pending_alerts": len(self._alerts),
            "last_error": self.last_error,
        }


def _noop_metrics():
    class _M:
        def record_sink(self, *a, **k):
            pass
    return _M()
