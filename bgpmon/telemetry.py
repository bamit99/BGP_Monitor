"""Telemetry: Prometheus counters/histograms plus pipeline bookkeeping."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict

logger = logging.getLogger(__name__)
_PREFIX = os.environ.get("BGPMON_METRIC_PREFIX", "bgpmon")

try:  # metrics are optional in constrained deployments
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore

    _ENABLED = True
except Exception as exc:  # noqa: BLE001
    _ENABLED = False
    logger.warning("prometheus_client unavailable (%s: %s); metrics disabled",
                   type(exc).__name__, exc)


if _ENABLED:
    UPDATES_TOTAL = Counter(f"{_PREFIX}_updates_total", "BGP updates ingested", ["collector", "type"])
    ALERTS_TOTAL = Counter(f"{_PREFIX}_alerts_total", "Alerts emitted", ["kind", "severity"])
    ALERTS_SUPPRESSED = Counter(f"{_PREFIX}_alerts_suppressed_total", "Alerts suppressed", ["reason"])
    DETECT_SECONDS = Histogram(
        f"{_PREFIX}_detect_seconds", "Per-update detection latency",
        buckets=(0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1),
    )
    QUEUE_DEPTH = Gauge(f"{_PREFIX}_queue_depth", "Pipeline queue depth")
    QUEUE_DROPPED = Counter(f"{_PREFIX}_queue_dropped_total", "Updates dropped on queue overflow")
    RPKI_SET_SIZE = Gauge(f"{_PREFIX}_rpki_vrp_prefixes", "Indexed RPKI prefixes")
    RPKI_SYNC_AGE = Gauge(f"{_PREFIX}_rpki_sync_age_seconds", "Age of the local RPKI set")
    RPKI_RESULTS = Counter(f"{_PREFIX}_rpki_results_total", "RPKI verdicts", ["state", "source"])
    SINK_WRITES = Counter(f"{_PREFIX}_sink_writes_total", "Sink writes", ["sink", "status"])
    SINK_LATENCY = Histogram(
        f"{_PREFIX}_sink_batch_seconds", "Sink batch write latency",
        buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5),
    )


@dataclass
class PipelineMetrics:
    """Fallback in-process metrics (used even when Prometheus is available)."""

    started_at: float = field(default_factory=time.time)
    updates: Dict[str, int] = field(default_factory=lambda: {"announcement": 0, "withdrawal": 0})
    alerts: int = 0
    alerts_by_kind: Dict[str, int] = field(default_factory=dict)
    alerts_by_severity: Dict[str, int] = field(default_factory=dict)
    suppressed: int = 0
    detect_seconds_total: float = 0.0
    detect_calls: int = 0

    @property
    def uptime_s(self) -> float:
        return time.time() - self.started_at

    @property
    def updates_per_second(self) -> float:
        total = sum(self.updates.values())
        return total / self.uptime_s if self.uptime_s > 0 else 0.0

    @property
    def mean_detect_us(self) -> float:
        return (self.detect_seconds_total / self.detect_calls * 1e6) if self.detect_calls else 0.0

    def record_update(self, update_type: str, collector: str) -> None:
        self.updates[update_type] = self.updates.get(update_type, 0) + 1
        if _ENABLED:
            UPDATES_TOTAL.labels(collector=collector, type=update_type).inc()

    def record_detect(self, seconds: float) -> None:
        self.detect_seconds_total += seconds
        self.detect_calls += 1
        if _ENABLED:
            DETECT_SECONDS.observe(seconds)

    def record_alert(self, kind: str, severity: str) -> None:
        self.alerts += 1
        self.alerts_by_kind[kind] = self.alerts_by_kind.get(kind, 0) + 1
        self.alerts_by_severity[severity] = self.alerts_by_severity.get(severity, 0) + 1
        if _ENABLED:
            ALERTS_TOTAL.labels(kind=kind, severity=severity).inc()

    def record_suppressed(self, reason: str = "rate_limit") -> None:
        self.suppressed += 1
        if _ENABLED:
            ALERTS_SUPPRESSED.labels(reason=reason).inc()

    def record_sink(self, sink: str, status: str, seconds: float, rows: int) -> None:
        if not _ENABLED:
            return
        SINK_WRITES.labels(sink=sink, status=status).inc(rows)
        SINK_LATENCY.observe(seconds)

    def gauge_queue(self, depth: int) -> None:
        if _ENABLED:
            QUEUE_DEPTH.set(depth)

    def count_queue_dropped(self, n: int = 1) -> None:
        if _ENABLED:
            QUEUE_DROPPED.inc(n)

    def gauge_rpki(self, prefixes: int, age_s: Optional[float]) -> None:
        if not _ENABLED:
            return
        RPKI_SET_SIZE.set(prefixes)
        if age_s is not None and age_s != float("inf"):
            RPKI_SYNC_AGE.set(age_s)

    def record_rpki(self, state: str, source: str) -> None:
        if _ENABLED:
            RPKI_RESULTS.labels(state=state, source=source).inc()

    def snapshot(self) -> Dict[str, object]:
        return {
            "uptime_s": round(self.uptime_s, 1),
            "updates_total": sum(self.updates.values()),
            "updates_by_type": dict(self.updates),
            "updates_per_second": round(self.updates_per_second, 1),
            "alerts_total": self.alerts,
            "alerts_by_kind": dict(self.alerts_by_kind),
            "alerts_by_severity": dict(self.alerts_by_severity),
            "suppressed_total": self.suppressed,
            "mean_detect_us": round(self.mean_detect_us, 1),
            "prometheus_enabled": _ENABLED,
        }
