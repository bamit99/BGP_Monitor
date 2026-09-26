"""Pipeline orchestrator: wires collector -> detection -> gate -> sinks.

Threading model
---------------
* one asyncio loop in a dedicated thread owns the RIS Live socket and the queue
* one worker thread drains the queue, runs detection, and hands off to sinks
* sinks own their own writer threads

Nothing in the detection path performs network I/O; RPKI is an in-process index
lookup and the graph sink is write-behind.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from bgpmon.collector import Collector
from bgpmon.config import Settings
from bgpmon.detect import ASGraph, DetectionEngine
from bgpmon.gate import AlertGate
from bgpmon.models import Alert, Severity, Update
from bgpmon.rpki import RPkiEngine
from bgpmon.sinks import GraphSink
from bgpmon.telemetry import PipelineMetrics

logger = logging.getLogger(__name__)

ALERT_BUFFER = 5000


class Pipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.metrics = PipelineMetrics()
        self.rpki = RPkiEngine(settings.rpki, remote_session=_make_session())
        self.as_graph = ASGraph()
        self.engine = DetectionEngine(settings.detection, self.rpki, self.as_graph)
        self.gate = AlertGate(confirm_updates=settings.detection.moas_confirm_updates)
        self.sink = GraphSink(settings.sink, metrics=self.metrics)

        self._work: "queue.Queue[Update]" = queue.Queue(maxsize=settings.source.queue_max)
        self._worker: Optional[threading.Thread] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._collector: Optional[Collector] = None
        self._stop = threading.Event()

        self.recent_alerts: "List[Alert]" = []
        self._alert_lock = threading.Lock()
        self._subscribers: "List[asyncio.Queue]" = []
        self._sub_lock = threading.Lock()
        self.visibility_alerts: List[Alert] = []

    # ---- lifecycle ----------------------------------------------------
    def start(self) -> None:
        logger.info("Loading AS relationship data from %s", self.settings.relationship_file)
        self.as_graph.load(self.settings.relationship_file)
        logger.info("Starting RPKI engine (RTR %s:%d)", self.settings.rpki.rtr_host, self.settings.rpki.rtr_port)
        self.rpki.start(background=True)
        self.sink.start()

        self._worker = threading.Thread(target=self._consume, name="detect-worker", daemon=True)
        self._worker.start()

        self._loop_thread = threading.Thread(target=self._run_feed, name="ris-feed", daemon=True)
        self._loop_thread.start()

        self._visibility_thread = threading.Thread(target=self._visibility_loop, name="visibility", daemon=True)
        self._visibility_thread.start()
        logger.info("Pipeline started: collectors=%s", ",".join(self.settings.source.collectors))

    def stop(self) -> None:
        self._stop.set()
        if self._collector:
            self._collector.stop()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(lambda: None)
        if self._loop_thread:
            self._loop_thread.join(timeout=10)
        if self._worker:
            self._worker.join(timeout=10)
        self.rpki.stop()
        self.sink.stop(drain=True)
        logger.info("Pipeline stopped")

    # ---- feed ---------------------------------------------------------
    def _run_feed(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._collector = Collector(self.settings.source)
        drain = loop.create_task(self._drain_collector_queue(self._collector))
        try:
            loop.run_until_complete(self._collector.run())
        except Exception as exc:  # noqa: BLE001
            logger.error("Feed loop crashed: %s", exc)
        finally:
            drain.cancel()
            loop.run_until_complete(asyncio.gather(drain, return_exceptions=True))
            loop.close()

    async def _drain_collector_queue(self, collector: Collector) -> None:
        """Move updates from the asyncio queue into the worker thread's queue."""
        while not self._stop.is_set():
            try:
                update = await asyncio.wait_for(collector.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                self.metrics.gauge_queue(self._work.qsize())
                continue
            try:
                self._work.put_nowait(update)
            except queue.Full:
                self.metrics.count_queue_dropped()
                logger.error("Detection queue full; dropping update %s", update.update_id)

    # ---- detection ----------------------------------------------------
    def _consume(self) -> None:
        while not self._stop.is_set():
            try:
                update = self._work.get(timeout=0.5)
            except queue.Empty:
                self.metrics.gauge_queue(0)
                continue
            try:
                self._process(update)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Detection failed for %s: %s", update.update_id, exc)
            finally:
                self._work.task_done()

    def _process(self, update: Update) -> None:
        started = time.perf_counter()
        self.metrics.record_update(update.update_type, update.collector)
        alerts = self.engine.evaluate(update)
        self.metrics.record_detect(time.perf_counter() - started)

        if update.update_type == "announcement":
            self.sink.submit_update(update)

        if not alerts:
            return

        admitted: List[Alert] = []
        for alert in alerts:
            result = self.gate.admit(alert)
            if result is None:
                self.metrics.record_suppressed("gate")
                continue
            admitted.append(result)

        for alert in admitted:
            self.metrics.record_alert(alert.kind.value, alert.severity.value)
            if alert.severity in (Severity.HIGH, Severity.CRITICAL):
                self.sink.submit_alert(alert)
            self._record_recent(alert)
            self._publish(alert)

    # ---- alert fanout -------------------------------------------------
    def _record_recent(self, alert: Alert) -> None:
        with self._alert_lock:
            self.recent_alerts.append(alert)
            if len(self.recent_alerts) > ALERT_BUFFER:
                del self.recent_alerts[:-ALERT_BUFFER]

    def _publish(self, alert: Alert) -> None:
        payload = alert.wire()
        with self._sub_lock:
            subs = list(self._subscribers)
        if not self._loop or not self._loop.is_running():
            return
        for sub in subs:
            try:
                self._loop.call_soon_threadsafe(sub.put_nowait, payload)
            except (RuntimeError, asyncio.QueueFull):
                continue

    def subscribe(self) -> asyncio.Queue:
        sub: asyncio.Queue = asyncio.Queue(maxsize=self.settings.api.ws_queue)
        with self._sub_lock:
            self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: asyncio.Queue) -> None:
        with self._sub_lock:
            if sub in self._subscribers:
                self._subscribers.remove(sub)

    def recent(self, limit: int = 200, min_severity: Optional[str] = None,
               kind: Optional[str] = None, owned_only: bool = False) -> List[Dict]:
        floor = Severity(min_severity.upper()).rank if min_severity else 0
        with self._alert_lock:
            items = list(self.recent_alerts)
        out = []
        for alert in reversed(items):
            if min_severity and alert.severity.rank < floor:
                continue
            if kind and alert.kind.value != kind:
                continue
            if owned_only and not alert.is_owned:
                continue
            out.append(alert.wire())
            if len(out) >= limit:
                break
        return out

    # ---- visibility ---------------------------------------------------
    def _visibility_loop(self) -> None:
        while not self._stop.wait(60):
            try:
                alerts = self.engine.check_visibility()
            except Exception as exc:  # noqa: BLE001
                logger.error("Visibility check failed: %s", exc)
                continue
            for alert in alerts:
                self.visibility_alerts.append(alert)
                self.metrics.record_alert(alert.kind.value, alert.severity.value)
                self.sink.submit_alert(alert)
                self._record_recent(alert)
                self._publish(alert)

    # ---- introspection ------------------------------------------------
    def health(self) -> Dict[str, object]:
        collector_stats = self._collector.stats if self._collector else {}
        return {
            "status": "running" if not self._stop.is_set() else "stopping",
            "collectors": list(self.settings.source.collectors),
            "feed": collector_stats,
            "queue_depth": self._work.qsize(),
            "rpki": self.rpki.stats,
            "detection": self.engine.snapshot(),
            "gate": self.gate.stats(),
            "sink": self.sink.stats(),
            "metrics": self.metrics.snapshot(),
            "subscribers": len(self._subscribers),
        }


def _make_session():
    try:
        import requests
        return requests.Session()
    except Exception:  # noqa: BLE001
        return None
