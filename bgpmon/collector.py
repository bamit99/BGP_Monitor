"""RIS Live collector: normalisation plus a bounded, loss-aware queue.

The previous implementation awaited a subscription acknowledgement that RIS
Live only sends when `acknowledge` is requested, silently discarding the first
BGP update per collector. Here the ack is explicit, and the socket reader never
blocks on analysis work.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import websockets

from bgpmon.config import SourceSettings
from bgpmon.models import Update, make_update_id

logger = logging.getLogger(__name__)


def parse_as_path(raw_path: Any) -> List[int]:
    """RIS Live may emit AS_SETs as nested lists; they contribute to length but
    have no single origin, so they are flattened and de-duplicated for length."""
    out: List[int] = []
    if not raw_path:
        return out
    for item in raw_path:
        if isinstance(item, int):
            out.append(item)
        elif isinstance(item, (list, tuple)):
            for sub in item:
                if isinstance(sub, int):
                    out.append(sub)
        elif isinstance(item, str) and item.isdigit():
            out.append(int(item))
    return out


class Collector:
    """Reads RIS Live and pushes normalised updates onto the pipeline queue."""

    def __init__(self, settings: SourceSettings) -> None:
        self.settings = settings
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=settings.queue_max)
        self.stats = {
            "messages": 0,
            "updates": 0,
            "withdrawals": 0,
            "dropped": 0,
            "reconnects": 0,
            "subscribe_errors": 0,
            "last_message_ts": 0.0,
        }
        self._stopping = False

    # ---- lifecycle ----------------------------------------------------
    async def run(self) -> None:
        delay = self.settings.reconnect_base_s
        while not self._stopping:
            try:
                await self._session()
                delay = self.settings.reconnect_base_s
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("RIS Live session ended: %s", exc)
            if self._stopping:
                break
            self.stats["reconnects"] += 1
            logger.info("Reconnecting to RIS Live in %.1fs", delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.settings.reconnect_max_s)

    def stop(self) -> None:
        self._stopping = True

    async def _session(self) -> None:
        url = f"{self.settings.url}?client={self.settings.client_tag}"
        async with websockets.connect(url, max_queue=None, ping_interval=20, ping_timeout=20) as ws:
            logger.info("Connected to RIS Live (%d collectors)", len(self.settings.collectors))
            for collector in self.settings.collectors:
                await self._subscribe(ws, collector)
            while not self._stopping:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=self.settings.stale_after_s * 3)
                except asyncio.TimeoutError:
                    logger.warning("RIS Live silent for %.0fs", self.settings.stale_after_s * 3)
                    continue
                self._handle(raw)

    async def _subscribe(self, ws, collector: str) -> None:
        payload = {
            "type": "ris_subscribe",
            "data": {
                "host": collector,
                "type": "UPDATE",
                "socketOptions": {
                    "includeRaw": self.settings.include_raw,
                    "acknowledge": self.settings.ack,
                },
            },
        }
        await ws.send(json.dumps(payload))
        # With acknowledge=true the server replies ris_subscribe_ok; drain until we
        # see it or a real message arrives, so nothing is lost either way.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
            except asyncio.TimeoutError:
                logger.warning("No acknowledgement for %s", collector)
                return
            msg = json.loads(raw)
            mtype = msg.get("type")
            if mtype == "ris_subscribe_ok":
                logger.info("Subscribed to %s (acknowledged)", collector)
                return
            if mtype == "ris_error":
                self.stats["subscribe_errors"] += 1
                logger.error("Subscription error for %s: %s", collector, msg.get("data"))
                return
            self._handle_message(msg)   # a real update beat the ack here — do not drop it

    # ---- normalisation ------------------------------------------------
    def _handle(self, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            logger.debug("Dropping non-JSON RIS frame")
            return
        self._handle_message(msg)

    def _handle_message(self, msg: dict) -> None:
        if msg.get("type") != "ris_message":
            if msg.get("type") == "ris_error":
                logger.error("RIS error: %s", msg.get("data"))
            return
        self.stats["messages"] += 1
        self.stats["last_message_ts"] = time.time()
        data = msg.get("data") or {}
        timestamp = datetime.fromtimestamp(data.get("timestamp", time.time()), tz=timezone.utc)
        collector = (data.get("host") or "unknown").split(".")[0]
        peer = str(data.get("peer") or "")
        peer_as = str(data.get("peer_asn") or "")
        path = parse_as_path(data.get("path"))
        as_path = ",".join(str(a) for a in path)
        communities = data.get("community")
        origin = path[-1] if path else None

        announcements = data.get("announcements") or []
        if announcements:
            for ann in announcements:
                prefixes = ann.get("prefixes") or ([ann["prefix"]] if ann.get("prefix") else [])
                next_hop = ann.get("next_hop")
                for prefix in prefixes:
                    if not prefix:
                        continue
                    self._enqueue(Update(
                        update_id=make_update_id(collector, timestamp, prefix),
                        timestamp=timestamp, prefix=prefix, collector=collector,
                        peer=peer, peer_as=peer_as, as_path=as_path,
                        as_path_list=path, origin_as=origin, next_hop=next_hop,
                        communities=communities, update_type="announcement", raw=None,
                    ))
        for wd in data.get("withdrawals") or []:
            prefix = wd.get("prefix") if isinstance(wd, dict) else wd
            if not prefix:
                continue
            self.stats["withdrawals"] += 1
            self._enqueue(Update(
                update_id=make_update_id(collector, timestamp, prefix),
                timestamp=timestamp, prefix=prefix, collector=collector,
                peer=peer, peer_as=peer_as, as_path=as_path, as_path_list=path,
                origin_as=None, communities=communities, update_type="withdrawal",
            ))

    def _enqueue(self, update: Update) -> None:
        try:
            self.queue.put_nowait(update)
            self.stats["updates"] += 1
        except asyncio.QueueFull:
            self.stats["dropped"] += 1
            if self.stats["dropped"] % 1000 == 1:
                logger.error("Pipeline queue full: %d updates dropped", self.stats["dropped"])
