"""Alert suppression for NOC signal-to-noise.

Two independent mechanisms:

* rate limiting per (kind, prefix) so one flapping prefix cannot flood the queue
* dampening of *new MOAS participants*: a fresh origin on an existing prefix is
  held for confirmation instead of paging on the first packet, which is what
  makes naive origin-change detectors unusable on real feeds.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from bgpmon.models import Alert, Kind, Severity

logger = logging.getLogger(__name__)


class AlertGate:
    def __init__(self,
                 per_key_interval_s: float = 60.0,
                 global_budget_per_min: int = 600,
                 confirm_updates: int = 3) -> None:
        self.per_key_interval_s = per_key_interval_s
        self.global_budget_per_min = global_budget_per_min
        self.confirm_updates = confirm_updates
        self._last_emit: Dict[str, datetime] = {}
        self._window: List[datetime] = []
        self._pending: Dict[Tuple[str, int, int], Set[int]] = defaultdict(set)
        self._confirmed: Dict[Tuple[str, int, int], datetime] = {}
        self.suppressed = 0
        self.emitted = 0
        self.budget_dropped = 0

    def _budget_ok(self, now: datetime) -> bool:
        cutoff = now - timedelta(minutes=1)
        self._window = [t for t in self._window if t > cutoff]
        if len(self._window) >= self.global_budget_per_min:
            self.budget_dropped += 1
            return False
        return True

    def admit(self, alert: Alert) -> Optional[Alert]:
        now = alert.timestamp if alert.timestamp.tzinfo else alert.timestamp.replace(tzinfo=timezone.utc)

        # Rate limit repeat alerts of the same class for the same prefix.
        key = f"{alert.kind.value}:{alert.prefix}"
        last = self._last_emit.get(key)
        if last is not None and (now - last).total_seconds() < self.per_key_interval_s:
            self.suppressed += 1
            return alert if alert.severity == Severity.CRITICAL and last != now else None

        # MOAS dampening: hold first sighting of a new origin until corroborated
        # by distinct sightings (different collectors count more than repeats).
        if alert.kind in (Kind.HIJACK_ORIGIN, Kind.MOAS_NEW_ORIGIN, Kind.NEW_PREFIX):
            moas_key = (alert.prefix, alert.origin_as or 0, alert.kind.value and 0 or 0)
            seen = self._pending[moas_key]
            seen.add(hash(alert.collector))
            if len(seen) < self.confirm_updates and alert.severity != Severity.CRITICAL:
                self.suppressed += 1
                return None

        self._last_emit[key] = now
        if not self._budget_ok(now):
            alert.suppressed = True
            return alert
        self._window.append(now)
        self.emitted += 1
        return alert

    def stats(self) -> Dict[str, int]:
        return {
            "emitted": self.emitted,
            "suppressed": self.suppressed,
            "budget_dropped": self.budget_dropped,
            "keys_tracked": len(self._last_emit),
        }
