"""Incident correlation: group related alerts into an episode.

An episode is one incident: the alerts for a prefix (optionally per origin)
within a time window, scored so a triage view can rank them.

Ported in design from `utils/episode_manager.py` on `archive/pre-rebuild-master`.
Five defects in that file were deliberately not carried over; each is pinned by a
test in `tests/test_episodes.py`:

  1. its `severity_map` had no CRITICAL, so a CRITICAL alert scored 0 and never
     raised `max_severity` above HIGH
  2. `cleanup_old_episodes` was defined twice; the second shadowed the first and
     the 24h threshold was dead code
  3. naive `datetime.now()` mixed with aware ISO timestamps raises TypeError
  4. `determine_hijack_scope` was a self-declared placeholder always returning
     the string "UNKNOWN"
  5. `process_event` stored an episode twice when it closed

The one semantic change. The old matcher keyed on `previous_origin_as`, which is
the "compare to the last origin seen" antipattern `Logic.md` rejects because it
fires on every update of a legitimate MOAS prefix.

An obvious-looking replacement — key on "any origin previously seen on this
prefix" — was tried and rejected. It misattributes: once an attacker's own
episode expires, the attacker's next announcement is filed under the legitimate
owner's episode, because the owner's episode still accepts any seen origin. A
hijack detector must not do that.

So membership is strictly `(prefix, origin AS)` inside a time window, which is
enough on its own once the last-seen comparison is gone. Origin history is still
tracked, but only to decide whether a *new* alert represents an origin change,
which affects score and subtype — never membership.

Consequence: a hijack and its recovery are two episodes, one per origin. That is
clearer than the old conflation, and an operator reading an episode sees a
single origin throughout.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Mapping, Optional, Set

from bgpmon.models import Alert, Severity

logger = logging.getLogger(__name__)

_DEFAULT_SCORES: Mapping[str, float] = {
    "LOW": 1.0,
    "MEDIUM": 5.0,
    "HIGH": 10.0,
    "CRITICAL": 25.0,
}


@dataclass(frozen=True)
class EpisodeConfig:
    """All tuning in one place.

    `cleanup_threshold_s` is deliberately a separate field from `time_window_s`.
    The old module declared `cleanup_old_episodes` twice, and the shadowed second
    definition used the 60-minute time window as its cleanup threshold while the
    24-hour setting sat unread. One named source of truth per threshold.
    """

    time_window_s: int = 3600
    max_events: int = 100
    cleanup_threshold_s: int = 86400
    severity_scores: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_SCORES))
    critical_prefix_multiplier: float = 2.0
    rpki_invalid_multiplier: float = 1.5

    def score_for(self, severity: Severity) -> float:
        return float(self.severity_scores.get(severity.value, 1.0))


class Episode:
    """One incident: related alerts for a prefix, optionally keyed by origin."""

    def __init__(self, prefix: str, origin_as: Optional[int], start_time: datetime,
                 config: EpisodeConfig) -> None:
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        self.id = str(uuid.uuid4())
        self.prefix = prefix
        self.origin_as = origin_as
        self.start_time = start_time
        self.end_time = start_time
        self.config = config
        self.event_count = 0
        self.score = 0.0
        self.max_severity = Severity.LOW
        self.status = "OPEN"
        self.alert_ids: List[str] = []
        self.origins: Set[int] = set()
        self.metadata: Dict[str, object] = {
            "hijack_subtype": "UNKNOWN",
            "edit_distance": None,
            "affected_asns": set(),
            "is_critical_prefix": False,
        }
        self._last_as_path: Optional[str] = None

    # ---- membership ---------------------------------------------------
    def should_include(self, alert: Alert) -> bool:
        """Does this alert belong to this episode?

        Strictly `(prefix, origin AS)` within the time window. A different origin
        is a different incident: an attacker's announcements must never be filed
        under the legitimate owner's episode.
        """
        if alert.prefix != self.prefix or alert.origin_as != self.origin_as:
            return False
        age = (alert.timestamp - self.end_time).total_seconds()
        return age <= self.config.time_window_s

    # ---- accumulation -------------------------------------------------
    def add_event(self, alert: Alert, origin_changed: bool,
                  is_critical_prefix: bool = False) -> None:
        if alert.timestamp.tzinfo is None:
            alert.timestamp = alert.timestamp.replace(tzinfo=timezone.utc)
        self.end_time = max(self.end_time, alert.timestamp)
        self.event_count += 1
        self.alert_ids.append(alert.alert_id)
        if alert.origin_as is not None:
            self.origins.add(alert.origin_as)

        self.max_severity = Severity.max(self.max_severity, alert.severity)
        self.score += self._event_score(alert, origin_changed, is_critical_prefix)
        self._update_metadata(alert, origin_changed, is_critical_prefix)

    def _event_score(self, alert: Alert, origin_changed: bool,
                     is_critical_prefix: bool) -> float:
        score = self.config.score_for(alert.severity)
        if is_critical_prefix:
            score *= self.config.critical_prefix_multiplier
        if origin_changed:
            score *= 1.5
        if any("rpki invalid" in reason.lower() for reason in alert.reasons):
            score *= self.config.rpki_invalid_multiplier
        return score

    def _update_metadata(self, alert: Alert, origin_changed: bool,
                         is_critical_prefix: bool) -> None:
        affected: Set[int] = self.metadata["affected_asns"]  # type: ignore[assignment]
        if alert.origin_as is not None:
            affected.add(alert.origin_as)

        if alert.as_path:
            if self._last_as_path is not None:
                distance = levenshtein(self._last_as_path, alert.as_path)
                current = self.metadata["edit_distance"]
                if current is None or distance > current:
                    self.metadata["edit_distance"] = distance
            self._last_as_path = alert.as_path

        # Only upgrade from the placeholder; once a real subtype is known, keep it.
        if self.metadata["hijack_subtype"] == "UNKNOWN":
            if origin_changed:
                self.metadata["hijack_subtype"] = "ORIGIN_CHANGE"
            elif any("more-specific" in r.lower() for r in alert.reasons):
                self.metadata["hijack_subtype"] = "MORE_SPECIFIC"
            elif any("prepend" in r.lower() for r in alert.reasons):
                self.metadata["hijack_subtype"] = "PATH_MANIPULATION"

        if is_critical_prefix:
            self.metadata["is_critical_prefix"] = True

    # ---- lifecycle ----------------------------------------------------
    def close(self) -> None:
        self.status = "CLOSED"

    def to_dict(self) -> Dict[str, object]:
        metadata = dict(self.metadata)
        metadata["affected_asns"] = sorted(metadata["affected_asns"])  # type: ignore[arg-type]
        return {
            "id": self.id,
            "prefix": self.prefix,
            "origin_as": self.origin_as,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "max_severity": self.max_severity.value,
            "score": round(self.score, 3),
            "event_count": self.event_count,
            "status": self.status,
            "alert_ids": list(self.alert_ids),
            "metadata": metadata,
        }


def levenshtein(left: str, right: str) -> int:
    """Edit distance between two comma-separated AS paths.

    Kept from the original module: how far a path moved is a cheap, explainable
    proxy for how badly a prefix's routing was disturbed.
    """
    if not left or not right:
        return 0
    a, b = left.split(","), right.split(",")
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                previous[j - 1] if ca == cb else 1 + min(previous[j], current[j - 1], previous[j - 1])
            )
        previous = current
    return previous[-1]


class EpisodeManager:
    """Session-scoped episode correlation.

    No persistence in this version: a restart mid-incident starts a new episode.
    `on_close` is the seam for adding storage later without changing the port.
    """

    def __init__(self, config: Optional[EpisodeConfig] = None,
                 on_close: Optional[Callable[[Episode], None]] = None) -> None:
        self.config = config or EpisodeConfig()
        self.on_close = on_close
        # Keyed by episode id, not (prefix, origin): once a window expires a new
        # episode opens for the same (prefix, origin) pair while the old one may
        # still be open, and a composite key would silently overwrite it.
        self._active: Dict[str, Episode] = {}
        self._origins_seen: Dict[str, Set[int]] = {}
        self._closed = 0
        self._created = 0

    # ---- ingest -------------------------------------------------------
    def process(self, alert: Alert, is_critical_prefix: bool = False) -> Optional[Episode]:
        """Add an alert to its episode, opening one if none matches."""
        if not alert.prefix:
            return None
        if alert.timestamp.tzinfo is None:
            alert.timestamp = alert.timestamp.replace(tzinfo=timezone.utc)

        seen = self._origins_seen.setdefault(alert.prefix, set())
        episode = self._find_match(alert)
        if episode is None:
            episode = Episode(alert.prefix, alert.origin_as, alert.timestamp, self.config)
            self._active[episode.id] = episode
            self._created += 1

        # "Changed" means this prefix had a prior origin and this is a different
        # one. The first alert for a prefix is not a change.
        origin_changed = bool(seen) and alert.origin_as is not None and alert.origin_as not in seen
        episode.add_event(alert, origin_changed, is_critical_prefix)

        # Recorded after matching, so an origin is only "previously seen" once it
        # has actually appeared.
        if alert.origin_as is not None:
            seen.add(alert.origin_as)

        if episode.event_count >= self.config.max_events:
            self._retire(episode)
        return episode

    def _find_match(self, alert: Alert) -> Optional[Episode]:
        """Most recent open episode for exactly this (prefix, origin).

        Scans newest-first so a repeat lands on the most recent incident rather
        than an older one that happens to share the key.
        """
        for episode in sorted(self._active.values(), key=lambda e: e.end_time, reverse=True):
            if episode.should_include(alert):
                return episode
        return None

    # ---- lifecycle ----------------------------------------------------
    def sweep(self, now: Optional[datetime] = None) -> int:
        """Close episodes with no recent activity. Returns how many were closed."""
        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        threshold = timedelta(seconds=self.config.cleanup_threshold_s)
        stale = [
            episode
            for episode in self._active.values()
            if episode.status == "OPEN" and moment - episode.end_time > threshold
        ]
        for episode in stale:
            self._retire(episode)
        return len(stale)

    def _retire(self, episode: Episode) -> None:
        """Close and remove exactly once, then notify."""
        if episode.status == "CLOSED":
            return
        episode.close()
        self._active.pop(episode.id, None)
        self._closed += 1
        if self.on_close is not None:
            try:
                self.on_close(episode)
            except Exception as exc:  # noqa: BLE001
                logger.error("Episode close callback failed: %s", exc)

    # ---- reads --------------------------------------------------------
    def active(self) -> List[Episode]:
        return list(self._active.values())

    def get(self, episode_id: str) -> Optional[Episode]:
        for episode in self._active.values():
            if episode.id == episode_id:
                return episode
        return None

    def stats(self) -> Dict[str, int]:
        return {"active": len(self._active), "created": self._created, "closed": self._closed}