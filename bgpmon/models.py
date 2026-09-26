"""Core data types shared across the BGP Monitor pipeline.

These are the stable contracts between the collector, detectors, sinks, and API.
Any change here ripples into every module — treat as an interface.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Ordered severity. Telecom NOC needs CRITICAL distinct from HIGH."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    @classmethod
    def max(cls, *values: "Severity") -> "Severity":
        return max(values, key=lambda s: s.rank) if values else cls.INFO


_SEVERITY_RANK = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}


class Kind(str, Enum):
    """Alert taxonomy."""

    HIJACK_ORIGIN = "HIJACK_ORIGIN"          # owned/monitored prefix seen from unexpected origin
    HIJACK_SUB_PREFIX = "HIJACK_SUB_PREFIX"  # more-specific of an owned prefix
    ROUTE_LEAK = "ROUTE_LEAK"                # valley-free violation / RFC9234-style
    RPKI_INVALID = "RPKI_INVALID"            # RPKI says origin is not authorised
    RPKI_ASPAS = "RPKI_ASPAS"                # route received from an AS not in the ROA's ASPAs
    BOGON_ASN = "BOGON_ASN"                  # reserved/private ASN in path
    BOGON_PREFIX = "BOGON_PREFIX"            # unallocated/reserved prefix
    PREPEND = "PREPEND"                      # excessive, *unexpected* prepending
    LONG_PATH = "LONG_PATH"                  # path far outside observed distribution
    VISIBILITY_LOSS = "VISIBILITY_LOSS"      # owned prefix lost from the feed
    NEW_PREFIX = "NEW_PREFIX"                # monitored AS announces a never-seen prefix
    MOAS_NEW_ORIGIN = "MOAS_NEW_ORIGIN"      # new participant on a legit MOAS prefix
    RPKI_ROA_CHANGE = "RPKI_ROA_CHANGE"      # ROA added/removed/expired for owned space


@dataclass(slots=True)
class Update:
    """A single BGP update as normalised from RIS Live."""

    update_id: str
    timestamp: datetime
    prefix: str
    collector: str
    peer: str
    peer_as: str
    as_path: str
    as_path_list: List[int] = field(default_factory=list)
    origin_as: Optional[int] = None
    next_hop: Optional[str] = None
    communities: Any = None
    update_type: str = "announcement"  # "announcement" | "withdrawal"
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d.pop("raw", None)
        return d


@dataclass(slots=True)
class Alert:
    """A detected routing security event.

    `update_id` links the alert to the exact BGPUpdate node in Neo4j; both are
    derived from the same function so the TRIGGERED_BY edge always resolves.
    """

    alert_id: str
    dedup_key: str
    timestamp: datetime
    kind: Kind
    severity: Severity
    confidence: float
    prefix: str
    as_path: str
    peer_as: str
    collector: str
    update_id: str
    origin_as: Optional[int] = None
    expected_origins: List[int] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    is_owned: bool = False
    suppressed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        return d

    def wire(self) -> Dict[str, Any]:
        """Compact form for WebSocket fanout / REST responses."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "kind": self.kind.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "prefix": self.prefix,
            "origin_as": self.origin_as,
            "expected_origins": self.expected_origins,
            "as_path": self.as_path,
            "peer_as": self.peer_as,
            "collector": self.collector,
            "is_owned": self.is_owned,
            "reasons": self.reasons,
            "evidence": self.evidence,
        }


def make_update_id(collector: str, timestamp: datetime, prefix: str) -> str:
    """Deterministic update identifier.

    Single source of truth: used by both the update writer and the alert writer
    so the graph link is never orphaned.
    """
    return f"{collector}_{timestamp.isoformat()}_{prefix}"


def make_alert_id(update_id: str, kind: "Kind") -> str:
    """Deterministic alert identifier derived from the update it came from."""
    digest = hashlib.sha1(f"{update_id}|{kind.value}".encode()).hexdigest()[:16]
    return f"{kind.value.lower()}_{digest}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
