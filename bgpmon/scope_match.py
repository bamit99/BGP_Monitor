"""Classify alerts against an operator-declared scope.

Pure: no network, no clock, no filesystem. Scope is registry-derived and therefore
approximate (spec 2.1) — it decides what an operator looks at and must never
decide what counts as a violation. Only the RPKI VRP set authorises an origin.

Reasons, not a boolean. A filtered view showing "0 alerts" is ambiguous — broken
detector, or genuinely nothing? `ORIGIN 0 . SUBSPACE 0 . TRANSIT 2` is a finding.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bgpmon.models import Alert

logger = logging.getLogger(__name__)

MAX_ASN = 4294967295
MAX_ASNS = 64
MAX_EXTRA_PREFIXES = 256

SCOPE_REASONS = ("ORIGIN", "SUBSPACE", "TRANSIT")

_TRUE_WORDS = {"true", "1", "yes", "on"}
_FALSE_WORDS = {"false", "0", "no", "off"}


def normalize_asn(value: object) -> Optional[int]:
    """Canonical integer for any spelling of an ASN, or None.

    Accepts 8220, "8220", "AS8220", "as8220", " 8220 ". A whole float is
    rejected rather than truncated: 8220.0 is a typo, not an ASN. Never raises —
    a corrupt config must not stop the service starting.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, float):
        return None  # 8220.0 is a typo; do not truncate it to 8220
    if isinstance(value, int):
        return value if 0 <= value <= MAX_ASN else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text[:2].lower() == "as":
        text = text[2:].strip()
    if not text.isdigit():
        return None
    number = int(text)
    return number if 0 <= number <= MAX_ASN else None


def normalize_prefix(value: object) -> Optional[str]:
    """Canonical CIDR string, or None. `'not-a-cidr'` and friends are rejected."""
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class ScopeConfig:
    """What an operator runs.

    ASNs are what a network engineer thinks in and change rarely; prefixes churn
    constantly. So the operator declares ASNs and prefixes are derived.

    `rejected` records input that could not be understood. It is never silently
    dropped: `"asns": ["AS8220"]` parsed by a bare `int()` raises, gets skipped,
    and leaves an empty scope — an operator who believes they scoped AS8220 and
    is filtering nothing.
    """

    asns: Tuple[int, ...] = ()
    extra_prefixes: Tuple[str, ...] = ()
    include_transit: bool = True
    rejected: Tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: Optional[Dict[str, Any]]) -> "ScopeConfig":
        """Parse defensively. Never raises; never discards silently."""
        raw = raw or {}
        rejected: List[str] = []

        asns: List[int] = []
        for value in raw.get("asns") or []:
            number = normalize_asn(value)
            if number is None:
                rejected.append(f"asns: {value!r} is not an ASN")
                continue
            if number not in asns:
                asns.append(number)

        prefixes: List[str] = []
        for value in raw.get("extra_prefixes") or []:
            cidr = normalize_prefix(value)
            if cidr is None:
                rejected.append(f"extra_prefixes: {value!r} is not a CIDR")
                continue
            if cidr not in prefixes:
                prefixes.append(cidr)

        include_transit = True
        if "include_transit" in raw and raw["include_transit"] is not None:
            flag = raw["include_transit"]
            if isinstance(flag, bool):
                include_transit = flag
            elif isinstance(flag, str) and flag.strip().lower() in _TRUE_WORDS:
                include_transit = True
            elif isinstance(flag, str) and flag.strip().lower() in _FALSE_WORDS:
                include_transit = False
            else:
                rejected.append(f"include_transit: {flag!r} is not a boolean")
                include_transit = True

        if len(asns) > MAX_ASNS:
            rejected.append(f"asns: truncated to the first {MAX_ASNS} of {len(asns)}")
        if len(prefixes) > MAX_EXTRA_PREFIXES:
            rejected.append(
                f"extra_prefixes: truncated to the first {MAX_EXTRA_PREFIXES} of {len(prefixes)}")

        return cls(
            asns=tuple(asns[:MAX_ASNS]),
            extra_prefixes=tuple(prefixes[:MAX_EXTRA_PREFIXES]),
            include_transit=include_transit,
            rejected=tuple(rejected),
        )

    def networks(self) -> List[ipaddress._BaseNetwork]:
        """Parseable networks only; already validated by `from_dict`."""
        out: List[ipaddress._BaseNetwork] = []
        for value in self.extra_prefixes:
            try:
                out.append(ipaddress.ip_network(value, strict=False))
            except ValueError:  # pragma: no cover - from_dict filtered these
                continue
        return out

    def cypher_asn_strings(self) -> List[str]:
        """ASNs as strings, for a Cypher `IN` comparison against `split()`.

        Cypher compares by type. `split('8220,64500', ',')` yields strings, so
        passing `[8220]` makes `x IN $asns` false for every x and the TRANSIT
        prefilter matches nothing at all — a silent total failure. Derived from
        the same normalised integers so the two can never diverge.
        """
        return [str(asn) for asn in self.asns]


class ScopeMatcher:
    """Alert -> match reasons."""

    def __init__(self, config: ScopeConfig,
                 prefixes: Sequence[ipaddress._BaseNetwork] = ()) -> None:
        self.config = config
        self._asns = frozenset(config.asns)
        self._prefixes = [p for p in prefixes if p is not None]

    def reasons(self, alert: Alert) -> Tuple[str, ...]:
        found: List[str] = []
        if alert.origin_as is not None and alert.origin_as in self._asns:
            found.append("ORIGIN")
        if self._in_subspace(alert.prefix):
            found.append("SUBSPACE")
        if self.config.include_transit and self._in_path(alert.as_path):
            found.append("TRANSIT")
        return tuple(found)

    def matches(self, alert: Alert) -> bool:
        return bool(self.reasons(alert))

    def _in_subspace(self, prefix: Optional[str]) -> bool:
        """True when the prefix is inside something we hold — which covers a
        more-specific announcement of our own space."""
        if not prefix or not self._prefixes:
            return False
        cidr = normalize_prefix(prefix)
        if cidr is None:
            return False
        net = ipaddress.ip_network(cidr, strict=False)
        for held in self._prefixes:
            if net.version == held.version and net.subnet_of(held):
                return True
        return False

    def _in_path(self, as_path: Optional[str]) -> bool:
        """Whole-hop containment only.

        8220 must not match inside 182205, and an AS_SET is not a path we can
        reason about. Hops may arrive bare (`8220`) or AS-prefixed (`AS8220`).
        """
        if not as_path:
            return False
        for hop in as_path.split(","):
            hop = hop.strip()
            if not hop or hop.startswith("{"):
                continue
            number = normalize_asn(hop)
            if number is None:
                continue
            if number in self._asns:
                return True
        return False