"""BGP security detection engine.

Every detector is grounded in an explicit baseline so it can distinguish
"unexpected" from "merely new":

* owned space + authorised origins  -> hijack / sub-prefix hijack
* RPKI VRPs (local, 1M entries)     -> invalid origin, invalid length
* CAIDA AS relationships            -> valley-free route leaks
* observed prefix state             -> visibility loss, new-prefix, MOAS growth
* per-path-length distribution      -> long path (statistical, not a magic 30)
* reserved space                    -> bogons

Alert volume is controlled by construction, not by suppression hacks: a
detector only fires when it has evidence the observation is wrong, and
repeated identical sightings collapse via `dedup_key`.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import time
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from bgpmon.config import DetectionSettings
from bgpmon.models import (
    Alert,
    Kind,
    Severity,
    Update,
    make_alert_id,
)
from bgpmon.rpki import RPkiEngine, VRPSet

logger = logging.getLogger(__name__)

# --- reserved space -------------------------------------------------------
BOGON_ASN_RANGES = (
    (0, 0), (23456, 23456), (64496, 64511), (64512, 65534),
    (65535, 65535), (65536, 65551), (65552, 131071),
    (4200000000, 4294967294), (4294967295, 4294967295),
)
BOGON_V4 = tuple(
    ipaddress.ip_network(p) for p in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32",
    )
)
BOGON_V6 = tuple(
    ipaddress.ip_network(p) for p in (
        "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32",
        "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
    )
)

_AS_SET = re.compile(r"\{([^}]*)\}")


def is_bogon_asn(asn: int) -> bool:
    return any(lo <= asn <= hi for lo, hi in BOGON_ASN_RANGES)


def is_bogon_prefix(prefix: str) -> bool:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False
    space = BOGON_V4 if net.version == 4 else BOGON_V6
    return any(net.subnet_of(b) for b in space)


# --- AS relationship graph ------------------------------------------------
P2C, P2P, S2S, C2P, UNKNOWN = -1, 0, 2, 1, 99


class ASGraph:
    """CAIDA as-rel graph with O(1) relationship lookup and valley-free check.

    Also maintains a degree-based heuristic for pairs absent from CAIDA, so
    valley-free reasoning still has signal where the dataset is sparse.
    """

    __slots__ = ("_rel", "_degree", "loaded")

    def __init__(self) -> None:
        self._rel: Dict[int, int] = {}
        self._degree: Dict[int, int] = defaultdict(int)
        self.loaded = 0

    def load(self, path) -> int:
        import bz2
        from pathlib import Path

        path = Path(path)
        if not path.exists():
            logger.warning("AS relationship file missing: %s (route-leak detection degraded)", path)
            return 0
        rel: Dict[int, int] = {}
        degree: Dict[int, int] = defaultdict(int)
        try:
            opener = bz2.open if str(path).endswith(".bz2") else open
            with opener(path, "rt", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    parts = line.strip().split("|")
                    if len(parts) != 3:
                        continue
                    try:
                        a, b, code = int(parts[0]), int(parts[1]), int(parts[2])
                    except ValueError:
                        continue
                    if a == b:
                        continue
                    # CAIDA serial-1/2 encodes direction explicitly: for code -1 the
                    # FIRST ASN is the provider. The direction must be preserved —
                    # assuming the lower ASN is the provider fabricates relationships
                    # for every pair where the provider has the higher number.
                    if code == -1:
                        rel[(a << 32) | b] = P2C      # a is provider of b
                    elif code == 0:
                        key = (min(a, b) << 32) | max(a, b)
                        rel[key] = P2P
                    elif code == 2:
                        key = (min(a, b) << 32) | max(a, b)
                        rel[key] = S2S
                    degree[a] += 1
                    degree[b] += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed loading AS relationships from %s: %s", path, exc)
            return 0
        self._rel = rel
        self._degree = degree
        self.loaded = len(rel)
        logger.info("Loaded %d AS relationships (%d ASNs with known degree)", len(rel), len(degree))
        return len(rel)

    def relationship(self, a: int, b: int) -> int:
        """Relationship for the propagation step a -> b (a announces to b).

        Directed pairs (provider/customer) are stored in CAIDA's own direction;
        symmetric pairs (peer/sibling) are stored once under a sorted key.
        """
        if a == b:
            return UNKNOWN
        forward = self._rel.get((a << 32) | b)
        if forward is not None:
            return forward
        reverse = self._rel.get((b << 32) | a)
        if reverse is None:
            return UNKNOWN
        if reverse == P2C:      # b is provider of a => a is customer of b
            return C2P
        if reverse == C2P:
            return P2C
        return reverse          # P2P / S2S are symmetric

    def inference_confidence(self, a: int, b: int) -> float:
        """How much we trust the pair's relationship: exact match, else degree prior."""
        if self.relationship(a, b) != UNKNOWN:
            return 1.0
        da, db = self._degree.get(a, 0), self._degree.get(b, 0)
        if da == 0 or db == 0:
            return 0.0
        # A large degree gap is weak evidence of provider->customer.
        return min(0.45, 0.15 + 0.05 * min(da, db) ** 0.5) if abs(da - db) > 50 else 0.15

    def valley_violation(self, path: Sequence[int]) -> Tuple[bool, Optional[Tuple[int, int]], float]:
        """Detect a route leak per RFC 7908 using the valley-free model.

        Correctness note: an AS path is written *from the collector's peer toward
        the origin*, so the propagation direction is the reverse of the list. A
        legal path, read in propagation order, is: uphill edges (customer→provider)
        optionally followed by a single peer edge, then downhill edges
        (provider→customer) — `up* flat? down*`. Re-announcing uphill after a peer
        or downhill edge is a leak (RFC 7908 type 1/2).

        Both edges of the offending transition must be known relationships; the
        degree-based inference is deliberately not used here because an inferred
        leak is not actionable for a NOC.
        """
        if len(path) < 3 or not self._rel:
            return False, None, 0.0
        hops = list(reversed(path))
        phase = "up"          # up -> flat -> down
        for i in range(len(hops) - 1):
            a, b = hops[i], hops[i + 1]
            if a == b:
                continue
            rel = self.relationship(a, b)   # a announces to b
            if rel == UNKNOWN:
                return False, None, 0.0     # unverifiable path: never accuse
            if rel == C2P:
                edge = "up"
            elif rel == P2C:
                edge = "down"
            elif rel in (P2P, S2S):
                edge = "flat"
            else:
                return False, None, 0.0
            if edge == "up":
                if phase != "up":
                    return True, (a, b), 0.95
            elif edge == "flat":
                if phase == "down":
                    return True, (a, b), 0.9
                phase = "flat"
            else:  # down
                phase = "down"
        return False, None, 0.0


# --- per-prefix state -----------------------------------------------------
@dataclass(slots=True)
class PrefixState:
    """Rolling view of one prefix's observed behaviour."""

    prefix: str
    origins: Dict[int, int] = field(default_factory=dict)      # origin -> sightings
    authorised: Set[int] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    last_path: str = ""
    path_lengths: Deque[int] = field(default_factory=lambda: deque(maxlen=256))
    collectors: Set[str] = field(default_factory=set)
    announced_since_loss: Optional[datetime] = None

    def observe(self, update: Update) -> None:
        if update.origin_as is not None:
            self.origins[update.origin_as] = self.origins.get(update.origin_as, 0) + 1
        self.collectors.add(update.collector)
        self.last_seen = update.timestamp
        if self.first_seen is None:
            self.first_seen = update.timestamp
        if self.last_path != update.as_path and update.as_path:
            self.last_path = update.as_path
        if update.origin_as is not None and update.as_path_list:
            self.path_lengths.append(len(update.as_path_list))
        self.announced_since_loss = update.timestamp

    def mean_len(self) -> float:
        return sum(self.path_lengths) / len(self.path_lengths) if self.path_lengths else 0.0

    def std_len(self) -> float:
        if len(self.path_lengths) < 8:
            return 0.0
        mean = self.mean_len()
        var = sum((x - mean) ** 2 for x in self.path_lengths) / (len(self.path_lengths) - 1)
        return math.sqrt(var)


class DetectionEngine:
    """Stateful, single-threaded detector. Called from the pipeline thread only."""

    def __init__(self, settings: DetectionSettings, rpki: RPkiEngine, as_graph: ASGraph) -> None:
        self.settings = settings
        self.rpki = rpki
        self.as_graph = as_graph
        self._state: Dict[str, PrefixState] = {}
        self._owned = settings.owned_prefixes
        self._critical = settings.critical_prefixes
        self._bogus_announcements: Dict[Tuple[str, int], Set[int]] = defaultdict(set)
        self._leak_pairs: Dict[str, List] = {}
        self._path_incidents: Dict[str, float] = {}
        self._evaluations = 0
        self.stats = defaultdict(int)

    # ---- helpers ------------------------------------------------------
    def _owned_match(self, prefix: str):
        """Return the owned/critical cover for a prefix, plus the more-specific delta."""
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return None, None, 0
        for owned in self._owned:
            if net.version != owned.version:
                continue
            if net.subnet_of(owned):
                return owned, net, net.prefixlen - owned.prefixlen
        for crit in self._critical:
            if net.version != crit.version:
                continue
            if net.subnet_of(crit):
                return crit, net, net.prefixlen - crit.prefixlen
        return None, None, 0

    def _state_for(self, prefix: str) -> PrefixState:
        st = self._state.get(prefix)
        if st is None:
            st = PrefixState(prefix=prefix)
            self._state[prefix] = st
        return st

    def _alert(self, update: Update, kind: Kind, severity: Severity, confidence: float,
               reasons: List[str], *, is_owned: bool = False,
               expected: Optional[Iterable[int]] = None, dedup_scope: str = "",
               **evidence) -> Alert:
        # A route leak is a property of the AS pair that committed it, not of each
        # prefix it affects: one leaky pair can drag thousands of prefixes, and
        # per-prefix keys would page the NOC thousands of times for one incident.
        scope = dedup_scope or str(update.origin_as)
        return Alert(
            alert_id=make_alert_id(f"{update.update_id}|{scope}", kind),
            dedup_key=f"{kind.value}:{scope}:{update.collector}",
            timestamp=update.timestamp,
            kind=kind,
            severity=severity,
            confidence=confidence,
            prefix=update.prefix,
            as_path=update.as_path,
            peer_as=update.peer_as,
            collector=update.collector,
            update_id=update.update_id,
            origin_as=update.origin_as,
            expected_origins=sorted(expected or ()),
            reasons=reasons,
            evidence=evidence,
            is_owned=is_owned,
        )

    def _sweep(self, now: float) -> None:
        """Expire incident state so a recurring condition re-alerts.

        Without expiry, a leak or anomalous path seen once would be silenced for
        the lifetime of the process: if the condition clears and returns hours
        later the NOC would never hear about it again.
        """
        ttl = self.settings.incident_ttl_s
        for scope, seen in list(self._leak_pairs.items()):
            if now - seen[2] > ttl:
                del self._leak_pairs[scope]
        for scope, seen in list(self._path_incidents.items()):
            if now - seen > ttl:
                del self._path_incidents[scope]

    # ---- public entry -------------------------------------------------
    def evaluate(self, update: Update) -> List[Alert]:
        """Run every detector for one announcement. Withdrawals are state-only."""
        alerts: List[Alert] = []
        self._evaluations += 1
        if self._evaluations % 4096 == 0:
            self._sweep(time.monotonic())
        if update.update_type == "withdrawal":
            st = self._state.get(update.prefix)
            if st:
                st.last_seen = update.timestamp
            return alerts

        owned_cover, net, delta = self._owned_match(update.prefix)
        is_owned = owned_cover is not None and owned_cover in self._owned
        is_critical = owned_cover is not None

        rpki_result = None
        if update.origin_as is not None:
            rpki_result = self.rpki.validate(update.prefix, update.origin_as)

        alerts.extend(self._check_bogon(update))
        alerts.extend(self._check_rpki(update, rpki_result, is_owned))
        alerts.extend(self._check_origin(update, rpki_result, owned_cover, is_owned))
        alerts.extend(self._check_sub_prefix(update, owned_cover, delta, rpki_result, is_critical))
        alerts.extend(self._check_leak(update))
        alerts.extend(self._check_path_shape(update, is_owned))
        alerts.extend(self._check_new_prefix(update, is_owned, is_critical))

        self._state_for(update.prefix).observe(update)
        if update.origin_as is not None:
            st = self._state[update.prefix]
            if rpki_result is not None and rpki_result.state == "VALID":
                st.authorised.add(update.origin_as)

        for a in alerts:
            self.stats[a.kind.value] += 1
        return alerts

    # ---- detectors ----------------------------------------------------
    def _check_bogon(self, update: Update) -> List[Alert]:
        out = []
        if self.settings.enforce_bogon_prefix and is_bogon_prefix(update.prefix):
            out.append(self._alert(
                update, Kind.BOGON_PREFIX, Severity.HIGH, 0.95,
                [f"Announcement for reserved/unallocated space {update.prefix}"],
            ))
        if self.settings.enforce_bogon_asn:
            bad = [a for a in update.as_path_list if is_bogon_asn(a)]
            if bad:
                out.append(self._alert(
                    update, Kind.BOGON_ASN, Severity.HIGH, 0.95,
                    [f"Reserved/private ASN(s) in path: {bad}"], bogons=bad,
                ))
        return out

    def _check_rpki(self, update: Update, result, is_owned: bool) -> List[Alert]:
        if result is None or result.state != "INVALID":
            return []
        sev = Severity.CRITICAL if is_owned else Severity.HIGH
        return [self._alert(
            update, Kind.RPKI_INVALID, sev, 0.99,
            [f"RPKI INVALID ({result.reason}) for {update.prefix} from AS{update.origin_as}"],
            is_owned=is_owned,
            rpki_source=result.source,
            offending=[{"asn": a, "max_length": m, "why": w} for a, m, w in result.offending],
        )]

    def _check_origin(self, update: Update, rpki_result, cover, is_owned: bool) -> List[Alert]:
        """Unexpected origin on owned/monitored space, MOAS-aware."""
        if update.origin_as is None or cover is None:
            return []
        key = int(cover.network_address)
        expected = set(self.settings.expected_origins.get(key, ()))
        if is_owned and not expected:
            # No explicit authorisation list: fall back to RPKI-authorised origins.
            st = self._state.get(update.prefix)
            authorised = (st.authorised if st else set())
            rpki_valid = rpki_result is not None and rpki_result.state == "VALID"
            if rpki_valid:
                return []
            # Nothing authorises this origin -> real hijack signal.
            if not authorised:
                sev = Severity.CRITICAL
                conf = 0.8
                reason = (f"Origin AS{update.origin_as} for owned space {cover} is neither "
                          f"RPKI-authorised nor previously observed")
            else:
                sev = Severity.HIGH
                conf = 0.7
                reason = (f"Origin AS{update.origin_as} differs from authorised "
                          f"{sorted(authorised)} for owned space {cover}")
            return [self._alert(update, Kind.HIJACK_ORIGIN, sev, conf, [reason],
                                is_owned=True, expected=sorted(authorised))]
        if expected and update.origin_as not in expected:
            return [self._alert(
                update, Kind.HIJACK_ORIGIN, Severity.CRITICAL, 0.97,
                [f"Origin AS{update.origin_as} not in authorised set {sorted(expected)} for {cover}"],
                is_owned=is_owned, expected=sorted(expected),
            )]
        return []

    def _check_sub_prefix(self, update: Update, cover, delta: int, rpki_result, is_critical: bool) -> List[Alert]:
        """More-specific of owned/critical space, ignoring legitimate splits."""
        if cover is None or delta < self.settings.more_specific_min_delta:
            return []
        if not is_critical:
            return []
        # RPKI-valid announcements of configured critical space are legitimate operator splits.
        if (self.settings.trust_rpki_valid_origins and rpki_result is not None
                and rpki_result.state == "VALID"):
            return []
        return [self._alert(
            update, Kind.HIJACK_SUB_PREFIX, Severity.HIGH, 0.85,
            [f"More-specific /{delta} beyond {cover} announced by AS{update.origin_as}"],
            is_owned=cover in self._owned, parent=str(cover), delta=delta,
        )]

    def _check_leak(self, update: Update) -> List[Alert]:
        violated, pair, conf = self.as_graph.valley_violation(update.as_path_list)
        if not violated or conf < self.settings.leak_confidence_floor:
            return []
        a, b = pair  # type: ignore[misc]
        # One alert per leaky AS pair; every affected prefix is counted, not paged.
        pair_key = f"AS{a}->AS{b}"
        seen = self._leak_pairs.get(pair_key)
        if seen is None:
            first = True
            self._leak_pairs[pair_key] = [1, update.prefix, time.monotonic()]
        else:
            seen[0] += 1
            seen[2] = time.monotonic()
            first = False
        if not first:
            self.stats["ROUTE_LEAK_prefixed"] += 1
            return []
        return [self._alert(
            update, Kind.ROUTE_LEAK, Severity.HIGH, conf,
            [f"Valley-free violation (RFC 7908): AS{a} re-announced to AS{b} over a "
             f"peer/customer edge; origin AS{update.origin_as}"],
            dedup_scope=pair_key,
            offending_pair=[a, b], example_prefix=update.prefix,
        )]

    def _check_path_shape(self, update: Update, is_owned: bool) -> List[Alert]:
        out = []
        path = update.as_path_list
        if not path:
            return out
        st = self._state.get(update.prefix)
        mean = st.mean_len() if st else 0.0
        std = st.std_len() if st else 0.0
        z = (len(path) - mean) / std if std > 0 else 0.0
        if (std > 0 and z >= self.settings.long_path_zscore and len(path) >= self.settings.long_path_floor):
            # One anomalous path is an incident for the origin, not for each of the
            # thousands of prefixes that origin happens to announce with it.
            scope = f"AS{update.origin_as}|len{len(path)}"
            if scope in self._path_incidents:
                self._path_incidents[scope] = time.monotonic()
                self.stats["LONG_PATH_prefixed"] += 1
                return out
            self._path_incidents[scope] = time.monotonic()
            out.append(self._alert(
                update, Kind.LONG_PATH, Severity.MEDIUM, min(0.9, 0.4 + z / 20),
                [f"Path length {len(path)} is {z:.1f}σ above this prefix's mean {mean:.1f}"],
                dedup_scope=scope,
                path_length=len(path), zscore=round(z, 2), mean=round(mean, 2),
            ))
        # Prepending is normal traffic engineering across the global table. It is
        # only actionable on space the operator is responsible for (or an AS they
        # are watching), so it is scoped there rather than firing on every prefix.
        watched = is_owned or (update.origin_as in self.settings.monitored_asns)
        if not watched:
            return out
        best_asn, best_len, prev = None, 0, None
        run_len = 0
        for asn in path:
            run_len = run_len + 1 if asn == prev else 1
            prev = asn
            if run_len > best_len:
                best_asn, best_len = asn, run_len
        if best_len >= self.settings.prepend_floor:
            out.append(self._alert(
                update, Kind.PREPEND, Severity.LOW, 0.6,
                [f"AS{best_asn} prepended {best_len}x on watched origin AS{update.origin_as}"],
                is_owned=is_owned, prepend_asn=best_asn, prepend_count=best_len,
            ))
        return out

    def _check_new_prefix(self, update: Update, is_owned: bool, is_critical: bool) -> List[Alert]:
        if update.origin_as is None:
            return []
        monitored = update.origin_as in self.settings.monitored_asns
        if not (monitored or is_owned):
            return []
        st = self._state.get(update.prefix)
        if st is not None and st.first_seen is not None and st.first_seen != update.timestamp:
            return []
        if st is None:
            return [self._alert(
                update, Kind.NEW_PREFIX, Severity.MEDIUM, 0.6,
                [f"AS{update.origin_as} announced {update.prefix} for the first time in this session"],
                is_owned=is_owned, monitored_origin=monitored,
            )]
        return []

    # ---- periodic -----------------------------------------------------
    def check_visibility(self, now: Optional[datetime] = None) -> List[Alert]:
        """Visibility loss for owned prefixes (grace period, multi-collector aware)."""
        now = now or datetime.now(timezone.utc)
        grace = timedelta(seconds=self.settings.visibility_loss_grace_s)
        out: List[Alert] = []
        for prefix, st in self._state.items():
            if st.last_seen is None or (now - st.last_seen) < grace:
                continue
            if len(st.collectors) < self.settings.visibility_min_expected_collectors:
                continue
            if st.announced_since_loss is not None and st.announced_since_loss == st.last_seen:
                # already reported for this gap
                if getattr(st, "_loss_reported", None) == st.last_seen:
                    continue
            placeholder = Update(
                update_id=f"visibility_{prefix}_{int(st.last_seen.timestamp())}",
                timestamp=now, prefix=prefix, collector="|".join(sorted(st.collectors)),
                peer="", peer_as="", as_path="",
            )
            alert = self._alert(
                placeholder, Kind.VISIBILITY_LOSS, Severity.CRITICAL, 0.85,
                [f"{prefix} not seen for {(now - st.last_seen).total_seconds() / 60:.0f} min "
                 f"across {len(st.collectors)} collectors"],
                is_owned=True, last_seen=st.last_seen.isoformat(),
                collectors=sorted(st.collectors),
            )
            st._loss_reported = st.last_seen  # type: ignore[attr-defined]
            out.append(alert)
        return out

    def snapshot(self) -> Dict[str, object]:
        return {
            "prefixes_tracked": len(self._state),
            "owned_prefixes": len(self._owned),
            "critical_prefixes": len(self._critical),
            "as_relationships_loaded": self.as_graph.loaded,
            "alerts_by_kind": dict(self.stats),
        }
