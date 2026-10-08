"""Resolve an operator's declared ASNs into the space they are responsible for.

Scope is registry-derived and approximate (spec 2.1): it decides what an operator
looks at, never what is a violation.

One source: `announced-prefixes` per ASN — what the ASN originates right now.
Customer space arrives here too, because an operator announcing a customer's
block *is* that customer's origin ASN. Verified against RIPEstat: AS8220
announces 62.23.14.0/24 with `origin: 8220` and `descr: TATA IZO`.

A per-prefix IRR `origin:` exclusion step was tried and removed. It cost 175
requests for one 174-prefix ASN, it was what made resolution time out, and its
logic was wrong: if we announce a prefix whose IRR names a different
originator, that is a *hijack signal*, not a reason to exclude the prefix from
scope. The RPKI verdict already runs per alert, so the check was redundant with
detection. RIPEstat's batch endpoint, which would have made it affordable, now
returns 403 without an API key.

**Known limitation.** Space held in IRR but not currently announced is not
discovered, because the lookup starts from announcements. Finding it needs a
reverse query — RIPE DB's `filter?attribute=origin&value=AS...` — which is
deferred. Until then `extra_prefixes` is the manual override.

Lazy, cached, and designed so failure degrades to "widen the filter", never
"narrow to nothing".
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from bgpmon.config import CONFIG_DIR, _read_json
from bgpmon.scope_match import ScopeConfig, ScopeMatcher

logger = logging.getLogger(__name__)

_ANNOUNCED_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"


@dataclass(frozen=True)
class ScopeSettings:
    refresh_s: int = 3600
    request_delay_s: float = 1.0
    timeout_s: float = 20.0
    scope_path: Path = CONFIG_DIR / "scope.json"
    cache_path: Path = CONFIG_DIR / ".scope_cache.json"

    @classmethod
    def from_env(cls) -> "ScopeSettings":
        import os

        delay = os.environ.get("BGPMON_SCOPE_REQUEST_DELAY")
        refresh = os.environ.get("BGPMON_SCOPE_REFRESH")
        try:
            delay_s = float(delay) if delay else cls.request_delay_s
        except ValueError:
            delay_s = cls.request_delay_s
        try:
            refresh_s = int(refresh) if refresh else cls.refresh_s
        except ValueError:
            refresh_s = cls.refresh_s
        return cls(refresh_s=refresh_s, request_delay_s=delay_s)


@dataclass(frozen=True)
class ResolvedScope:
    config: ScopeConfig
    networks: tuple = ()
    resolved_at: Optional[datetime] = None
    stale: bool = False
    error: Optional[str] = None
    last_change: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "asns": list(self.config.asns),
            "extra_prefixes": list(self.config.extra_prefixes),
            "include_transit": self.config.include_transit,
            "rejected": list(self.config.rejected),
            "prefix_count": len(self.networks),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "stale": self.stale,
            "error": self.error,
            "last_change": self.last_change,
        }


class RipestatTransport:
    """RIPEstat access, serialised and rate-limited.

    RIPEstat is shared free infrastructure and this tool is not its only user.
    The delay is enforced here rather than per call site so no caller can forget.
    """

    def __init__(self, delay_s: float = 1.0, timeout_s: float = 20.0) -> None:
        self.delay_s = delay_s
        self.timeout_s = timeout_s
        self._http = None
        self._last = 0.0

    async def _get(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        import httpx

        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=self.timeout_s, follow_redirects=True)
        gap = self.delay_s - (time.monotonic() - self._last)
        if gap > 0:
            await asyncio.sleep(gap)
        self._last = time.monotonic()
        response = await self._http.get(url, params=params)
        response.raise_for_status()
        return response.json()

    async def announced_prefixes(self, asn: int) -> List[str]:
        """Prefixes the ASN currently announces.

        RIPEstat nests these at `data.prefixes[]`, each entry carrying `prefix`
        and a `timelines` array. Pinned by a test built from a real response —
        an earlier assumption that `data` was a list produced an
        AttributeError in production-shaped use.
        """
        data = await self._get(_ANNOUNCED_URL, {"resource": f"AS{asn}"})
        payload = data.get("data")
        if not isinstance(payload, dict):
            return []
        entries = payload.get("prefixes")
        if not isinstance(entries, list):
            return []
        prefixes: List[str] = []
        for entry in entries:
            if isinstance(entry, dict) and entry.get("prefix"):
                prefixes.append(str(entry["prefix"]))
        return prefixes


def _collapse(networks: Sequence[ipaddress._BaseNetwork]) -> tuple:
    """Merge adjacent/contained networks, per address family.

    `ipaddress.collapse_addresses` raises TypeError on a mixed list, and every
    real operator announces both IPv4 and IPv6. Found by resolving AS8220 live.
    """
    v4 = [n for n in networks if n.version == 4]
    v6 = [n for n in networks if n.version == 6]
    merged: List[ipaddress._BaseNetwork] = []
    for family in (v4, v6):
        if family:
            merged.extend(ipaddress.collapse_addresses(family))
    return tuple(merged)


class ScopeResolver:
    """Owns the declared config, the resolved space, and the cache between them."""

    def __init__(self, settings: ScopeSettings, config: Optional[ScopeConfig] = None,
                 transport=None) -> None:
        self.settings = settings
        self._config = config if config is not None else self.load()
        self._transport = transport
        self._resolved: Optional[ResolvedScope] = None
        # Scope is security-relevant configuration: a quiet change to it blinds
        # the operator. Records THAT it changed, never WHO — a shared bearer
        # token carries no identity (spec 4.3).
        self._last_change: Optional[Dict[str, Any]] = None

    # ---- config ------------------------------------------------------
    def load(self) -> ScopeConfig:
        return ScopeConfig.from_dict(_read_json(self.settings.scope_path))

    def save(self, config: ScopeConfig) -> None:
        """Write atomically: a truncated scope.json would resolve to empty and
        silently blind the operator."""
        previous = self._config.asns
        payload = {
            "asns": list(config.asns),
            "extra_prefixes": list(config.extra_prefixes),
            "include_transit": config.include_transit,
        }
        self.settings.scope_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.settings.scope_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.settings.scope_path)
        self._config = config
        self._resolved = None  # the resolved set is now stale
        self._last_change = {
            "at": datetime.now(timezone.utc).isoformat(),
            "asns": list(config.asns),
            "previous_asns": list(previous),
        }
        logger.warning("scope changed: ASNs %s -> %s", previous, config.asns)

    # ---- reads -------------------------------------------------------
    def status(self) -> ResolvedScope:
        return self._resolved or self._cached()

    def matcher(self) -> ScopeMatcher:
        status = self.status()
        return ScopeMatcher(status.config, status.networks)

    def ensure_resolved(self) -> ResolvedScope:
        """Sync read path for status polling and UI."""
        if self._resolved is not None:
            return self._resolved
        cached = self._cached()
        fresh = (
            cached.resolved_at is not None
            and datetime.now(timezone.utc) - cached.resolved_at
            < timedelta(seconds=self.settings.refresh_s)
        )
        return self._resolved if fresh else cached

    def _cached(self) -> ResolvedScope:
        raw = _read_json(self.settings.cache_path) or {}
        stamp = raw.get("resolved_at")
        resolved_at = None
        if isinstance(stamp, str):
            try:
                resolved_at = datetime.fromisoformat(stamp)
            except ValueError:
                resolved_at = None
        if resolved_at is not None and resolved_at.tzinfo is None:
            resolved_at = resolved_at.replace(tzinfo=timezone.utc)
        networks = []
        for value in raw.get("prefixes") or []:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except (ValueError, TypeError):
                continue
        return ResolvedScope(self._config, tuple(networks), resolved_at,
                             stale=resolved_at is None, last_change=self._last_change)

    # ---- resolution --------------------------------------------------
    def transport(self):
        if self._transport is None:
            self._transport = RipestatTransport(delay_s=self.settings.request_delay_s,
                                                timeout_s=self.settings.timeout_s)
        return self._transport

    async def refresh(self) -> ResolvedScope:
        """Resolve now. On upstream failure, serve what we have and say so."""
        if not self._config.asns and not self._config.extra_prefixes:
            self._resolved = ResolvedScope(self._config, (), None, stale=False,
                                           last_change=self._last_change)
            return self._resolved

        transport = self.transport()
        found: Dict[str, None] = {}
        error: Optional[str] = None

        for asn in self._config.asns:
            try:
                for prefix in await transport.announced_prefixes(asn):
                    found[prefix] = None
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
                logger.warning("Scope resolution failed at AS%s: %s", asn, error)
                break

        networks = []
        for value in list(found) + list(self._config.extra_prefixes):
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except (ValueError, TypeError):
                continue
        collapsed = _collapse(networks)

        if not collapsed:
            # Nothing resolved and nothing cached: degrade to "no scope", loudly.
            cached = self._cached()
            if not cached.networks:
                self._resolved = ResolvedScope(self._config, (), None, stale=True,
                                               error=error, last_change=self._last_change)
                return self._resolved
            # Serve the stale cache rather than narrowing to nothing.
            self._resolved = ResolvedScope(self._config, cached.networks, cached.resolved_at,
                                           stale=True, error=error,
                                           last_change=self._last_change)
            return self._resolved

        self._persist_cache(collapsed, bool(error))
        self._resolved = ResolvedScope(self._config, collapsed, datetime.now(timezone.utc),
                                       stale=bool(error), error=error,
                                       last_change=self._last_change)
        return self._resolved

    def _persist_cache(self, networks: Sequence[ipaddress._BaseNetwork], partial: bool) -> None:
        """Persist even on a partial failure, so one bad ASN does not cost the
        operator the whole scope on the next restart."""
        payload = {
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "prefixes": [str(n) for n in networks],
            "partial": partial,
        }
        try:
            self.settings.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.settings.cache_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(self.settings.cache_path)
        except OSError as exc:
            logger.warning("Scope cache write failed: %s", exc)