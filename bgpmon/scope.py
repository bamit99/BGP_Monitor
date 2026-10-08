"""ASN / telecom scope lookup.

Search by ASN number or by telecom/operator name, returning announced prefixes
with RPKI-valid origins where available. Uses RIPEstat for prefix/origin data
and PeeringDB for name→ASN directory search.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

_ASN_RE = re.compile(r"^AS(\d+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ScopedPrefix:
    prefix: str
    origin_as: Optional[int]
    rpki_state: Optional[str]  # VALID / INVALID / NOT_FOUND / unknown


@dataclass(frozen=True, slots=True)
class ScopedASN:
    asn: int
    name: str
    country: Optional[str]
    prefixes: List[ScopedPrefix]


class ScopeLookup:
    """Async lookup with a shared client and small in-memory cache."""

    def __init__(self, timeout_s: float = 20.0) -> None:
        self.timeout = httpx.Timeout(timeout_s)
        self._http: Optional[httpx.AsyncClient] = None
        self._cache: Dict[str, List[ScopedASN]] = {}

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self._http

    async def search(self, query: str, rpki_validator=None) -> List[ScopedASN]:
        q = (query or "").strip()
        if not q:
            return []
        if q.lower() in self._cache:
            return self._cache[q.lower()]

        asn_match = _ASN_RE.match(q)
        if asn_match:
            asn = int(asn_match.group(1))
            single = await self._lookup_asn(asn, rpki_validator)
            result: List[ScopedASN] = [single] if single else []
        else:
            asns = await self._search_name(q)
            result = []
            for asn, name, country in asns[:5]:
                scoped = await self._lookup_asn(asn, rpki_validator, name=name, country=country)
                if scoped:
                    result.append(scoped)

        self._cache[q.lower()] = result
        return result

    async def _search_name(self, name: str) -> List[tuple[int, str, Optional[str]]]:
        """Return [(asn, name, country)] matching name via PeeringDB."""
        url = "https://www.peeringdb.com/api/net"
        params = {"name__contains": name, "limit": 10}
        try:
            client = await self._client()
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            return [
                (
                    int(net["asn"]),
                    net.get("name", f"AS{net['asn']}"),
                    net.get("country", None),
                )
                for net in data
                if "asn" in net
            ]
        except Exception as exc:  # noqa: BLE001
            logger.debug("PeeringDB name search failed for %r: %s", name, exc)
            return []

    async def _lookup_asn(
        self,
        asn: int,
        rpki_validator=None,
        name: Optional[str] = None,
        country: Optional[str] = None,
    ) -> Optional[ScopedASN]:
        """Pull announced prefixes for an ASN from RIPEstat."""
        url = "https://stat.ripe.net/data/announced-prefixes/data.json"
        params = {"resource": f"AS{asn}"}
        try:
            client = await self._client()
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            body = resp.json().get("data", {}).get("prefixes", [])
            entries = [e for e in body[:500] if e.get("prefix")]
            prefixes = await self._validate_prefixes(entries, asn, rpki_validator)
            if not name:
                name = await self._asn_name(asn)
            return ScopedASN(asn=asn, name=name or f"AS{asn}", country=country, prefixes=prefixes)
        except Exception as exc:  # noqa: BLE001
            logger.debug("RIPEstat prefix lookup failed for AS%d: %s", asn, exc)
            return None

    async def _validate_prefixes(
        self,
        entries: List[Dict[str, Any]],
        origin: int,
        rpki_validator=None,
        max_concurrency: int = 16,
    ) -> List[ScopedPrefix]:
        """Cross-check prefixes against local RPKI with bounded concurrency."""

        def _check(entry: Dict[str, Any]) -> ScopedPrefix:
            prefix = entry["prefix"]
            rpki_state: Optional[str] = None
            if rpki_validator is not None:
                try:
                    verdict = rpki_validator.validate(prefix, origin)
                    rpki_state = verdict.state
                except Exception:  # noqa: BLE001
                    rpki_state = "unknown"
            return ScopedPrefix(prefix=prefix, origin_as=origin, rpki_state=rpki_state)

        if rpki_validator is None:
            return [ScopedPrefix(prefix=e["prefix"], origin_as=origin, rpki_state=None) for e in entries]

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bound(entry: Dict[str, Any]) -> ScopedPrefix:
            async with semaphore:
                return await asyncio.to_thread(_check, entry)

        return list(await asyncio.gather(*[_bound(e) for e in entries]))

    async def _asn_name(self, asn: int) -> Optional[str]:
        """Best-effort organisation name for an ASN from RIPEstat ASN Neighbours."""
        url = "https://stat.ripe.net/data/as-overview/data.json"
        try:
            client = await self._client()
            resp = await client.get(url, params={"resource": f"AS{asn}"})
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return data.get("holder") or data.get("block") or None
        except Exception:  # noqa: BLE001
            return None

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    def __del__(self) -> None:
        if self._http and not self._http.is_closed:
            try:
                asyncio.get_running_loop().create_task(self._http.aclose())
            except RuntimeError:
                pass
