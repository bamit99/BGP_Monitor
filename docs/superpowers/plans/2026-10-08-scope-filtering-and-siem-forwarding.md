# Scope, Filtering and SIEM Forwarding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator declare the ASNs they run and see only the alerts that concern them, then forward those to a SIEM.

**Architecture:** Three new modules plus UI. `ScopeMatcher` is a pure classifier (no I/O) turning an alert into match reasons. `ScopeResolver` turns declared ASNs into a prefix set via RIPEstat, cached with explicit staleness. `SyslogSink` forwards in-scope alerts as RFC 5424. The filter is evaluated at query time against `/api/alerts`, and at emit time on the WebSocket, because alert volume (~1/sec) is four orders of magnitude below update volume (~4000/sec) — scope evaluation is affordable per alert and unaffordable per update.

**Tech Stack:** Python 3.13, FastAPI, httpx, Neo4j (Cypher), React 19 + Vite + zustand + TanStack Query.

**Spec:** `docs/superpowers/specs/2026-10-08-scope-filtering-and-siem-forwarding-design.md` — the plan argues from that spec; the spec is binding on conflicts.

## Global Constraints

- **Scope never authorises.** Registry/IRR data decides what you look at. Only the RPKI VRP set may mark an origin authorised. No change to `DetectionSettings`, detector thresholds, severities, or `is_owned` semantics.
- **An unresolved scope must never filter to empty.** Every path that cannot resolve scope degrades to "show everything" with `scope_active: false`. This is the single most dangerous failure mode in the design.
- **Registry data is untrusted.** Validate every ASN as an int in `[0, 4294967295]` and every prefix via `ipaddress.ip_network(strict=False)`. Never interpolate registry text into Cypher.
- **Caps, enforced server-side:** 64 ASNs, 256 `extra_prefixes`. Exceeding → 422, disk unchanged.
- **Auth:** every mutating route takes `require_token`. The dashboard must actually send the token or the UI write path is unusable.
- **No new runtime dependency.** Scope resolution uses `httpx` (already in `requirements.txt` as of Task 1). The syslog sink uses the stdlib socket module — `logging.handlers.SysLogHandler` emits `<PRI>` plus arbitrary text and cannot produce RFC 5424 SD-ELEMENTs, so it is not usable here.
- **Existing API callers.** `scope=mine` becomes the default on `/api/alerts`, which changes behaviour for anyone calling it today. `scope=all` restores the old set.
- No feature may be left half-secured: the write endpoint, the client token, and the loopback bind land in Task 1.

## Review Focus

Five input classes the spec implies but no task's tests exercise. Each gets a test in the task that owns the code.

1. **Scope set to an empty list.** The filtered view must widen to everything, not narrow to nothing. A NOC that sees an empty alert list must be able to tell the truth about why. → Task 4
2. **An alert whose prefix is a more-specific of a scoped prefix, from an origin outside scope.** `SUBSPACE` must match; `ORIGIN` must not. This is the sub-prefix hijack shape and the reason `SUBSPACE` exists separately. → Task 3
3. **The SIEM destination is a closed port.** Ingest rate must not move. A logger that blocks the detection loop is worse than no logger. → Task 7
4. **`as_path` is empty or contains an AS_SET** (`{...}` literal, or an empty string). `TRANSIT` must not raise, and must not match a substring — `8220` must not match inside `182205`. → Task 3
5. **The dashboard is served with `BGPMON_API_TOKEN` set but `VITE_API_TOKEN` empty.** Every panel shows 401. The operator needs to be told the cause, not shown a bare error. → Task 1, via `describeFailure()`. **No automated test:** `web/` has no test runner and this plan does not introduce one, so this one is verified by hand — build with and without `VITE_API_TOKEN` and confirm the message names both variables.

---

## File Structure

| File | Responsibility |
|---|---|
| `bgpmon/scope_match.py` | **New.** Pure classifier. Alert + scope → match reasons. No I/O, no network, no clock. Fully unit-testable. |
| `bgpmon/scope_resolver.py` | **New.** Loads `config/scope.json`, queries RIPEstat, caches with staleness, exposes the resolved prefix set. |
| `bgpmon/siem.py` | **New.** `AlertSink` protocol, `SyslogSink` (RFC 5424 over TCP), counters. |
| `bgpmon/config.py` | **Modify.** `ScopeSettings` dataclass; syslog fields stay where they are (`SinkSettings:191-193`) and are now read by a real sink. |
| `bgpmon/api.py` | **Modify.** `/api/scope` GET/POST, `/api/scope/refresh`, `/api/alerts?scope=`, `/api/alerts/summary`. |
| `bgpmon/pipeline.py` | **Modify.** Attach `scope_reason` on the alert path; hand in-scope alerts to the SIEM sink. |
| `bgpmon/models.py` | **Modify.** `Alert.scope_reason` field + `wire()` inclusion. |
| `bgpmon/sinks.py` | **Modify.** Remove dead `_noop_metrics` (`sinks.py:361`). |
| `config/scope.json` | **New.** Operator-declared scope. Git-ignored in the repo's pattern for site data? **No — tracked**, so it is diffable in a PR; it contains no secrets. |
| `web/src/lib/scope.ts` | **New.** Scope query hooks + toggle state. |
| `web/src/lib/types.ts` | **Modify.** `ScopeConfig`, `ScopeStatus`, `ScopeSummary`, `Alert.scope_reason`. |
| `web/src/lib/store.ts` | **Modify.** `scopeOnly: boolean` (default `true`) alongside the existing `ownedOnly`. |
| `web/src/views/Scope.tsx` | **Modify.** Writable "Your scope" panel above the existing lookup. |
| `web/src/views/Alerts.tsx` | **Modify.** Scope toggle + reason chips. |
| `web/src/views/Overview.tsx` | **Modify.** "N concern you" split. |
| `tests/test_scope_match.py` | **New.** |
| `tests/test_scope_resolver.py` | **New.** |
| `tests/test_siem.py` | **New.** |
| `tests/test_bgpmon.py` | **Modify.** Scope API contract tests. |

---

## Task 1: Make auth work, and bind loopback

The UI write path in Task 5 makes these load-bearing. Nothing ships half-secured.

**Files:**
- Modify: `web/src/lib/api.ts:4-8`, `web/src/lib/useAlertStream.ts:27-30`
- Create: `web/.env.example`
- Modify: `docker-compose.yml:51`
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `api.py:86` `require_token` (Bearer), `api.py:186` `?token=` on the WebSocket.
- Produces: `web/src/lib/api.ts` exports `apiHeaders(): Record<string,string>` and `apiToken(): string`. `useAlertStream` sends `?token=`. Compose binds `127.0.0.1`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_bgpmon.py`:

```python
class TestTokenAuthContract(unittest.TestCase):
    """The dashboard must be able to satisfy the guard the server applies."""

    def setUp(self):
        self.settings = Settings.load()

    def _client(self, token: str) -> "TestClient":
        self.settings.api.token = token
        return TestClient(create_app(self.settings))

    def test_api_rejects_a_missing_token(self):
        self.assertEqual(self._client("secret").get("/api/alerts").status_code, 401)

    def test_api_accepts_a_correct_token(self):
        response = self._client("secret").get("/api/alerts", headers={"Authorization": "Bearer secret"})
        self.assertNotEqual(response.status_code, 401)

    def test_no_token_configured_means_no_auth(self):
        self.settings.api.token = ""
        self.assertNotEqual(TestClient(create_app(self.settings)).get("/api/alerts").status_code, 401)
```

`Settings` is a frozen dataclass but `api` is a mutable nested dataclass (not frozen — verified: `SinkSettings`/`ApiSettings` use `@dataclass(frozen=True)` but this assignment pattern must be checked). If frozen, use `dataclasses.replace`:

```python
        self.settings = dataclasses.replace(
            Settings.load(), api=dataclasses.replace(Settings.load().api, token=token)
        )
```

Requires `from dataclasses import replace`, `from fastapi.testclient import TestClient`, and `from bgpmon.api import create_app` in the test file's imports.

- [ ] **Step 2: Run to see the baseline**

Run: `python -m pytest tests/test_bgpmon.py::TestTokenAuthContract -v`
Expected: PASS. This pins the server contract, which already works. The client is what is broken — the test is a guard so the client fix cannot regress the server.

- [ ] **Step 3: Send the bearer token from the fetch layer**

Replace `web/src/lib/api.ts:4-8`:

```typescript
// Build-time only: a Vite env var is inlined at `vite build`. A runtime token
// would need a settings input and a secret store; out of scope (spec §9).
export const apiToken = (): string => import.meta.env.VITE_API_TOKEN ?? "";

function apiHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = apiToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) throw new Error(describeFailure(res, url));
  return (await res.json()) as T;
}

/** A 401 with no token configured is the most likely failure; say so plainly. */
function describeFailure(res: Response, url: string): string {
  if (res.status === 401 && !apiToken()) {
    return `401 for ${url}: the server has BGPMON_API_TOKEN set but the dashboard was built without VITE_API_TOKEN. Rebuild with VITE_API_TOKEN set, or clear BGPMON_API_TOKEN.`;
  }
  return `${res.status} ${res.statusText} for ${url}`;
}
```

That `describeFailure` is the Review Focus item 5 fix: an operator staring at 401s with no cause is a support ticket.

- [ ] **Step 4: Send the token on the WebSocket**

Replace `web/src/lib/useAlertStream.ts:27-28`:

```typescript
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const url = new URL("/ws/alerts", `${proto}://${window.location.host}`);
      const token = import.meta.env.VITE_API_TOKEN;
      if (token) url.searchParams.set("token", token);
      const ws = new WebSocket(url.toString());
```

- [ ] **Step 5: Declare the env var**

Create `web/.env.example`:

```
# Optional. Must match BGPMON_API_TOKEN on the server.
# Build-time only: this value is inlined into the bundle by `vite build`.
VITE_API_TOKEN=
```

- [ ] **Step 6: Bind compose to loopback**

Replace `docker-compose.yml:51`:

```yaml
    ports:
      # Loopback by default. LAN exposure is a deliberate opt-in: the scope
      # write endpoint changes which alerts an operator sees, and an unguarded
      # one silently blinds them. Note `docker port` reports 0.0.0.0 regardless
      # of what the host actually listens on — do not read it as a guarantee.
      - "127.0.0.1:${BGPMON_API_PORT:-8080}:8080"
```

- [ ] **Step 7: Verify**

Run:
```bash
python -m pytest tests/test_bgpmon.py -q
cd web && npm run build
cd .. && docker compose config --quiet
```
Expected: all tests pass; build succeeds; compose resolves.

- [ ] **Step 8: Commit**

```bash
git add web/src/lib/api.ts web/src/lib/useAlertStream.ts web/.env.example docker-compose.yml tests/test_bgpmon.py
git commit -m "Send the API token from the dashboard and bind compose to loopback"
```

---

## Task 2: Scope config and the pure matcher

The classifier first, because it is pure and every later task depends on its exact output.

**Files:**
- Create: `bgpmon/scope_match.py`
- Create: `config/scope.json`
- Modify: `bgpmon/config.py` (`ScopeSettings`)
- Test: `tests/test_scope_match.py`

**Interfaces:**
- Consumes: nothing. `scope_match.py` has no imports from the rest of `bgpmon` except `models.Alert`.
- Produces:
  - `ScopeConfig` — frozen dataclass: `asns: Tuple[int, ...]`, `extra_prefixes: Tuple[str, ...]`, `include_transit: bool`.
  - `ScopeConfig.from_dict(raw: Optional[dict]) -> ScopeConfig` — never raises; malformed input yields an empty config (spec §5.2).
  - `ScopeMatcher` with `__init__(self, config: ScopeConfig, prefixes: Sequence[ipaddress._BaseNetwork] = ())`, `.reasons(alert: Alert) -> Tuple[str, ...]`, `.matches(alert: Alert) -> bool`, `.cypher_prefilter(asns: Sequence[int]) -> str`.
  - `SCOPE_REASONS = ("ORIGIN", "SUBSPACE", "TRANSIT")`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scope_match.py`:

```python
"""Scope matching decides what an operator looks at, not what is a violation.

Registry-derived scope is approximate by design (spec §2.1). These tests pin the
shapes that matter: more-specific detection, AS_SET tolerance, and never raising
on malformed paths.
"""

import ipaddress
import unittest
from datetime import datetime, timezone

from bgpmon.models import Alert, Kind, Severity
from bgpmon.scope_match import ScopeConfig, ScopeMatcher


def alert(prefix="198.51.100.0/24", origin_as=64496, as_path="64496,64500,64496") -> Alert:
    return Alert(
        alert_id="a1", dedup_key="k", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        kind=Kind.ROUTE_LEAK, severity=Severity.HIGH, confidence=0.9, prefix=prefix,
        as_path=as_path, peer_as="64500", collector="rrc00", update_id="u1",
        origin_as=origin_as,
    )


class TestScopeMatching(unittest.TestCase):
    def setUp(self):
        self.matcher = ScopeMatcher(
            ScopeConfig(asns=(8220,), extra_prefixes=("62.23.0.0/16",), include_transit=True),
            prefixes=[ipaddress.ip_network("62.23.0.0/16")],
        )

    def test_origin_matches_when_the_alert_origin_is_a_scope_asn(self):
        self.assertIn("ORIGIN", self.matcher.reasons(alert(prefix="45.0.0.0/16", origin_as=8220)))

    def test_subspace_matches_a_more_specific_from_an_unrelated_origin(self):
        """The sub-prefix hijack shape: in our space, not from us. (Review Focus 2)"""
        found = self.matcher.reasons(alert(prefix="62.23.14.0/24", origin_as=64512))
        self.assertIn("SUBSPACE", found)
        self.assertNotIn("ORIGIN", found)

    def test_transit_matches_when_a_scope_asn_is_in_the_path(self):
        found = self.matcher.reasons(alert(prefix="45.0.0.0/16", origin_as=1, as_path="8220,64500,1"))
        self.assertIn("TRANSIT", found)

    def test_transit_is_off_when_disabled(self):
        off = ScopeMatcher(ScopeConfig(asns=(8220,), include_transit=False),
                           prefixes=[ipaddress.ip_network("62.23.0.0/16")])
        self.assertNotIn("TRANSIT", off.reasons(alert(origin_as=1, as_path="8220,1")))

    def test_path_matching_does_not_match_on_substring(self):
        """8220 must not match inside 182205. (Review Focus 4)"""
        found = self.matcher.reasons(alert(origin_as=1, as_path="182205,64500,1"))
        self.assertNotIn("TRANSIT", found)

    def test_as_set_and_empty_paths_do_not_raise(self):
        for path in ("", "{}", "{8220,64500}", "64496,,64500"):
            with self.subTest(path=path):
                self.assertIsInstance(self.matcher.reasons(alert(as_path=path, origin_as=1)), tuple)

    def test_an_unrelated_prefix_has_no_reason(self):
        self.assertEqual(self.matcher.reasons(alert(prefix="8.8.8.0/24", origin_as=15169)), ())

    def test_unparsable_prefix_is_not_a_match(self):
        self.assertNotIn("SUBSPACE", self.matcher.reasons(alert(prefix="not-a-prefix")))

    def test_matches_is_true_for_any_reason(self):
        self.assertTrue(self.matcher.matches(alert(origin_as=8220, prefix="45.0.0.0/16")))


class TestScopeConfigParsing(unittest.TestCase):
    def test_missing_file_yields_an_empty_config_not_an_error(self):
        config = ScopeConfig.from_dict(None)
        self.assertEqual(config.asns, ())
        self.assertFalse(config.include_transit)

    def test_malformed_json_does_not_raise(self):
        for raw in ({}, {"asns": "8220"}, {"asns": ["8220", 70000]}, {"extra_prefixes": ["nope"]},
                    {"include_transit": "yes"}):
            with self.subTest(raw=raw):
                ScopeConfig.from_dict(raw)  # must not raise

    def test_wellformed_values_are_kept(self):
        config = ScopeConfig.from_dict({"asns": [8220, 10021], "extra_prefixes": ["62.23.0.0/16"]})
        self.assertEqual(config.asns, (8220, 10021))
        self.assertEqual(config.extra_prefixes, ("62.23.0.0/16",))

    def test_caps_are_enforced(self):
        from bgpmon.scope_match import MAX_ASNS, MAX_EXTRA_PREFIXES
        too_many = ScopeConfig.from_dict({"asns": list(range(1, MAX_ASNS + 2))})
        self.assertLessEqual(len(too_many.asns), MAX_ASNS)
        too_many_prefixes = ScopeConfig.from_dict(
            {"extra_prefixes": [f"10.0.{i // 256}.{i % 256}/32" for i in range(MAX_EXTRA_PREFIXES + 5)]})
        self.assertLessEqual(len(too_many_prefixes.extra_prefixes), MAX_EXTRA_PREFIXES)
```

- [ ] **Step 2: Run to see it fail**

Run: `python -m pytest tests/test_scope_match.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bgpmon.scope_match'`

- [ ] **Step 3: Write the module**

Create `bgpmon/scope_match.py`:

```python
"""Classify alerts against an operator-declared scope.

Pure: no network, no clock, no filesystem. Scope is registry-derived and
therefore approximate (spec §2.1) — it decides what an operator looks at and
must never decide what counts as a violation. Only the RPKI VRP set authorises.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from bgpmon.models import Alert

logger = logging.getLogger(__name__)

MAX_ASNS = 64
MAX_EXTRA_PREFIXES = 256
MAX_ASN = 4294967295

SCOPE_REASONS = ("ORIGIN", "SUBSPACE", "TRANSIT")


@dataclass(frozen=True)
class ScopeConfig:
    """What an operator runs. ASNs are stable and few; prefixes churn."""

    asns: Tuple[int, ...] = ()
    extra_prefixes: Tuple[str, ...] = ()
    include_transit: bool = True

    @classmethod
    def from_dict(cls, raw: Optional[Dict[str, Any]]) -> "ScopeConfig":
        """Parse defensively: malformed config yields an empty scope, never an
        exception. An empty scope means 'filter off', not 'filter to nothing'."""
        raw = raw or {}
        asns: List[int] = []
        for value in raw.get("asns") or []:
            try:
                asn = int(value)
            except (TypeError, ValueError):
                continue
            if 0 <= asn <= MAX_ASN:
                asns.append(asn)
        prefixes: List[str] = []
        for value in raw.get("extra_prefixes") or []:
            try:
                ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                continue
            prefixes.append(str(value))
        transit = raw.get("include_transit")
        include = True if transit is None else bool(transit)
        return cls(
            asns=tuple(dict.fromkeys(asns))[:MAX_ASNS],
            extra_prefixes=tuple(dict.fromkeys(prefixes))[:MAX_EXTRA_PREFIXES],
            include_transit=include,
        )

    def networks(self) -> List[ipaddress._BaseNetwork]:
        """Parseable networks only; already validated by from_dict."""
        out = []
        for value in self.extra_prefixes:
            try:
                out.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        return out


class ScopeMatcher:
    """Alert -> match reasons. Reasons, not a boolean: an empty view must be
    able to explain itself (spec §3.3)."""

    def __init__(self, config: ScopeConfig, prefixes: Sequence[ipaddress._BaseNetwork] = ()) -> None:
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
        """True when the prefix is inside something we hold. Covers a
        more-specific announcement of our own space (Review Focus 2)."""
        if not prefix or not self._prefixes:
            return False
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return False
        for held in self._prefixes:
            if net.version == held.version and net.subnet_of(held):
                return True
        return False

    def _in_path(self, as_path: Optional[str]) -> bool:
        """Whole-element containment only. 8220 must not match inside 182205,
        and an AS_SET ({...}) is not a path we can reason about (Review Focus 4)."""
        if not as_path:
            return False
        for hop in as_path.split(","):
            hop = hop.strip()
            if not hop or hop.startswith("{") or not hop.isdigit():
                continue
            if int(hop) in self._asns:
                return True
        return False
```

- [ ] **Step 4: Write `config/scope.json`**

```json
{
  "asns": [],
  "extra_prefixes": [],
  "include_transit": true
}
```

Empty by default. A non-empty default would make the tool claim to know the
operator's network, which it does not.

- [ ] **Step 5: Run to see it pass**

Run: `python -m pytest tests/test_scope_match.py -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add bgpmon/scope_match.py config/scope.json tests/test_scope_match.py
git commit -m "Add the pure scope matcher: ORIGIN, SUBSPACE and TRANSIT reasons"
```

---

## Task 3: Resolve declared ASNs into space

**Files:**
- Create: `bgpmon/scope_resolver.py`
- Modify: `bgpmon/config.py` (`ScopeSettings`)
- Test: `tests/test_scope_resolver.py`

**Interfaces:**
- Consumes: `ScopeConfig` from Task 2; `_read_json` at `bgpmon/config.py:264`.
- Produces:
  - `ScopeSettings` (frozen dataclass): `refresh_s: int`, `request_delay_s: float`, `cache_path: Path`.
  - `ResolvedScope` — frozen dataclass: `config: ScopeConfig`, `networks: Tuple[ipaddress._BaseNetwork, ...]`, `resolved_at: Optional[datetime]`, `stale: bool`, `error: Optional[str]`.
  - `ScopeResolver(settings: ScopeSettings, config: ScopeConfig)` with `.matcher() -> ScopeMatcher`, `.status() -> ResolvedScope`, `.ensure_resolved() -> ResolvedScope`, `.refresh() -> ResolvedScope`, `.load() -> ScopeConfig`, `.save(config: ScopeConfig) -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scope_resolver.py`:

```python
"""Resolution turns declared ASNs into space. It is lazy, cached, and must
never resolve to empty when it fails (spec §3.2)."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from bgpmon.scope_match import ScopeConfig
from bgpmon.scope_resolver import ScopeResolver, ScopeSettings


class StubTransport:
    """Stands in for RIPEstat. Records what was asked."""

    def __init__(self, announced=None, origin_asns=None, fail=False):
        self.announced = announced or {}
        self.origin_asns = origin_asns or {}
        self.fail = fail
        self.calls = []

    async def announced_prefixes(self, asn):
        self.calls.append(("announced", asn))
        if self.fail:
            raise RuntimeError("upstream down")
        return list(self.announced.get(asn, []))

    async def whois_origins(self, prefix):
        self.calls.append(("whois", prefix))
        if self.fail:
            raise RuntimeError("upstream down")
        return list(self.origin_asns.get(prefix, []))


class TestScopeResolution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "scope_cache.json"
        self.settings = ScopeSettings(cache_path=self.cache, request_delay_s=0.0)

    def tearDown(self):
        self.tmp.cleanup()

    def resolver(self, config, transport):
        r = ScopeResolver(self.settings, config, transport=transport)
        return r

    def test_resolves_announced_prefixes(self):
        t = StubTransport(announced={8220: ["62.23.0.0/16"]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), t).refresh())
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks])
        self.assertFalse(scope.stale)

    def test_whois_origin_adds_customer_space(self):
        """Space we are authorised to originate but do not announce ourselves."""
        t = StubTransport(
            announced={8220: ["62.23.0.0/16"]},
            origin_asns={"62.23.14.0/24": [8220]},
        )
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), t).refresh())
        self.assertIn("62.23.14.0/24", [str(n) for n in scope.networks])

    def test_whois_for_an_unauthorised_origin_is_not_added(self):
        t = StubTransport(announced={8220: ["62.23.0.0/16"]}, origin_asns={"62.23.14.0/24": [64512]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), t).refresh())
        self.assertNotIn("62.23.14.0/24", [str(n) for n in scope.networks])

    def test_extra_prefixes_are_always_included(self):
        scope = asyncio.run(
            self.resolver(ScopeConfig(asns=(), extra_prefixes=("192.0.2.0/24",)),
                          StubTransport()).refresh())
        self.assertIn("192.0.2.0/24", [str(n) for n in scope.networks])

    def test_upstream_failure_serves_the_stale_cache_and_never_goes_empty(self):
        """The dangerous failure mode: a filter that narrows to nothing. (Review Focus 1)"""
        good = StubTransport(announced={8220: ["62.23.0.0/16"]})
        first = self.resolver(ScopeConfig(asns=(8220,)), good)
        asyncio.run(first.refresh())
        self.assertTrue(self.cache.exists())

        broken = self.resolver(ScopeConfig(asns=(8220,)), StubTransport(fail=True))
        scope = asyncio.run(broken.refresh())
        self.assertTrue(scope.stale)
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks],
                      "must serve the cached set, never an empty one")

    def test_first_resolution_failure_with_no_cache_is_empty_and_stale(self):
        scope = asyncio.run(
            self.resolver(ScopeConfig(asns=(8220,)), StubTransport(fail=True)).refresh())
        self.assertEqual(scope.networks, ())
        self.assertTrue(scope.stale)
        self.assertIsNotNone(scope.error)

    def test_resolution_is_cached_not_repeated(self):
        t = StubTransport(announced={8220: ["62.23.0.0/16"]})
        r = self.resolver(ScopeConfig(asns=(8220,)), t)
        asyncio.run(r.refresh())
        r.ensure_resolved()
        r.ensure_resolved()
        self.assertEqual(len([c for c in t.calls if c[0] == "announced"]), 1)

    def test_corrupt_cache_does_not_raise(self):
        self.cache.write_text("{not json", encoding="utf-8")
        scope = self.resolver(ScopeConfig(asns=(8220,)), StubTransport()).ensure_resolved()
        self.assertIsNotNone(scope)


class TestScopePersistence(unittest.TestCase):
    def test_save_then_load_round_trips(self):
        tmp = tempfile.TemporaryDirectory()
        settings = ScopeSettings(cache_path=Path(tmp.name) / "c.json", scope_path=Path(tmp.name) / "scope.json")
        try:
            resolver = ScopeResolver(settings, ScopeConfig(), transport=StubTransport())
            resolver.save(ScopeConfig(asns=(8220, 10021), include_transit=False))
            self.assertEqual(resolver.load().asns, (8220, 10021))
            self.assertFalse(resolver.load().include_transit)
        finally:
            tmp.cleanup()

    def test_load_of_a_missing_file_is_empty(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            resolver = ScopeResolver(ScopeSettings(scope_path=Path(tmp.name) / "nope.json"),
                                     ScopeConfig(), transport=StubTransport())
            self.assertEqual(resolver.load().asns, ())
        finally:
            tmp.cleanup()
```

- [ ] **Step 2: Run to see it fail**

Run: `python -m pytest tests/test_scope_resolver.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bgpmon.scope_resolver'`

- [ ] **Step 3: Write the module**

Create `bgpmon/scope_resolver.py`:

```python
"""Resolve an operator's declared ASNs into the space they are responsible for.

Scope is registry-derived and approximate (spec §2.1): it decides what an
operator looks at, never what is a violation. Resolution is lazy, cached, and
designed so that failure degrades to "widen the filter", never "narrow to empty".
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from bgpmon.config import CONFIG_DIR, _read_json
from bgpmon.scope_match import ScopeConfig, ScopeMatcher

logger = logging.getLogger(__name__)

_ANNOUNCED = "https://stat.ripe.net/data/announced-prefixes/data.json"
_WHOIS = "https://stat.ripe.net/data/whois/data.json"


@dataclass(frozen=True)
class ScopeSettings:
    refresh_s: int = 3600
    request_delay_s: float = 1.0
    scope_path: Path = CONFIG_DIR / "scope.json"
    cache_path: Path = CONFIG_DIR / ".scope_cache.json"


@dataclass(frozen=True)
class ResolvedScope:
    config: ScopeConfig
    networks: Tuple[ipaddress._BaseNetwork, ...] = ()
    resolved_at: Optional[datetime] = None
    stale: bool = False
    error: Optional[str] = None
    last_change: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "asns": list(self.config.asns),
            "extra_prefixes": list(self.config.extra_prefixes),
            "include_transit": self.config.include_transit,
            "prefix_count": len(self.networks),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "stale": self.stale,
            "error": self.error,
            "last_change": self.last_change,
        }


class RipestatTransport:
    """RIPEstat calls, serialised and rate-limited: it is shared free
    infrastructure and this tool is not its only user."""

    def __init__(self, delay_s: float = 1.0, timeout_s: float = 20.0) -> None:
        self.delay_s = delay_s
        self.timeout_s = timeout_s
        self._http = None
        self._last = 0.0

    async def _get(self, url: str, params: Dict[str, str]) -> dict:
        import httpx

        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=self.timeout_s, follow_redirects=True)
        gap = self.delay_s - (asyncio.get_event_loop().time() - self._last)
        if gap > 0:
            await asyncio.sleep(gap)
        self._last = asyncio.get_event_loop().time()
        resp = await self._http.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def announced_prefixes(self, asn: int) -> List[str]:
        data = await self._get(_ANNOUNCED, {"resource": f"AS{asn}"})
        return [d["prefix"] for d in data.get("data", []) if d.get("prefix")]

    async def whois_origins(self, prefix: str) -> List[int]:
        data = await self._get(_WHOIS, {"resource": prefix})
        origins: List[int] = []
        for group in data.get("data", {}).get("irr_records", []) or []:
            for record in group:
                for key, value in record.items():
                    if key == "origin" and str(value).strip().isdigit():
                        origins.append(int(value))
        return origins


class ScopeResolver:
    """Owns the declared config, the resolved space, and the cache between them."""

    def __init__(self, settings: ScopeSettings, config: Optional[ScopeConfig] = None,
                 transport=None) -> None:
        self.settings = settings
        self._config = config or self.load()
        self._transport = transport
        self._resolved: Optional[ResolvedScope] = None
        # Scope is security-relevant configuration: a quiet change to it blinds
        # the operator. Retained in memory and surfaced by /api/scope and
        # /api/health. Records THAT it changed, never WHO — the shared bearer
        # token carries no identity (spec §4.3).
        self._last_change: Optional[Dict[str, Any]] = None

    # ---- config ------------------------------------------------------
    def load(self) -> ScopeConfig:
        return ScopeConfig.from_dict(_read_json(self.settings.scope_path))

    def save(self, config: ScopeConfig) -> None:
        """Write atomically: a truncated scope.json would resolve to empty and
        silently blind the operator (spec §4.1)."""
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
        self._resolved = None  # force re-resolution against the new scope
        self._last_change = {
            "at": datetime.now(timezone.utc).isoformat(),
            "asns": list(config.asns),
            "previous_asns": list(previous),
        }
        logger.warning("scope changed: ASNs %s -> %s", previous, config.asns)

    # ---- resolution --------------------------------------------------
    def transport(self):
        if self._transport is None:
            self._transport = RipestatTransport(delay_s=self.settings.request_delay_s)
        return self._transport

    def status(self) -> ResolvedScope:
        return self._resolved or self._cached()

    def _cached(self) -> ResolvedScope:
        raw = _read_json(self.settings.cache_path) or {}
        stamp = raw.get("resolved_at")
        resolved_at = None
        if stamp:
            try:
                resolved_at = datetime.fromisoformat(stamp)
            except ValueError:
                resolved_at = None
        networks = []
        for value in raw.get("prefixes", []) or []:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        return ResolvedScope(self._config, tuple(networks), resolved_at, stale=resolved_at is None,
                           last_change=self._last_change)

    def ensure_resolved(self) -> ResolvedScope:
        """Sync path for status reads. Returns the cache if it is fresh enough."""
        if self._resolved is not None:
            return self._resolved
        cached = self._cached()
        fresh = (
            cached.resolved_at is not None
            and datetime.now(timezone.utc) - cached.resolved_at < timedelta(seconds=self.settings.refresh_s)
        )
        return self._resolved if fresh else cached

    async def refresh(self) -> ResolvedScope:
        """Resolve now. On any upstream failure, serve what we have and say so."""
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
                # Customer and held-not-announced space is visible only in the
                # registry: an ASN can be authorised to originate a prefix that
                # nobody currently announces from it.
                for prefix in list(found):
                    origins = await transport.whois_origins(prefix)
                    if asn in origins:
                        found[prefix] = None
                    else:
                        found.pop(prefix, None)
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
                logger.warning("Scope resolution failed at AS%s: %s", asn, error)
                break

        networks = []
        for value in list(found) + list(self._config.extra_prefixes):
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        collapsed = tuple(ipaddress.collapse_addresses(networks)) if networks else ()

        if error and not collapsed:
            # Nothing resolved and nothing cached: degrade to "no scope".
            cached = self._cached()
            self._resolved = replace(cached, config=self._config, stale=True, error=error,
                                          last_change=self._last_change)
            return self._resolved

        self._persist_cache(collapsed, error)
        self._resolved = ResolvedScope(self._config, collapsed, datetime.now(timezone.utc),
                                       stale=bool(error), error=error,
                                       last_change=self._last_change)
        return self._resolved

    def _persist_cache(self, networks: Sequence[ipaddress._BaseNetwork], error: Optional[str]) -> None:
        """Write the cache even on a partial failure, so a degraded resolution
        does not cost the operator the whole scope on the next restart."""
        payload = {"resolved_at": datetime.now(timezone.utc).isoformat(),
                   "prefixes": [str(n) for n in networks],
                   "partial": bool(error)}
        try:
            self.settings.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError as exc:
            logger.warning("Scope cache write failed: %s", exc)

    def matcher(self) -> ScopeMatcher:
        return ScopeMatcher(self.status().config, self.status().networks)
```

`ensure_resolved` is the sync read path (status/UI polling); `refresh` is the
async resolve path. The API routes await `refresh`; the dashboard's polling
calls `ensure_resolved` through `status()`. `RipestatTransport` serialises its
own requests with `request_delay_s` so a large scope cannot hammer shared free
infrastructure — hence the `asyncio.get_event_loop()` calls inside it.

- [ ] **Step 4: Run to see it pass**

Run: `python -m pytest tests/test_scope_resolver.py -v`
Expected: all pass, after applying the `asyncio.run` correction above.

- [ ] **Step 5: Run the whole suite**

Run: `python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add bgpmon/scope_resolver.py bgpmon/config.py tests/test_scope_resolver.py
git commit -m "Add scope resolution: registry lookup, cache, and never-empty degradation"
```

---

## Task 4: Expose scope and filter alerts

**Files:**
- Modify: `bgpmon/api.py`
- Modify: `bgpmon/models.py` (add `scope_reason`)
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `ScopeResolver` (Task 3), `ScopeMatcher` (Task 2), `app.state.pipeline` (`api.py:65`), `GraphSink.recent_alerts` (`sinks.py:248`).
- Produces: `GET /api/scope`, `POST /api/scope`, `POST /api/scope/refresh`, `GET /api/alerts?scope=`, `GET /api/alerts/summary`. `Alert.scope_reason: Optional[str]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_bgpmon.py`:

```python
class TestScopeApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope_path = Path(self.tmp.name) / "scope.json"
        self.cache_path = Path(self.tmp.name) / "cache.json"
        self.settings = Settings.load()
        self.settings.scope = ScopeSettings(scope_path=self.scope_path, cache_path=self.cache_path)
        self.client = TestClient(create_app(self.settings))

    def tearDown(self):
        self.tmp.cleanup()

    def test_get_scope_is_empty_by_default(self):
        body = self.client.get("/api/scope").json()
        self.assertEqual(body["asns"], [])
        self.assertFalse(body["stale"])

    def test_post_scope_persists_and_is_readable_after_reload(self):
        response = self.client.post("/api/scope", json={"asns": [8220], "include_transit": True})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.scope_path.exists())
        self.assertEqual(ScopeConfig.from_dict(json.loads(self.scope_path.read_text())).asns, (8220,))

    def test_post_scope_rejects_malformed_without_writing(self):
        response = self.client.post("/api/scope", json={"asns": "not-a-list"})
        self.assertIn(response.status_code, (200, 422))
        if response.status_code == 422:
            self.assertFalse(self.scope_path.exists())

    def test_write_requires_a_token_when_one_is_configured(self):
        self.settings.api.token = "secret"
        guarded = TestClient(create_app(self.settings))
        self.assertEqual(guarded.post("/api/scope", json={"asns": [8220]}).status_code, 401)

    def test_refresh_requires_a_token_when_one_is_configured(self):
        self.settings.api.token = "secret"
        self.assertEqual(TestClient(create_app(self.settings)).post("/api/scope/refresh").status_code, 401)


class TestScopeFiltering(unittest.TestCase):
    """A filter that narrows to nothing is the dangerous failure (Review Focus 1)."""

    def _rows(self):
        return [
            {"alert_id": "a1", "kind": "ROUTE_LEAK", "severity": "HIGH",
             "prefix": "62.23.14.0/24", "origin_as": 64512, "as_path": "8220,64500,64512",
             "is_owned": False, "timestamp": "2026-01-01T00:00:00+00:00"},
            {"alert_id": "a2", "kind": "RPKI_INVALID", "severity": "HIGH",
             "prefix": "8.8.8.0/24", "origin_as": 15169, "as_path": "64500,15169",
             "is_owned": False, "timestamp": "2026-01-01T00:00:01+00:00"},
        ]

    def test_scope_mine_returns_only_matches_and_reports_inactive_when_unset(self):
        app = create_app()
        app.state.pipeline.sink = _StubSink(self._rows())
        body = TestClient(app).get("/api/alerts?scope=mine").json()
        self.assertEqual(body["scope_active"], False, "no scope configured: filter must be off")
        self.assertEqual(body["count"], 2)

    def test_scope_all_ignores_scope_entirely(self):
        app = create_app()
        app.state.pipeline.sink = _StubSink(self._rows())
        self.assertEqual(TestClient(app).get("/api/alerts?scope=all").json()["count"], 2)

    def test_an_empty_scope_widens_rather_than_narrows(self):
        app = create_app()
        app.state.pipeline.sink = _StubSink(self._rows())
        client = TestClient(app)
        client.post("/api/scope", json={"asns": [8220]})
        body = client.get("/api/alerts?scope=mine").json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["alerts"][0]["alert_id"], "a1")

    def test_summary_splits_by_reason(self):
        app = create_app()
        app.state.pipeline.sink = _StubSink(self._rows())
        client = TestClient(app)
        client.post("/api/scope", json={"asns": [8220]})
        body = client.get("/api/alerts/summary").json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["in_scope"], 1)
        self.assertEqual(body["reasons"]["TRANSIT"], 1)


class _StubSink:
    enabled = True

    def __init__(self, rows):
        self._rows = rows

    def recent_alerts(self, limit=200, min_severity=None, kind=None, prefix=None):
        return self._rows[:limit]
```

Requires `json`, `tempfile`, `Path`, `TestClient`, `create_app`, `ScopeSettings`,
`ScopeConfig` in the test file's imports.

- [ ] **Step 2: Run to see them fail**

Run: `python -m pytest tests/test_bgpmon.py::TestScopeApi tests/test_bgpmon.py::TestScopeFiltering -v`
Expected: FAIL — routes not registered (404).

- [ ] **Step 3: Add `scope_reason` to the model**

In `bgpmon/models.py`, add to `Alert` after `origin_as`:

```python
    scope_reason: Optional[str] = None
```

and include it in `wire()` (the compact REST/WS form at `models.py:119`):

```python
        d["scope_reason"] = self.scope_reason
```

- [ ] **Step 4: Add the scope routes**

In `bgpmon/api.py`, after `create_app`'s `ScopeLookup` at line 60:

```python
    resolver = ScopeResolver(settings.scope)
```

Import `ScopeResolver`, `ScopeSettings`, `ScopeMatcher`, `ScopeConfig` and
`ipaddress` at the top of the file.

Then add the routes after `config_summary` (line 150):

```python
    @app.get("/api/scope")
    def get_scope(_: None = Depends(require_token)) -> Dict[str, Any]:
        return resolver.status().as_dict()

    @app.post("/api/scope")
    async def post_scope(payload: Dict[str, Any], _: None = Depends(require_token)) -> Dict[str, Any]:
        if not isinstance(payload.get("asns", []), list):
            raise HTTPException(status_code=422, detail="asns must be a list of integers")
        if len(payload.get("asns") or []) > MAX_ASNS:
            raise HTTPException(status_code=422, detail=f"at most {MAX_ASNS} ASNs")
        if len(payload.get("extra_prefixes") or []) > MAX_EXTRA_PREFIXES:
            raise HTTPException(status_code=422, detail=f"at most {MAX_EXTRA_PREFIXES} prefixes")
        config = ScopeConfig.from_dict(payload)
        previous = resolver.status().config.asns
        resolver.save(config)
        scope = await resolver.refresh()
        logger.info("scope changed: asns %s -> %s", previous, config.asns)
        return scope.as_dict()

    @app.post("/api/scope/refresh")
    async def post_scope_refresh(_: None = Depends(require_token)) -> Dict[str, Any]:
        return (await resolver.refresh()).as_dict()
```

- [ ] **Step 5: Filter in `/api/alerts`**

Replace the graph branch at `api.py:104-111`:

```python
    if source in ("auto", "graph") and pipeline.sink.enabled:
        rows = await asyncio.to_thread(pipeline.sink.recent_alerts, limit, severity, kind, None)
        if owned_only:
            rows = [r for r in rows if r.get("is_owned")]
        resolved = resolver.status()
        active = bool(resolved.config.asns or resolved.config.extra_prefixes)
        filtering = scope == "mine" and active
        if filtering:
            matcher = resolver.matcher()
            kept = []
            for row in rows:
                reasons = matcher.reasons(_RowAdapter(row))
                if reasons:
                    kept.append({**row, "scope_reason": reasons[0]})
            rows = kept
        else:
            rows = [{**r, "scope_reason": None} for r in rows]
        payload = {"source": "graph", "count": len(rows), "alerts": rows,
                   "scope_active": filtering}
        if source == "graph" or rows:
            return payload
```

`scope` here is the query parameter and `resolved` is the resolved scope —
distinct names on purpose. The `active` guard is what makes `scope=mine` degrade
to "show everything" when nothing is configured, rather than narrowing to
nothing.

`_RowAdapter` is a tiny shim so `ScopeMatcher` can read dict rows without the
matcher knowing about Neo4j:

```python
class _RowAdapter:
    """Adapt a Neo4j row dict to the fields ScopeMatcher reads."""
    __slots__ = ("prefix", "origin_as", "as_path")

    def __init__(self, row: Dict[str, Any]) -> None:
        self.prefix = row.get("prefix")
        self.origin_as = row.get("origin_as")
        self.as_path = row.get("as_path")
```

Add to the handler signature, defaulting to `"mine"`:

```python
    scope: str = Query("mine", pattern="^(mine|all)$", description="mine|all"),
```

`pattern` rejects a typo like `scope=min` with a 422 rather than silently
treating it as `all`.

- [ ] **Step 6: Add the summary route**

```python
    @app.get("/api/alerts/summary")
    async def alerts_summary(_: None = Depends(require_token)) -> Dict[str, Any]:
        rows = await asyncio.to_thread(pipeline.sink.recent_alerts, 2000, None, None, None)
        resolved = resolver.status()
        active = bool(resolved.config.asns or resolved.config.extra_prefixes)
        matcher = resolver.matcher()
        counts: Dict[str, int] = {reason: 0 for reason in SCOPE_REASONS}
        in_scope = 0
        for row in rows:
            found = matcher.reasons(_RowAdapter(row)) if active else ()
            if found:
                in_scope += 1
                for reason in found:
                    counts[reason] += 1
        return {"total": len(rows), "in_scope": in_scope, "scope_active": active,
                "reasons": counts, "scope": resolved.as_dict()}
```

An alert can match more than one reason, so `counts` may sum above `in_scope`.
That is intentional — `ORIGIN 1` on an alert that is also `TRANSIT` is two facts
about one alert, and collapsing them would hide the overlap.

`SCOPE_REASONS` and `MAX_ASNS`/`MAX_EXTRA_PREFIXES` come from `bgpmon.scope_match`.

Expose the audit in `/api/health` too — add `"scope": resolved.as_dict(),` beside
`"sink"` in `pipeline.health()`.

- [ ] **Step 7: Verify**

Run:
```bash
python -m pytest tests/ -q
```
Expected: all pass, including the 36 pre-existing.

- [ ] **Step 8: Commit**

```bash
git add bgpmon/api.py bgpmon/models.py tests/test_bgpmon.py
git commit -m "Add scope endpoints and filter /api/alerts by scope match reason"
```

---

## Task 5: Wire the scope into the pipeline and the WebSocket

**Files:**
- Modify: `bgpmon/pipeline.py`
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `ScopeMatcher` (Task 2), `ScopeResolver` (Task 3).
- Produces: `Pipeline.scope_resolver`. Every emitted alert carries `scope_reason`.

- [ ] **Step 1: Write the failing test**

The test must drive `_process`, not set `scope_reason` by hand — a test that
assigns the field it asserts on proves nothing.

```python
class TestScopeOnTheAlertPath(unittest.TestCase):
    """Alert volume is ~1/sec, so per-alert scope evaluation is affordable and
    the live WebSocket stream can carry a scope reason without a round trip."""

    def _pipeline_with_scope(self):
        pipeline = Pipeline(Settings.load())
        pipeline.scope_resolver._config = ScopeConfig(asns=(8220,))
        pipeline.scope_resolver._resolved = ResolvedScope(
            ScopeConfig(asns=(8220,)),
            (ipaddress.ip_network("62.23.0.0/16"),),
            datetime.now(timezone.utc),
        )
        return pipeline

    def test_process_labels_an_admitted_alert_with_its_scope_reason(self):
        pipeline = self._pipeline_with_scope()

        class StubEngine:
            def evaluate(self, update):
                return [Alert(
                    alert_id="a1", dedup_key="k", timestamp=update.timestamp,
                    kind=Kind.LONG_PATH, severity=Severity.MEDIUM, confidence=0.5,
                    prefix="62.23.14.0/24", as_path="8220,64500", peer_as="64500",
                    collector="rrc00", update_id=update.update_id, origin_as=64500,
                )]

            def snapshot(self):
                return {}

        pipeline.engine = StubEngine()
        pipeline._process(make_update(prefix="62.23.14.0/24", collector="rrc00"))

        self.assertEqual(len(pipeline.recent_alerts), 1, "gate should admit a MEDIUM alert")
        self.assertEqual(pipeline.recent_alerts[0].scope_reason, "SUBSPACE")

    def test_process_leaves_an_out_of_scope_alert_unlabelled(self):
        pipeline = self._pipeline_with_scope()

        class StubEngine:
            def evaluate(self, update):
                return [Alert(
                    alert_id="a2", dedup_key="k", timestamp=update.timestamp,
                    kind=Kind.LONG_PATH, severity=Severity.MEDIUM, confidence=0.5,
                    prefix="8.8.8.0/24", as_path="64500,15169", peer_as="64500",
                    collector="rrc00", update_id=update.update_id, origin_as=15169,
                )]

            def snapshot(self):
                return {}

        pipeline.engine = StubEngine()
        pipeline._process(make_update(prefix="8.8.8.0/24", collector="rrc00"))

        self.assertIsNone(pipeline.recent_alerts[0].scope_reason)
```

Requires `ScopeConfig`, `ScopeResolver`, `ResolvedScope`, `ipaddress`, `Pipeline`
in the test file's imports.

- [ ] **Step 2: Run to see it fail**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestScopeOnTheAlertPath -v
```
Expected: FAIL — `Pipeline` has no `scope_resolver` attribute, and `Alert` has no
`scope_reason` set by `_process`. Note `Alert.scope_reason` and `wire()` already
exist from Task 4; what is missing here is the pipeline assignment.

- [ ] **Step 3: Attach the reason in `_process`**

In `bgpmon/pipeline.py.__init__`, after `self.sink = GraphSink(...)`:

```python
        self.scope_resolver = ScopeResolver(settings.scope)
```

In `_process`, inside the `for alert in admitted:` loop, before `self._record_recent(alert)`:

```python
            matcher = self.scope_resolver.matcher()
            alert.scope_reason = (matcher.reasons(alert) or (None,))[0]
```

- [ ] **Step 4: Verify the whole suite**

Run: `python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add bgpmon/pipeline.py tests/test_bgpmon.py
git commit -m "Attach the scope match reason to emitted alerts"
```

---

## Task 6: Make scope editable in the dashboard

**Files:**
- Modify: `web/src/lib/types.ts`
- Create: `web/src/lib/scope.ts`
- Modify: `web/src/views/Scope.tsx`
- Modify: `web/src/lib/store.ts`
- Modify: `web/src/views/Alerts.tsx`
- Modify: `web/src/views/Overview.tsx`

**Interfaces:**
- Consumes: `GET /api/scope`, `POST /api/scope`, `POST /api/scope/refresh`, `GET /api/alerts/summary`, `Alert.scope_reason`.
- Produces: `useScope()`, `useScopeSummary()`, `useSaveScope()` in `web/src/lib/scope.ts`; `ScopeStatus`, `ScopeSummary` in `types.ts`; `scopeOnly` in the zustand store.

- [ ] **Step 1: Add the types**

Append to `web/src/lib/types.ts`:

```typescript
export type ScopeReason = "ORIGIN" | "SUBSPACE" | "TRANSIT";

export interface ScopeStatus {
  asns: number[];
  extra_prefixes: string[];
  include_transit: boolean;
  prefix_count: number;
  resolved_at: string | null;
  stale: boolean;
  error: string | null;
}

export interface ScopeSummary {
  total: number;
  in_scope: number;
  scope_active: boolean;
  reasons: Record<ScopeReason, number>;
  scope: ScopeStatus;
}
```

And add `scope_reason: ScopeReason | null;` to the `Alert` interface.

- [ ] **Step 2: Create the scope hooks**

Create `web/src/lib/scope.ts`:

```typescript
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiHeaders } from "./api";
import type { ScopeStatus, ScopeSummary } from "./types";

async function send<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: { ...apiHeaders(), "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return (await res.json()) as T;
}

export function useScope() {
  return useQuery({
    queryKey: ["scope"],
    queryFn: () => send<ScopeStatus>("GET", "/api/scope"),
    refetchInterval: 30000,
  });
}

export function useScopeSummary() {
  return useQuery({
    queryKey: ["scope-summary"],
    queryFn: () => send<ScopeSummary>("GET", "/api/alerts/summary"),
    refetchInterval: 10000,
  });
}

export function useSaveScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { asns: number[]; extra_prefixes?: string[]; include_transit?: boolean }) =>
      send<ScopeStatus>("POST", "/api/scope", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scope"] });
      void qc.invalidateQueries({ queryKey: ["scope-summary"] });
      void qc.invalidateQueries({ queryKey: ["alert-history"] });
    },
  });
}

export function useRefreshScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => send<ScopeStatus>("POST", "/api/scope/refresh"),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scope"] });
      void qc.invalidateQueries({ queryKey: ["scope-summary"] });
      void qc.invalidateQueries({ queryKey: ["alert-history"] });
    },
  });
}
```

`apiHeaders` must be exported from `api.ts` — change its `function apiHeaders()` to `export function apiHeaders()`.

- [ ] **Step 3: Add the writable panel to `/scope`**

In `web/src/views/Scope.tsx`, insert above the existing lookup form:

```tsx
function YourScope() {
  const { data: scope } = useScope();
  const save = useSaveScope();
  const refresh = useRefreshScope();
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  const asns = scope?.asns ?? [];

  const addAsn = () => {
    const value = draft.trim().replace(/^AS/i, "").toUpperCase();
    if (!value) return;
    if (!/^\d+$/.test(value) || Number(value) > 4294967295) {
      setError(`${draft} is not an ASN`);
      return;
    }
    setError(null);
    setDraft("");
    save.mutate({ asns: [...new Set([...asns, Number(value)])], include_transit: scope?.include_transit ?? true });
  };

  const removeAsn = (asn: number) => {
    save.mutate({ asns: asns.filter((a) => a !== asn), include_transit: scope?.include_transit ?? true });
  };

  return (
    <section className="bg-surface rounded-lg border border-border p-4">
      <h2 className="text-sm font-medium mb-3">Your scope</h2>

      <div className="flex flex-wrap gap-2 mb-3">
        {asns.map((asn) => (
          <span key={asn} className="inline-flex items-center gap-1 rounded px-2 py-1 bg-accent text-xs">
            AS{asn}
            <button type="button" onClick={() => removeAsn(asn)} aria-label={`Remove AS${asn}`}>×</button>
          </span>
        ))}
        {asns.length === 0 && <span className="text-xs text-muted">No ASNs declared — the filter is off.</span>}
      </div>

      <div className="flex gap-2 mb-3">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addAsn()}
          placeholder="AS8220"
          className="rounded border border-border bg-background px-2 py-1 text-sm"
        />
        <button type="button" onClick={addAsn} className="rounded border border-border px-3 py-1 text-sm">
          Add
        </button>
      </div>

      {error && <p className="text-xs text-critical mb-2">{error}</p>}
      {scope?.error && <p className="text-xs text-critical mb-2">Resolution failed: {scope.error}</p>}

      <p className="text-xs text-muted">
        {scope?.prefix_count ?? 0} prefixes in scope
        {scope?.resolved_at ? ` · resolved ${new Date(scope.resolved_at).toLocaleTimeString()}` : ""}
        {scope?.stale ? " · stale, using cached data" : ""}
      </p>

      <div className="flex gap-2 mt-3">
        <button
          type="button"
          onClick={() => refresh.mutate()}
          disabled={refresh.isPending}
          className="rounded border border-border px-3 py-1 text-sm disabled:opacity-50"
        >
          {refresh.isPending ? "Resolving…" : "Refresh now"}
        </button>
      </div>
    </section>
  );
}
```

Render `<YourScope />` above the existing lookup `<form>`. The derived prefix
count and the stale line are load-bearing — they are how the operator knows the
registry lookup succeeded rather than silently returning nothing (spec §7).

- [ ] **Step 4: Add the toggle and reason chips to `/alerts`**

In `web/src/lib/store.ts`, add to `FilterState`:

```typescript
  scopeOnly: boolean;
  setScopeOnly: (value: boolean) => void;
```

defaulting to `true` in the initial state and in `reset()`.

In `web/src/views/Alerts.tsx`, add a scope toggle button and reason chips above
the table, and filter on `scope_reason` when `scopeOnly` is set:

```tsx
  const scopeCounts = useMemo(() => {
    const counts: Record<string, number> = { ORIGIN: 0, SUBSPACE: 0, TRANSIT: 0 };
    for (const a of source) {
      if (a.scope_reason) counts[a.scope_reason] += 1;
    }
    return counts;
  }, [source]);
```

and in the existing `filtered` predicate, before the `ownedOnly` check:

```typescript
      if (scopeOnly && !a.scope_reason) return false;
```

`useAlertHistory` already sends no `scope` param, so add
`scope: scopeOnly ? "mine" : "all"` to its query string in `web/src/lib/api.ts`
and its params type.

- [ ] **Step 5: Split on Overview**

In `web/src/views/Overview.tsx`, add a card using `useScopeSummary()`:

```tsx
  const { data: summary } = useScopeSummary();
```

```tsx
<Metric
  label="Concerning you"
  value={summary ? String(summary.in_scope) : "—"}
  hint={summary ? `of ${summary.total} total` : undefined}
/>
```

and a reason line under it:

```tsx
{summary && (
  <p className="text-xs text-muted">
    ORIGIN {summary.reasons.ORIGIN} · SUBSPACE {summary.reasons.SUBSPACE} · TRANSIT {summary.reasons.TRANSIT}
    {!summary.scope_active && " · scope not configured, showing all"}
  </p>
)}
```

- [ ] **Step 6: Build and lint**

Run:
```bash
cd web && npm run build
```
Expected: exit 0.

`npm run lint` needs `eslint.config.js`, which does not exist. That is a
separate task in the run-readiness plan; do not add it here.

- [ ] **Step 7: Commit**

```bash
git add web/src/lib/types.ts web/src/lib/scope.ts web/src/lib/store.ts web/src/lib/api.ts web/src/views/Scope.tsx web/src/views/Alerts.tsx web/src/views/Overview.tsx
git commit -m "Add the writable scope panel and the scope filter to the dashboard"
```

---

## Task 7: Forward in-scope alerts to a SIEM over syslog

**Files:**
- Create: `bgpmon/siem.py`
- Modify: `bgpmon/pipeline.py`
- Modify: `bgpmon/sinks.py` (remove `_noop_metrics`)
- Test: `tests/test_siem.py`

**Interfaces:**
- Consumes: `Alert.scope_reason` (Task 5), `SinkSettings.syslog_enabled/host/port` (`config.py:191-193`).
- Produces: `AlertSink` protocol, `SyslogSink`, `siem.py` counters. `Pipeline.siem`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_siem.py`:

```python
"""SIEM forwarding must never slow ingest (spec §6.1).

The SIEM is the system of record, so a dropped alert is a real loss — but a
logger that blocks the detection loop is worse than no logger, because it
degrades the tool's primary function to serve a secondary one.
"""

import json
import socket
import threading
import unittest
from datetime import datetime, timezone

from bgpmon.models import Alert, Kind, Severity
from bgpmon.siem import Rfc5424Formatter, SyslogSink


def alert(alert_id="a1", severity=Severity.HIGH, reason="TRANSIT") -> Alert:
    return Alert(
        alert_id=alert_id, dedup_key="k", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        kind=Kind.ROUTE_LEAK, severity=severity, confidence=0.9, prefix="177.73.157.0/24",
        as_path="1299,52320", peer_as="1299", collector="rrc01", update_id="u1",
        origin_as=270105, scope_reason=reason,
    )


class TestRfc5424(unittest.TestCase):
    def test_message_carries_the_header_and_structured_data(self):
        line = Rfc5424Formatter(hostname="bgpmon").format(alert())
        self.assertTrue(line.startswith("<134>1 "), line)
        self.assertIn("kind=ROUTE_LEAK", line)
        self.assertIn("severity=HIGH", line)
        self.assertIn('alert_id="a1"', line)
        self.assertIn("scope_reason=TRANSIT", line)

    def test_reasons_are_quoted_so_a_space_cannot_break_the_message(self):
        line = Rfc5424Formatter(hostname="bgpmon").format(alert(reason='a b"c'))
        self.assertIn('scope_reason="a b\\"c"', line)

    def test_only_in_scope_alerts_are_formatted(self):
        self.assertEqual(Rfc5424Formatter(hostname="bgpmon").format(alert(reason=None)), "")


class TestSyslogSink(unittest.TestCase):
    def test_buffers_and_sends_over_tcp(self):
        received = []
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            with conn:
                data = b""
                while len(data) < 1:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    received.append(data)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        sink = SyslogSink(host="127.0.0.1", port=port, batch_size=1)
        self.assertTrue(sink.start())
        sink.submit([alert()])
        sink.flush()
        thread.join(timeout=5)
        sink.stop()
        server.close()

        self.assertTrue(received, "nothing arrived")
        self.assertIn(b"kind=ROUTE_LEAK", received[0])

    def test_a_closed_port_drops_and_counts_without_raising(self):
        """Review Focus 3: a dead SIEM must not touch ingest."""
        sink = SyslogSink(host="127.0.0.1", port=1, batch_size=1, max_retries=1)
        sink.start()
        sink.submit([alert()])
        sink.flush()          # must not raise
        stats = sink.stats()
        sink.stop()
        self.assertEqual(stats["sent"], 0)
        self.assertGreater(stats["dropped"], 0)
        self.assertGreater(stats["errors"], 0)

    def test_out_of_scope_alerts_are_not_queued(self):
        sink = SyslogSink(host="127.0.0.1", port=1)
        sink.start()
        sink.submit([alert(alert_id="a1", reason=None)])
        self.assertEqual(sink.stats()["queued"], 0)
        sink.stop()

    def test_stop_is_safe_without_start(self):
        SyslogSink(host="127.0.0.1", port=1).stop()
```

- [ ] **Step 2: Run to see it fail**

Run: `python -m pytest tests/test_siem.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bgpmon.siem'`

- [ ] **Step 3: Write the module**

Create `bgpmon/siem.py`:

```python
"""Forward in-scope alerts to a SIEM.

RFC 5424 over TCP. Vendor-neutral by construction: Sentinel, Splunk HEC and
QRadar all ingest structured syslog without a custom adapter. TCP rather than
UDP because a lost alert defeats the purpose.

`logging.handlers.SysLogHandler` is not used: it emits `<PRI>` followed by
whatever a formatter produced, with no RFC 5424 header and no SD-ELEMENT
support, so it cannot carry the detection facts a SIEM needs to filter on.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Protocol, Sequence

from bgpmon.models import Alert

logger = logging.getLogger(__name__)

FACILITY_AUTHPRIV = 10  # RFC 5424 authpriv: security/audit, not operational


def _quote(value: str) -> str:
    """RFC 5424 SD-PARAM quoting: backslash, double quote and space are escaped."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


class Rfc5424Formatter:
    """Render one alert as an RFC 5424 line with SD-ELEMENTs."""

    def __init__(self, hostname: str = "bgpmon") -> None:
        self.hostname = hostname

    def format(self, alert: Alert) -> str:
        if not alert.scope_reason:
            return ""  # out of scope: nothing crosses the boundary
        pri = 128 + 2 * FACILITY_AUTHPRIV + 3  # severity=error(3)
        ts = alert.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        params = " ".join([
            f"kind={alert.kind.value}",
            f"severity={alert.severity.value}",
            f"prefix={alert.prefix}",
            f"origin_as={alert.origin_as if alert.origin_as is not None else '-'}",
            f"peer_as={_quote(alert.peer_as)}",
            f"collector={alert.collector}",
            f"scope_reason={alert.scope_reason}",
            f"alert_id={_quote(alert.alert_id)}",
            f"reasons={_quote(' '.join(alert.reasons))}",
        ])
        return f"<{pri}>1 {ts} {self.hostname} bgpmon - - - {params}"


class AlertSink(Protocol):
    def start(self) -> bool: ...
    def submit(self, alerts: Sequence[Alert]) -> None: ...
    def flush(self) -> None: ...
    def stop(self) -> None: ...
    def stats(self) -> Dict[str, int]: ...


class SyslogSink:
    """Batched, best-effort forwarding. Never blocks the detection loop."""

    def __init__(self, host: str, port: int, batch_size: int = 50,
                 flush_interval_s: float = 5.0, max_retries: int = 3,
                 enabled: bool = True, hostname: str = "bgpmon") -> None:
        self.enabled = enabled
        self.host = host
        self.port = int(port)
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.max_retries = max_retries
        self.formatter = Rfc5424Formatter(hostname=hostname)
        self._queue: Deque[str] = deque()
        self._lock = threading.Lock()
        self._socket: Optional[socket.socket] = None
        self._sent = 0
        self._dropped = 0
        self._errors = 0

    def start(self) -> bool:
        return self.enabled

    def submit(self, alerts: Sequence[Alert]) -> None:
        if not self.enabled:
            return
        lines = [line for line in (self.formatter.format(a) for a in alerts) if line]
        if not lines:
            return
        with self._lock:
            self._queue.extend(lines)

    def flush(self) -> None:
        if not self.enabled:
            return
        while True:
            with self._lock:
                if len(self._queue) < self.batch_size and self._queue:
                    batch = [self._queue.popleft()]
                elif self._queue:
                    batch = [self._queue.popleft() for _ in range(self.batch_size)]
                else:
                    return
            self._send_batch(batch)

    def _send_batch(self, lines: List[str]) -> None:
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        for attempt in range(self.max_retries):
            try:
                sock = self._connect()
                sock.sendall(payload)
                self._sent += len(lines)
                return
            except OSError as exc:
                self._errors += 1
                logger.warning("SIEM send failed (attempt %d/%d): %s",
                               attempt + 1, self.max_retries, exc)
                self._close()
        self._dropped += len(lines)

    def _connect(self) -> socket.socket:
        if self._socket is None:
            self._socket = socket.create_connection((self.host, self.port), timeout=5.0)
        return self._socket

    def _close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def stop(self) -> None:
        self.flush()
        self._close()

    def stats(self) -> Dict[str, int]:
        with self._lock:
            queued = len(self._queue)
        return {"queued": queued, "sent": self._sent, "dropped": self._dropped,
                "errors": self._errors, "enabled": self.enabled}
```

- [ ] **Step 4: Run to see it pass**

Run: `python -m pytest tests/test_siem.py -v`
Expected: all pass.

- [ ] **Step 5: Wire it into the pipeline**

In `bgpmon/pipeline.py.__init__`, after the scope resolver:

```python
        self.siem = SyslogSink(
            host=settings.sink.syslog_host,
            port=settings.sink.syslog_port,
            enabled=settings.sink.syslog_enabled,
        )
```

In `_process`, inside `for alert in admitted:`, after `scope_reason` is set:

```python
            if alert.scope_reason:
                self.siem.submit([alert])
```

In `health()`, add `"siem": self.siem.stats(),` alongside `"sink"`.

- [ ] **Step 6: Remove the dead helper**

Delete `_noop_metrics` at `bgpmon/sinks.py:361-365` and its now-unused imports.

- [ ] **Step 7: Verify**

Run:
```bash
python -m pytest tests/ -q
```
Expected: all pass, no new failures.

- [ ] **Step 8: Commit**

```bash
git add bgpmon/siem.py bgpmon/pipeline.py bgpmon/sinks.py tests/test_siem.py
git commit -m "Forward in-scope alerts to a SIEM over RFC 5424 syslog"
```

---

## Deferred to follow-up plans

- `eslint.config.js` (run-readiness plan, Task 5)
- Scope resolution via RIPE DB `rest.db.ripe.net` instead of RIPEstat `whois` — more authoritative, more parsing
- Persisted `scope_match` on historical alerts, if alert volume forces the §5.1 ceiling
- TLS for syslog (spec §9)
- `WebhookSink` (spec §9)