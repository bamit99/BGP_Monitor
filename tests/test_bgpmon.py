"""Regression tests for defects found and fixed during the telecom-grade rebuild.

Each test pins a specific bug that was observed in production output, so a
regression fails loudly rather than silently degrading detection quality.

Run:  python -m pytest tests/test_bgpmon.py -v
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import sys
import tempfile
import time
import unittest
import ipaddress
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from bgpmon.api import create_app, mount_dashboard
from bgpmon.config import DetectionSettings, RPkiSettings, Settings, SourceSettings
from bgpmon.detect import ASGraph, DetectionEngine, is_bogon_asn, is_bogon_prefix
from bgpmon.gate import AlertGate
from bgpmon.pipeline import Pipeline
from bgpmon.models import Alert, Kind, Severity, Update, make_alert_id, make_update_id
from bgpmon.rpki import RPkiEngine, VRPSet


def make_update(prefix: str, path: list[int], collector: str = "rrc00", when: datetime | None = None) -> Update:
    ts = when or datetime.now(timezone.utc)
    return Update(
        update_id=make_update_id(collector, ts, prefix),
        timestamp=ts,
        prefix=prefix,
        collector=collector,
        peer="192.0.2.1",
        peer_as="174",
        as_path=",".join(str(a) for a in path),
        as_path_list=path,
        origin_as=path[-1] if path else None,
    )


def write_asrel(rows: list[tuple[int, int, int]]) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    for a, b, code in rows:
        handle.write(f"{a}|{b}|{code}\n")
    handle.close()
    return handle.name


class TestUpdateIdentity(unittest.TestCase):
    """The alert->update graph edge broke because the two ids were derived
    differently. Both must now come from the same helpers."""

    def test_alert_id_matches_update_id_used_by_sink(self):
        when = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)
        update_id = make_update_id("rrc00", when, "203.0.113.0/24")
        self.assertEqual(update_id, "rrc00_2026-09-26T12:00:00+00:00_203.0.113.0/24")
        first = make_alert_id(update_id, Kind.RPKI_INVALID)
        second = make_alert_id(update_id, Kind.RPKI_INVALID)
        self.assertEqual(first, second, "alert ids must be deterministic for idempotent MERGE")

    def test_different_kinds_produce_different_alert_ids(self):
        update_id = make_update_id("rrc00", datetime.now(timezone.utc), "203.0.113.0/24")
        self.assertNotEqual(make_alert_id(update_id, Kind.ROUTE_LEAK),
                            make_alert_id(update_id, Kind.RPKI_INVALID))


class TestASRelationshipDirection(unittest.TestCase):
    """CAIDA encodes direction explicitly and the provider is NOT always the
    lower ASN; assuming so fabricated relationships and produced a 7% alert rate."""

    def test_provider_with_higher_asn_is_read_correctly(self):
        path = write_asrel([(9000, 1, -1), (1, 2, -1), (2, 7, 0)])
        try:
            graph = ASGraph()
            self.assertEqual(graph.load(path), 3)
            self.assertEqual(graph.relationship(9000, 1), -1, "AS9000 is provider of AS1")
            self.assertEqual(graph.relationship(1, 9000), 1, "reverse must invert")
            self.assertEqual(graph.relationship(2, 7), 0, "peer link is symmetric")
            self.assertEqual(graph.relationship(7, 2), 0)
        finally:
            os.unlink(path)

    def test_unknown_pairs_are_never_accused(self):
        path = write_asrel([(1, 2, -1)])
        try:
            graph = ASGraph()
            graph.load(path)
            self.assertEqual(graph.relationship(1, 999), 99)
            violated, pair, conf = graph.valley_violation([999, 1, 2])
            self.assertFalse(violated, "a path with unknown edges must not be flagged")
            self.assertIsNone(pair)
        finally:
            os.unlink(path)


class TestValleyFree(unittest.TestCase):
    """RFC 7908 semantics on the propagation direction (reverse of AS path order)."""

    def setUp(self):
        self.file = write_asrel([(1, 2, -1), (3, 2, -1), (2, 7, -1), (2, 6, 0)])
        self.graph = ASGraph()
        self.graph.load(self.file)

    def tearDown(self):
        os.unlink(self.file)

    def test_flat_then_uphill_is_a_leak(self):
        # path 1,2,6 -> propagation 6 -> 2, then 2 -> 1 uphill past a peer edge.
        violated, pair, conf = self.graph.valley_violation([1, 2, 6])
        self.assertTrue(violated)
        self.assertEqual(pair, (2, 1))
        self.assertGreater(conf, 0.5)

    def test_provider_to_peer_is_a_leak(self):
        # RFC 7908 Type 5: route received from a provider (3 -> 2 downhill) and
        # then re-announced to a peer (2 -> 6 flat).
        violated, pair, _ = self.graph.valley_violation([6, 2, 3])
        self.assertTrue(violated)
        self.assertEqual(pair, (2, 6))

    def test_pure_downhill_multi_hop_is_legitimate(self):
        # AS1 -> AS2 -> AS7 reads as provider -> customer -> customer: every
        # propagation step is downhill, so the path is legal.
        violated, _, _ = self.graph.valley_violation([7, 2, 1])
        self.assertFalse(violated)

    def test_uphill_then_downhill_is_legitimate(self):
        # AS9 is a customer of AS1 (edge 1|9|-1). AS9 announcing up to its
        # provider AS1 and AS1 then passing it down to customer AS2 is the
        # canonical legal shape up* down*.
        path = write_asrel([(1, 2, -1), (1, 9, -1)])
        try:
            graph = ASGraph()
            graph.load(path)
            violated, _, _ = graph.valley_violation([2, 1, 9])
            self.assertFalse(violated, "up then down is the legal valley-free shape")
        finally:
            os.unlink(path)


class TestSpaDeepLinks(unittest.TestCase):
    """StaticFiles(html=True) mounted at "/" 404s a fresh GET of /alerts, which
    breaks bookmarks and refreshes in the console."""

    def setUp(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from bgpmon.api import mount_dashboard

        self.dist = Path(tempfile.mkdtemp())
        (self.dist / "index.html").write_text("<html><body>shell</body></html>", encoding="utf-8")
        (self.dist / "assets").mkdir()
        (self.dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
        app = FastAPI()

        @app.get("/api/health")
        def health():
            return {"status": "ok"}

        mount_dashboard(app, self.dist)
        self.client = TestClient(app)

    def test_deep_link_returns_shell(self):
        for route in ("/alerts", "/rpki", "/alerts/1234"):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200, route)
            self.assertIn("shell", response.text)

    def test_removed_topology_route_still_returns_the_shell(self):
        """The global AS map is gone, but a stale bookmark must not 404.

        The SPA fallback is a catch-all, so /topology resolves to the shell and
        the client router renders its not-found state.
        """
        response = self.client.get("/topology")
        self.assertEqual(response.status_code, 200)
        self.assertIn("shell", response.text)

    def test_console_nav_no_longer_offers_topology(self):
        """A removed view must also disappear from the navigation."""
        source = (Path(__file__).resolve().parent.parent / "web" / "src" / "App.tsx").read_text(
            encoding="utf-8")
        self.assertNotIn('to: "/topology"', source)
        self.assertNotIn("views/Topology", source)

    def test_root_returns_shell(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_api_routes_are_not_shadowed(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_assets_are_served(self):
        response = self.client.get("/assets/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("console.log", response.text)


class TestApiNotFoundIsJson(unittest.TestCase):
    """The SPA catch-all is a GET /{full_path:path}, so an unknown /api/* path
    used to resolve to index.html with a 200. A client debugging a missing route
    got HTML and no indication the route was absent."""

    def setUp(self):
        # Held on self: a TemporaryDirectory left as a local is collected when
        # setUp returns, which deletes the directory before the first request.
        self.tmp = tempfile.TemporaryDirectory()
        dist = Path(self.tmp.name)
        (dist / "index.html").write_text("<html>shell</html>", encoding="utf-8")
        assets = dist / "assets"
        assets.mkdir()
        (assets / "app.js").write_text("console.log(1)", encoding="utf-8")

        app = FastAPI()
        mount_dashboard(app, dist)
        self.client = TestClient(app)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_api_route_is_json_404(self):
        response = self.client.get("/api/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertIn("application/json", response.headers.get("content-type", ""))
        self.assertEqual(response.json()["detail"], "Not Found")

    def test_reserved_prefixes_all_return_json_404(self):
        for prefix in ("api/anything", "ws/anything", "metrics/anything", "assets/../api"):
            response = self.client.get(f"/{prefix}")
            self.assertEqual(response.status_code, 404, prefix)
            self.assertIn("application/json", response.headers.get("content-type", ""), prefix)

    def test_real_spa_routes_still_serve_html(self):
        for route in ("/", "/alerts", "/topology", "/alerts/1234", "/rpki"):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200, route)
            self.assertIn("text/html", response.headers.get("content-type", ""), route)

    def test_a_real_asset_file_is_still_served(self):
        response = self.client.get("/assets/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("console.log", response.text)


class _StubSink:
    """Stands in for GraphSink with the row shape the handler consumes."""

    enabled = True

    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def recent_alerts(self, limit=200, min_severity=None, kind=None, prefix=None):
        self.calls.append({"limit": limit, "min_severity": min_severity,
                           "kind": kind, "prefix": prefix})
        return [dict(row) for row in self._rows][:limit]


class TestOwnedOnlyIsConsistentAcrossSources(unittest.TestCase):
    """`owned_only` reached the memory path and silently skipped the graph path,
    so the same query returned owned alerts from memory and everything from
    Neo4j. The `is_owned` flag is persisted on the SecurityAlert node."""

    ROWS = [
        {"alert_id": "a1", "kind": "HIJACK_ORIGIN", "severity": "CRITICAL",
         "prefix": "203.0.113.0/24", "origin_as": 64496, "as_path": "64496,1",
         "is_owned": True, "timestamp": "2026-01-01T00:00:00+00:00"},
        {"alert_id": "a2", "kind": "ROUTE_LEAK", "severity": "HIGH",
         "prefix": "8.8.8.0/24", "origin_as": 15169, "as_path": "15169,1",
         "is_owned": False, "timestamp": "2026-01-01T00:00:01+00:00"},
    ]

    def _client(self):
        client = TestClient(create_app())
        client.app.state.pipeline.sink = _StubSink(self.ROWS)
        return client

    def test_graph_source_honours_owned_only(self):
        body = self._client().get("/api/alerts?source=graph&owned_only=true").json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["alerts"][0]["alert_id"], "a1")
        self.assertTrue(body["alerts"][0]["is_owned"])

    def test_graph_source_without_owned_only_returns_everything(self):
        body = self._client().get("/api/alerts?source=graph").json()
        self.assertEqual(body["count"], 2)

    def test_owned_only_false_is_not_treated_as_truthy(self):
        body = self._client().get("/api/alerts?source=graph&owned_only=false").json()
        self.assertEqual(body["count"], 2)


class TestWebSocketFanoutIsThreadSafe(unittest.TestCase):
    """`call_soon_threadsafe(sub.put_nowait, ...)` defers put_nowait onto the
    event loop, so a full subscriber raises QueueFull *inside* the loop, where
    the try/except around call_soon_threadsafe cannot see it. The exception
    escaped into the loop's default handler instead of being counted.

    The loop runs in a thread here, as it does in the real pipeline, because
    `_publish` bails out when the loop is not running.
    """

    def setUp(self):
        import threading

        self.pipeline = Pipeline(Settings.load())
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.pipeline._loop = self.loop
        self.sub = self.pipeline.subscribe()
        self.queue_size = self.pipeline.settings.api.ws_queue
        self.loop_errors = []
        self.loop.set_exception_handler(
            lambda loop, context: self.loop_errors.append(context))

    def tearDown(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)
        self.loop.close()

    def _drain(self):
        """Let the loop process whatever `_publish` scheduled."""
        for _ in range(50):
            self.loop.call_soon_threadsafe(lambda: None)
            time.sleep(0.01)

    def test_a_full_subscriber_queue_does_not_raise(self):
        for _ in range(self.queue_size):
            self.sub.put_nowait({"type": "alert"})
        self.assertTrue(self.sub.full())

        self.pipeline._publish(_alert())
        self._drain()

        self.assertEqual(self.loop_errors, [], "QueueFull escaped into the event loop")

    def test_the_drop_is_counted(self):
        for _ in range(self.queue_size):
            self.sub.put_nowait({"type": "alert"})
        self.pipeline._publish(_alert())
        self._drain()
        self.assertEqual(self.pipeline.ws_drops(), 1)

    def test_a_healthy_subscriber_still_receives(self):
        self.pipeline._publish(_alert())
        self._drain()
        self.assertEqual(self.sub.qsize(), 1)

    def test_one_full_subscriber_does_not_starve_the_others(self):
        healthy = self.pipeline.subscribe()
        for _ in range(self.queue_size):
            self.sub.put_nowait({"type": "alert"})

        self.pipeline._publish(_alert())
        self._drain()
        self.assertEqual(healthy.qsize(), 1)
        self.assertEqual(self.sub.qsize(), self.queue_size, "the full queue is untouched")


def _alert(prefix="203.0.113.0/24"):
    return Alert(
        alert_id="ws1", dedup_key="k", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        kind=Kind.ROUTE_LEAK, severity=Severity.HIGH, confidence=0.9, prefix=prefix,
        as_path="64496,1", peer_as="1", collector="rrc00", update_id="u1", origin_as=64496,
        reasons=["test"],
    )


class TestVisibilityLoss(unittest.TestCase):
    """A documented CRITICAL detector that raises AttributeError is not a detector.

    `PrefixState` is a slots dataclass; assigning an undeclared attribute raises.
    `pipeline._visibility_loop` swallowed the error into a log line, so the
    detector in README.md and Logic.md looked alive and never ran.
    """

    def setUp(self):
        self.rpki = RPkiEngine(RPkiSettings(enable_remote_fallback=False))
        self.rpki.vrps.replace([], [], serial=1, session_id=1)
        self.settings = DetectionSettings(
            owned_prefixes=(ipaddress.ip_network("203.0.113.0/24"),),
            visibility_loss_grace_s=900,
            visibility_min_expected_collectors=2,
        )
        self.engine = DetectionEngine(self.settings, self.rpki, ASGraph())
        self.base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for collector in ("rrc00", "rrc01"):
            self.engine.evaluate(make_update("203.0.113.0/24", [64496], collector, self.base))

    def test_no_alert_inside_grace(self):
        self.assertEqual(self.engine.check_visibility(self.base + timedelta(seconds=600)), [])

    def test_alert_after_grace_across_two_collectors(self):
        alerts = self.engine.check_visibility(self.base + timedelta(seconds=1000))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].kind, Kind.VISIBILITY_LOSS)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)
        self.assertEqual(alerts[0].prefix, "203.0.113.0/24")

    def test_one_alert_per_gap(self):
        past = self.base + timedelta(seconds=1000)
        self.assertEqual(len(self.engine.check_visibility(past)), 1)
        self.assertEqual(self.engine.check_visibility(past + timedelta(seconds=10)), [],
                         "the same gap must not re-alert")

    def test_fresh_sighting_rearms_the_detector(self):
        past = self.base + timedelta(seconds=1000)
        self.engine.check_visibility(past)
        seen_again = past + timedelta(seconds=100)
        for collector in ("rrc00", "rrc01"):
            self.engine.evaluate(
                make_update("203.0.113.0/24", [64496], collector, seen_again))
        self.assertEqual(len(self.engine.check_visibility(seen_again + timedelta(seconds=1000))), 1,
                         "a new gap is a new incident")

    def test_single_collector_is_not_an_outage(self):
        """One collector's session blip is not a customer-visible outage."""
        engine = DetectionEngine(self.settings, self.rpki, ASGraph())
        engine.evaluate(make_update("203.0.113.0/24", [64496], "rrc00", self.base))
        self.assertEqual(engine.check_visibility(self.base + timedelta(seconds=1000)), [])


class TestTokenAuthContract(unittest.TestCase):
    """The dashboard must be able to satisfy the guard the server applies.

    Both `Settings` and `ApiSettings` are frozen, so a configured token means
    building a new instance rather than assigning.
    """

    def _client(self, token: str):
        base = Settings.load()
        settings = replace(base, api=replace(base.api, token=token))
        return TestClient(create_app(settings))

    def test_api_rejects_a_missing_token(self):
        self.assertEqual(self._client("secret").get("/api/alerts").status_code, 401)

    def test_api_rejects_a_wrong_token(self):
        response = self._client("secret").get("/api/alerts", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(response.status_code, 401)

    def test_api_accepts_a_correct_token(self):
        response = self._client("secret").get("/api/alerts", headers={"Authorization": "Bearer secret"})
        self.assertNotEqual(response.status_code, 401)

    def test_no_token_configured_means_no_auth(self):
        self.assertNotEqual(self._client("").get("/api/alerts").status_code, 401)

    def test_health_stays_open_when_a_token_is_configured(self):
        """The compose healthcheck and any uptime probe must not need the token."""
        response = self._client("secret").get("/api/health")
        self.assertNotEqual(response.status_code, 401)


class TestLoopbackBind(unittest.TestCase):
    """The scope write endpoint changes what an operator sees, so the published
    port must default to loopback."""

    def test_compose_publishes_on_loopback(self):
        import re

        compose = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(
            encoding="utf-8")
        published = re.findall(r'^\s*-\s*"([\d.]+:)?\$\{BGPMON_API_PORT', compose, re.MULTILINE)
        self.assertTrue(published, "no BGPMON_API_PORT mapping found")
        self.assertTrue(
            all(entry.startswith("127.0.0.1:") for entry in published),
            f"monitor port must be published on loopback, found: {published}",
        )


class TestIncidentExpiry(unittest.TestCase):
    """Incident dedup must expire: a condition that clears and returns hours
    later has to alert again, or the NOC never learns of the recurrence."""

    def setUp(self):
        self.file = write_asrel([(1, 2, -1), (3, 2, -1), (2, 6, 0)])
        graph = ASGraph()
        graph.load(self.file)
        self.rpki = RPkiEngine(RPkiSettings(enable_remote_fallback=False))
        self.rpki.vrps.replace([], [], serial=1, session_id=1)
        self.graph = graph

    def tearDown(self):
        os.unlink(self.file)

    def test_leak_realerts_after_ttl(self):
        import time as _time
        settings = DetectionSettings(incident_ttl_s=60)
        engine = DetectionEngine(settings, self.rpki, self.graph)

        first = [a for a in engine.evaluate(make_update("198.51.100.0/24", [1, 2, 6]))
                 if a.kind == Kind.ROUTE_LEAK]
        self.assertEqual(len(first), 1)

        repeat = [a for a in engine.evaluate(make_update("198.51.101.0/24", [1, 2, 6]))
                  if a.kind == Kind.ROUTE_LEAK]
        self.assertEqual(repeat, [], "same pair within TTL must not re-alert")

        # age the incident beyond the TTL, then confirm it fires again
        for scope in list(engine._leak_pairs):
            engine._leak_pairs[scope][2] -= 120
        engine._sweep(_time.monotonic())
        after = [a for a in engine.evaluate(make_update("198.51.102.0/24", [1, 2, 6]))
                 if a.kind == Kind.ROUTE_LEAK]
        self.assertEqual(len(after), 1, "incident must re-alert after expiry")


class TestRpkiFallbackDiscipline(unittest.TestCase):
    """A complete local VRP set fully determines RFC 6811 validity, so the
    remote validator must not be consulted — it only adds latency and rate
    limits."""

    def test_remote_not_called_when_local_set_is_ready(self):
        engine = RPkiEngine(RPkiSettings(enable_remote_fallback=True))
        v4 = int.from_bytes(socket.inet_aton("203.0.113.0"), "big")
        engine.vrps.replace([(4, v4, 24, 64496, 24)], [], serial=1, session_id=1)

        calls = []
        engine._validate_remote = lambda prefix, origin: calls.append((prefix, origin))
        verdict = engine.validate("198.51.100.0/24", 64496)
        self.assertEqual(verdict.state, "NOT_FOUND")
        self.assertEqual(calls, [], "remote must not be queried while the local set answers")

    def test_remote_used_only_when_set_is_empty(self):
        engine = RPkiEngine(RPkiSettings(enable_remote_fallback=True))
        calls = []

        class _Response:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return {"data": {"status": "valid", "description": "remote"}}

        class _Session:
            def get(self, *a, **k):
                calls.append(a)
                return _Response()

        engine._remote_session = _Session()
        verdict = engine.validate("198.51.100.0/24", 64496)
        self.assertEqual(verdict.state, "VALID")
        self.assertEqual(len(calls), 1)


class TestOwnedSpace(unittest.TestCase):
    """Owned-space detection must be RPKI-anchored so unauthorised origins are
    caught without an operator having to enumerate every legitimate origin."""

    def setUp(self):
        self.settings = DetectionSettings(owned_prefixes=())
        self.graph = ASGraph()
        self.rpki = RPkiEngine(RPkiSettings(enable_remote_fallback=False))
        self.rpki.vrps.replace([(4, int.from_bytes(socket.inet_aton("203.0.113.0"), "big"), 24, 64496, 24)],
                               [], serial=1, session_id=1)

    def test_rpki_valid_is_not_a_hijack(self):
        engine = DetectionEngine(self.settings, self.rpki, self.graph)
        alerts = engine.evaluate(make_update("203.0.113.0/24", [174, 64496]))
        self.assertEqual([a.kind for a in alerts if a.kind == Kind.HIJACK_ORIGIN], [])

    def test_rpki_invalid_origin_is_flagged(self):
        engine = DetectionEngine(self.settings, self.rpki, self.graph)
        alerts = engine.evaluate(make_update("203.0.113.0/24", [174, 64500]))
        kinds = {a.kind for a in alerts}
        self.assertIn(Kind.RPKI_INVALID, kinds)
        invalid = next(a for a in alerts if a.kind == Kind.RPKI_INVALID)
        self.assertEqual(invalid.severity, Severity.HIGH)

    def test_owned_prefix_invalid_is_critical(self):
        import ipaddress
        settings = DetectionSettings(owned_prefixes=(ipaddress.ip_network("203.0.113.0/24"),))
        engine = DetectionEngine(settings, self.rpki, self.graph)
        alerts = engine.evaluate(make_update("203.0.113.0/24", [174, 64500]))
        invalid = next(a for a in alerts if a.kind == Kind.RPKI_INVALID)
        self.assertEqual(invalid.severity, Severity.CRITICAL)
        self.assertTrue(invalid.is_owned)


class TestAlertVolumeControls(unittest.TestCase):
    """One incident must not generate one alert per affected prefix."""

    def setUp(self):
        self.file = write_asrel([(1, 2, -1), (3, 2, -1), (2, 6, 0)])
        self.graph = ASGraph()
        self.graph.load(self.file)
        self.rpki = RPkiEngine(RPkiSettings(enable_remote_fallback=False))
        self.rpki.vrps.replace([], [], serial=1, session_id=1)
        self.engine = DetectionEngine(DetectionSettings(), self.rpki, self.graph)

    def tearDown(self):
        os.unlink(self.file)

    def test_leak_reported_once_per_as_pair(self):
        # 40 different prefixes sharing the same leaky pair.
        alerts = []
        for i in range(40):
            alerts.extend(self.engine.evaluate(make_update(f"198.51.{i}.0/24", [1, 2, 6])))
        leaks = [a for a in alerts if a.kind == Kind.ROUTE_LEAK]
        self.assertEqual(len(leaks), 1, "one leaky pair == one alert")

    def test_gate_rate_limits_repeats(self):
        gate = AlertGate(per_key_interval_s=60)
        base = datetime.now(timezone.utc)
        first = Alert(alert_id="a", dedup_key="k", timestamp=base, kind=Kind.ROUTE_LEAK,
                      severity=Severity.HIGH, confidence=0.9, prefix="198.51.100.0/24",
                      as_path="1,2,6", peer_as="1", collector="rrc00", update_id="u")
        second = Alert(alert_id="b", dedup_key="k", timestamp=base, kind=Kind.ROUTE_LEAK,
                       severity=Severity.HIGH, confidence=0.9, prefix="198.51.100.0/24",
                       as_path="1,2,6", peer_as="1", collector="rrc00", update_id="u")
        self.assertIsNotNone(gate.admit(first))
        self.assertIsNone(gate.admit(second))
        self.assertEqual(gate.stats()["suppressed"], 1)


class TestRpkiSet(unittest.TestCase):
    """RFC 6811 semantics: valid match, wrong origin, over-long prefix, no coverage."""

    def setUp(self):
        self.vrps = VRPSet()
        v4 = int.from_bytes(socket.inet_aton("203.0.113.0"), "big")
        self.vrps.replace([(4, v4, 24, 64496, 24)], [], serial=1, session_id=1)

    def test_valid(self):
        self.assertEqual(self.vrps.validate("203.0.113.0/24", 64496).state, "VALID")

    def test_invalid_origin(self):
        result = self.vrps.validate("203.0.113.0/24", 64500)
        self.assertEqual(result.state, "INVALID")
        self.assertEqual(result.offending[0][2], "origin not authorised")

    def test_invalid_length(self):
        result = self.vrps.validate("203.0.113.128/25", 64496)
        self.assertEqual(result.state, "INVALID")
        self.assertEqual(result.offending[0][2], "prefix longer than maxLength")

    def test_not_found(self):
        self.assertEqual(self.vrps.validate("198.51.100.0/24", 64496).state, "NOT_FOUND")

    def test_indexed_prefix_count_is_not_vrp_count(self):
        self.assertEqual(self.vrps.size, 1)


class TestRtrTransport(unittest.TestCase):
    """The RTR client must parse real PDUs, not just open a socket."""

    def test_reset_query_parses_end_of_data(self):
        settings = RPkiSettings()
        try:
            sock = socket.create_connection((settings.rtr_host, settings.rtr_port), timeout=5)
        except OSError:
            self.skipTest("no local RTR server available")
        sock.close()
        engine = RPkiEngine(settings)
        self.assertTrue(engine.sync_once())
        self.assertGreater(engine.vrps.size, 1000, "global VRP set should be large")
        self.assertEqual(engine.stats["transport"], "rtr")


class TestConfigGuards(unittest.TestCase):
    def test_route_views_collectors_are_rejected(self):
        os.environ["BGPMON_COLLECTORS"] = "route-views.chicago,rrc00"
        try:
            with self.assertRaises(ValueError):
                SourceSettings.from_env()
        finally:
            del os.environ["BGPMON_COLLECTORS"]

    def test_rrc_collectors_accepted(self):
        os.environ["BGPMON_COLLECTORS"] = "rrc00,rrc01"
        try:
            self.assertEqual(SourceSettings.from_env().collectors, ("rrc00", "rrc01"))
        finally:
            del os.environ["BGPMON_COLLECTORS"]

    def test_secrets_come_from_environment(self):
        os.environ["BGPMON_NEO4J_PASSWORD"] = "from-env"
        try:
            self.assertEqual(Settings.load().sink.neo4j_password, "from-env")
        finally:
            del os.environ["BGPMON_NEO4J_PASSWORD"]


class TestBogonClassification(unittest.TestCase):
    """Ranges verified against the IANA AS Number Registry (last updated 2026-06-01).

    Reserved is not the same as private use. RFC 6996 private-use ASNs are
    legitimately deployed inside large networks and do appear in BGP paths, so
    flagging them as bogons manufactures false positives — 772 of 4 890
    BOGON_ASN alerts on a live run came from this.
    """

    def test_reserved_asns_are_bogons(self):
        for asn in (0, 23456, 64496, 64511, 65535, 65536, 65551, 4294967295):
            self.assertTrue(is_bogon_asn(asn), f"AS{asn} is IANA-reserved")

    def test_the_65552_to_131071_gap_is_reserved_and_stays_a_bogon(self):
        for asn in (65552, 65600, 100000, 131071):
            self.assertTrue(is_bogon_asn(asn), f"AS{asn} is IANA Reserved")

    def test_rfc6996_private_use_asns_are_not_bogons(self):
        """16-bit and 32-bit private-use ranges are deployed, not reserved."""
        for asn in (64512, 65000, 65534, 4200000000, 4250000000, 4294967294):
            self.assertFalse(is_bogon_asn(asn), f"AS{asn} is RFC 6996 private use")

    def test_valid_public_asns_around_the_boundaries_are_not_bogons(self):
        """Every range boundary, stated explicitly rather than derived."""
        cases = {
            64495: False,   # ARIN, last public 16-bit before documentation
            64496: True,    # RFC 5398 documentation
            64511: True,    # RFC 5398 documentation, upper bound
            64512: False,   # RFC 6996 private use begins
            65534: False,   # RFC 6996 private use ends
            65535: True,    # RFC 7300 reserved
            65536: True,    # RFC 5398 documentation, 32-bit side
            65551: True,
            131071: True,   # end of the IANA Reserved gap
            131072: False,  # APNIC allocation begins
            4199999999: False,  # last unallocated-but-public 32-bit ASN
            4200000000: False,  # RFC 6996 private use begins
            4294967294: False,
            4294967295: True,   # RFC 7300 reserved
        }
        for asn, expected in cases.items():
            self.assertEqual(is_bogon_asn(asn), expected, f"AS{asn}")

    def test_apnic_assigned_32bit_block_is_not_bogon(self):
        for asn in (131072, 140601, 155961):
            self.assertFalse(is_bogon_asn(asn))

    def test_bogon_prefixes(self):
        for prefix in ("10.0.0.0/8", "192.168.1.0/24", "203.0.113.0/24", "2001:db8::/32"):
            self.assertTrue(is_bogon_prefix(prefix))
        self.assertFalse(is_bogon_prefix("8.8.8.0/24"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
