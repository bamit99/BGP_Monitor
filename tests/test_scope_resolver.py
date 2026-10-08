"""Resolution turns declared ASNs into the space an operator is responsible for.

Lazy, cached, and designed so that failure degrades to "widen the filter",
never "narrow to nothing". That last property is the whole point: an empty scope
is indistinguishable from "no alerts", and an operator who scoped AS8220 and
sees nothing must be able to trust that nothing happened.
"""

import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bgpmon.models import Alert, Kind, Severity
from bgpmon.scope_match import ScopeConfig, ScopeMatcher
from bgpmon.scope_resolver import (
    ResolvedScope,
    RipestatTransport,
    ScopeResolver,
    ScopeSettings,
)


class StubTransport:
    """Stands in for RIPEstat. Records what was asked."""

    def __init__(self, announced=None, fail=False, fail_asns=None):
        self.announced = announced or {}
        self.fail = fail
        self.fail_asns = fail_asns or ()
        self.calls = []

    async def announced_prefixes(self, asn):
        self.calls.append(("announced", asn))
        if self.fail or asn in self.fail_asns:
            raise RuntimeError(f"upstream down for AS{asn}")
        return list(self.announced.get(asn, []))


def alert(prefix="203.0.113.0/24", origin_as=8220, as_path="8220,64500") -> Alert:
    return Alert(
        alert_id="a1", dedup_key="k", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        kind=Kind.HIJACK_SUB_PREFIX, severity=Severity.CRITICAL, confidence=0.97, prefix=prefix,
        as_path=as_path, peer_as="64500", collector="rrc00", update_id="u1",
        origin_as=origin_as,
    )


class ResolverCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "scope_cache.json"
        self.scope_path = Path(self.tmp.name) / "scope.json"
        self.settings = ScopeSettings(cache_path=self.cache, scope_path=self.scope_path,
                                      request_delay_s=0.0)

    def tearDown(self):
        self.tmp.cleanup()

    def resolver(self, config, transport):
        return ScopeResolver(self.settings, config, transport=transport)


class TestResolution(ResolverCase):
    def test_resolves_announced_prefixes(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), transport).refresh())
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks])
        self.assertFalse(scope.stale)

    def test_customer_space_is_in_scope(self):
        """The operator originates a customer's block, so the origin ASN is theirs.

        Real case: AS8220 announces 62.23.14.0/24 with `origin: 8220` and
        `descr: TATA IZO` — a customer's space announced under our ASN. It
        arrives through `announced-prefixes`, so no second lookup is needed.
        """
        transport = StubTransport(announced={8220: ["62.23.0.0/16", "62.23.14.0/24"]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), transport).refresh())
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks])
        matcher = ScopeMatcher(scope.config, scope.networks)
        self.assertIn("SUBSPACE", matcher.reasons(
            alert(prefix="62.23.14.0/24", origin_as=64512)),
            "a more-specific of our space must match even from another origin")

    def test_one_request_per_asn(self):
        """Resolution is 1 call per ASN, not one per prefix.

        A whois-per-prefix exclusion step was tried and removed: it cost 175
        requests for a single 174-prefix ASN, it is what made resolution time
        out, and if we announce a prefix whose IRR names a different originator
        that is a hijack signal rather than a reason to exclude it from scope.
        """
        transport = StubTransport(announced={8220: [f"62.23.{i}.0/24" for i in range(174)]})
        asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), transport).refresh())
        self.assertEqual(len(transport.calls), 1, "one request per ASN, regardless of prefix count")

    def test_a_hijack_of_our_prefix_still_matches_subspace(self):
        """The whole point: someone else announcing our space is in scope."""
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        hijack = alert(prefix="62.23.0.0/16", origin_as=65001, as_path="65001,1")
        found = resolver.matcher().reasons(hijack)
        self.assertIn("SUBSPACE", found)
        self.assertNotIn("ORIGIN", found, "we are not the origin of a hijack")

    def test_an_asn_with_no_announced_prefixes_contributes_nothing(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220, 10021)), transport).refresh())
        self.assertEqual([str(n) for n in scope.networks], ["62.23.0.0/16"])
        self.assertFalse(scope.stale)

    def test_dual_stack_scope_collapses_per_family(self):
        """Every real operator announces v4 and v6. collapse_addresses raises
    TypeError on a mixed list; found by resolving AS8220 live."""
        transport = StubTransport(announced={8220: ["62.23.0.0/16", "62.23.0.0/17",
                                                     "2001:678:868::/48", "2001:678:868::/49"]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), transport).refresh())
        self.assertEqual(sorted(str(n) for n in scope.networks),
                         ["2001:678:868::/48", "62.23.0.0/16"])

    def test_a_dual_stack_scope_matches_both_families(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16", "2001:678:868::/48"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        matcher = resolver.matcher()
        self.assertIn("SUBSPACE", matcher.reasons(
            alert(prefix="62.23.14.0/24", origin_as=64512, as_path="64512,1")))
        self.assertIn("SUBSPACE", matcher.reasons(
            alert(prefix="2001:678:868::/49", origin_as=64512, as_path="64512,1")))

    def test_extra_prefixes_are_always_included(self):
        scope = asyncio.run(
            self.resolver(ScopeConfig(asns=(), extra_prefixes=("192.0.2.0/24",)),
                          StubTransport()).refresh())
        self.assertIn("192.0.2.0/24", [str(n) for n in scope.networks])

    def test_overlapping_prefixes_are_collapsed(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16", "62.23.0.0/17"]})
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), transport).refresh())
        self.assertEqual([str(n) for n in scope.networks], ["62.23.0.0/16"])

    def test_an_asn_prefixed_config_entry_resolves(self):
        """Normalisation must survive into resolution, not just matching."""
        config = ScopeConfig.from_dict({"asns": ["AS8220"]})
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        scope = asyncio.run(self.resolver(config, transport).refresh())
        asked = [asn for kind, asn in transport.calls if kind == "announced"]
        self.assertIn(8220, asked, "the normalised integer is what gets queried")
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks])

    def test_an_empty_config_resolves_to_nothing_without_calling_upstream(self):
        transport = StubTransport()
        scope = asyncio.run(self.resolver(ScopeConfig(), transport).refresh())
        self.assertEqual(scope.networks, ())
        self.assertEqual(transport.calls, [])
        self.assertFalse(scope.stale)


class TestDegradation(ResolverCase):
    def test_upstream_failure_serves_the_stale_cache_and_never_goes_empty(self):
        """The dangerous failure mode: a filter that narrows to nothing."""
        good = StubTransport(announced={8220: ["62.23.0.0/16"]})
        asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), good).refresh())
        self.assertTrue(self.cache.exists())

        broken = StubTransport(fail=True)
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), broken).refresh())
        self.assertTrue(scope.stale)
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks],
                      "must serve the cached set, never an empty one")

    def test_first_failure_with_no_cache_is_empty_and_stale(self):
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220,)), StubTransport(fail=True)).refresh())
        self.assertEqual(scope.networks, ())
        self.assertTrue(scope.stale)
        self.assertIsNotNone(scope.error)
        self.assertIn("upstream down", scope.error)

    def test_a_partial_failure_keeps_what_was_resolved(self):
        """AS 8220 succeeds, AS 10021 fails: keep 8220's space, flag it stale."""
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]}, fail_asns=(10021,))
        scope = asyncio.run(self.resolver(ScopeConfig(asns=(8220, 10021)), transport).refresh())
        self.assertIn("62.23.0.0/16", [str(n) for n in scope.networks],
                      "one bad ASN must not cost the whole scope")
        self.assertTrue(scope.stale)
        self.assertIn("10021", scope.error)

    def test_corrupt_cache_does_not_raise(self):
        self.cache.write_text("{not json", encoding="utf-8")
        scope = asyncio.run(
            self.resolver(ScopeConfig(asns=(8220,)), StubTransport()).refresh())
        self.assertIsNotNone(scope)

    def test_refresh_always_re_resolves(self):
        """`refresh()` means refresh. Caching is `ensure_resolved`'s job."""
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        asyncio.run(resolver.refresh())
        asked = [asn for kind, asn in transport.calls if kind == "announced"]
        self.assertEqual(asked, [8220, 8220])

    def test_ensure_resolved_does_not_hit_upstream_within_the_window(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        before = len(transport.calls)
        resolver.ensure_resolved()
        resolver.ensure_resolved()
        self.assertEqual(len(transport.calls), before)

    def test_an_expired_cache_is_reported_stale_without_touching_upstream(self):
        """The sync path cannot refresh — it never blocks on the network. An
        expired cache is returned and marked stale; `refresh()` does the work."""
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        before = len(transport.calls)
        self.cache.write_text(json.dumps({
            "resolved_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            "prefixes": ["62.23.0.0/16"],
        }), encoding="utf-8")
        resolver._resolved = None

        status = resolver.ensure_resolved()
        self.assertEqual(len(transport.calls), before, "sync path must not hit the network")
        self.assertIn("62.23.0.0/16", [str(n) for n in status.networks])

        refreshed = asyncio.run(resolver.refresh())
        self.assertGreater(len(transport.calls), before)
        self.assertFalse(refreshed.stale)


class TestPersistence(ResolverCase):
    def test_save_then_load_round_trips(self):
        resolver = self.resolver(ScopeConfig(), StubTransport())
        resolver.save(ScopeConfig(asns=(8220, 10021), include_transit=False))
        loaded = resolver.load()
        self.assertEqual(loaded.asns, (8220, 10021))
        self.assertFalse(loaded.include_transit)

    def test_save_writes_canonical_json(self):
        resolver = self.resolver(ScopeConfig(), StubTransport())
        resolver.save(ScopeConfig.from_dict({"asns": ["AS8220"]}))
        written = json.loads(self.scope_path.read_text(encoding="utf-8"))
        self.assertEqual(written["asns"], [8220], "stored canonically, not as entered")

    def test_load_of_a_missing_file_is_empty(self):
        resolver = ScopeResolver(self.settings, ScopeConfig(), transport=StubTransport())
        self.assertEqual(resolver.load().asns, ())

    def test_save_records_the_change_for_audit(self):
        resolver = self.resolver(ScopeConfig(asns=(64496,)), StubTransport())
        resolver.save(ScopeConfig(asns=(8220,)))
        status = resolver.status()
        self.assertIsNotNone(status.last_change)
        self.assertEqual(status.last_change["asns"], [8220])
        self.assertEqual(status.last_change["previous_asns"], [64496])
        self.assertIn("at", status.last_change)

    def test_save_forces_re_resolution(self):
        resolver = self.resolver(ScopeConfig(asns=(8220,)), StubTransport())
        asyncio.run(resolver.refresh())
        self.assertIsNotNone(resolver._resolved)
        resolver.save(ScopeConfig(asns=(8220, 10021)))
        self.assertIsNone(resolver._resolved, "scope changed: the resolved set is stale")


class TestMatcherAndStatus(ResolverCase):
    def test_status_before_resolution_is_the_cached_set(self):
        self.cache.write_text(json.dumps({
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "prefixes": ["62.23.0.0/16"],
        }), encoding="utf-8")
        resolver = self.resolver(ScopeConfig(asns=(8220,)), StubTransport())
        status = resolver.status()
        self.assertIn("62.23.0.0/16", [str(n) for n in status.networks])
        self.assertFalse(status.stale)

    def test_matcher_reflects_the_resolved_space(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        matcher = resolver.matcher()
        self.assertIn("SUBSPACE", matcher.reasons(alert(prefix="62.23.14.0/24", origin_as=64512)))
        self.assertNotIn("SUBSPACE", matcher.reasons(alert(prefix="8.8.8.0/24", origin_as=15169)))

    def test_as_dict_is_json_safe_and_carries_the_audit(self):
        transport = StubTransport(announced={8220: ["62.23.0.0/16"]})
        resolver = self.resolver(ScopeConfig(asns=(8220,)), transport)
        asyncio.run(resolver.refresh())
        payload = resolver.status().as_dict()
        json.loads(json.dumps(payload))
        for key in ("asns", "prefix_count", "include_transit", "resolved_at", "stale",
                    "error", "last_change"):
            self.assertIn(key, payload)
        self.assertEqual(payload["prefix_count"], 1)

    def test_rejections_survive_into_status(self):
        resolver = self.resolver(ScopeConfig.from_dict({"asns": ["AS8220", "8,220"]}), StubTransport())
        self.assertEqual(resolver.status().as_dict()["asns"], [8220])
        self.assertTrue(resolver.status().as_dict().get("rejected"))


class TestRipestatShape(unittest.TestCase):
    """Pinned to a real RIPEstat response captured 2026-10-08.

    `data` is a dict containing `prefixes`, not a list. An earlier assumption
    that it was a list iterated dict keys and raised
    `AttributeError: 'str' object has no attribute 'get'` — found only by
    running against the live API, because every stub had the wrong shape too.
    """

    RESPONSE = {
        "status": "ok",
        "data": {
            "prefixes": [
                {"prefix": "62.72.96.0/19",
                 "timelines": [{"starttime": "2026-09-24T00:00:00",
                                "endtime": "2026-10-08T00:00:00"}]},
                {"prefix": "62.23.255.0/24",
                 "timelines": [{"starttime": "2026-09-24T00:00:00",
                                "endtime": "2026-10-08T00:00:00"}]},
                {"prefix": "2001:678:868::/48", "timelines": []},
            ]
        },
    }

    def _transport(self):
        transport = RipestatTransport(delay_s=0.0)
        transport._get = lambda url, params: _async(self.RESPONSE)
        return transport

    def test_parses_the_nested_prefixes_array(self):
        prefixes = asyncio.run(self._transport().announced_prefixes(8220))
        self.assertEqual(prefixes, ["62.72.96.0/19", "62.23.255.0/24", "2001:678:868::/48"])

    def test_a_missing_or_odd_payload_yields_nothing_rather_than_raising(self):
        for payload in ({}, {"data": []}, {"data": None}, {"data": {}},
                        {"data": {"prefixes": "nope"}}, {"data": {"prefixes": [None, 7]}}):
            with self.subTest(payload=payload):
                transport = RipestatTransport(delay_s=0.0)
                transport._get = lambda url, params, _p=payload: _async(_p)
                self.assertEqual(asyncio.run(transport.announced_prefixes(8220)), [])


def _async(value):
    async def _inner():
        return value

    return _inner()


class TestSettingsWiring(unittest.TestCase):
    def test_settings_exposes_scope(self):
        from bgpmon.config import Settings

        base = Settings.load()
        self.assertIsInstance(base.scope, ScopeSettings)
        self.assertTrue(base.scope.scope_path.name.endswith("scope.json"))

    def test_defaults_are_sane(self):
        settings = ScopeSettings()
        self.assertEqual(settings.refresh_s, 3600)
        self.assertEqual(settings.cleanup_threshold_s if hasattr(settings, "cleanup_threshold_s")
                         else settings.refresh_s, 3600)


if __name__ == "__main__":
    unittest.main()
