"""Scope matching decides what an operator looks at, not what is a violation.

Registry-derived scope is approximate by design (spec 2.1). These tests pin the
shapes that matter: ASN normalisation, more-specific detection, AS_SET tolerance,
and never raising or silently dropping on malformed input.

The silent-drop case is the one that matters most. `"asns": ["AS8220"]` parsed by
a naive `int()` raises, gets skipped, and leaves an empty scope — an operator who
believes they scoped AS8220 and is filtering nothing. Rejected entries are
recorded, never discarded quietly.
"""

import ipaddress
import unittest
from datetime import datetime, timezone

from bgpmon.models import Alert, Kind, Severity
from bgpmon.scope_match import (
    MAX_ASNS,
    MAX_ASN,
    MAX_EXTRA_PREFIXES,
    ScopeConfig,
    ScopeMatcher,
    normalize_asn,
)


def alert(prefix="198.51.100.0/24", origin_as=64496, as_path="64496,64500,64496") -> Alert:
    return Alert(
        alert_id="a1", dedup_key="k", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        kind=Kind.ROUTE_LEAK, severity=Severity.HIGH, confidence=0.9, prefix=prefix,
        as_path=as_path, peer_as="64500", collector="rrc00", update_id="u1",
        origin_as=origin_as,
    )


class TestAsnNormalisation(unittest.TestCase):
    def test_accepts_every_spelling_of_the_same_asn(self):
        for value in (8220, "8220", "AS8220", "as8220", "As8220", " 8220 ", " AS8220 "):
            with self.subTest(value=value):
                self.assertEqual(normalize_asn(value), 8220)

    def test_rejects_things_that_are_not_asns(self):
        for value in ("8,220", "8220.0", "abc", "", "AS", "ASabc", None, [], {}, 3.5, "8_220"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_asn(value))

    def test_range_is_enforced(self):
        self.assertEqual(normalize_asn(0), 0)
        self.assertEqual(normalize_asn(MAX_ASN), MAX_ASN)
        self.assertIsNone(normalize_asn(MAX_ASN + 1))
        self.assertIsNone(normalize_asn(-1))

    def test_a_float_that_is_whole_is_rejected_not_truncated(self):
        """8220.0 must not silently become 8220."""
        self.assertIsNone(normalize_asn(8220.0))

    def test_both_spellings_of_a_scope_behave_identically(self):
        numeric = ScopeConfig.from_dict({"asns": [8220]})
        prefixed = ScopeConfig.from_dict({"asns": ["AS8220"]})
        self.assertEqual(numeric.asns, prefixed.asns)
        prefixes = [ipaddress.ip_network("45.0.0.0/16")]
        as_alert = alert(prefix="45.0.0.0/16", origin_as=8220, as_path="8220,64500")
        self.assertEqual(
            ScopeMatcher(numeric, prefixes).reasons(as_alert),
            ScopeMatcher(prefixed, prefixes).reasons(as_alert),
        )


class TestScopeConfigParsing(unittest.TestCase):
    def test_missing_file_yields_an_empty_config_not_an_error(self):
        config = ScopeConfig.from_dict(None)
        self.assertEqual(config.asns, ())
        self.assertFalse(config.rejected)

    def test_malformed_json_does_not_raise(self):
        for raw in ({}, {"asns": "8220"}, {"asns": ["8220", 70000]}, {"extra_prefixes": ["nope"]},
                    {"include_transit": 17}, {"asns": None}, {"extra_prefixes": "62.23.0.0/16"}):
            with self.subTest(raw=raw):
                ScopeConfig.from_dict(raw)  # must not raise

    def test_wellformed_values_are_kept(self):
        config = ScopeConfig.from_dict({"asns": [8220, 10021], "extra_prefixes": ["62.23.0.0/16"]})
        self.assertEqual(config.asns, (8220, 10021))
        self.assertEqual(config.extra_prefixes, ("62.23.0.0/16",))
        self.assertFalse(config.rejected)

    def test_duplicates_are_collapsed_across_spellings(self):
        config = ScopeConfig.from_dict({"asns": [8220, "8220", "AS8220", "as8220"]})
        self.assertEqual(config.asns, (8220,))

    def test_rejected_entries_are_reported_not_silently_dropped(self):
        config = ScopeConfig.from_dict({"asns": [8220, "8,220", "nonsense"],
                                        "extra_prefixes": ["62.23.0.0/16", "not-a-cidr"]})
        self.assertEqual(config.asns, (8220,))
        self.assertEqual(config.extra_prefixes, ("62.23.0.0/16",))
        # Each bad entry must be nameable, so the operator can fix it.
        reported = " | ".join(config.rejected)
        for offending in ("8,220", "nonsense", "not-a-cidr"):
            self.assertIn(offending, reported)

    def test_caps_are_enforced(self):
        too_many = ScopeConfig.from_dict({"asns": list(range(1, MAX_ASNS + 2))})
        self.assertEqual(len(too_many.asns), MAX_ASNS)
        too_many_prefixes = ScopeConfig.from_dict(
            {"extra_prefixes": [f"10.0.{i // 256}.{i % 256}/32" for i in range(MAX_EXTRA_PREFIXES + 5)]})
        self.assertEqual(len(too_many_prefixes.extra_prefixes), MAX_EXTRA_PREFIXES)

    def test_include_transit_reads_the_string_false_as_false(self):
        """bool('false') is True in Python. A config saying false must mean false."""
        self.assertFalse(ScopeConfig.from_dict({"include_transit": "false"}).include_transit)
        self.assertFalse(ScopeConfig.from_dict({"include_transit": "FALSE"}).include_transit)
        self.assertFalse(ScopeConfig.from_dict({"include_transit": False}).include_transit)
        self.assertTrue(ScopeConfig.from_dict({"include_transit": "true"}).include_transit)
        self.assertTrue(ScopeConfig.from_dict({"include_transit": True}).include_transit)

    def test_include_transit_defaults_to_true_when_absent(self):
        self.assertTrue(ScopeConfig.from_dict({}).include_transit)

    def test_networks_parses_only_valid_prefixes(self):
        config = ScopeConfig.from_dict({"extra_prefixes": ["62.23.0.0/16"]})
        self.assertEqual([str(n) for n in config.networks()], ["62.23.0.0/16"])

    def test_cypher_asn_strings_are_strings(self):
        """Cypher compares by type: split() yields strings, so an int list
        matches nothing. This parameter exists so that cannot happen silently."""
        config = ScopeConfig.from_dict({"asns": ["AS8220", 10021]})
        self.assertEqual(config.cypher_asn_strings(), ["8220", "10021"])
        self.assertTrue(all(isinstance(v, str) for v in config.cypher_asn_strings()))


class TestScopeMatching(unittest.TestCase):
    def setUp(self):
        self.matcher = ScopeMatcher(
            ScopeConfig(asns=(8220,), extra_prefixes=("62.23.0.0/16",), include_transit=True),
            prefixes=[ipaddress.ip_network("62.23.0.0/16")],
        )

    def test_origin_matches_when_the_alert_origin_is_a_scope_asn(self):
        self.assertIn("ORIGIN", self.matcher.reasons(alert(prefix="45.0.0.0/16", origin_as=8220)))

    def test_subspace_matches_a_more_specific_from_an_unrelated_origin(self):
        """The sub-prefix hijack shape: in our space, not from us."""
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
        """8220 must not match inside 182205."""
        found = self.matcher.reasons(alert(origin_as=1, as_path="182205,64500,1"))
        self.assertNotIn("TRANSIT", found)

    def test_as_set_and_empty_paths_do_not_raise(self):
        for path in ("", "{}", "{8220,64500}", "64496,,64500", "AS8220", "as8220,"):
            with self.subTest(path=path):
                self.assertIsInstance(self.matcher.reasons(alert(as_path=path, origin_as=1)), tuple)

    def test_path_hops_written_with_an_as_prefix_still_match(self):
        """RIS messages sometimes carry AS-prefixed hops."""
        found = self.matcher.reasons(alert(origin_as=1, as_path="AS8220,64500"))
        self.assertIn("TRANSIT", found)

    def test_an_unrelated_prefix_has_no_reason(self):
        self.assertEqual(self.matcher.reasons(alert(prefix="8.8.8.0/24", origin_as=15169)), ())

    def test_unparsable_prefix_is_not_a_match(self):
        self.assertNotIn("SUBSPACE", self.matcher.reasons(alert(prefix="not-a-prefix")))

    def test_a_v4_prefix_never_matches_a_v6_scope(self):
        config = ScopeConfig(asns=(), extra_prefixes=("2001:db8::/32",))
        matcher = ScopeMatcher(config, [ipaddress.ip_network("2001:db8::/32")])
        self.assertEqual(matcher.reasons(alert(prefix="62.23.14.0/24")), ())

    def test_matches_is_true_for_any_reason(self):
        self.assertTrue(self.matcher.matches(alert(origin_as=8220, prefix="45.0.0.0/16")))
        self.assertFalse(self.matcher.matches(alert(prefix="8.8.8.0/24", origin_as=15169)))

    def test_an_empty_scope_matches_nothing(self):
        """Empty scope must never narrow the view; the API decides not to filter."""
        empty = ScopeMatcher(ScopeConfig(), [])
        self.assertEqual(empty.reasons(alert(origin_as=8220, prefix="45.0.0.0/16",
                                             as_path="8220,1")), ())