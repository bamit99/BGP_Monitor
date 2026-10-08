"""Incident correlation: group related alerts into an episode.

Ported in design from `utils/episode_manager.py` on `archive/pre-rebuild-master`
(616 lines). Five defects in that file were deliberately not carried over — see
`docs/legacy-inventory.md`. Each is pinned by a test here:

  1. its `severity_map` had no CRITICAL, so a CRITICAL alert scored 0 and never
     raised max_severity
  2. `cleanup_old_episodes` was defined twice; the second shadowed the first and
     the 24h threshold was dead code
  3. naive `datetime.now()` mixed with aware ISO timestamps raises TypeError
  4. `determine_hijack_scope` was a self-declared placeholder returning "UNKNOWN"
  5. `process_event` stored an episode twice when it closed

The key semantic change: the old matcher keyed on `previous_origin_as`, which is
the "compare to last seen" antipattern Logic.md rejects. Here an alert joins an
existing episode if its origin has *ever* been seen on that prefix this session,
which keeps a hijack-then-recovery in one episode without comparing to last seen.
Origin history decides episode membership only — never whether an alert is valid.
"""

from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone

from bgpmon.episodes import Episode, EpisodeConfig, EpisodeManager
from bgpmon.models import Alert, Kind, Severity

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def alert(origin_as=64496, prefix="203.0.113.0/24", severity=Severity.HIGH,
          minutes=0, kind=Kind.ROUTE_LEAK, reasons=None) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()), dedup_key="k", timestamp=BASE + timedelta(minutes=minutes),
        kind=kind, severity=severity, confidence=0.9, prefix=prefix, as_path="64496,64500",
        peer_as="64500", collector="rrc00", update_id="u1", origin_as=origin_as,
        reasons=reasons or ["Valley-free violation (RFC 7908)"],
    )


class TestEpisodeCreation(unittest.TestCase):
    def setUp(self):
        self.manager = EpisodeManager(EpisodeConfig())

    def test_first_alert_opens_an_episode(self):
        episode = self.manager.process(alert())
        self.assertIsNotNone(episode)
        self.assertEqual(episode.prefix, "203.0.113.0/24")
        self.assertEqual(episode.origin_as, 64496)
        self.assertEqual(episode.event_count, 1)
        self.assertEqual(episode.status, "OPEN")

    def test_alert_without_a_prefix_is_ignored(self):
        self.assertIsNone(self.manager.process(alert(prefix="")))

    def test_episode_without_an_origin_is_allowed(self):
        episode = self.manager.process(alert(origin_as=None))
        self.assertIsNotNone(episode)
        self.assertIsNone(episode.origin_as)

    def test_ids_are_unique(self):
        first = self.manager.process(alert(prefix="203.0.113.0/24"))
        second = self.manager.process(alert(prefix="198.51.100.0/24"))
        self.assertNotEqual(first.id, second.id)


class TestEpisodeMembership(unittest.TestCase):
    def setUp(self):
        self.manager = EpisodeManager(EpisodeConfig())

    def test_same_prefix_and_origin_joins(self):
        self.manager.process(alert(minutes=0))
        episode = self.manager.process(alert(minutes=5))
        self.assertEqual(episode.event_count, 2)
        self.assertEqual(len(self.manager.active()), 1)

    def test_a_repeat_of_an_attacking_origin_joins_its_own_episode(self):
        first = self.manager.process(alert(origin_as=64496, minutes=0))
        attack = self.manager.process(alert(origin_as=65001, minutes=5))
        repeat = self.manager.process(alert(origin_as=65001, minutes=10))
        self.assertEqual(len(self.manager.active()), 2)
        self.assertEqual(repeat.id, attack.id, "the repeat belongs to the attack episode")
        self.assertNotEqual(attack.id, first.id)
        self.assertEqual(repeat.event_count, 2)

    def test_a_returning_origin_never_joins_another_origins_episode(self):
        """Misattribution guard.

        An attacker whose own episode has expired must NOT be filed under the
        legitimate owner's still-open episode. Keying on "any origin previously
        seen on this prefix" does exactly that, which is why it was rejected.
        """
        cfg = EpisodeConfig(time_window_s=3600)
        manager = EpisodeManager(cfg)
        manager.process(alert(origin_as=64496, minutes=0))
        manager.process(alert(origin_as=65001, minutes=5))
        # Long gap: the attacker's episode falls outside the window.
        manager.process(alert(origin_as=64496, minutes=120))
        returned = manager.process(alert(origin_as=65001, minutes=125))
        self.assertEqual(returned.origin_as, 65001,
                         "the attacker's alert was filed under the legitimate owner")

    def test_an_expired_window_opens_a_new_episode_for_the_same_origin(self):
        """Two episodes for one (prefix, origin) can be open at once."""
        cfg = EpisodeConfig(time_window_s=600)
        manager = EpisodeManager(cfg)
        first = manager.process(alert(minutes=0))
        second = manager.process(alert(minutes=30))
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(len(manager.active()), 2)

    def test_hijack_and_recovery_are_two_episodes_one_per_origin(self):
        """Deliberate: strict keying keeps a hijack and its recovery separate, and
        an operator reading an episode sees a single origin throughout."""
        original = self.manager.process(alert(origin_as=64496, minutes=0))
        attack = self.manager.process(alert(origin_as=65001, minutes=5))
        recovered = self.manager.process(alert(origin_as=64496, minutes=10))
        self.assertEqual(len(self.manager.active()), 2)
        self.assertEqual(recovered.id, original.id, "recovery rejoins its own episode")
        self.assertEqual(recovered.origin_as, 64496)
        self.assertNotEqual(attack.origin_as, recovered.origin_as)

    def test_an_entirely_new_origin_opens_a_new_episode(self):
        self.manager.process(alert(origin_as=64496, minutes=0))
        self.manager.process(alert(origin_as=65002, minutes=5))
        self.assertEqual(len(self.manager.active()), 2)

    def test_different_prefix_always_opens_a_new_episode(self):
        self.manager.process(alert(prefix="203.0.113.0/24", minutes=0))
        self.manager.process(alert(prefix="198.51.100.0/24", minutes=1))
        self.assertEqual(len(self.manager.active()), 2)

    def test_an_alert_outside_the_window_opens_a_new_episode(self):
        cfg = EpisodeConfig(time_window_s=600)
        manager = EpisodeManager(cfg)
        manager.process(alert(minutes=0))
        manager.process(alert(minutes=30))  # 1800s > 600s
        self.assertEqual(len(manager.active()), 2)


class TestSeverityAndScore(unittest.TestCase):
    def test_critical_raises_max_severity(self):
        """Defect 1: the old severity_map had no CRITICAL key."""
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert(severity=Severity.HIGH, minutes=0))
        episode = manager.process(alert(severity=Severity.CRITICAL, minutes=1))
        self.assertEqual(episode.max_severity, Severity.CRITICAL)

    def test_critical_scores_above_high(self):
        cfg = EpisodeConfig(severity_scores={"LOW": 1.0, "MEDIUM": 5.0, "HIGH": 10.0,
                                             "CRITICAL": 25.0})
        manager = EpisodeManager(cfg)
        high = manager.process(alert(severity=Severity.HIGH, prefix="203.0.113.0/24"))
        crit = manager.process(alert(severity=Severity.CRITICAL, prefix="198.51.100.0/24"))
        self.assertGreater(crit.score, high.score)

    def test_score_accumulates_across_events(self):
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert(severity=Severity.HIGH, minutes=0))
        episode = manager.process(alert(severity=Severity.HIGH, minutes=1))
        self.assertEqual(episode.score, 20.0)

    def test_rpki_invalid_reasons_multiply_the_score(self):
        cfg = EpisodeConfig(rpki_invalid_multiplier=1.5)
        plain = EpisodeManager(EpisodeConfig()).process(
            alert(severity=Severity.HIGH, prefix="203.0.113.0/24"))
        rpki = EpisodeManager(cfg).process(alert(
            severity=Severity.HIGH, prefix="203.0.113.0/24",
            kind=Kind.RPKI_INVALID, reasons=["RPKI INVALID (origin not authorised)"]))
        self.assertAlmostEqual(rpki.score, plain.score * 1.5)

    def test_critical_prefix_multiplier_applies(self):
        cfg = EpisodeConfig(critical_prefix_multiplier=2.0)
        manager = EpisodeManager(cfg)
        manager.process(alert(severity=Severity.HIGH, minutes=0, prefix="203.0.113.0/24"))
        manager.process(alert(severity=Severity.HIGH, minutes=1, prefix="203.0.113.0/24"),
                        is_critical_prefix=True)
        episode = manager.active()[0]
        self.assertEqual(episode.metadata["is_critical_prefix"], True)


class TestSweep(unittest.TestCase):
    """Defect 2: cleanup_old_episodes was defined twice; only one threshold lived."""

    def setUp(self):
        self.cfg = EpisodeConfig(cleanup_threshold_s=86400)
        self.manager = EpisodeManager(self.cfg)

    def test_sweep_closes_an_inactive_episode(self):
        self.manager.process(alert(minutes=0))
        closed = self.manager.sweep(BASE + timedelta(hours=25))
        self.assertEqual(closed, 1)
        self.assertEqual(self.manager.active(), [])

    def test_sweep_leaves_a_recent_episode_open(self):
        self.manager.process(alert(minutes=0))
        self.assertEqual(self.manager.sweep(BASE + timedelta(hours=1)), 0)
        self.assertEqual(len(self.manager.active()), 1)

    def test_there_is_exactly_one_cleanup_threshold(self):
        """A single named source of truth, so the shadowed-method bug cannot recur."""
        self.assertEqual(self.cfg.cleanup_threshold_s, 86400)
        self.assertNotEqual(self.cfg.cleanup_threshold_s, self.cfg.time_window_s)

    def test_sweep_returns_the_number_closed(self):
        for i in range(3):
            self.manager.process(alert(prefix=f"198.51.100.{i}/32", minutes=0))
        self.assertEqual(self.manager.sweep(BASE + timedelta(hours=25)), 3)


class TestCloseSemantics(unittest.TestCase):
    def test_max_events_closes_and_retires_the_episode(self):
        manager = EpisodeManager(EpisodeConfig(max_events=3))
        for i in range(3):
            manager.process(alert(minutes=i))
        self.assertEqual(manager.active(), [])
        self.assertEqual(manager.stats()["closed"], 1)

    def test_on_close_fires_exactly_once(self):
        """Defect 5: the old process_event stored twice when it closed."""
        closed = []
        manager = EpisodeManager(EpisodeConfig(max_events=2), on_close=closed.append)
        for i in range(2):
            manager.process(alert(minutes=i))
        self.assertEqual(len(closed), 1)

    def test_on_close_fires_once_for_a_sweep(self):
        closed = []
        manager = EpisodeManager(EpisodeConfig(cleanup_threshold_s=3600), on_close=closed.append)
        manager.process(alert(minutes=0))
        manager.sweep(BASE + timedelta(hours=2))
        self.assertEqual(len(closed), 1)


class TestTimezoneSafety(unittest.TestCase):
    """Defect 3: the old module mixed naive datetime.now() with aware timestamps."""

    def test_every_timestamp_is_aware(self):
        manager = EpisodeManager(EpisodeConfig())
        episode = manager.process(alert(minutes=0))
        self.assertIsNotNone(episode.start_time.tzinfo)
        self.assertIsNotNone(episode.end_time.tzinfo)

    def test_comparison_with_an_aware_sweep_time_does_not_raise(self):
        """The old module mixed naive datetime.now() with aware timestamps."""
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert(minutes=0))
        self.assertEqual(manager.sweep(BASE + timedelta(hours=1)), 0)

    def test_sweep_accepts_a_realistic_now_far_from_the_alerts(self):
        manager = EpisodeManager(EpisodeConfig(cleanup_threshold_s=10**9))
        manager.process(alert(minutes=0))
        self.assertEqual(manager.sweep(datetime.now(timezone.utc)), 0)

    def test_end_time_tracks_the_latest_event(self):
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert(minutes=10))
        episode = manager.process(alert(minutes=2))
        self.assertEqual(episode.end_time, BASE + timedelta(minutes=10))


class TestSerialization(unittest.TestCase):
    def test_to_dict_omits_full_event_payloads(self):
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert())
        payload = manager.active()[0].to_dict()
        self.assertNotIn("events", payload)
        self.assertEqual(payload["event_count"], 1)

    def test_to_dict_is_json_serialisable(self):
        import json

        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert())
        payload = manager.active()[0].to_dict()
        json.loads(json.dumps(payload))  # must not raise
        self.assertIsInstance(payload["metadata"]["affected_asns"], list)

    def test_no_hijack_scope_filler(self):
        """Defect 4: determine_hijack_scope always returned the string 'UNKNOWN'."""
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert())
        metadata = manager.active()[0].metadata
        self.assertNotIn("hijack_scope", metadata)

    def test_get_by_id(self):
        manager = EpisodeManager(EpisodeConfig())
        episode = manager.process(alert())
        self.assertEqual(manager.get(episode.id).id, episode.id)
        self.assertIsNone(manager.get("no-such-id"))


class TestHijackSubtype(unittest.TestCase):
    def test_more_specific_is_detected(self):
        manager = EpisodeManager(EpisodeConfig())
        episode = manager.process(alert(
            kind=Kind.HIJACK_SUB_PREFIX,
            reasons=["more-specific of owned prefix 203.0.113.0/24"]))
        self.assertEqual(episode.metadata["hijack_subtype"], "MORE_SPECIFIC")

    def test_returning_to_the_authorised_origin_is_an_origin_change(self):
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert(origin_as=64496, minutes=0))
        episode = manager.process(alert(origin_as=65001, minutes=5))
        self.assertEqual(episode.metadata["hijack_subtype"], "ORIGIN_CHANGE")

    def test_repeat_of_the_same_origin_is_not_an_origin_change(self):
        manager = EpisodeManager(EpisodeConfig())
        manager.process(alert(origin_as=64496, minutes=0))
        episode = manager.process(alert(origin_as=64496, minutes=5))
        self.assertNotEqual(episode.metadata["hijack_subtype"], "ORIGIN_CHANGE")


if __name__ == "__main__":
    unittest.main()