# BGP Monitor — Detection Logic

How each alert is produced, and what its severity means. Every rule below is
implemented in `bgpmon/detect.py`; the entry point is
`DetectionEngine.evaluate(update)`, which runs on every announcement and returns
zero or more alerts.

## The central idea: detection needs a baseline

A routing observation is only suspicious relative to something. "Origin AS 64500
announced 203.0.113.0/24" is meaningless until you know which origins are
*authorised* for that prefix. So each detector is anchored to a baseline that
exists independently of the observed traffic:

| Baseline | Source | Feeds |
|---|---|---|
| Authorised origins per prefix | `BGPMON_OWNED_PREFIXES` + RPKI-valid origins | hijack, sub-prefix hijack |
| RPKI VRPs | Routinator over RTR (1.01M objects) | RPKI invalid, authorised origins |
| AS relationships | CAIDA `as-rel` (525 848 edges) | route leaks |
| Reserved space | RFC 6890 / RFC 6996 ranges | bogons |
| Observed prefix state | rolling per-prefix history in memory | visibility loss, new prefix, path z-score |

Without owned prefixes configured the engine runs in **observe-only** mode: RPKI,
leaks and bogons still fire (they are self-evident from public data), while
hijack and visibility classification stay silent by design.

## Alert kinds

### `RPKI_INVALID` — CRITICAL if owned, else HIGH

RFC 6811 validation against the local VRP set:

- **VALID** — a VRP covers the prefix, its origin ASN matches, and the announced
  length is within `maxLength`. No alert. The origin is also treated as
  *authorised* for the prefix, which is what makes the hijack rule MOAS-safe.
- **INVALID** — a VRP covers the prefix but the origin differs, or the announced
  prefix is longer than `maxLength` (sub-prefix announcement of authorised space).
- **NOT_FOUND** — no VRP covers the prefix. Not an alert: most of the address
  space has no ROA, and absence of a ROA is not a routing fault.

### `HIJACK_ORIGIN` — CRITICAL

The announced origin is not authorised for an owned prefix. Authorisation comes
from, in order: an explicit `expected_origins` entry, an RPKI-valid verdict, or a
previously observed origin for that prefix in this session. Anything else is a
hijack.

This is the rule that makes the difference between a usable detector and a false
positive generator. Comparing against *the last origin seen* — which is what a
naive implementation does — fires on every update of a legitimate MOAS prefix,
where two ASes share one prefix by design (anycast, CDN). Anchoring on
authorised origins instead means those prefixes stay quiet.

### `HIJACK_SUB_PREFIX` — HIGH

The announcement is a more-specific of owned or critical space, and is not
RPKI-valid. RPKI-valid splits are exempt because that is how operators
legitimately sub-allocate their own blocks.

### `ROUTE_LEAK` — HIGH

RFC 7908 valley-free violation, evaluated in **propagation order** — the reverse
of the AS path string, since a path is written from the collector's peer toward
the origin.

A legal path, read in propagation order, is `up* flat? down*`:

- `up` = customer announces to provider
- `flat` = peer or sibling announces to peer
- `down` = provider announces to customer

Announcing uphill again after a flat or down edge is a leak (RFC 7908 types 1/2);
receiving from a provider and re-announcing to a peer is type 5 and is also
flagged.

Two deliberate conservatisms:

1. **Unknown edges produce silence, not suspicion.** If any hop's relationship is
   absent from the CAIDA dataset the path is not judged. An inferred leak is not
   actionable for a NOC.
2. **One alert per offending AS pair**, not per prefix. A single leaky pair can
   drag thousands of prefixes; reporting each would be thousands of pages for one
   incident. The first occurrence alerts and carries an example prefix.

### `BOGON_ASN` / `BOGON_PREFIX` — HIGH

Reserved ASN ranges (0, 23456, 64496-65551, 4200000000+) and RFC 6890 special-use
address space appearing in an announcement.

### `VISIBILITY_LOSS` — CRITICAL

An owned prefix has not been seen for longer than the grace period (default
15 min) across at least two collectors. Multi-collector is required so a single
collector's session blip is not reported as a customer-visible outage.

### `NEW_PREFIX` — MEDIUM

A monitored AS announced a prefix it has not been seen announcing in this
session. Useful for change control, noisy if the monitored set is large.

### `LONG_PATH` — MEDIUM

The path length exceeds the prefix's own rolling mean by more than
`long_path_zscore` standard deviations (default 4σ), with an absolute floor so
short paths are never flagged. Per-prefix rather than global, because path length
is a property of the prefix's position in the topology.

Deduplicated by (origin, path length) for the session — one anomalous path is one
incident for the origin, not one per prefix the origin happens to announce.

### `PREPEND` — LOW

Consecutive AS prepending at or above `prepend_floor` (default 6). Scoped to
owned prefixes and monitored ASNs only: prepending is normal traffic engineering
globally, and flagging it across the whole table was the largest single source of
alert volume before this scoping was added.

## Volume control

Alert rate is controlled by construction, not by blanket suppression:

- incidents deduplicate on AS pair (leaks) or origin+length (long paths)
- `AlertGate` rate-limits repeats per (kind, prefix) within a window
- a global per-minute budget caps the worst case
- MOAS-style first sightings are held for corroboration before paging

Tuning lives in `DetectionSettings` (`bgpmon/config.py`); owned space comes from
`BGPMON_OWNED_PREFIXES`.

## What is deliberately not implemented

- **ASPA (RFC 9234)** — no ASPA objects are published in the global RPKI yet
  (verified: RTR v2 emits none), so the check reports NOT_FOUND rather than
  implying coverage. See ROADMAP for the operator-supplied object file.
- **ROA change monitoring** — the VRP set carries the data but diffing owned-space
  VRPs between syncs is not wired up yet (ROADMAP).
- **ML anomaly detection** — the earlier Isolation Forest never fitted a model and
  was removed rather than shipped inert. See ROADMAP for the baseline approach.
