# BGP Monitor — telecom-grade rebuild

## Status: implemented and verified

The previous revision was a proof of concept: it connected to RIS Live and had
heuristics, but it could not sustain a real feed (0.2 RPKI lookups/s), alerted on
7% of all updates, silently discarded updates, and never linked an alert to the
update that caused it. This rebuild targets NOC operation.

**Measured on live RIS Live (4 collectors, rrc00/rrc01/rrc11/rrc12) against Neo4j 5.26:**

| Metric | Before | After |
|---|---|---|
| RPKI verdicts | 0.2 lookups/s (RIPEstat, rate-limited to `UNKNOWN`) | **71 000+ lookups/s**, 1 013 990 VRPs indexed locally in 11 s |
| Ingest throughput | analyzer capped at ~21 updates/min | **2 662 updates/s**, sustained, 0 dropped |
| Alert rate | 7.08% of updates (1 007 prepend alerts in 120 s) | **0.21%**, and falling as baselines stabilise |
| Detection latency | blocking HTTP per update | **112–150 µs/update** |
| Graph writes | 1 transaction per announcement | **419 764 updates** batched, **0 failed batches** |
| Alert→update link | 0 edges ever created | deterministic shared id, edge resolves |
| Invalid collectors | 14 of 30 entries dead (Route Views ids) | RRC-only, validated at config load |

## Architecture

```mermaid
flowchart LR
  RIS[RIS Live<br/>RRC collectors] -->|asyncio| C[Collector<br/>normalise + bounded queue]
  C --> W[Detection worker<br/>single thread, no I/O]
  R[Routinator<br/>RTR :3323] -->|1M VRPs, 11s sync| RPKI[RPKI engine<br/>in-process index]
  CAIDA[CAIDA as-rel<br/>525k relationships] --> G[AS graph<br/>directed p2c/p2p]
  RPKI --> W
  G --> W
  W --> Gate[Alert gate<br/>dedup + budget]
  Gate --> N[(Neo4j<br/>batched write-behind)]
  Gate --> WS[WebSocket fanout]
  WS --> UI[React dashboard]
  W --> M[Prometheus /metrics]
```

## Detection

Every detector is baselined, so "unexpected" is distinguishable from "merely new":

| Kind | Baseline | Severity |
|---|---|---|
| `HIJACK_ORIGIN` | owned prefix + authorised/RPKI-valid origins | CRITICAL |
| `HIJACK_SUB_PREFIX` | more-specific of owned/critical space, RPKI-valid splits exempt | HIGH |
| `RPKI_INVALID` | local VRP set, RFC 6811 | CRITICAL if owned, else HIGH |
| `ROUTE_LEAK` | RFC 7908 valley-free on directed CAIDA graph, unknown edges never accused | HIGH |
| `BOGON_ASN` / `BOGON_PREFIX` | reserved ASN ranges and RFC 6890 space | HIGH |
| `VISIBILITY_LOSS` | owned prefix absent past grace across ≥2 collectors | CRITICAL |
| `NEW_PREFIX` | monitored AS announcing unseen space | MEDIUM |
| `LONG_PATH` | per-prefix path-length distribution, z-score | MEDIUM |
| `PREPEND` | watched/owned origins only | LOW |

Alert volume is controlled by construction: leaks are keyed by offending AS pair
(one incident ≠ 1 000 alerts), anomalous paths by origin+length, and the gate
applies per-key rate limits plus a global budget.

## Quick start

```bash
cp .env.example .env          # set NEO4J_PASSWORD and BGPMON_OWNED_PREFIXES
docker compose up -d --build  # neo4j + routinator + monitor
open http://localhost:8080    # dashboard
```

Without Docker:

```bash
pip install -r requirements-service.txt -r requirements.txt
docker run -d --name routinator -p 3323:3323 -p 8323:8323 nlnetlabs/routinator
python -m bgpmon              # API + monitoring
python -m bgpmon --soak 120   # headless throughput test
```

## Configuration

All secrets come from the environment (`.env`, git-ignored). `config/db_config.json`
was tracked with a plaintext password and has been removed from the index —
**rotate that credential.**

| Variable | Purpose |
|---|---|
| `BGPMON_OWNED_PREFIXES` | your originated space; drives hijack and visibility alerts |
| `BGPMON_COLLECTORS` | RRC ids only (`route-views.*` is rejected — invalid for RIS Live) |
| `BGPMON_NEO4J_*` | graph sink connection |
| `BGPMON_RPKI_RTR_HOST` / `_PORT` | Routinator RTR endpoint |
| `BGPMON_API_TOKEN` | optional bearer auth for API and WebSocket |

## Dashboard

React 19 + Vite + Tailwind v4 + shadcn/ui conventions + Recharts, served by
FastAPI from `web/dist` so deployment is one service.

- **Overview** — ingest rate, alert mix, RPKI set health, latency, queue depth, sparklines
- **Alerts** — virtualised table, severity/category/text filters, sortable
- **Topology** — observed AS adjacency (deterministic layout, not a drifting physics sim)
- **RPKI** — on-demand validation against the local VRP set, honest about `NOT_FOUND`

## Detection reference

Every alert kind, its baseline, and its severity semantics are documented in
[Logic.md](Logic.md). Tuning lives in `DetectionSettings` (`bgpmon/config.py`).

## Tests

```bash
python -m pytest tests/test_bgpmon.py -v    # 25 passing
```

Each test pins a defect observed in live output: AS-relationship direction,
valley-free semantics, alert-per-incident scoping, id consistency, RTR parsing,
collector validation, bogon classification, and secret handling.

## Operational notes

- **Owned prefixes are empty by default.** Until `BGPMON_OWNED_PREFIXES` is set,
  the tool runs in observe-only mode: RPKI, leaks and bogons still fire, but
  hijack/visibility classification has no baseline. This is deliberate — a
  hijack detector with no authorised set is a false-positive machine.
- **ASPA is inert.** No ASPA objects are published in the global RPKI yet (verified:
  RTR v2 emits none). The check reports that state rather than implying coverage.
- **CAIDA data** is refreshed by re-downloading into `data/`; the file is not in git.
