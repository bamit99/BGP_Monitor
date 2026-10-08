# Roadmap

Track for continuing from the 2.0 rebuild. Items are grouped by what unlocks them;
"Done" anchors what is already shipped and verified (see git log and `tests/`).

## Done in the 2.0 rebuild

| Area | Shipped |
|---|---|
| Ingest | Async RIS Live collector, explicit subscription acks, bounded queue, reconnect backoff |
| RPKI | RTR client against Routinator; 1.01M VRPs indexed locally in ~11 s; ~71k validations/s; RIPEstat fallback only when the local set is unavailable |
| Leaks | RFC 7908 valley-free check on the directed CAIDA graph (525 848 relationships); unknown edges never accused |
| Hijacks | Owned-prefix + authorised-origin baseline; RPKI-valid origins accepted as authorised (MOAS-safe) |
| Other detectors | Bogon ASN/prefix, new-prefix, visibility-loss, per-prefix path-length z-score |
| Noise control | Incident-scoped dedup (leaks by AS pair, long paths by origin), gate rate limiting, global budget |
| Storage | Batched write-behind Neo4j sink; alert→update `TRIGGERED_BY` resolves (25 622 edges, 0 orphans) |
| Observability | Prometheus `/metrics`, `/api/health`, structured feed/sink/gate counters |
| Console | React 19 + Vite + Tailwind v4: Overview, Alerts (virtualised), Topology, RPKI inspector. An ASN Scope lookup and a scope filter are specced and planned but not yet in `master` |
| Ops | docker-compose (neo4j + routinator + monitor), `.env` secrets, `INSTALL.md`, 36 regression tests |

## Shipped after the 2.0 rebuild (2026-10-08)

Verified on this host against live RIS Live, Routinator and Neo4j 5.26.

| Fix | Commit | Evidence |
|---|---|---|
| **`httpx` was missing from `requirements.txt`.** `bgpmon/scope.py` imports it at module scope and `bgpmon/api.py` imports `scope`, so the container could not start at all | `1f36c06` | `ModuleNotFoundError` reproduced in the built image; both modules now import in a clean `python:3.13-slim` with only `requirements.txt` |
| **`requirements-service.txt` did not exist** but was cited by `README.md:70` and `install_linux.sh:9`. Both non-Docker install paths failed on the pip line | `1f36c06` | `pip install -r requirements-service.txt` errored; file now present |
| **`VISIBILITY_LOSS` could never fire.** `PrefixState` is `slots=True` but the code assigned an undeclared attribute, so the documented CRITICAL detector raised `AttributeError` on every invocation and `pipeline._visibility_loop` swallowed it into a log line | `9b6e87d` | Reproduced; 5 regression tests added, 3 failed before the fix |
| **SPA deep links** — `StaticFiles(html=True)` 404'd on a fresh GET of `/alerts`; replaced with a catch-all serving `index.html` | `faf81d7` | Covered by `tests/test_bgpmon.py` (`TestSpaDeepLinks`) |
| **Incident TTL eviction** — `_leak_pairs` / `_path_incidents` were session-scoped, so a long-lived leak was silenced forever after a restart | `faf81d7` | Covered by `TestIncidentExpiry` |
| **`.dockerignore`** exists, so `data/` and credentials never enter a build context | `faf81d7` | Verified by a from-scratch `docker compose build` |
| **Configurable host port** — compose parameterised as `${BGPMON_API_PORT:-8080}` | `faf81d7` | Needed on this host: 8080 is held by `svchost` |
| **`INSTALL.md`** — step-by-step install, verification and troubleshooting | `964947f` | Every command verified on this host |

Measured after the fixes, 4 collectors, ~13 min uptime:

```
RIS Live     3 352 872 updates, 0 dropped, 4 406 updates/s
RPKI         268 009 prefixes / 289 142 VRPs over RTR, 0 failures
Neo4j        2 188 742 updates + 678 alerts written, 0 failed batches
Detection    98 µs mean
```

## Next: scope your space (unlocks hijack + visibility)

**Specced and planned** — see
`docs/superpowers/specs/2026-10-08-scope-filtering-and-siem-forwarding-design.md`
and `docs/superpowers/plans/2026-10-08-scope-filtering-and-siem-forwarding.md`.

Measured motivation: on an unscoped install, 1 723 alerts in the recent window
contained **zero** concerning a sample operator's ASN and **two** where that ASN
appeared as transit. The filter is the feature that makes anything else usable.

The load-bearing design decision: **scope (registry-derived, decides what you look
at) and authorised space (RPKI-derived, the only thing that may mark an origin
legitimate) are deliberately separate objects.** Feeding IRR data into a CRITICAL
detector produces both false positives (space you sub-let, announced legitimately
by the customer) and false negatives (stale IRR means no baseline at all).

1. **Declare ASNs, derive space.** `config/scope.json` lists the ASNs you operate;
   the tool resolves them to prefixes via RIPEstat. Verified that registry data
   distinguishes own space from customer space in one call — `62.23.0.0/16`
   returns `origin: 8220` on the /16 (`descr: FR-COLT-FRANCE`) and on seven /24s
   inside it with `descr: TATA IZO`.
2. **Match reasons, not a boolean.** `ORIGIN` (you announce it), `SUBSPACE` (a
   more-specific of your space), `TRANSIT` (your ASN in the AS path). Shown
   individually, so an empty view explains itself instead of looking broken.
3. **Scope entered through the UI**, persisted to `config/scope.json`. This makes
   working auth a prerequisite, not an optional extra — the write endpoint changes
   which alerts an operator sees, and a shared bearer token cannot say who changed it.
4. **SIEM forwarding over syslog RFC 5424/TCP**, gated on scope. Vendor-neutral so
   Sentinel, Splunk HEC and QRadar all ingest it unchanged.
1. **Ship the untracked scope lookup** — `bgpmon/scope.py` and
   `web/src/views/Scope.tsx` exist in the working tree but are untracked, while
   their four integration points (`bgpmon/api.py`, `web/src/App.tsx`,
   `web/src/lib/api.ts`, `web/src/lib/types.ts`) are modified and uncommitted.
   Ship as one commit with tests, or shelve it — do not leave it half-staged.
   Rename `scope.py` to `scope_lookup.py` first, so the name does not collide
   with a future `scope` CLI subcommand.
2. **Visibility tuning for a large cone** — after scope exists, start at 15 min
   grace across ≥2 collectors, then measure observed per-prefix collector counts
   for a day and tune `BGPMON_VISIBILITY_GRACE` from data rather than guesswork.
   Note `visibility_min_expected_collectors` has **no** env var
   (`bgpmon/config.py:151`) — changing the multi-collector floor needs a code
   edit, so wire `BGPMON_VISIBILITY_MIN_COLLECTORS` first.
3. **Synthetic hijack rehearsal** — inject a fabricated announcement for a
   configured owned prefix from an unauthorised origin; confirm `HIJACK_ORIGIN`
   (CRITICAL) and `HIJACK_SUB_PREFIX` fire before pointing the baseline at real space.
4. **Server-side scoping** — once scope exists, consider switching the RIS
   subscription from "all updates, client-side filter" to per-prefix
   `ris_subscribe` filters (verified: `moreSpecific` filters server-side). Cuts
   ingest volume by orders of magnitude, at the cost of losing the "who is
   announcing toward me" view.

## Open defects found while bringing the stack up (2026-10-08)

Reproduced on this host, not inferred from reading. Severity reflects NOC impact.
Fixes are specced in the plan referenced above where noted.

| # | Severity | Defect | Where |
|---|---|---|---|
| 1 | Medium | Dashboard sends no `Authorization` header and no `?token=`, so `BGPMON_API_TOKEN` breaks every view. Fix: plan Task 1 | `web/src/lib/api.ts:5`, `web/src/lib/useAlertStream.ts:28` |
| 2 | Medium | `GET /api/<unknown>` returns 200 + `index.html` instead of a JSON 404 — the SPA catch-all swallows it. Fix: plan Task 4 | `bgpmon/api.py:44` |
| 3 | Medium | MEDIUM/LOW alerts are never written to Neo4j, so they vanish on restart and `/api/alerts?source=graph` never returns them | `bgpmon/pipeline.py:159` |
| 4 | Medium | `owned_only` is ignored on the graph path of `/api/alerts` | `bgpmon/api.py:104-109` |
| 5 | Medium | MOAS corroboration key's third element is always `0`, so `HIJACK_ORIGIN` and `NEW_PREFIX` share a pending set. Fix: plan Task 8 | `bgpmon/gate.py:60` |
| 6 | Medium | `telemetry.py` annotates `Optional` without importing it; `gauge_rpki`/`record_rpki` are never called, so three Prometheus series never carry samples. Fix: plan Task 8 | `bgpmon/telemetry.py:9,107,114` |
| 7 | Medium | compose bind-mounts `./config` over the baked-in `security_config.json`; a missing host file silently drops all 7 `critical_prefixes`. Fix: plan Task 8 | `docker-compose.yml:70`, `Dockerfile:25` |
| 8 | Medium | `ScopeLookup` cache is unbounded with no TTL and no upstream politeness delay — up to 10 requests per uncached query | `bgpmon/scope.py:44` |
| 9 | Low | `RPKI_ASPAS`, `MOAS_NEW_ORIGIN`, `RPKI_ROA_CHANGE` are declared and shown as filter chips but never emitted | `bgpmon/models.py:43`, `web/src/lib/format.ts:20-28` |
| 10 | Low | `Pipeline._visibility_thread` is assigned in `start()` but never initialised in `__init__`, unlike its siblings | `bgpmon/pipeline.py:74` |
| 11 | Low | The SIGINT handler at `__main__.py:79` is dead in the API path — uvicorn replaces it and the lifespan teardown already drains the sink. Harmless, but it reads as if it owns shutdown | `bgpmon/__main__.py:79` |
| 12 | Low | `npm run lint` cannot run — ESLint 9 requires `eslint.config.js`, which does not exist. This blocks the CI item | `web/package.json:10` |
| 13 | Low | `web/tsconfig.tsbuildinfo` is untracked and not git-ignored; it will be committed by accident | `.gitignore` |

## Security

1. ~~Rotate the Neo4j password~~ — **done.** The instance credential was rotated by the operator and
   the stale local `config/db_config.json` was deleted; the engine reads `BGPMON_NEO4J_PASSWORD`
   from `.env` only.
2. ~~Scrub history~~ — **done.** The credential sat in several blobs (the file itself, its deletions,
   and prose that quoted it), so the rewrite used
   `git filter-repo --replace-text` rather than a path filter, then force-pushed `master` and
   `archive/pre-rebuild-master` (they share the affected ancestry). Verified: no ref on GitHub
   contains the string, and the pre-scrub commits are no longer retrievable by SHA (404).
   Note that the rewrite changed every commit SHA, so any hash quoted elsewhere is stale.
3. **Stay clean** — the repo has no secret scanning; a pre-commit hook or a GitHub secret-scanning
   rule for `config/*.json` and `.env` would catch a repeat before it is pushed.
4. **Loopback bind** — compose should publish `127.0.0.1:${BGPMON_API_PORT}:8080` rather than all
   interfaces. `docker port` reports `0.0.0.0` regardless of what the host actually listens on, so
   that output is not evidence either way. Covered by the scope plan, Task 1.

## Console (UI)

1. **Bundle split** — 767 kB single chunk (224 kB gzip); `manualChunks` for recharts and react-router
2. **Live polish** — severity filter chips already persist in the store; add per-user persistence
   (localStorage) and a "paused" state so triage can freeze the stream while reading
3. **Episode view** — an incident timeline (alerts grouped by AS pair/origin) is the
   NOC-grade triage surface, and it does not exist yet: there is no episode concept
   anywhere in the rebuild. An implementation does exist in the archived pre-rebuild
   tree — `utils/episode_manager.py`, 616 lines, with `Episode` / `EpisodeManager`,
   event scoring, and hijack scope/subtype classification. It was not carried forward
   and is worth porting rather than rewriting. The field mapping and the one
   semantic change it requires are documented in
   [docs/legacy-inventory.md](docs/legacy-inventory.md).
4. **Topology depth** — currently derived from a recency sample of AS paths; once scope is
   configured, offer an owned-space-first view with provider/customer edges from CAIDA drawn
   directionally rather than undirected
5. **Lint config** — add `eslint.config.js`; `npm run lint` cannot pass as written (open defect 12)

## Engine

1. **ASPA** — inert by design (verified: RTR v2 emits no ASPA objects globally); wire an
   operator-supplied ASPA object file (`BGPMON_ASPA_FILE`) and surface coverage honestly in `/api/rpki`
2. **ROA change detection** — the VRP set already carries the data; diff VRPs covering owned space
   between syncs to emit `RPKI_ROA_CHANGE` (add/remove/maxLength change)
3. **Peer-lock / RFC 9234** — `ROUTE_LEAK` currently infers from path shape only; OTC community
   (35:0) is present in RIS Live messages and should be a first-class signal
4. **Sink backpressure** — Neo4j lock contention was observed when two writers ran; single-writer
   is now guaranteed by design, but add a queue-depth alert to catch a slow sink
5. **Observed-origin authorisation** — `Logic.md` documents a third path by which `HIJACK_ORIGIN`
   accepts an origin: "a previously observed origin for this prefix in this session". That makes
   observed traffic an authorisation input, which sits against the RPKI-first trust hierarchy the
   scope spec relies on. Defensible for genuine MOAS; needs a deliberate ruling rather than
   inherited silence.

## Carried over from the pre-rebuild tracker

Items from `IMPROVEMENT_TRACKER.md` that the rebuild did not cover and that remain
worth doing. The rest of that tracker described the retired analyzer and is either
shipped above or obsolete.

1. **IRR validation** — check announcements against registered `route:`/`route6:`
   objects (RADb) as a second authorisation source alongside RPKI. Reuses the
   resolution plumbing from the scope work. **Informative only, never authorising**
   — see the trust hierarchy in the scope spec.
2. **Dynamic threat intelligence** — replace the static `known_bad_actors` concept
   with a feed-driven malicious-ASN/prefix list (CIRCL, Spamhaus, commercial),
   refreshed on a schedule with source attribution on each alert. Note
   `known_bad_actors` in `config/security_config.json` is currently dead config:
   nothing reads it.
3. **Anomaly detection beyond z-scores** — split into a quick win and a long-term
   track. Neither puts a model in the detection path; see
   [docs/legacy-inventory.md](docs/legacy-inventory.md) for why the previous
   attempt is being removed rather than revived.

   **Quick win — persisted seasonal baseline.** `LONG_PATH` today z-scores over a
   256-sample in-memory deque (`detect.py:PrefixState.path_lengths`) that resets on
   restart and models no seasonality, while BGP path length is strongly diurnal. A
   real 30-day-old prefix sitting 4σ above its own history at 03:00 is invisible.
   Replace the deque with a persisted per-prefix baseline: median and MAD per
   *hour-of-day* bucket, decaying over ~30 days.
   - Explainable: "4σ above this prefix's own 30-day profile for this hour" — a
     sentence a NOC can put in a ticket
   - No training pipeline, no drift story, no model version
   - Degrades to silence with no history, exactly like every other baselined detector
   - Store in Neo4j as per-prefix aggregates; no new datastore
   - Prerequisite the old tracker already flagged: persistence

   **Long term — offline-validated triage ranking, never detection.** Rank which
   of today's alerts a human should open first. Wrong there costs nothing; wrong
   in the detector costs trust in the deterministic detectors, which are the ones
   that can explain themselves with a specification number (RPKI is cryptographic,
   leaks are RFC 7908, bogons are RFC 6890).
   - Train offline against a week of recorded alerts, measure ranking quality
     against human triage order, and ship disabled until it beats a
     severity-then-recency sort
   - Keep it out of `bgpmon/detect.py` entirely — it consumes the alert stream, it
     does not produce alerts
   - If it cannot be validated out-of-sample, do not ship it. The previous
     Isolation Forest was removed precisely because it was never fitted and would
     have been shipped inert
4. **Documentation and runbooks** — NOC-facing material: what each alert kind means,
   first-response actions, escalation, and false-positive history for tuning

## Deployment: enterprise target (stated 2026-10-08)

Intended end state: a dedicated server in the operator's office, dashboard over
HTTPS with a real login, reachable remotely. Not a local dashboard.

The application shape stays as-is — **bind loopback, terminate TLS at a reverse
proxy**. Cert renewal, HSTS, rate limiting and connection limits belong in
nginx/Caddy, not in the Python process. Do not move the app to a public bind.

That target changes one committed ruling. The scope spec deferred per-user
identity and recorded the consequence: a shared bearer token can show *that*
scope changed, never *who*. With a login screen that stops being acceptable,
because scope decides which alerts an operator sees.

Sequence, roughly:

1. **Reverse proxy** — nginx or Caddy in front of the loopback bind, TLS cert,
   HSTS, request-size and rate limits. Small, and unblocks remote access.
2. **Authentication** — a login screen means sessions, not a bearer header.
   Decide the identity source before building: OIDC/SAML against the office IdP,
   LDAP, or local accounts. Each changes the storage and the session model.
3. **Authorisation** — at minimum, who may edit scope. Scope write is currently
   any valid token, which is too broad once there are several people.
4. **Audit with identity** — the existing `last_change` ring records that scope
   changed. It needs the actor. Until then it is a debugging aid, not an audit
   trail, and should not be described as one.
5. **Per-user state** — filter persistence in `localStorage` becomes per-user;
   see Console item 2.
6. **Availability** — the Neo4j and Routinator volumes are currently local. A
   single office server needs a restore story for the graph, and the RPKI cache
   must survive a restart or the first sync blocks startup.

Before any of this: scope and SIEM forwarding are still unbuilt. A login screen
in front of a firehose is not an enterprise tool.

## Infra

1. **CI** — GitHub Actions running `pytest` + `npm run build` on PR; the repo has no CI today.
   Add `eslint.config.js` first or leave `npm run lint` out of the workflow — it cannot pass as written.
2. **Grafana** — `/metrics` is exposed; ship a starter dashboard JSON alongside compose
3. **`install_linux.sh`** — assumes `python3` on PATH, creates a `.venv` the Windows route cannot use,
   and pins a date-stamped CAIDA URL (`20260901`) that goes stale monthly. There is no `latest`
   alias on CAIDA serial-1, so a fresh install needs the newest `YYYYMMDD` from the index.
4. **Compose config shadowing** — `./config` is bind-mounted over the baked-in
   `config/security_config.json`; see open defect 7.