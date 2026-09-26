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
| Console | React 19 + Vite + Tailwind v4: Overview, Alerts (virtualised), Topology, RPKI inspector |
| Ops | docker-compose (neo4j + routinator + monitor), `.env` secrets, 25 regression tests |

## Next: baseline your space (unlocks hijack + visibility)

1. **`bgpmon scope --asn AS8220 --asn AS10021`** — importer that pulls announced prefixes for
   Colt's two ASNs from RIPEstat and writes `config/owned_prefixes.json`
   (prefix → authorised origins). No manual list-typing; no address space shared in chat.
   - Validate the mapping with `bgpmon scope --check` (RIPEstat re-query + diff, exit non-zero on drift)
   - Optional `--irr` flag to also pull `route:`/`route6:` objects from RADb as a second source
2. **Synthetic hijack rehearsal** — inject a fabricated announcement for a configured owned prefix
   from an unauthorised origin; confirm `HIJACK_ORIGIN` (CRITICAL) and `HIJACK_SUB_PREFIX` fire
   before pointing the baseline at real Colt space
3. **Visibility tuning for a large cone** — AS8220 announces many prefixes; start at
   15 min grace across ≥2 collectors, then measure observed per-prefix collector counts for a day
   and tune `BGPMON_VISIBILITY_GRACE` / `_MIN_COLLECTORS` from data rather than guesswork
4. **Server-side scoping** — once `owned_prefixes.json` exists, switch the RIS subscription from
   "all updates, client-side filter" to per-prefix `ris_subscribe` filters
   (verified: `moreSpecific` filters server-side). Cuts ingest volume by orders of magnitude

## Security

1. **Rotate the Neo4j password** — `config/db_config.json` containing `***REMOVED-CREDENTIAL***` was removed
   from the index but remains in git history (`d5971dd`, `a8e0fe2`); the credential is live and shared
   with other projects on this instance, so rotate it and store the new value in `.env` only
2. **Scrub history** — `git filter-repo --path config/db_config.json --invert-paths` on a fresh clone
   and force-push, *after* rotation; requires coordinating anyone else with a clone

## Console (UI)

1. **Deep links** — FastAPI serves the built SPA with `StaticFiles(html=True)`, which 404s on a fresh
   GET of `/alerts` or `/topology`; add a catch-all returning `index.html` for non-API paths
   (mount assets at `/assets`, keep `/api`, `/ws`, `/metrics` reserved)
2. **Bundle split** — 761 kB single chunk (222 kB gzip); `manualChunks` for recharts and react-router
3. **Live polish** — severity filter chips already persist in the store; add per-user persistence
   (localStorage) and a "paused" state so triage can freeze the stream while reading
4. **Episode view** — episodes exist in the engine's model but have no tab yet; a timeline per
   incident (alerts grouped by AS pair/origin) is the NOC-grade triage surface
5. **Topology depth** — currently derived from a recency sample of AS paths; once owned space is
   configured, offer an owned-space-first view with provider/customer edges from CAIDA drawn
   directionally rather than undirected

## Engine

1. **ASPA** — inert by design (verified: RTR v2 emits no ASPA objects globally); wire an
   operator-supplied ASPA object file (`BGPMON_ASPA_FILE`) and surface coverage honestly in `/api/rpki`
2. **ROA change detection** — the VRP set already carries the data; diff VRPs covering owned space
   between syncs to emit `RPKI_ROA_CHANGE` (add/remove/maxLength change)
3. **Peer-lock / RFC 9234** — `ROUTE_LEAK` currently infers from path shape only; OTC community
   (35:0) is present in RIS Live messages and should be a first-class signal
4. **Suppression memory** — `_leak_pairs` / `_path_incidents` are session-scoped; add TTL eviction
   so a long-lived leak re-alerts instead of being silenced forever after a restart
5. **Sink backpressure** — Neo4j lock contention was observed when two writers ran; single-writer
   is now guaranteed by design, but add a queue-depth alert to catch a slow sink

## Infra

1. **`docker compose build`** — the image is authored but never built; verify it and add
   `.dockerignore` so `config/db_config.json` and `data/` never enter a build context
2. **Configurable host port** — compose publishes `8080`; this host holds 8080 for a Windows
   service, so parameterise as `${BGPMON_API_PORT:-8080}`
3. **CI** — GitHub Actions running `pytest` + `npm run build` on PR; the repo has no CI today
4. **Grafana** — `/metrics` is exposed; ship a starter dashboard JSON alongside compose