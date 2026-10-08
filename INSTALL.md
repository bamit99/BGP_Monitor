# Installing and running BGP Monitor

Step-by-step for a first run. [README.md](README.md) has the architecture and
measured performance; [Logic.md](Logic.md) explains every alert kind.

- **Docker or Podman — [Route A](#route-a-docker-or-podman)** — the normal path, one command to deploy
- **Native Python — [Route B](#route-b-native-python)** — for development and for inspecting a detector without containers

Expect 5–10 minutes for Route A. The first RPKI sync is the slow part.

---

## What you need

| | Requirement | Notes |
|---|---|---|
| **Container runtime** | Docker 20.10+ or Podman 4+ | Docker and Podman both work with the same `docker-compose.yml` |
| **Disk** | ~5 GB | 3–4 GB is the Neo4j graph after a day of ingest, ~2 GB the RPKI cache |
| **Memory** | 4 GB free | Neo4j is configured for a 2 GB heap plus 1 GB page cache |
| **CPU** | 2 cores | Measured 90 µs per update on one core; the rest is I/O |
| **Network** | Outbound HTTPS and WSS | RIS Live over WSS, Routinator's RPKI sources over HTTPS |
| **Python** (Route B) | 3.11+ | 3.13 tested |
| **Node** (Route B, only to build the dashboard) | 20+ | 24 tested. Skipped if you use Route A — the image builds it for you |

No API key is needed. RIS Live, Routinator and CAIDA are all public.

---

## Before either route: get the CAIDA relationship file

`ROUTE_LEAK` detection is **RFC 7908 valley-free checking against CAIDA's AS
relationship graph**. That graph is a 1.6 MB download and it is **not in git**,
because it is site data rather than source.

Without it the service starts and looks healthy — every other detector works —
but `ROUTE_LEAK` never fires. The only symptom is one warning at startup:

```
WARNING bgpmon.detect: AS relationship file missing: data/as_relationships.txt.bz2
(route-leak detection degraded)
```

```bash
curl -o data/as_relationships.txt.bz2 \
  https://publicdata.caida.org/datasets/as-relationships/serial-1/20261001.as-rel.txt.bz2
```

Create `data/` first if it does not exist (`mkdir -p data`). The filename is
date-stamped and CAIDA publishes a new snapshot monthly; to refresh, browse
<https://publicdata.caida.org/datasets/as-relationships/serial-1/> and use the
newest `YYYYMMDD.as-rel.txt.bz2`. There is no `latest` alias — a 404 on a
hardcoded date just means a newer snapshot has landed.

Verify it landed — about 1.6 MB:

```bash
ls -la data/as_relationships.txt.bz2
```

On Windows PowerShell use `curl.exe` (PowerShell aliases `curl` to
`Invoke-WebRequest`, whose flags differ):

```powershell
curl.exe -o data\as_relationships.txt.bz2 https://publicdata.caida.org/datasets/as-relationships/serial-1/20261001.as-rel.txt.bz2
```

Route B does this for you; Route A does not, which is why this section is
before both routes.

---

## Route A: Docker or Podman

### A1. Configure

```bash
cp .env.example .env
```

Two values need your attention in `.env`:

| Variable | What to set |
|---|---|
| `NEO4J_PASSWORD` | Any password. Required — `docker compose` refuses to start without it. |
| `BGPMON_OWNED_PREFIXES` | The space your organisation originates. Empty is valid and means observe-only. |

`BGPMON_OWNED_PREFIXES` is the one setting worth thinking about before you start.
It is the baseline for `HIJACK_ORIGIN`, `HIJACK_SUB_PREFIX` and `VISIBILITY_LOSS` —
the CRITICAL detectors. Leave it empty and those three stay silent by design while
RPKI, leaks and bogons still work. See
[operational notes](README.md#operational-notes).

Leave `BGPMON_API_PORT=8080` unless 8080 is taken. It very often is on Windows —
`svchost` holds it. Check and pick a free port if so:

```bash
# Windows PowerShell
Get-NetTCPConnection -State Listen -LocalPort 8080
```

Then set `BGPMON_API_PORT=8090` (or any free port) in `.env`.

### A2. Validate before starting anything

```bash
docker compose config --quiet
```

Exit code 0 and no output means the compose file and your `.env` agree. This
catches a missing `NEO4J_PASSWORD` in one second instead of after a two-minute
build.

### A3. Build and start

```bash
docker compose up -d --build
```

The first build takes a few minutes: it compiles the React dashboard in a Node
stage, then installs Python dependencies in a `python:3.13-slim` runtime. Only
`requirements.txt` is installed there, so the dashboard build does not leak into
the runtime image.

Watch it come up:

```bash
docker compose logs -f monitor
```

A healthy start looks like this:

```
bgpmon.detect: Loaded 503327 AS relationships (80963 ASNs with known degree)
bgpmon.rpki: RPKI synced over RTR: 268009 indexed prefixes (289142 VRPs), 0 ASPA objects
bgpmon.sinks: Graph sink online at bolt://neo4j:7687
bgpmon.pipeline: Pipeline started: collectors=rrc00,rrc01,rrc11,rrc12
bgpmon.collector: Connected to RIS Live (4 collectors)
bgpmon.collector: Subscribed to rrc00 (acknowledged)
```

Press Ctrl-C to stop following. The container keeps running.

### A4. Verify it is actually working

Do not stop at "the container is up". Ask `/api/health`:

```bash
curl -s http://localhost:8090/api/health
```

Four fields prove the pipeline is live. Wait 30 s after start for the first sync.

| Field | Working looks like | If it does not |
|---|---|---|
| `rpki.indexed_prefixes` | `268009`, rising | `0` — RPKI has not synced; see [troubleshooting](#troubleshooting) |
| `rpki.failures` | `0` | Non-zero — Routinator is not serving RTR |
| `feed.updates` | Climbing into the hundreds of thousands | `0` — no RIS Live connection |
| `feed.dropped` | `0` | Non-zero — the queue is overflowing; see [troubleshooting](#troubleshooting) |
| `detection.as_relationships_loaded` | `500000`-ish | `0` — you skipped the CAIDA step; leaks are dead |

Then confirm the dashboard serves and that deep links work (a SPA served from a
catch-all route, so this is a real failure mode, not a formality):

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8090/         # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8090/alerts   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8090/topology # 200
```

Open the dashboard and confirm the Overview page populates.

### A5. Watch it over time

```bash
docker compose logs -f monitor        # feed and detector logs
docker compose ps                     # health status per service
curl -s http://localhost:8090/metrics # Prometheus exposition
```

`/metrics` is the monitoring surface if you want to graph it. Note that three
RPKI series (`bgpmon_rpki_vrp_prefixes`, `bgpmon_rpki_sync_age_seconds`,
`bgpmon_rpki_results_total`) are declared but currently carry no samples —
tracked in [ROADMAP.md](ROADMAP.md).

### A6. Stop and clean up

```bash
docker compose stop          # stop, keep data
docker compose down          # remove containers, keep volumes
docker compose down -v       # remove containers AND volumes — destroys the graph and the RPKI cache
```

`-v` is destructive and slow to undo: it discards your alert history and forces
a full RPKI re-sync. There is no reason to use it unless you are reclaiming disk.

---

## Route A on Windows with Podman

The compose file is unchanged. What differs is the CLI.

### Podman's CLI may not work out of the box

Podman's Windows client talks to the Linux VM over SSH and parses
`~/.ssh/known_hosts`. A single malformed line makes the whole file unreadable:

```
podman version
Error: unable to connect to Podman socket: knownhosts: C:\Users\you\.ssh\known_hosts:30:
knownhosts: missing key type pattern
```

The cause is a `known_hosts` entry with a key but no hostname — often a paste
that lost its first field. Find and delete it:

```powershell
# List entries with fewer than 3 fields; those are malformed
$l = Get-Content $HOME\.ssh\known_hosts
for ($i = 0; $i -lt $l.Count; $i++) {
  $f = ($l[$i] -split '\s+') | Where-Object { $_ -ne '' }
  if ($f.Count -lt 3) { "line $($i+1): $($l[$i])" }
}
```

Fixing that restores `podman`. The alternative is to skip Podman's CLI entirely
and use Docker's, which talks to the same VM over a named pipe and does not read
`known_hosts`:

```powershell
docker context ls        # expect podman-machine-default as the current context
docker info              # confirms which engine answers
```

Everything in Route A works unchanged with `docker` in place of `podman`.

### Container names may already be taken

If a previous run left containers behind on a different network, compose refuses
to create its own:

```
Error: container name "bgpmon-routinator" is already in use
```

Check what exists, then start what is already there rather than recreating it —
recreating throws away the RPKI cache volume, which costs a full re-sync:

```bash
docker ps -a --filter "name=bgpmon"
docker start bgpmon-neo4j bgpmon-routinator
docker compose up -d --no-deps monitor
```

`--no-deps` tells compose not to try to recreate the data services that are
already running. This is the normal shape of a restart on an existing install.

### Bind mounts

Compose bind-mounts `./data` and `./config` from the host into the container.
Podman on Windows mounts these through WSL. If a file you created is invisible
inside the container, check the path is inside the repository and not a symlink
pointing outside it.

---

## Route B: native Python

Use this to work on a detector, or to run without a container runtime. Neo4j and
Routinator still need to be somewhere — either containers or already running.

### B1. Virtualenv and dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-service.txt -r requirements.txt
```

`install_linux.sh` does this plus the CAIDA download in one step:

```bash
bash install_linux.sh
```

### B2. Routinator

```bash
docker run -d --name bgpmon-routinator \
  -p 127.0.0.1:3323:3323 \
  -v bgpmon-routinator-cache:/home/routinator/.rpki-cache \
  nlnetlabs/routinator
```

The named volume matters. Routinator downloads the global RPKI data set, which is
large and slow to fetch; with a volume it restores from cache in about 11 seconds
on every start after the first. Without one, every restart pays the full cost.

Port 3323 is RTR, which is what the monitor syncs over. 8323 is Routinator's HTTP
API, used for debugging.

### B3. Neo4j

```bash
docker run -d --name bgpmon-neo4j \
  -p 127.0.0.1:7474:7474 \
  -p 127.0.0.1:7687:7687 \
  -e NEO4J_AUTH=neo4j/yourpassword \
  -v bgpmon-neo4j-data:/data \
  neo4j:5.26-community
```

The password must match `BGPMON_NEO4J_PASSWORD` in your environment. If you
change it on an existing volume, Neo4j ignores the change and keeps the old
password — the setting only applies before the database is first started.

Set the password for a native run:

```bash
export BGPMON_NEO4J_PASSWORD=yourpassword
export BGPMON_NEO4J_URI=bolt://127.0.0.1:7687
```

### B4. Build the dashboard

The service serves the built SPA from `web/dist`. Without it the API works but
every dashboard route is a blank page, and a warning says so at startup.

```bash
cd web
npm ci
npm run build
cd ..
```

`npm ci` installs exactly what `package-lock.json` pins. `npm run lint` needs an
`eslint.config.js` that does not exist yet — see [ROADMAP.md](ROADMAP.md).

### B5. Run

```bash
python -m bgpmon
```

Or, to measure ingest without the API, which is the honest way to check a
deployment:

```bash
python -m bgpmon --soak 120
```

That runs headless for 120 s and prints a report: update rate, alert rate by
severity, mean detection latency, and graph writes. A useful working baseline is
3 000–4 000 updates/s, ~90 µs mean detection, and an alert rate well under 1%.

`python main.py` is equivalent to `python -m bgpmon`.

---

## Configuration reference

All secrets come from the environment — `.env` for compose, your shell for a
native run. `.env` is git-ignored; never commit it.

| Variable | Default | Purpose |
|---|---|---|
| `BGPMON_OWNED_PREFIXES` | *(empty)* | Your originated space. Drives hijack and visibility alerts. Empty = observe-only |
| `BGPMON_COLLECTORS` | `rrc00,rrc01,rrc11,rrc12,rrc24` | RRC ids only — `route-views.*` is rejected at config load as invalid for RIS Live |
| `BGPMON_NEO4J_ENABLED` | `true` | Graph sink on/off |
| `BGPMON_NEO4J_URI` | `bolt://127.0.0.1:7687` | Bolt endpoint |
| `BGPMON_NEO4J_USER` | `neo4j` | |
| `BGPMON_NEO4J_PASSWORD` | *(required)* | The one secret with no default |
| `BGPMON_RPKI_RTR_HOST` | `127.0.0.1` | Routinator RTR host |
| `BGPMON_RPKI_RTR_PORT` | `3323` | |
| `BGPMON_API_TOKEN` | *(empty)* | Bearer auth for the API and WebSocket. Empty = no auth |
| `BGPMON_API_HOST` | `127.0.0.1` | Compose sets `0.0.0.0` inside the container |
| `BGPMON_API_PORT` | `8080` | Host port under compose; in-process port natively |
| `BGPMON_VISIBILITY_GRACE` | `900` | Seconds before an unseen owned prefix is a `VISIBILITY_LOSS` |
| `BGPMON_INCIDENT_TTL` | `3600` | Seconds an incident signature suppresses a repeat |
| `BGPMON_LOG_LEVEL` | `INFO` | |
| `BGPMON_METRIC_PREFIX` | `bgpmon` | Prometheus metric name prefix |

`BGPMON_API_TOKEN` needs care: the server enforces it on every `/api/*` route and
on `/ws/alerts`, but **the bundled dashboard does not send it**. Set it only
behind a reverse proxy that terminates auth, or expect every panel to fail with
401.

Tuning lives in `DetectionSettings` in `bgpmon/config.py`. One caveat:
`visibility_min_expected_collectors` has **no** environment variable — changing
the multi-collector floor for `VISIBILITY_LOSS` needs a code edit.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `required variable NEO4J_PASSWORD is missing` | No `.env`, or the line is absent | `cp .env.example .env` and set it |
| `address already in use` on start | Host port taken — commonly `svchost` on 8080 | Set a free `BGPMON_API_PORT` in `.env` |
| `ModuleNotFoundError: No module named 'httpx'` | Image built before the `httpx` floor was added, or `requirements.txt` is stale | `docker compose build --no-cache monitor` |
| `container name "bgpmon-routinator" is already in use` | Leftover container on another network | See [Route A on Windows](#route-a-on-windows-with-podman) — start it, do not recreate it |
| `knownhosts: missing key type pattern` | Malformed `~/.ssh/known_hosts` | See [Route A on Windows](#route-a-on-windows-with-podman) |
| `rpki.indexed_prefixes` stays `0` | Routinator not serving RTR on 3323 | `docker logs bgpmon-routinator`; it must not be stuck downloading |
| RPKI sync takes minutes every restart | No volume on the Routinator cache | Mount `bgpmon-routinator-cache` (Route B2) |
| `AS relationship file missing` warning | Skipped the CAIDA step | See [before either route](#before-either-route-get-the-caida-relationship-file) |
| `ROUTE_LEAK` never fires | Same as above — every other detector still works, so it looks healthy | Same |
| `HIJACK_ORIGIN` never fires | `BGPMON_OWNED_PREFIXES` is empty, so there is no authorised-origin baseline | Set it. This is deliberate: a hijack detector with no authorised set is a false-positive machine |
| `VISIBILITY_LOSS` never fires | Same, plus the prefix needs to be absent past the grace period across ≥2 collectors | Set owned prefixes |
| `feed.dropped` climbing | Queue overflow — the detector is not keeping up with the feed | Check `queue_depth` in `/api/health`; sustained non-zero means the sink is slow |
| Dashboard 404s or a blank page | `web/dist` missing or stale | `cd web && npm ci && npm run build`, then rebuild the image |
| Every dashboard panel fails with 401 | `BGPMON_API_TOKEN` is set but the dashboard does not send it | Clear the token, or terminate auth at a proxy |
| `GET /api/anything` returns HTML instead of JSON | Known defect — the SPA catch-all shadows unknown API paths | See [ROADMAP.md](ROADMAP.md) |

---

## Where to go next

| Want | Read |
|---|---|
| What each alert means and why it has that severity | [Logic.md](Logic.md) |
| Performance numbers and architecture | [README.md](README.md) |
| What is not built yet | [ROADMAP.md](ROADMAP.md) |
| Verify your install | `python -m pytest tests/test_bgpmon.py -v` |

To make the tool useful for your own network rather than the whole Internet, set
`BGPMON_OWNED_PREFIXES` to the space you originate. That single change turns on
the two CRITICAL detectors that matter most to you.