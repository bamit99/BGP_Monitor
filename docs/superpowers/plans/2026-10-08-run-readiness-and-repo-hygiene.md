# BGP Monitor Run-Readiness and Repo Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get BGP Monitor running on this host from the containers that already exist in Podman, and make the tracked documentation match what the code actually does.

**Architecture:** Two independent halves. (A) Run-readiness: fix three defects that block a clean start (missing `httpx` dependency, broken `VISIBILITY_LOSS` detector, missing `requirements-service.txt`), then bring up Neo4j + Routinator + monitor and verify `/api/health` and a live alert. (B) Doc hygiene: correct the claims in `README.md` / `ROADMAP.md` that no longer match the tree, and reconcile the untracked "scope lookup" feature that is half-committed.

**Tech Stack:** Python 3.13 (FastAPI, websockets, neo4j driver, prometheus-client), React 19 + Vite 6 + Tailwind v4, Neo4j 5.26, Routinator, Podman 6.0.2 (WSL backend), `pytest`.

**Spec:** This document. There is no separate design doc; the findings in "Verified Findings" below are the evidence base and were reproduced on this host.

## Verified Findings

Everything below was reproduced on this host, not inferred from reading alone.

### Environment

| Fact | Value |
|---|---|
| Podman CLI on Windows | **Broken.** `podman version` fails: `knownhosts: C:\Users\amitb\.ssh\known_hosts:30: knownhosts: missing key type pattern`. Line 30 of that file has only 2 fields (` ssh-ed25519 AAAA...`) — a key entry with no hostname. Go's knownhosts parser rejects the whole file. |
| Docker CLI | Works, and is wired to the Podman machine: `docker context ls` → `podman-machine-default`, endpoint `npipe:////./pipe/podman-machine-default`. `docker info` → `Razor \| fedora \| 6.0.2`. |
| Podman machine | `podman-machine-default`, WSL backend, running, 8 CPU, 2 GiB configured memory, 100 GiB disk. WSL reports 16 GiB total / 15 GiB free, so the 2 GiB figure is not enforced. |
| Existing containers | `bgpmon-neo4j` (Exited 137, 43 h ago), `bgpmon-routinator` (Exited 143, 43 h ago). **No `bgpmon-monitor` container exists.** |
| Existing images | `bgp_monitor-monitor:latest` (186 MB) is built. `neo4j:5.26-community`, `nlnetlabs/routinator:latest`, `python:3.13-slim`, `node:22-alpine` all present. |
| Neo4j data | Volume `bgp_monitor_neo4j-data` holds 3.7 GB with `databases/neo4j` and `databases/system`. Existing graph history is preserved. Password is `testpass123` (from container env `NEO4J_AUTH`). |
| Routinator cache | Volume `bgpmon_routinator_tal` holds 2.9 GB of `repository/{rrdp,rsync,stored}`. A full re-sync is not needed; the RPKI set will rebuild from this cache in ~11 s. |
| Host port 8080 | **Occupied by `svchost` (PID 3956)**, listening on `0.0.0.0:8080`. Compose's `${BGPMON_API_PORT:-8080}` default will fail to bind. 8088/8090/8099 are free. |
| `docker compose config` | Fails: `required variable NEO4J_PASSWORD is missing`. No `.env` file exists in the repo. |
| Bind mounts | Work. Verified `docker run -v E:\Git\BGP_Monitor\data:/app/data:ro` lists the CAIDA file. |
| `python -m pytest` | 30 passed, 1 skipped. 31 test functions in 13 classes. |
| `npm run build` | Succeeds. 767 kB single JS chunk (224 kB gzip). |
| `npm run lint` | **Fails:** `ESLint couldn't find an eslint.config.(js|mjs|cjs) file`. |

### Defects

| # | Severity | Defect | Evidence |
|---|---|---|---|
| D1 | **High** | `httpx` missing from `requirements.txt`. `bgpmon/scope.py:16` imports it at module scope; `bgpmon/api.py:22` imports `scope` at module scope; `__main__.run_api()` builds the app. Confirmed in the built image: `docker run --entrypoint sh bgp_monitor-monitor:latest -c "python -c 'import httpx'"` → `ModuleNotFoundError`. Only `fastapi[standard]` pulls httpx, and requirements uses bare `fastapi`. The host has httpx 0.28.1 only because conda installed it for unrelated tools, which masks this locally. | reproduced |
| D2 | **High** | `VISIBILITY_LOSS` can never fire. `PrefixState` is `@dataclass(slots=True)` (`detect.py:221`) but `detect.py:576` assigns `st._loss_reported`. Reproduced: `AttributeError: 'PrefixState' object has no attribute '_loss_reported' and no __dict__ for setting new attributes`. `pipeline.py:216` swallows it into a log line. Documented as a working CRITICAL detector in `README.md:50` and `Logic.md:90`. No test covers it. `detect.py:576` carries `# type: ignore[attr-defined]`, which suppressed the linter that would have caught it. | reproduced |
| D3 | **High** | `requirements-service.txt` does not exist but is referenced by `README.md:70` and `install_linux.sh:9`. Both non-Docker install paths fail on the pip line. | reproduced |
| D4 | Medium | Dashboard cannot authenticate. `web/src/lib/api.ts:5` sends no `Authorization` header; `useAlertStream.ts:28` opens `/ws/alerts` with no `?token=`. Server requires both (`api.py:86`, `api.py:186`). Setting the documented `BGPMON_API_TOKEN` breaks every view. | read |
| D5 | Medium | SPA catch-all masks unknown API paths. `api.py:44` is a `GET /{full_path:path}`. `GET /api/nonexistent` returns 200 + `index.html`, not 404 JSON. Reproduced. | reproduced |
| D6 | Medium | MEDIUM/LOW alerts never reach Neo4j. `pipeline.py:159` only calls `sink.submit_alert` for HIGH/CRITICAL, so `/api/alerts?source=graph` can never return them, and the `TRIGGERED_BY` story in `README.md:19` holds only for HIGH/CRITICAL. | read |
| D7 | Medium | `owned_only` is ignored on the graph path. `api.py:104-109` returns graph rows without filtering; only the memory fallback at `api.py:110` passes it. | read |
| D8 | Medium | `gate.py:60`: `moas_key = (alert.prefix, alert.origin_as or 0, alert.kind.value and 0 or 0)` — the third element is always `0`. `HIJACK_ORIGIN` and `NEW_PREFIX` for the same (prefix, origin) share one pending-corroboration set. The expression is also nonsense: a non-empty string is truthy, so it always yields `0`. | read |
| D9 | Medium | `telemetry.py:107` annotates `Optional[float]` but line 9 imports only `Dict`. Masked by `from __future__ import annotations`. `typing.get_type_hints(PipelineMetrics.gauge_rpki)` → `NameError`. Both `gauge_rpki` and `record_rpki` are never called, so three declared Prometheus series (`bgpmon_rpki_vrp_prefixes`, `bgpmon_rpki_sync_age_seconds`, `bgpmon_rpki_results_total`) never appear in `/metrics`. | reproduced |
| D10 | Medium | `docker-compose.yml:70` mounts `./config:/app/config:ro` over the `config/security_config.json` baked in at `Dockerfile:25`. A host `config/` without that file silently yields `{}` at `config.py:159`, dropping all 7 `critical_prefixes`. | read |
| D11 | Medium | `ScopeLookup._cache` (`scope.py:44`) is unbounded with no TTL. Also no politeness delay, unlike `RPkiEngine` (`rpki.py:385`): an uncached name search fans out to up to 5 PeeringDB lookups plus a RIPEstat `_asn_name` call each. | read |
| D12 | Low | Three declared alert kinds are never emitted but still render as selectable filter chips: `RPKI_ASPAS`, `MOAS_NEW_ORIGIN`, `RPKI_ROA_CHANGE` (`models.py:43`, `web/src/lib/format.ts:20-28`). | read |
| D13 | Low | `Pipeline._visibility_thread` is assigned in `start()` (`pipeline.py:74`) but never initialised in `__init__` (`pipeline.py:38-58`), unlike `_worker` and `_loop_thread` which are. Any `stop()` path or test that touches it before `start()` raises `AttributeError`. | read |
| D14 | Low | The SIGINT handler at `__main__.py:79` is dead in the API path. Uvicorn's `Server.capture_signals` replaces it with `handle_exit`, which drives a graceful shutdown that runs the FastAPI lifespan teardown — and `pipeline.stop()` at `api.py:69` already calls `sink.stop(drain=True)`. In `--soak` mode `sys.exit(0)` raises `SystemExit`, which propagates through `run_soak`'s `finally: pipeline.stop()` (`__main__.py:55-56`). Draining works in both paths; the handler is simply misleading. **Verified, not assumed** — see Task 12. | verified |

### Documentation drift (README.md for GitHub)

| Claim | Reality |
|---|---|
| `README.md:70` pip line cites `requirements-service.txt` | file does not exist (D3) |
| `README.md:108` "25 passing" | 31 tests, 30 pass + 1 skip |
| `README.md:92` "shadcn/ui conventions" | no `web/src/components/`, no `web/src/lib/utils.ts`, no shadcn components. `web/components.json` aliases point at three paths that do not exist |
| `README.md:97` lists 4 dashboard views | 5 — `Scope` exists (untracked) |
| `README.md:10` benchmarks 4 collectors | `config.py:101` defaults to 5 (`rrc24` included); `.env.example` and compose set 4 |
| Quick start `docker compose up -d --build` | fails without `.env`; 8080 is taken on this host |
| — | `CONTRIBUTING.md:7` says branch from `main`; the default branch is `master` |
| — | `CONTRIBUTING.md:37` and `GOVERNANCE.md:32` link `./CODE_OF_CONDUCT.md`, which does not exist |
| `ROADMAP.md:54-56` "Deep links" listed as outstanding | shipped in `api.py:27-54`, tested at `tests/test_bgpmon.py:144` |
| `ROADMAP.md:100-101` `.dockerignore` listed as outstanding | file exists |
| `ROADMAP.md:102-103` configurable host port listed as outstanding | done at `docker-compose.yml:51` |
| `ROADMAP.md:74-75` TTL eviction listed as outstanding | done at `detect.py:328`, tested at `tests/test_bgpmon.py:201` |
| `ROADMAP.md:23-27` headlines `bgpmon scope --asn … --check --irr` | no subparsers exist (`__main__.py:69-73`). Untracked `scope.py` is a different thing: a read-only dashboard lookup with no file output, no `--check`, no RADb |
| `ROADMAP.md:33` tells operators to tune `BGPMON_VISIBILITY_GRACE` / `_MIN_COLLECTORS` | only `_GRACE` is wired (`config.py:177`); `visibility_min_expected_collectors` (`config.py:151`) has no env var |
| `README.md:88` documents `BGPMON_API_TOKEN` | setting it breaks the dashboard (D4) |

## Global Constraints

- No new runtime dependencies beyond adding `httpx` to `requirements.txt` with a floor consistent with the file's existing style (`>=x.y,<z`).
- Do not change detection semantics, alert severities, or thresholds. `DetectionSettings` (`bgpmon/config.py`) values are the tuned baseline.
- Every doc change must be checkable against the tree — no claim added to `README.md` that a grep cannot confirm.
- Do not delete the Neo4j volume `bgp_monitor_neo4j-data` (3.7 GB of existing history) or the Routinator volume `bgpmon_routinator_tal` (2.9 GB cache). Both are unreproducible in reasonable time.
- Windows-specific findings belong in `README.md` as a short subsection, not woven into the generic Linux quick start.
- Secrets: `NEO4J_PASSWORD` goes in `.env` only. Never commit it. The known password `testpass123` is a local dev credential and must not be written into a tracked file.

## Review Focus

The failure modes a person running this on their own host will hit, most likely first. Each line gets a test in the task that owns the code.

1. **A fresh clone on Windows**: `docker compose up -d --build` fails on the missing `NEO4J_PASSWORD` with an error that does not name the file to create. Expect a one-line "copy .env.example to .env" hint.
2. **Host port 8080 already in use** (very common on Windows — `svchost` holds it here): compose fails to bind with a bare "address already in use". Expect the error to name `BGPMON_API_PORT` and print the port actually in use.
3. **`GET /api/nonexistent` returns HTML 200 instead of JSON 404**: a frontend dev debugging a 404 gets `index.html` and never learns the route is missing. Expect 404 with a JSON body.
4. **Dashboard against a token-protected API**: every panel shows an error and the WebSocket closes 4401, with no hint that a token is the cause. Expect a clear message naming `BGPMON_API_TOKEN`.
5. **MEDIUM/LOW alert visible live but missing after a restart**: the alert stream shows it, then `/api/alerts` (graph source) loses it. Expect MEDIUM/LOW persisted like HIGH/CRITICAL.

---

## HIGH PRIORITY

### Task 1: Add the missing `httpx` dependency and the missing requirements file

Fixes D1, D3 — the two defects that break every documented install path.

**Files:**
- Modify: `requirements.txt` (add one line)
- Create: `requirements-service.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: `requirements-service.txt` as the optional-extras file that `README.md:70` and `install_linux.sh:9` already cite.

- [ ] **Step 1: Confirm both install paths are broken before changing anything**

Run:
```bash
python -m pip install --dry-run -r requirements-service.txt
```
Expected: FAIL — `ERROR: Could not open requirements file: [Errno 2] No such file or directory: 'requirements-service.txt'`

- [ ] **Step 2: Create `requirements-service.txt`**

Exact content:
```
# Optional extras for the BGP Monitor service (API, monitoring, dashboard).
# Installed alongside requirements.txt, which carries the hard runtime floors.
# These are feature-complete but non-essential; the ingest path runs without them.

fastapi[standard]>=0.115,<1     # includes httpx, required by bgpmon/scope.py
uvicorn[standard]>=0.30,<1
neo4j>=5.28,<7
prometheus-client>=0.20,<1
```

Rationale for the `[standard]` extra rather than a bare `httpx` line: `fastapi[standard]` is the supported way to get `httpx`, and it keeps the two files from drifting on the FastAPI floor.

- [ ] **Step 3: Add the hard `httpx` floor to `requirements.txt`**

Add to the `uvicorn[standard]` block in `requirements.txt`, immediately after the `prometheus-client` line:

```
httpx>=0.27,<1             # required by bgpmon/scope.py at module scope
```

This is the load-bearing fix. `requirements.txt` is what the Dockerfile installs (`Dockerfile:22`), and `bgpmon/api.py:22` imports `scope` at module scope, so a missing `httpx` means the container cannot start at all.

- [ ] **Step 4: Verify the fix against a clean environment, not the host**

Run:
```bash
python -m pip install --dry-run -r requirements.txt 2>&1 | Select-String "httpx"
```
Expected: a resolved `httpx` line.

Also confirm the module graph closes:
```bash
python -c "import bgpmon.api, httpx; print('ok', httpx.__version__)"
```
Expected: `ok 0.28.1` (or whatever resolves)

- [ ] **Step 5: Commit**

```bash
git add requirements.txt requirements-service.txt
git commit -m "Add the missing httpx floor and the requirements-service.txt the install docs cite"
```

---

### Task 2: Fix the dead `VISIBILITY_LOSS` detector

Fixes D2. A documented CRITICAL detector that raises `AttributeError` on every invocation.

**Files:**
- Modify: `bgpmon/detect.py:221-246` (add the slot), `bgpmon/detect.py:560-563` (simplify the guard), `bgpmon/detect.py:576` (drop the `type: ignore`)
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `DetectionSettings.visibility_loss_grace_s` and `visibility_min_expected_collectors` (`bgpmon/config.py:150-151`).
- Produces: `PrefixState.loss_reported: Optional[datetime]` — a real field, readable and writable.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_bgpmon.py`:

```python
class TestVisibilityLoss(unittest.TestCase):
    """A documented CRITICAL detector that raises AttributeError is not a detector."""

    def test_visibility_loss_fires_after_grace(self):
        settings = DetectionSettings(
            owned_prefixes={"203.0.113.0/24": set()},
            visibility_loss_grace_s=900,
            visibility_min_expected_collectors=2,
        )
        engine = DetectionEngine(settings, rpki=None, as_graph=ASGraph())
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for collector in ("rrc00", "rrc01"):
            engine.evaluate(make_update(prefix="203.0.113.0/24", collector=collector,
                                        as_path="64496 203.0.113.0", timestamp=base))

        # Still inside the grace period.
        self.assertEqual(engine.check_visibility(base + timedelta(seconds=600)), [])

        past = base + timedelta(seconds=1000)
        alerts = engine.check_visibility(past)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].kind, Kind.VISIBILITY_LOSS)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_visibility_loss_reports_once_per_gap(self):
        settings = DetectionSettings(
            owned_prefixes={"203.0.113.0/24": set()},
            visibility_loss_grace_s=900,
            visibility_min_expected_collectors=2,
        )
        engine = DetectionEngine(settings, rpki=None, as_graph=ASGraph())
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for collector in ("rrc00", "rrc01"):
            engine.evaluate(make_update(prefix="203.0.113.0/24", collector=collector,
                                        as_path="64496 203.0.113.0", timestamp=base))
        past = base + timedelta(seconds=1000)
        self.assertEqual(len(engine.check_visibility(past)), 1)
        self.assertEqual(engine.check_visibility(past + timedelta(seconds=10)), [])
        # A fresh sighting re-arms the detector.
        for collector in ("rrc00", "rrc01"):
            engine.evaluate(make_update(prefix="203.0.113.0/24", collector=collector,
                                        as_path="64496 203.0.113.0", timestamp=past))
        self.assertEqual(len(engine.check_visibility(past + timedelta(seconds=1100))), 1)
```

Add to the import block at the top of `tests/test_bgpmon.py`, matching whatever the file already imports from `bgpmon.detect`, `bgpmon.models`, and `datetime`: `PrefixState` is not needed; `DetectionSettings`, `DetectionEngine`, `ASGraph`, `Kind`, `Severity`, `datetime`, `timedelta`, and `timezone` are. `make_update` already accepts `prefix`, `collector`, `as_path`, and `timestamp` (see `tests/test_bgpmon.py:29`).

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestVisibilityLoss -v
```
Expected: FAIL with `AttributeError: 'PrefixState' object has no attribute '_loss_reported' and no __dict__ for setting new attributes`

- [ ] **Step 3: Declare the field**

In `bgpmon/detect.py`, add one line to `PrefixState` after `announced_since_loss` (line 233):

```python
    announced_since_loss: Optional[datetime] = None
    loss_reported: Optional[datetime] = None
```

- [ ] **Step 4: Rewrite the guard and drop the suppression**

Replace `bgpmon/detect.py:560-563`:

```python
            if st.announced_since_loss is not None and st.announced_since_loss == st.last_seen:
                # already reported for this gap
                if getattr(st, "_loss_reported", None) == st.last_seen:
                    continue
```

with:

```python
            # One alert per gap: re-arm only when the prefix is seen again.
            if st.loss_reported == st.last_seen:
                continue
```

and replace `bgpmon/detect.py:576`:

```python
            st._loss_reported = st.last_seen  # type: ignore[attr-defined]
```

with:

```python
            st.loss_reported = st.last_seen
```

The `# type: ignore[attr-defined]` is removed deliberately: it is what let this reach `master` with no failing test.

- [ ] **Step 5: Run the test to verify it passes**

Run:
```bash
python -m pytest tests/test_bgpmon.py -v
```
Expected: 32 passed, 1 skipped.

- [ ] **Step 6: Confirm the whole detector suite still passes and the file has no unused imports**

Run:
```bash
python -m pytest tests/test_bgpmon.py -q
```
Expected: 32 passed, 1 skipped, 0 failed.

- [ ] **Step 7: Commit**

```bash
git add bgpmon/detect.py tests/test_bgpmon.py
git commit -m "Fix VISIBILITY_LOSS raising AttributeError on a slotted PrefixState"
```

---

### Task 3: Bring the stack up on this host and verify it end to end

The containers exist and hold 3.7 GB of graph and 2.9 GB of RPKI cache. This task starts them without rebuilding data, then proves the detector path works.

**Files:**
- Create: `.env` (git-ignored — never commit)
- Modify: none required if the optional-extras approach in Task 1 holds

**Interfaces:**
- Consumes: `docker-compose.yml`, `bgp_monitor-monitor:latest`, volumes `bgp_monitor_neo4j-data` and `bgpmon_routinator_tal`.
- Produces: a running stack with the dashboard on `http://localhost:8090`.

- [ ] **Step 1: Create `.env` with a free host port**

`8080` is held by `svchost` (PID 3956) on this host, so the compose default will not bind. Write `.env` with `BGPMON_API_PORT=8090`:

```
NEO4J_PASSWORD=testpass123
BGPMON_API_PORT=8090
BGPMON_API_TOKEN=
BGPMON_OWNED_PREFIXES=
BGPMON_COLLECTORS=rrc00,rrc01,rrc11,rrc12
BGPMON_LOG_LEVEL=INFO
```

`NEO4J_PASSWORD` must match the value the existing Neo4j volume was initialised with (`NEO4J_AUTH=neo4j/testpass123`), otherwise the 3.7 GB store will refuse to open.

- [ ] **Step 2: Verify compose resolves before starting anything**

Run:
```bash
docker compose config --quiet
```
Expected: exit 0, no output. (Currently exits 1 on the missing `NEO4J_PASSWORD` — that is the check.)

- [ ] **Step 3: Start the two data services first**

Run:
```bash
docker compose up -d neo4j routinator
```
Expected: `bgpmon-neo4j` and `bgpmon-routinator` reach `Up`. Neo4j takes ~10 s; Routinator restores 2.9 GB of cache.

Then wait for the healthcheck:
```bash
docker compose ps
```
Expected: `bgpmon-neo4j` and `bgpmon-routinator` show `healthy` (or at least `Up` for Routinator, whose healthcheck always exits 0).

- [ ] **Step 4: Start the monitor and watch for the import-time failure**

Run:
```bash
docker compose up -d monitor
docker compose logs -f monitor --tail 40
```
Expected: FastAPI starts on 0.0.0.0:8080 inside the container. **If Task 1 was skipped, this is where it fails** with `ModuleNotFoundError: No module named 'httpx'`.

Press Ctrl-C to stop following once `Uvicorn running on http://0.0.0.0:8080` appears.

- [ ] **Step 5: Verify the API answers from the host**

Run:
```bash
curl.exe -s http://localhost:8090/api/health
```
Expected: JSON containing `"queue_depth"` and `"rpki"`. Confirm `rpki.vrp_count` climbs above zero within ~30 s — that is the Routinator cache restoring over RTR.

- [ ] **Step 6: Verify ingest and detection are actually live**

Run:
```bash
curl.exe -s "http://localhost:8090/api/health" | Select-String "updates|queue"
```
Expected: a rising `updates` counter within ~60 s. RIS Live delivers continuously on the subscribed RRCs.

- [ ] **Step 7: Verify the dashboard is served and its deep links resolve**

Run:
```bash
curl.exe -s -o NUL -w "%{http_code}" http://localhost:8090/alerts
curl.exe -s -o NUL -w "%{http_code}" http://localhost:8090/topology
curl.exe -s -o NUL -w "%{http_code}" http://localhost:8090/assets/ -w "%{http_code}"
```
Expected: `200`, `200`, and the assets path answering. Then open `http://localhost:8090` in a browser and confirm the Overview page populates.

If `web/dist` inside the image predates the untracked `Scope` view, the container serves the 4-view build. That is expected until the image is rebuilt; note it, do not chase it.

- [ ] **Step 8: Confirm the visibility loop no longer logs the old error**

Run:
```bash
docker compose logs monitor | Select-String "Visibility check failed"
```
Expected: no output. With Task 2 applied this is silent; without Task 2 it would repeat `AttributeError` every 60 s.

- [ ] **Step 9: Commit nothing**

This task produces `.env`, which is git-ignored. Verify:
```bash
git status --short
```
Expected: `.env` does not appear. Commit only if Task 4 changed a tracked file.

---

### Task 4: Correct README.md and ROADMAP.md against the tree

The GitHub-facing docs currently assert things that are false. This is the task the user asked for by name.

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: `requirements-service.txt` (Task 1), the 31-test suite, `web/src/views/Scope.tsx`.
- Produces: docs where every claim is grep-checkable.

- [ ] **Step 1: Fix the broken pip line and the test count in README.md**

Replace `README.md:69-74`:

````markdown
Without Docker:

```bash
pip install -r requirements-service.txt -r requirements.txt
docker run -d --name routinator -p 3323:3323 -p 8323:8323 nlnetlabs/routinator
python -m bgpmon              # API + monitoring
python -m bgpmon --soak 120   # headless throughput test
```
````

(`requirements-service.txt` now exists — Task 1.)

Replace `README.md:105-109`:

````markdown
## Tests

```bash
python -m pytest tests/test_bgpmon.py -v
```

31 tests, 30 passing and 1 skipped (the skipped test needs a live RTR server).
````

- [ ] **Step 2: Add a Windows/Podman subsection to the quick start**

Insert after the `docker compose up -d --build` block at `README.md:61-65`:

````markdown
### On Windows with Podman

Podman's CLI needs a working `~/.ssh/known_hosts`. If `podman version` reports
`knownhosts: missing key type pattern`, one line in that file is malformed —
delete it. The Docker CLI works regardless and can drive the same machine:

```bash
docker context ls                       # expect podman-machine-default
docker compose config --quiet           # fails until .env exists
docker compose up -d
```

If the host port is taken (`8080` commonly is, via `svchost`), set
`BGPMON_API_PORT` in `.env` to a free port — `8090` is usually clear.
````

- [ ] **Step 3: Correct the dashboard section**

Replace `README.md:90-98`:

````markdown
## Dashboard

React 19 + Vite + Tailwind v4 + Recharts, served by FastAPI from `web/dist`
so deployment is one service. Components are hand-rolled against Tailwind
design tokens; `web/components.json` is present for future shadcn/ui use but
no shadcn components are installed yet.

- **Overview** — ingest rate, alert mix, RPKI set health, latency, queue depth, sparklines
- **Alerts** — virtualised table, severity/category/text filters, sortable
- **Topology** — observed AS adjacency (deterministic layout, not a drifting physics sim)
- **Scope** — ASN/telecom lookup: announced prefixes with live RPKI state
- **RPKI** — on-demand validation against the local VRP set, honest about `NOT_FOUND`
````

- [ ] **Step 4: Fix the API-token claim**

Replace `README.md:88`:

```markdown
| `BGPMON_API_TOKEN` | optional bearer auth for API and WebSocket (see caveat below) |
```

and append to the Operational notes section:

````markdown
- **`BGPMON_API_TOKEN` is API-only today.** The server enforces it on every
  `/api/*` route and on `/ws/alerts`, but the bundled dashboard does not send
  it — the fetch layer omits the `Authorization` header and the WebSocket
  omits `?token=`. Set it only when a reverse proxy terminates auth in front
  of the dashboard, or expect every panel to fail with 401.
````

This documents the D4 limitation honestly instead of implying the token works
end to end. Fixing it is Task 6 (Medium).

- [ ] **Step 5: Add a collector-default note**

Append to the Configuration table area, after `README.md:88`:

```markdown
`BGPMON_COLLECTORS` defaults to five RRCs including `rrc24`
(`bgpmon/config.py:101`); `.env.example` and `docker-compose.yml` set four.
The benchmark above was measured on four.
```

- [ ] **Step 6: Retire the shipped ROADMAP items**

In `ROADMAP.md`, delete these four entries and renumber what remains:

- Console item 1 "Deep links" — shipped at `api.py:27-54`, tested at `tests/test_bgpmon.py:144`
- Infra item 1 "`docker compose build`" — the image builds; `.dockerignore` exists
- Infra item 2 "Configurable host port" — done at `docker-compose.yml:51`
- Engine item 4 "Suppression memory — TTL eviction" — done at `detect.py:328`, tested at `tests/test_bgpmon.py:201`

Replace Infra item 1 with the residual, which is real:

```markdown
1. **`docker compose build` on a clean checkout** — `.dockerignore` now excludes
   `data/` and `config/db_config.json`; verify a from-scratch build still finds
   `config/security_config.json`, which `docker-compose.yml:70` shadows with a
   host bind mount
```

- [ ] **Step 7: Correct the `bgpmon scope` entry to match reality**

Replace `ROADMAP.md:23-27`. The current text describes an importer that does not
exist. What exists is a read-only lookup (`bgpmon/scope.py`, untracked,
wired to `GET /api/scope/search` and the `Scope` view):

```markdown
1. **Scope importer — not started.** `bgpmon/scope.py` currently answers one
   question: "which prefixes does this ASN announce, and what is their RPKI
   state?" It writes nothing, so it cannot configure a baseline.
   - `python -m bgpmon scope --asn AS8220 --asn AS10021` → write
     `config/owned_prefixes.json` (prefix → authorised origins). No manual
     list-typing; no address space shared in chat
   - `python -m bgpmon scope --check` → re-query and diff, exit non-zero on drift
   - Optional `--irr` to also pull `route:`/`route6:` from RADb as a second source
   - `DetectionSettings.from_env` must then learn to read `owned_prefixes.json`;
     it currently reads only `BGPMON_OWNED_PREFIXES` and `config/security_config.json`
   - **Naming hazard**: the lookup module already owns the name `scope`. Rename
     it (`scope_lookup.py`) or name the importer `scope_import.py` before both exist.
```

- [ ] **Step 8: Fix the visibility-tuning env var claim**

Replace `ROADMAP.md:31-33`:

```markdown
3. **Visibility tuning for a large cone** — AS8220 announces many prefixes; start at
   15 min grace across ≥2 collectors, then measure observed per-prefix collector counts
   and tune `BGPMON_VISIBILITY_GRACE` from data. `visibility_min_expected_collectors`
   has **no** env var today (`bgpmon/config.py:151`) — changing it needs a code edit,
   so wire `BGPMON_VISIBILITY_MIN_COLLECTORS` first.
```

- [ ] **Step 9: Record the newly-found defects in the ROADMAP**

Add a new section after "Engine" in `ROADMAP.md`:

```markdown
## Found while bringing the stack up (2026-10-08)

Reproduced on this host, not inferred. Severity reflects NOC impact.

| # | Severity | Defect | Where |
|---|---|---|---|
| 1 | Medium | Dashboard sends no `Authorization` header and no `?token=`, so `BGPMON_API_TOKEN` breaks every view | `web/src/lib/api.ts:5`, `web/src/lib/useAlertStream.ts:28` |
| 2 | Medium | `GET /api/<unknown>` returns 200 + `index.html` instead of a JSON 404 — the SPA catch-all swallows it | `bgpmon/api.py:44` |
| 3 | Medium | MEDIUM/LOW alerts are never written to Neo4j, so they vanish on restart and `/api/alerts?source=graph` never returns them | `bgpmon/pipeline.py:159` |
| 4 | Medium | `owned_only` is ignored on the graph path of `/api/alerts` | `bgpmon/api.py:104-109` |
| 5 | Medium | MOAS corroboration key's third element is always `0`, so `HIJACK_ORIGIN` and `NEW_PREFIX` share a pending set | `bgpmon/gate.py:60` |
| 6 | Medium | `telemetry.py` annotates `Optional` without importing it; `gauge_rpki`/`record_rpki` are never called, so three Prometheus series never appear in `/metrics` | `bgpmon/telemetry.py:9,107,114` |
| 7 | Medium | compose bind-mounts `./config` over the baked-in `security_config.json`; a missing host file silently drops all 7 critical prefixes | `docker-compose.yml:70`, `Dockerfile:25` |
| 8 | Medium | `ScopeLookup` cache is unbounded and has no RIPEstat politeness delay — up to 10 upstream requests per uncached query | `bgpmon/scope.py:44` |
| 9 | Low | `RPKI_ASPAS`, `MOAS_NEW_ORIGIN`, `RPKI_ROA_CHANGE` are declared and shown as filter chips but never emitted | `bgpmon/models.py:43`, `web/src/lib/format.ts:20-28` |
| 10 | Low | `Pipeline._visibility_thread` is assigned in `start()` but never initialised in `__init__`, unlike its siblings | `bgpmon/pipeline.py:74` |
| 11 | Low | The SIGINT handler at `__main__.py:79` is dead in the API path — uvicorn replaces it and the lifespan teardown already drains the sink. Harmless, but it reads as if it owns shutdown | `bgpmon/__main__.py:79` |
| 12 | Low | `npm run lint` cannot run — ESLint 9 requires `eslint.config.js`, which does not exist. This blocks the CI item below | `web/package.json:10` |
| 13 | Low | `web/tsconfig.tsbuildinfo` is untracked and not git-ignored; it will be committed by accident | `.gitignore` |
```

Also update Infra item 3 (CI) to note the lint dependency:

```markdown
3. **CI** — GitHub Actions running `pytest` + `npm run build` on PR; the repo has no CI
   today. Add `eslint.config.js` first or drop `npm run lint` from the workflow — it
   cannot pass as written.
```

- [ ] **Step 10: Fix CONTRIBUTING.md**

Replace `CONTRIBUTING.md:7`:

```markdown
1. **Fork the repository** and create your branch from `master` (the default branch).
```

Replace `CONTRIBUTING.md:34-37` — the CoC link points at a file that does not exist:

```markdown
## Code of Conduct

Be respectful and inclusive in all project communications.

## License

By contributing, you agree that your contributions will be licensed under the
project's open source license.
```

And remove the equivalent dangling link from `GOVERNANCE.md:30-32`:

```markdown
## Code of Conduct

All participants are expected to be respectful and inclusive. There is no
separate code of conduct document in this repository yet; the expectation in
`CONTRIBUTING.md` applies.
```

- [ ] **Step 11: Verify every doc claim is now checkable**

Run each of these and confirm the output matches the claim:

```bash
Select-String -Path requirements.txt -Pattern httpx
Test-Path requirements-service.txt
python -m pytest tests/test_bgpmon.py -q
Get-ChildItem web/src/views
Test-Path CODE_OF_CONDUCT.md
Select-String -Path ROADMAP.md -Pattern "Deep links|requirements-service"
```

Expected: `httpx` found in requirements; `requirements-service.txt` exists;
`32 passed, 1 skipped`; five view files; `CODE_OF_CONDUCT.md` returns `False`;
and the ROADMAP grep returns nothing.

- [ ] **Step 12: Commit**

```bash
git add README.md ROADMAP.md CONTRIBUTING.md GOVERNANCE.md
git commit -m "Correct README and ROADMAP against the tree; record reproduced defects"
```

---

## MEDIUM PRIORITY

### Task 5: Add the eslint config so linting and CI can run

**Files:**
- Create: `web/eslint.config.js`
- Test: n/a — the lint run is the test.

**Interfaces:**
- Consumes: `eslint@9`, `typescript-eslint` (needs installing).
- Produces: a working `npm run lint`.

- [ ] **Step 1: Confirm it fails**

Run: `npm run lint`
Expected: `ESLint couldn't find an eslint.config.(js|mjs|cjs) file.`

- [ ] **Step 2: Install the TypeScript plugin**

Run: `npm install -D typescript-eslint@^8 eslint-plugin-react-hooks@^5`
Expected: exit 0, `package.json` and `package-lock.json` updated.

- [ ] **Step 3: Create `web/eslint.config.js`**

```javascript
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
);
```

- [ ] **Step 4: Run it**

Run: `npm run lint`
Expected: passes, or reports only real findings. If real findings appear, fix
them — `no-unused-vars` and `no-explicit-any` will flag the loose edges the
exploration found (unused imports in `bgpmon` are Python-side and not in scope).

- [ ] **Step 5: Commit**

```bash
git add web/eslint.config.js web/package.json web/package-lock.json
git commit -m "Add flat ESLint config so npm run lint and the planned CI can run"
```

---

### Task 6: Make the dashboard work against a token-protected API

Fixes D4. Today `BGPMON_API_TOKEN` is documented and unusable from the UI.

**Files:**
- Modify: `web/src/lib/api.ts:4-8`
- Modify: `web/src/lib/useAlertStream.ts:27-30`
- Test: `tests/test_bgpmon.py` (assert the server side already matches)

**Interfaces:**
- Consumes: `api.py:86` `require_token` (Bearer) and `api.py:186` `?token=`.
- Produces: a single token source in the browser — a Vite env var `VITE_API_TOKEN`, or a `localStorage` key set at runtime.

- [ ] **Step 1: Write the failing test**

The server behaviour is already correct and needs no change; the fix is
client-side, so this test pins the contract the client must honour. Append to
`tests/test_bgpmon.py`:

```python
class TestTokenAuth(unittest.TestCase):
    """The dashboard must be able to satisfy the token guard it is given."""

    def test_api_rejects_missing_bearer_token(self):
        app = create_app(Settings.load())
        client = TestClient(app)
        response = client.get("/api/alerts", headers={"Authorization": ""})
        self.assertIn(response.status_code, (401, 422))

    def test_api_accepts_correct_bearer_token(self):
        settings = Settings.load()
        settings.api.token = "test-token"
        app = create_app(settings)
        client = TestClient(app)
        response = client.get("/api/alerts", headers={"Authorization": "Bearer test-token"})
        self.assertNotEqual(response.status_code, 401)
```

Requires `from bgpmon.api import create_app`, `from bgpmon.config import Settings`, and `from fastapi.testclient import TestClient` at the top of the test file.

- [ ] **Step 2: Run to see the baseline**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestTokenAuth -v
```
Expected: passes, confirming the server contract. The client is what is broken.

- [ ] **Step 3: Send the bearer token from the fetch layer**

Replace `web/src/lib/api.ts:4-8`:

```typescript
// Build-time only: a Vite env var is inlined into the bundle at `vite build`.
// A runtime token would need a settings input, which is out of scope.
const TOKEN = import.meta.env.VITE_API_TOKEN ?? "";

function apiHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  return headers;
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return (await res.json()) as T;
}
```

- [ ] **Step 4: Send the token on the WebSocket**

Replace the WebSocket construction in `web/src/lib/useAlertStream.ts:27-30`:

```typescript
  const url = new URL("/ws/alerts", `${proto}://${window.location.host}`);
  const token = import.meta.env.VITE_API_TOKEN;
  if (token) url.searchParams.set("token", token);
  const ws = new WebSocket(url.toString());
```

- [ ] **Step 5: Declare the env var**

Append to `web/.env.example` (create the file):
```
# Optional. Must match BGPMON_API_TOKEN. Build-time only — baked into the bundle.
VITE_API_TOKEN=
```

- [ ] **Step 6: Verify the build still passes and the token reaches the server**

Run:
```bash
npm run build
```
Expected: exit 0.

Then in `README.md`, replace the caveat written in Task 4 Step 4 with:

````markdown
- **`BGPMON_API_TOKEN` works from the dashboard** when `VITE_API_TOKEN` is set
  to the same value at build time (`web/.env`). It is a build-time variable, so
  the token is baked into the bundle — use a reverse proxy for anything stronger.
  The WebSocket receives it as `?token=`, matching `api.py:186`.
````

- [ ] **Step 7: Commit**

```bash
git add web/src/lib/api.ts web/src/lib/useAlertStream.ts web/.env.example README.md tests/test_bgpmon.py
git commit -m "Send the API token from the dashboard fetch and WebSocket layers"
```

---

### Task 7: Fix the API contract defects — 404 masking, alert persistence, owned_only

Fixes D5, D6, D7. Three related gaps in `/api`.

**Files:**
- Modify: `bgpmon/api.py:44-51` (catch-all scope), `bgpmon/api.py:97-111` (filters)
- Modify: `bgpmon/pipeline.py:159-160`
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `GraphSink.recent_alerts(limit, min_severity, kind, prefix)` (`sinks.py:248`), `Pipeline.recent(limit, min_severity, kind, owned_only)` (`pipeline.py:194`).
- Produces: `/api/alerts` returns JSON 404 for unknown `/api/*`; all severities persist; `owned_only` honoured on both sources.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_bgpmon.py`:

```python
class TestApiContract(unittest.TestCase):
    def test_unknown_api_path_is_json_404(self):
        client = TestClient(create_app())
        response = client.get("/api/definitely-not-a-route")
        self.assertEqual(response.status_code, 404)
        self.assertIn("application/json", response.headers.get("content-type", ""))

    def test_spa_route_still_serves_html(self):
        client = TestClient(create_app())
        response = client.get("/alerts")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
```

The second test guards against over-correcting: the SPA fallback is load-bearing and already tested at `tests/test_bgpmon.py:144`.

- [ ] **Step 2: Run to see them fail**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestApiContract -v
```
Expected: `test_unknown_api_path_is_json_404` FAILS with status 200; `test_spa_route_still_serves_html` PASSES.

- [ ] **Step 3: Reserve the `/api` prefix in the catch-all**

Replace `bgpmon/api.py:44-51`:

```python
    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        # Unknown API paths must 404 as JSON, not resolve to the SPA shell.
        # Anything under a reserved prefix is never a dashboard route.
        if full_path.startswith(("api/", "ws/", "metrics", "assets/")):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = (dist / full_path).resolve()
        # Serve a real file when asked for one (favicon, manifest), but never
        # escape the build directory via a crafted path.
        if full_path and candidate.is_file() and str(candidate).startswith(str(dist.resolve())):
            return FileResponse(candidate)
        return FileResponse(index)
```

Add `HTTPException` to the `from fastapi import ...` line at `bgpmon/api.py` if not already imported.

- [ ] **Step 4: Write the failing test for MEDIUM/LOW persistence**

Drive `_process` end to end so the severity gate at `bgpmon/pipeline.py:159` is
actually exercised — calling `submit_alert` directly would pass regardless and
prove nothing. Stub the engine so the alert's severity is the only variable;
using a real detector here makes the test depend on baseline state that varies
with `config/security_config.json`.

```python
    def test_medium_alert_reaches_the_sink(self):
        """A MEDIUM alert shown live must also persist, or it vanishes on restart."""
        pipeline = Pipeline(Settings.load())
        recorded = []
        pipeline.sink.submit_alert = recorded.append

        class StubEngine:
            def evaluate(self, update):
                return [Alert(
                    alert_id="a1", dedup_key="k", timestamp=update.timestamp,
                    kind=Kind.LONG_PATH, severity=Severity.MEDIUM, confidence=0.6,
                    prefix=update.prefix, as_path="", peer_as="",
                    collector=update.collector, update_id=update.update_id,
                )]

            def snapshot(self):
                return {}

        pipeline.engine = StubEngine()
        pipeline._process(make_update(prefix="45.33.32.0/20", collector="rrc00"))

        self.assertEqual(len(pipeline.recent_alerts), 1, "gate should admit a MEDIUM alert")
        self.assertEqual(len(recorded), 1, "MEDIUM alert never reached the sink")
```

Requires `Pipeline` and `Alert` added to the test file's imports.

- [ ] **Step 5: Run to see it fail**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestApiContract::test_medium_alert_reaches_the_sink -v
```
Expected: FAIL on the second assertion — `recorded` is empty, because `bgpmon/pipeline.py:159` gates on `Severity.HIGH, Severity.CRITICAL`. The first assertion passes, proving the gate admitted the alert and the loss is downstream.

- [ ] **Step 6: Persist every severity**

Replace `bgpmon/pipeline.py:159-160`:

```python
            # Every severity reaches the graph: /api/alerts?source=graph and the
            # TRIGGERED_BY edge must not silently lose MEDIUM/LOW.
            self.sink.submit_alert(alert)
```

If volume becomes a problem, the lever is `SinkSettings.batch_size`
(`bgpmon/config.py:200`) or the gate's global budget — not a severity filter.

- [ ] **Step 7: Honour `owned_only` on the graph path**

`_UPSERT_ALERT` already persists `is_owned` on every `SecurityAlert` node
(`bgpmon/sinks.py:77`), and the Cypher in `recent_alerts` (`bgpmon/sinks.py:253`)
already returns the whole node. So the graph path only needs the same predicate
the memory path already applies — no CIDR reimplementation, no engine accessor.

Replace `bgpmon/api.py:104-111`:

```python
    if source in ("auto", "graph") and pipeline.sink.enabled:
        rows = await asyncio.to_thread(pipeline.sink.recent_alerts, limit, severity, kind)
        if owned_only:
            rows = [r for r in rows if r.get("is_owned")]
        if source == "graph":
            return {"source": "graph", "count": len(rows), "alerts": rows}
        if rows:
            return {"source": "graph", "count": len(rows), "alerts": rows}
```

`pipeline.sink.recent_alerts` is called via `asyncio.to_thread` because it blocks
on Bolt; that is already how the current handler reaches it. `limit` and
`severity`/`kind` keep their existing meaning.

- [ ] **Step 8: Write the failing test for `owned_only` on the graph path**

```python
    def test_owned_only_filters_graph_rows(self):
        class StubSink:
            enabled = True

            def recent_alerts(self, limit, min_severity, kind):
                return [
                    {"alert_id": "a1", "prefix": "203.0.113.0/24", "is_owned": True},
                    {"alert_id": "a2", "prefix": "198.51.100.0/24", "is_owned": False},
                ]

        app = create_app()
        stub = StubSink()
        with patch.object(app.state.pipeline, "sink", stub):
            response = TestClient(app).get("/api/alerts?source=graph&owned_only=true")
        body = response.json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["alerts"][0]["alert_id"], "a1")
```

This requires `app.state.pipeline` to be reachable. If `create_app` does not
already store the pipeline on `app.state`, add one line after the `Pipeline`
construction at `bgpmon/api.py:59`:

```python
    app.state.pipeline = pipeline
```

(`create_app` builds the app at `bgpmon/api.py:63`, so this line goes after that
assignment, not before.)

- [ ] **Step 9: Run the API contract tests**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestApiContract -v
```
Expected: `test_unknown_api_path_is_json_404` PASSES, `test_owned_only_filters_graph_rows` PASSES.

- [ ] **Step 10: Run the full suite**

Run: `python -m pytest tests/test_bgpmon.py -q`
Expected: all pass, 0 failed.

- [ ] **Step 11: Commit**

```bash
git add bgpmon/api.py bgpmon/pipeline.py tests/test_bgpmon.py
git commit -m "Return JSON 404 for unknown API paths; persist all severities; honour owned_only on the graph path"
```

---

### Task 8: Fix the engine-side defects — MOAS key, telemetry, config shadowing

Fixes D8, D9, D10.

**Files:**
- Modify: `bgpmon/gate.py:60`
- Modify: `bgpmon/telemetry.py:9`, `bgpmon/telemetry.py:107`
- Modify: `bgpmon/pipeline.py:65` (call the RPKI gauges)
- Modify: `docker-compose.yml:70`
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `RPkiEngine.stats` (`rpki.py:349`) for the gauges.
- Produces: distinct MOAS keys per kind; `Optional` importable; three RPKI series present in `/metrics`; compose that cannot shadow `security_config.json`.

- [ ] **Step 1: Write the failing MOAS key test**

Append to `tests/test_bgpmon.py`:

```python
class TestMoasKeyIsolatesKinds(unittest.TestCase):
    def test_hijack_and_new_prefix_do_not_share_pending_state(self):
        """Each MOAS-gated kind corroborates independently."""
        ts = datetime.now(timezone.utc)

        def alert(alert_id, kind, severity):
            return Alert(
                alert_id=alert_id, dedup_key="k", timestamp=ts, kind=kind,
                severity=severity, confidence=0.9, prefix="203.0.113.0/24",
                as_path="", peer_as="", collector="rrc00", update_id=alert_id,
                origin_as=65001,
            )

        gate = AlertGate(confirm_updates=3)
        self.assertIsNone(gate.admit(alert("h1", Kind.HIJACK_ORIGIN, Severity.HIGH)))
        self.assertIsNone(gate.admit(alert("n1", Kind.NEW_PREFIX, Severity.MEDIUM)))

        # Same prefix, same origin, different kinds: two buckets, each with one
        # sighting. A shared key collapses these into one bucket of two, letting
        # a hijack sighting corroborate a new-prefix alert.
        self.assertEqual(len(gate._pending), 2)
        self.assertTrue(all(len(v) == 1 for v in gate._pending.values()))
```

Reading `gate._pending` is deliberate here: the bug *is* the key's shape, and a
public accessor would obscure it. Requires `AlertGate` and `Alert` in the test
file's imports.

- [ ] **Step 2: Run to see it fail**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestMoasKeyIsolatesKinds -v
```
Expected: FAIL on `assertEqual(len(gate._pending), 2)` — actual is 1, with both sightings in a single bucket keyed `('203.0.113.0/24', 65001, 0)`.

- [ ] **Step 3: Fix the key**

Replace `bgpmon/gate.py:60`:

```python
            moas_key = (alert.kind.value, alert.prefix, alert.origin_as or 0)
```

- [ ] **Step 4: Fix the `Optional` annotation**

Replace `bgpmon/telemetry.py:9`:

```python
from typing import Dict, Optional
```

- [ ] **Step 5: Write the failing metrics test**

Three Prometheus series are declared at `bgpmon/telemetry.py:34-36` but never
written, so they appear in `/metrics` only as bare `# HELP`/`# TYPE` lines with
no samples. Pin the sample values.

```python
@unittest.skipUnless(telemetry._ENABLED, "prometheus_client not installed")
class TestRpkiMetrics(unittest.TestCase):
    def test_rpki_gauges_carry_samples(self):
        metrics = telemetry.PipelineMetrics()
        metrics.gauge_rpki(1_013_990, 11.0)
        metrics.record_rpki("VALID", "local")
        body = generate_latest().decode()

        self.assertIn("bgpmon_rpki_vrp_prefixes 1.01399e+06", body)
        self.assertIn("bgpmon_rpki_sync_age_seconds 11.0", body)
        self.assertIn('bgpmon_rpki_results_total{source="local",state="VALID"}', body)
```

Requires `from prometheus_client import generate_latest`, `from bgpmon import telemetry`,
and the module-level `_PREFIX` (`bgpmon/telemetry.py:12`) in the test file. The
series names use the default `bgpmon` prefix; assert against `_PREFIX` if a test
env overrides `BGPMON_METRIC_PREFIX`.

- [ ] **Step 6: Run to see it pass, and see why**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestRpkiMetrics -v
```
Expected: PASS once the `Optional` import is fixed. This test guards the
annotation fix and the wiring in the next step; it does not itself go red,
because `gauge_rpki` works when called — the defect is that nobody calls it.

- [ ] **Step 7: Wire the gauges into the pipeline**

`RPkiEngine.stats` (`bgpmon/rpki.py:349`) already exposes the two numbers needed:
`indexed_prefixes` and `set_age_s`. `PipelineMetrics.snapshot()` reads
`self.rpki.stats` for `health()` (`bgpmon/pipeline.py:228`) — refresh the gauges
at the same point so `/metrics` and `/api/health` cannot disagree.

Add a helper next to `_visibility_loop` in `bgpmon/pipeline.py`:

```python
    def _refresh_rpki_metrics(self) -> None:
        """Keep the RPKI gauges honest; declared series with no sample look like
        a working exporter reporting nothing."""
        stats = self.rpki.stats
        age = stats.get("set_age_s")
        self.metrics.gauge_rpki(
            int(stats.get("indexed_prefixes") or 0),
            float(age) if age is not None else float("inf"),
        )
```

`set_age_s` is `None` before the first sync (`rpki.py:353`), and `gauge_rpki`
skips the age sample on `inf` (`bgpmon/telemetry.py:111`) — that is the intended
"no sync yet" signal.

Call it from two places so the gauge updates without waiting for alert traffic:
once at the end of `start()` after the RPKI sync at `bgpmon/pipeline.py:65`, and
once from `health()` (`bgpmon/pipeline.py:228`), which every dashboard client
hits at 2 s intervals. `health()` is the safer of the two — the visibility loop
(`bgpmon/pipeline.py:213`) also runs Task 2's detector, and coupling the two
changes in one function makes a regression in either harder to read.

So add the call at the top of `health()` and once at the end of `start()`:

```python
    def health(self) -> Dict[str, object]:
        self._refresh_rpki_metrics()
        return {
            ...
```

For `record_rpki`, instrument `RPkiEngine.validate` (`bgpmon/rpki.py:360`). It
has three return points (remote fallback at `:371`, not-loaded at `:373`, local
verdict at `:374`), so record at each rather than trying to wrap one call.
Give `RPkiEngine` an optional metrics reference — add a keyword parameter to
`__init__` (`bgpmon/rpki.py:282`) defaulting to `None`:

```python
    def __init__(self, settings: RPkiSettings, remote_session=None, metrics=None) -> None:
        ...
        self._metrics = metrics
```

Then record in `validate`, replacing the whole body after the docstring:

```python
        result = self._validate(prefix, origin_as)
        if self._metrics is not None:
            self._metrics.record_rpki(result.state, result.source)
        return result

    def _validate(self, prefix: str, origin_as: int) -> ValidationResult:
        if not self.ready:
            if self.settings.enable_remote_fallback:
                remote = self._validate_remote(prefix, origin_as)
                if remote is not None:
                    return remote
            return ValidationResult(_STATE_NOT_FOUND, "RPKI set not loaded", "none")
        return self.vrps.validate(prefix, origin_as)
```

Renaming the original body to `_validate` keeps `validate()` free of side
effects, which matters because it is called on the hot detection path
(`bgpmon/detect.py`) — one extra call per verdict is acceptable, but so is
keeping the two concerns separable.

Pass it at the construction site (`bgpmon/pipeline.py:41`), where `self.metrics`
is created on the line above (`bgpmon/pipeline.py:40`):

```python
        self.rpki = RPkiEngine(settings.rpki, remote_session=_make_session(),
                               metrics=self.metrics)
```

`record_rpki` is already a no-op when Prometheus is absent
(`bgpmon/telemetry.py:115`), so no further guard is needed.

- [ ] **Step 8: Stop compose shadowing the security config**

`docker-compose.yml:70` mounts `./config:/app/config:ro`, which hides `Dockerfile:25`'s baked `config/security_config.json`. Mount the file, not the directory:

```yaml
    volumes:
      - ./data:/app/data
      # Mount the file, not the directory: a directory mount hides the
      # security_config.json baked in at Dockerfile:25, silently dropping all
      # critical_prefixes.
      - ./config/security_config.json:/app/config/security_config.json:ro
```

Then remove the `COPY config/security_config.json` line at `Dockerfile:25` — with
the file bind-mounted it is unreachable, and keeping both invites exactly this
confusion. A host missing the file then fails loudly at start instead of
degrading silently, which is the correct trade.

- [ ] **Step 9: Verify the gauges now carry samples**

Run:
```bash
docker compose up -d monitor
curl.exe -s http://localhost:8090/metrics | Select-String "rpki_vrp_prefixes|rpki_sync_age"
```
Expected after ~30 s: `bgpmon_rpki_vrp_prefixes` with a non-zero sample (the
2.9 GB Routinator cache restores ~1M VRPs) and `bgpmon_rpki_sync_age_seconds`
with a small value.

Then confirm compose still resolves and the suite is green:
```bash
docker compose config --quiet
python -m pytest tests/ -q
```
Expected: exit 0; all tests pass.

- [ ] **Step 10: Commit**

```bash
git add bgpmon/gate.py bgpmon/telemetry.py bgpmon/pipeline.py bgpmon/rpki.py docker-compose.yml Dockerfile tests/test_bgpmon.py
git commit -m "Fix the MOAS key, the Optional annotation, unexported RPKI metrics, and config shadowing"
```

---

## LOW PRIORITY

### Task 9: Bound the scope lookup cache and add upstream politeness

Fixes D11.

**Files:**
- Modify: `bgpmon/scope.py:44` (cache), `bgpmon/scope.py:51-69` (throttle)

- [ ] **Step 1: Bound the cache**

`ScopeLookup.__init__` sets `self._cache = {}` (`scope.py:44`). Cap it:

```python
        self._cache: Dict[str, List[ScopedASN]] = {}
        self._cache_max = 128
        self._last_request = 0.0
        self._min_interval_s = 1.0
```

In `search`, after a cache miss and before the first network call:

```python
        # Politeness: RIPEstat and PeeringDB are shared free infrastructure.
        wait = self._min_interval_s - (time.monotonic() - self._last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()
```

and on store:

```python
        if len(self._cache) >= self._cache_max:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = results
```

Add `import time` at the top.

- [ ] **Step 2: Verify**

Run:
```bash
python -c "from bgpmon.scope import ScopeLookup; s=ScopeLookup(); print('ok')"
python -m pytest tests/test_bgpmon.py -q
```
Expected: `ok`; suite still green.

- [ ] **Step 3: Commit**

```bash
git add bgpmon/scope.py
git commit -m "Bound the scope lookup cache and throttle upstream requests"
```

---

### Task 10: Reconcile the untracked scope feature

The "scope lookup" work is half-committed: `bgpmon/scope.py` and `web/src/views/Scope.tsx` are untracked, while `api.py`, `App.tsx`, `lib/api.ts`, `lib/types.ts` are modified. Ship it as a unit or shelve it — but do not leave it half-staged.

**Files:**
- Add: `bgpmon/scope.py`, `web/src/views/Scope.tsx`
- Modify: `.gitignore`

- [ ] **Step 1: Give scope lookup tests before it ships**

Create `tests/test_scope.py`:

```python
import unittest
from unittest.mock import patch

from bgpmon.scope import ScopeLookup, ScopedASN


class TestScopeParsing(unittest.TestCase):
    def test_asn_query_is_recognised(self):
        self.assertTrue(ScopeLookup._is_asn("AS8220"))
        self.assertTrue(ScopeLookup._is_asn("as8220"))
        self.assertFalse(ScopeLookup._is_asn("Colt"))

    @patch.object(ScopeLookup, "_lookup_asn")
    def test_search_returns_parsed_results(self, lookup):
        async def fake(asn, rpki_validator=None, name=None, country=None):
            return ScopedASN(asn=asn, name="Example", country="GB", prefixes=[])
        lookup.side_effect = fake

        import asyncio
        results = asyncio.run(ScopeLookup().search("AS8220"))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].asn, 8220)
```

If `_is_asn` is not factored out of `search` (`scope.py:58`), extract it — `_ASN_RE` (`scope.py:20`) already exists.

- [ ] **Step 2: Run the new tests**

Run: `python -m pytest tests/test_scope.py -v`
Expected: pass.

- [ ] **Step 3: Git-ignore the build artefact**

Append to `.gitignore`:

```
*.tsbuildinfo
```

`web/tsconfig.tsbuildinfo` is currently untracked and would be committed by a
bare `git add -A`.

- [ ] **Step 4: Stage the feature as one commit**

```bash
git add bgpmon/scope.py web/src/views/Scope.tsx tests/test_scope.py .gitignore
git add bgpmon/api.py web/src/App.tsx web/src/lib/api.ts web/src/lib/types.ts
git status --short
git commit -m "Add the ASN/telecom scope lookup: API endpoint, dashboard view, and tests"
```

- [ ] **Step 5: Rename to avoid the roadmap collision**

Per ROADMAP Step 7, `scope.py` will collide with a future `scope` subcommand.
Rename now, before both exist:

```bash
git mv bgpmon/scope.py bgpmon/scope_lookup.py
```

Update the import in `bgpmon/api.py:22`:

```python
from bgpmon.scope_lookup import ScopeLookup
```

and the import in `tests/test_scope.py`. Re-run:
```bash
python -m pytest tests/ -q
```
Expected: all pass.

```bash
git add -A
git commit -m "Rename scope.py to scope_lookup.py ahead of the scope subcommand"
```

---

### Task 11: Remove the dead code and unimplemented config surface

Not a bug, but every dead surface is a trap for the next person — and `BGPMON_SYSLOG_*` is plumbed all the way through compose and `.env.example` for a feature that does not exist.

**Files:**
- Modify: `bgpmon/rpki.py` (drop `_sync_via_http`, `severity_for`)
- Modify: `bgpmon/sinks.py:361` (drop `_noop_metrics`)
- Modify: `bgpmon/gate.py:34` (drop `_confirmed`)
- Modify: `bgpmon/detect.py:63` (drop `_AS_SET`), `bgpmon/detect.py:269` (drop `_bogus_announcements`)
- Modify: `bgpmon/config.py:190-193` (drop `csv_dir`, `syslog_*`)
- Modify: `docker-compose.yml`, `.env.example` (drop `BGPMON_SYSLOG_*`)
- Modify: `config/security_config.json` (drop `trusted_transit_asns`, `known_bad_actors`)
- Modify: `web/package.json` (drop `tailwind-merge`, `class-variance-authority` — installed, never imported)

- [ ] **Step 1: Confirm each item is unreferenced before deleting**

Run:
```bash
Select-String -Path bgpmon\*.py,tests\*.py -Pattern "_sync_via_http|severity_for|_noop_metrics|_confirmed|_AS_SET|_bogus_announcements|csv_dir|syslog_|trusted_transit_asns|known_bad_actors"
Select-String -Path web\src\**\*.ts,web\src\**\*.tsx -Pattern "tailwind-merge|class-variance-authority"
```
Expected: matches only at the definition sites. Any call site means the item is live — skip it.

- [ ] **Step 2: Delete the confirmed-dead Python items**

Remove `_sync_via_http` (`rpki.py:337-341`), `severity_for` (`rpki.py:408`),
`_noop_metrics` (`sinks.py:361-365`), `_confirmed` (`gate.py:34`),
`_AS_SET` (`detect.py:63`), `_bogus_announcements` (`detect.py:269`),
`SinkSettings.csv_dir` (`config.py:190`), and
`SinkSettings.syslog_enabled/host/port` (`config.py:191-193`).

Also remove the now-orphaned imports the exploration flagged:
`VRPSet` in `detect.py:38`, `Iterable` in `sinks.py:16`, `field` shadowing in
`rpki.py:21`/`rpki.py:229`.

- [ ] **Step 3: Delete the dead config keys**

Remove `trusted_transit_asns` and `known_bad_actors` from
`config/security_config.json`. Nothing reads them, and ROADMAP item 2 under
"Carried over" describes replacing `known_bad_actors` with a feed — better as a
new feature than as a stub that looks wired.

- [ ] **Step 4: Remove the syslog plumbing from the deployment files**

Delete `BGPMON_SYSLOG_ENABLED` and `BGPMON_SYSLOG_HOST` from `docker-compose.yml`
and `.env.example`. If syslog forwarding is wanted, it is a feature — see the
ROADMAP, not a config toggle for nothing.

- [ ] **Step 5: Drop the unused frontend deps**

```bash
npm uninstall tailwind-merge class-variance-authority
npm run build
```
Expected: exit 0. `web/components.json` still references `@/lib/utils`; leave the
file (it documents intent) but note in the commit body that it is aspirational.

- [ ] **Step 6: Verify nothing broke**

Run:
```bash
python -m pytest tests/ -q
python -c "import bgpmon.api, bgpmon.pipeline; print('imports ok')"
npm run lint
npm run build
```
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Remove dead code and config for features that were never wired"
```

---

### Task 12: Clarify the SIGINT path and mark unimplemented alert kinds

Fixes D12, D13, D14. No drain bug — D14 turned out to be a misleading handler,
not a lost flush. The correction matters: a future reader who "fixes" it by
moving `sink.stop()` into the handler would double-drain, because the lifespan
teardown at `bgpmon/api.py:69` already does it.

**Files:**
- Modify: `bgpmon/__main__.py:79` (SIGINT handler)
- Modify: `bgpmon/pipeline.py:52` (initialise `_visibility_thread`)
- Modify: `web/src/lib/format.ts:15-31` (filter chips)
- Test: `tests/test_bgpmon.py`

**Interfaces:**
- Consumes: `Server.handle_exit` (uvicorn), `api.py:69` `pipeline.stop()`.
- Produces: an accurate SIGINT contract, and a pipeline whose thread attributes exist from construction.

- [ ] **Step 1: Write the failing test for the uninitialised thread attribute**

```python
class TestPipelineThreadAttributes(unittest.TestCase):
    def test_thread_handles_exist_before_start(self):
        """stop() joins these; they must exist even if start() never ran."""
        pipeline = Pipeline(Settings.load())
        for name in ("_worker", "_loop_thread", "_visibility_thread"):
            self.assertIsNone(getattr(pipeline, name), name)
```

Requires `Pipeline` and `Settings` in the test file's imports.

- [ ] **Step 2: Run to see it fail**

Run:
```bash
python -m pytest tests/test_bgpmon.py::TestPipelineThreadAttributes -v
```
Expected: FAIL on `_visibility_thread` with `AttributeError`.

- [ ] **Step 3: Initialise the attribute**

In `bgpmon/pipeline.py:52`, alongside `self._stop = threading.Event()`:

```python
        self._stop = threading.Event()
        self._visibility_thread: Optional[threading.Thread] = None
```

- [ ] **Step 4: Write the test that pins the real drain contract**

```python
    def test_lifespan_teardown_drains_the_sink(self):
        """Uvicorn replaces the SIGINT handler; the lifespan teardown is the
        real drain path. Pin it so a future edit to either does not lose it."""
        drained = []
        settings = Settings.load()
        app = create_app(settings)
        app.state.pipeline.sink.stop = lambda drain=True: drained.append(drain)

        with TestClient(app):
            pass  # entering the context starts the lifespan

        self.assertIn(True, drained)
```

This passes today. It is a regression pin, not a bug fix — which is the point:
the handler at `__main__.py:79` looks like it is responsible for shutdown and is
not. Requires `create_app` and `TestClient` in the test file's imports, and
requires `app.state.pipeline`, which Task 7 Step 8 adds. If Task 7 has not run
yet, add `app.state.pipeline = pipeline` after the app is constructed at
`bgpmon/api.py:63`.

Note the test costs a real pipeline start (three threads plus a Neo4j connection
attempt). If that proves too slow for the suite, instead assert on the source of
`lifespan` — weaker, but honest about what it checks.

- [ ] **Step 5: Replace the misleading handler with a comment**

Replace `bgpmon/__main__.py:79`:

```python
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
```

with:

```python
    # No SIGINT handler here on purpose. In the API path uvicorn installs its
    # own (Server.capture_signals) and runs the FastAPI lifespan teardown, which
    # calls pipeline.stop() -> sink.stop(drain=True). In --soak mode the
    # SystemExit raised below propagates through run_soak's finally block,
    # which does the same. Installing a second handler here would only obscure
    # where the drain actually happens.
```

`--soak` relies on `SystemExit` propagating through `run_soak`'s
`try/finally` (`__main__.py:45-56`). Verified: raising SIGINT under that handler
runs the `finally` block, so `pipeline.stop()` executes. Keep the handler, but
state why it is harmless.

- [ ] **Step 6: Remove the never-emitted filter chips**

In `web/src/lib/format.ts`, remove the `RPKI_ASPAS`, `MOAS_NEW_ORIGIN`, and
`RPKI_ROA_CHANGE` entries from `KIND_LABEL` (lines 20, 27, 28) and from
`ALL_KINDS` (line 31). Keep them in `bgpmon/models.py` — they are part of the
detection contract, and ROADMAP plans to emit two of them.

- [ ] **Step 7: Verify**

Run:
```bash
python -m pytest tests/ -q
npm run build
```
Expected: green, and the filter chip list no longer offers kinds nothing emits.

- [ ] **Step 8: Commit**

```bash
git add bgpmon/__main__.py bgpmon/pipeline.py web/src/lib/format.ts tests/test_bgpmon.py
git commit -m "Document the real drain path, initialise the visibility thread, and drop filters for unemitted kinds"
```

---

## Deferred (not in this plan)

- `ROADMAP.md` "Next: baseline your space" items 1–4 — feature work, gated on the scope importer (Task 10's follow-up).
- Synthetic hijack rehearsal — needs a fault-injection hook the collector does not have.
- ASPA wiring, ROA change detection, RFC 9234 peer-lock — engine features, ROADMAP-tracked.
- Bundle split (`manualChunks`) — 767 kB is a warning, not a blocker.
- IRR validation, threat-intel feeds, ML anomaly detection — ROADMAP-tracked.
- Grafana dashboard JSON, NOC runbooks — ROADMAP-tracked.