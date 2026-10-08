# Scope, Filtering and SIEM Forwarding — Design Spec

**Date:** 2026-10-08
**Status:** Awaiting review
**Supersedes:** ROADMAP item 1 ("baseline your space"), partially
**Relates to:** ROADMAP "Carried over" item 1 (IRR validation), plan Tasks 6 and 8

---

## 1. The problem, with evidence

The tool currently shows every operator every alert, and most of them concern
nobody reading the screen.

Measured on a live 4-collector run against this host, 13 minutes after start:

```
alerts_total: 880          (809 HIGH, 71 MEDIUM, 0 CRITICAL)
detection.alerts_by_kind: ROUTE_LEAK 432, RPKI_INVALID 1152, LONG_PATH 136,
                           BOGON_ASN 159, BOGON_PREFIX 8, HIJACK_SUB_PREFIX 6
owned_prefixes: 0
```

Against 1 723 alerts in the recent window, filtered by AS8220:

| Test | Matches |
|---|---|
| `alert.origin_as == 8220` | 0 |
| `alert.prefix` inside a prefix AS8220 announces | 0 |
| `8220` anywhere in `alert.as_path` | 2 |

**99.9% of what an operator sees is not theirs.** Two consequences:

1. **The filter is the feature.** Not deep links, not clickability. Without it
   every other triage affordance makes the firehose worse.
2. **Zero CRITICAL is not health.** `HIJACK_ORIGIN`, `HIJACK_SUB_PREFIX` and
   `VISIBILITY_LOSS` are all gated on `BGPMON_OWNED_PREFIXES`, which is empty by
   default. The CRITICAL path has never executed.

The scope lookup needed to close this already exists: `/api/scope/search?q=AS8220`
returns 174 prefixes with live RPKI state, resolving in about 10 seconds.

---

## 2. Design decision: two concepts, deliberately not one

Both derive from operator-declared ASNs. They must not be the same object.

```
config/scope.json   {"asns": [8220, 10021], "extra_prefixes": [], "include_transit": true}
      │
      ├──► SCOPE              registry/IRR-derived, best-effort, approximate
      │       → display filter, SIEM forward gate, "is this mine"
      │       → over/under-approximation is tolerable: it only decides what you look at
      │
      └──► AUTHORISED_SPACE    RPKI ROA-derived, authoritative
              → HIJACK_ORIGIN / HIJACK_SUB_PREFIX expected_origins ONLY
              → unchanged from Logic.md; no new detection semantics
```

### 2.1 Why they must stay separate

IRR data is registry-moderated, inconsistent between RIRs, and sometimes wrong.
It is **not** a sufficient trust anchor for a CRITICAL detector. Deriving the
hijack baseline from it creates two failure modes:

| Failure mode | Mechanism | Impact |
|---|---|---|
| **False positive** | IRR still lists your ASN as origin for space you sub-let. The customer announces legitimately from their own ASN. | Your own detector calls it a hijack. You learn to ignore your CRITICAL alarm |
| **False negative** | IRR is missing or stale for space you hold. No baseline. | A real hijack goes undetected. The failure the tool was bought to prevent |

Splitting the concepts bounds the blast radius: a bad registry lookup degrades
to "slightly the wrong set of alerts on screen", never "hijack detection is
broken".

### 2.2 Trust hierarchy

| Source | Strength | Permitted use |
|---|---|---|
| **RPKI ROA** — local VRP set over RTR | Cryptographically verifiable | The only thing that may mark an origin authorised |
| **IRR `route:` / `route6:`** | Registry-moderated, inconsistent | Informing scope. Never authorising |
| **WHOIS `inetnum` / `origin`** | Weakest, frequently absent | Human confirmation in the Scope view only |
| **Observed traffic** | Descriptive, not prescriptive | See 2.3 |

### 2.3 Known weakness, flagged not silently inherited

`Logic.md` documents a third authorisation path for `HIJACK_ORIGIN`: "a
previously observed origin for that prefix in this session." This makes observed
traffic an authorisation input. It is defensible for genuine MOAS — two ASes
sharing a prefix by design — but it is the weakest available anchor, and a
persistent hijack could in principle seed it.

This spec does not change that behaviour. It is recorded here as a decision
needing an explicit ruling rather than inherited silence, because it sits
directly against the trust hierarchy above.

---

## 3. Scope model

### 3.1 File format — `config/scope.json`

```json
{
  "asns": [8220, 10021],
  "extra_prefixes": [],
  "include_transit": true
}
```

| Field | Type | Meaning |
|---|---|---|
| `asns` | list[int] | ASNs the operator operates. Stable, few, human-maintained |
| `extra_prefixes` | list[str] | Explicit CIDRs added to scope directly. For space not derivable from IRR |
| `include_transit` | bool | Whether `TRANSIT` matches participate in filtering |

ASNs are what a network engineer thinks in and change rarely. Prefixes churn
constantly, which is why they are derived rather than listed — this is also why
`BGPMON_OWNED_PREFIXES` has always been empty: nobody will type 174 CIDRs by hand.

Loaded via the existing `_read_json` path (`bgpmon/config.py:264`), same as
`config/security_config.json`. Not stored in Neo4j: the file is diffable in a
pull request and readable without a running graph.

### 3.2 Resolution

`ScopeResolver` derives SCOPE from `scope.json`:

1. `announced-prefixes` per ASN via RIPEstat — what each ASN originates now
2. `whois` per prefix — IRR `origin` ASNs, for customer space and held-not-announced space
3. Union, plus `extra_prefixes`

Verified against live RIPEstat: `whois` for `62.23.0.0/16` returns the Colt
`inetnum` (netname `UK-COLT-20001017`) and IRR records with `origin: 8220` on the
/16 (`descr: FR-COLT-FRANCE`) **and** on seven /24s inside it carrying
`descr: TATA IZO` — customer space that AS8220 originates on someone else's
behalf. One call distinguishes own from customer space.

**Resolution is lazy and cached**, never on every scope save:

- First resolution is on demand ("Refresh now"), not at startup
- Cached to `config/.scope_cache.json` with a timestamp
- Refreshed when older than `BGPMON_SCOPE_REFRESH_S` (default 3600)
- On upstream failure: keep serving the stale cache and mark it stale. **Never
  resolve to empty** — an empty scope is indistinguishable from "no alerts" and
  is the dangerous failure mode.

### 3.3 Match reasons

Every alert is classified against scope. Not a boolean — the reason is what makes
an empty view trustworthy.

| Reason | Test | Catches | Implementation |
|---|---|---|---|
| `ORIGIN` | `alert.origin_as` ∈ scope ASNs | You are announcing it | Cypher, indexable |
| `SUBSPACE` | `alert.prefix` ⊆ a scope prefix | More-specific of your space | Python CIDR containment |
| `TRANSIT` | a scope ASN ∈ `alert.as_path` | Leaks flowing through your network | Cypher `any(... split ...)`, gated on `include_transit` |

An alert is in scope if **any** reason matches. `OWN_ALERT` (all three) and
`SUBSPACE` together are what a hijack of your space looks like; `TRANSIT` is
carrier accountability — you cannot prevent it, but a NOC wants to know.

Showing the reason means "0 alerts" is never ambiguous: the view reads
`ORIGIN 0 · SUBSPACE 0 · TRANSIT 2`, which is a finding rather than a silence.

---

## 4. Security design

### 4.1 The write endpoint is the primary new attack surface

Anyone who can reach the port can redefine "my scope". Every relevant attack is
quiet rather than destructive:

| Attack | Consequence | Mitigation |
|---|---|---|
| Set scope to `[]` | Operator blinded — no alerts surface | Audit log entry; UI confirms the resolved prefix count |
| Set scope to an attacker-controlled ASN | Noise floods the filtered view, burying real alerts | Scope capped at 64 ASNs; resolved-prefix count shown |
| Submit a huge `extra_prefixes` list | Burns operator's registry rate limit | Capped at 256 CIDRs |
| Submit malformed CIDR/ASN | Crash or injection into a query | Strict validation before use; never interpolate IRR text into Cypher |

### 4.2 Registry data is untrusted input

Everything from RIPEstat is attacker-influenceable in the sense that any party
may publish IRR objects for space they control. Treat as untrusted strings:
validate ASN as an integer in `[0, 4294967295]`, prefix via
`ipaddress.ip_network(strict=False)`, reject anything else. Never string-format
registry data into a Cypher query.

### 4.3 Audit

Scope is security-relevant configuration. Every change records to the service log
and to a bounded in-process ring exposed in `/api/health`:

```json
"scope": {
  "asns": [8220, 10021],
  "resolved_prefixes": 174,
  "include_transit": true,
  "resolved_at": "2026-10-08T08:42:11Z",
  "stale": false,
  "last_change": {"at": "...", "asns": [8220, 10021], "previous_asns": []}
}
```

**Known limitation, stated rather than hidden:** `BGPMON_API_TOKEN` is a single
shared bearer secret. There is no user identity, so an audit entry records *that*
scope changed, never *who* changed it. Acceptable for a single-operator
deployment; not acceptable for a shared one. Per-user identity is explicitly out
of scope (see §9).

### 4.4 Transport

Compose binds `127.0.0.1:${BGPMON_API_PORT}:8080` rather than
`${BGPMON_API_PORT}:8080`. Loopback is the default; LAN exposure is a deliberate
opt-in.

This matters: `docker port` reported `0.0.0.0:8090` on this host while Windows was
in fact listening on loopback only. That was host luck, not a property of the
config.

---

## 5. API surface

All write routes require the bearer token via the existing `require_token`
dependency (`bgpmon/api.py:86`).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/scope` | token | Current scope, derived counts, staleness, last change |
| `POST` | `/api/scope` | token | Replace scope. Validates, persists `config/scope.json`, returns new state |
| `POST` | `/api/scope/refresh` | token | Force registry re-resolution, discard cache |
| `GET` | `/api/alerts` | token | Existing. Adds `scope=mine\|all`, default `mine` |
| `GET` | `/api/alerts/summary` | token | Counts by severity and kind, split by scope match reason |

`app.state.pipeline` already exists (`bgpmon/api.py:65`), so routes reach the
resolver without new plumbing.

`/api/alerts/summary` exists because `/api/alerts` returns up to 2 000 alert rows;
counting those client-side to render the Overview split would ship a thousand
times more data than the answer requires.

**Resolution order for the `scope` parameter**, so the default is unambiguous:

1. `scope=all` → no filtering, whatever the scope file says
2. `scope=mine` (the default) → filter, **unless** scope is unresolved or absent,
   in which case no filtering and the response carries
   `"scope_active": false` with the reason

So "default `mine`" and "no default scope means no filtering" are not in
conflict: `mine` resolves to *show everything* when there is nothing to filter by.
A filter that silently narrows to nothing is the failure this ordering exists to
prevent.

### 5.1 Filtering mechanics — query-time, with a stated ceiling

**Cypher cannot do CIDR containment.** No APOC in this image. Decision:

- Cypher pre-filters `ORIGIN` (`origin_as IN $asns`, indexable) and `TRANSIT`
  (`any(a IN split(a.as_path, ',') WHERE trim(a) IN $asns)`)
- Python performs exact CIDR containment for `SUBSPACE` on the survivors

Exact, cannot go stale, no migration. **Ceiling: this runs over the
`recent_alerts` window.** Fine to tens of thousands of alert rows; not a day of
traffic at 880 alerts per 13 minutes. Persisting a `scope_match` field on
historical alerts is the escape hatch and is deliberately deferred — the volume
that breaks the query is the volume that makes the SIEM gate more important than
query latency.

### 5.2 Failure behaviour

| Condition | Behaviour |
|---|---|
| Scope unresolved, no cache | Filter off, banner "scope unresolved — showing all alerts". **Never show an empty filter** |
| Registry upstream failing | Serve stale cache, `stale: true` in `/api/scope` and `/api/health` |
| Scope file unreadable | Log, keep last good in-memory value, `stale: true` |
| `POST /api/scope` validation failure | 422 with the specific offending field. Scope unchanged on disk |

---

## 6. SIEM forwarding

Operator decision: **the SIEM is the system of record.** This tool forwards and
does not implement case management. No acknowledgement button, no assignment, no
triage state — duplicating that here would create two systems disagreeing about
what is open.

Vendor-neutral transport: **syslog RFC 5424 over TCP**. Sentinel, Splunk HEC and
QRadar all ingest structured syslog without a custom adapter. TCP, not UDP — an
alert lost in transit defeats the purpose, and at this volume fire-and-forget buys
nothing.

### 6.1 Sink interface

```python
class AlertSink(Protocol):
    def start(self) -> bool: ...
    def submit(self, alerts: Sequence[Alert]) -> None: ...
    def flush(self) -> None: ...
    def stop(self) -> None: ...
    def stats(self) -> Dict[str, int]: ...
```

`SyslogSink` implements it. A `WebhookSink` (POST JSON) is a later addition with
no change to callers.

**Discipline copied from `GraphSink` (`bgpmon/sinks.py:88`) exactly:** buffered,
batched, retried with linear backoff, and **never blocking the detection loop**. A
SIEM that is down must not slow ingest. It drops and counts:
`bgpmon_siem_dropped_total`, `bgpmon_siem_sent_total`, `bgpmon_siem_errors_total`.

### 6.2 Gate

Only alerts matching SCOPE are forwarded. A scope error therefore causes
under-forwarding rather than flooding a SIEM that would then de-prioritise the
source.

### 6.3 Message shape

RFC 5424 with `SD-ELEMENT`s carrying the detection facts, so a SIEM can filter on
them without regex:

```
<134>1 2026-10-08T08:42:11Z host bgpmon - - -
  kind=ROUTE_LEAK severity=HIGH prefix=177.73.157.0/24 origin_as=270105
  peer_as=1299 collector=rrc01 scope_reason=TRANSIT
  alert_id=route_leak_ca2d4065aee5738a
  reasons="Valley-free violation (RFC 7908): AS11514 re-announced..."
```

### 6.4 Security properties of forwarding

| Property | Position |
|---|---|
| Transport encryption | **TCP syslog is plaintext.** If the destination is not loopback or VPN, alert content — including which of your prefixes is under attack and by whom — crosses the network in cleartext. TLS is a follow-up (see §9); until then the constraint is documented in `INSTALL.md` and the config carries a comment |
| Content sensitivity | The SIEM becomes security-sensitive infrastructure, not just logging |
| Authentication | Syslog offers none. Do not put the destination on an untrusted network |

### 6.5 Replaces dead configuration

`BGPMON_SYSLOG_ENABLED`, `BGPMON_SYSLOG_HOST`, `BGPMON_SYSLOG_PORT` already exist
in `SinkSettings` (`bgpmon/config.py:191-193`) and are plumbed through
`docker-compose.yml` and `.env.example` for an implementation that does not
exist. `SyslogSink` adopts these exact names rather than introducing a parallel
vocabulary. `bgpmon/sinks.py:361` `_noop_metrics` is removed.

---

## 7. UI — extend `/scope`

No new nav item. `/scope` is already the page about ASNs and space; it currently
only reads, and the writable half is its natural other side.

```
┌─ Your scope ─────────────────────────────────────────┐
│  ASNs  [8220] [10021] [+]     include transit ☑      │
│  extra prefixes: [none]                              │
│  → 174 prefixes in scope · resolved 4 min ago        │
│  ⚠ stale — registry unreachable, using 6 h old cache  │
│                              [Save]  [Refresh now]    │
├─ Look up any ASN ────────────────────────────────────┤
│  [ AS8220 ] → COLT · 174 prefixes · RPKI state each   │
└──────────────────────────────────────────────────────┘
```

The derived count and the "resolved N min ago" timestamp are load-bearing: they
are how the operator knows the registry lookup **succeeded** rather than silently
returning nothing. A stale banner is shown when `stale: true`.

`/alerts` gains a scope toggle, **default ON**, plus reason chips
(`ORIGIN 0 · SUBSPACE 0 · TRANSIT 2`). `/` gains the same split — "880 alerts,
**2 concern you**" — because that number should drive whether the operator looks
at all.

---

## 8. Authentication prerequisite

The UI write path makes three items load-bearing that were previously optional.
None is new work; all are already in the plan.

1. **Dashboard sends the token.** `web/src/lib/api.ts:5` currently sends no
   `Authorization` header; `useAlertStream.ts:28` opens `/ws/alerts` with no
   `?token=`. Both must send `import.meta.env.VITE_API_TOKEN`. Build-time only —
   the token is inlined into the bundle, so a runtime token needs an input UI
   that is out of scope.
2. **Write routes are token-guarded.** Every mutating route takes `require_token`.
3. **Loopback bind.** `docker-compose.yml` binds `127.0.0.1:${BGPMON_API_PORT}:8080`.

Nothing ships half-secured: no write endpoint without working client auth.

---

## 9. Out of scope

| Deferred | Why |
|---|---|
| Per-user identity / attribution for scope changes | Needs a user model. §4.3 records the limitation instead |
| Runtime API token entry in the UI | `VITE_API_TOKEN` is build-time. A runtime token needs a settings field and a secret store |
| TLS for syslog | Real need for remote SIEMs, but it needs a custom socket handler, not stdlib `SyslogHandler`. Documented as a constraint in §6.4 rather than half-built |
| `WebhookSink` | Trivial once `AlertSink` exists; no reason to ship before a syslog destination is proven |
| Persisted `scope_match` field | Escape hatch for the §5.1 ceiling, deferred until volume forces it |
| In-app acknowledgement / assignment | SIEM owns triage (§6) |
| Alert deep-links to RIS Live / RIPEstat | Agreed to defer. Worth building *after* the filter — then you are clicking 2 alerts, not 1 723 |
| Roving the "observed origin" authorisation path (§2.3) | Needs a deliberate security decision, not a side effect of this work |

---

## 10. Testing

TDD per unit. Every item names the defect it pins.

| Unit | Test intent |
|---|---|
| `ScopeResolver` | Own space resolves; customer space (IRR `origin`) included; `extra_prefixes` union; malformed CIDR rejected without touching the network; upstream failure keeps the stale cache and never yields empty |
| Match reasons | `ORIGIN` on origin match; `SUBSPACE` on a more-specific; `TRANSIT` on path containment only when `include_transit`; a prefix belonging to neither ASN yields no reason |
| `/api/scope` | GET shape; POST persists and reloads; POST without token → 401; POST over cap → 422 and disk unchanged; `refresh` discards cache |
| `/api/alerts?scope=` | `mine` returns only matched; `all` returns everything; reason breakdown correct; empty scope returns **all** alerts, never none |
| `SyslogSink` | Buffers and batches; retry then drop on failure; `stats()` counts match what was dropped; never raises into the detection loop |
| `config` | `scope.json` malformed → stale, not empty; syslog env vars reach the sink |

Integration: a live end-to-end check that AS8220 scope returns the 2 transit
alerts and zero origin/subspace alerts — the exact numbers in §1, which makes the
test a regression detector against scope silently becoming empty.

---

## 11. Compatibility and migration

- **No default scope.** Absent `config/scope.json`, filter defaults to **off**
  and the UI says why. An empty scope must never look like "no alerts".
- **No detection behaviour changes.** `AUTHORISED_SPACE` stays RPKI-derived as
  today. No threshold, severity, or detector semantics move.
- **`is_owned` unchanged.** It remains detection-time provenance, not a display
  filter. The new `scope_reason` is a separate, query-time concept.
- **Existing `/api/alerts` callers.** `scope=mine` becomes the default, which is
  a behaviour change for anyone calling it today. Documented in `ROADMAP.md`;
  `scope=all` restores the old behaviour.

---

## 12. Success criteria

1. On this host, AS8220 scope over the live feed yields **2 alerts, both
   `TRANSIT`** — matching §1 — and `/api/alerts?scope=all` still yields all 1 723.
2. `/alerts` and `/` load with the filter on and show reason chips.
3. Setting scope to `[]` in the UI changes the visible set to everything and logs
   an audit entry.
4. A syslog sink pointed at a closed port drops and counts without slowing
   ingest: `updates_per_second` stays within noise of baseline.
5. `POST /api/scope` without a token → 401. With a token → persists.
6. All existing tests still pass.