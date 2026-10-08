# Pre-rebuild legacy inventory

Everything the 2.0 rebuild replaced still exists, intact, on the branch
`archive/pre-rebuild-master` (`4983f79`, also pushed to `origin`). This file
records what is in it so the branch can be deleted without losing anything that
matters.

**30 Python files, 7 773 lines.** The credential history scrub rewrote commit
SHAs across both branches but did not touch this branch's contents.

## Decision

The tool is **web-only**. Everything Tkinter is dead by decision, not by
oversight: the React console replaced it, and `Logic.md` and the benchmark table
in `README.md` are the surviving record of what it did.

**Port:** `utils/episode_manager.py` (616 lines) — incident correlation, which the
rebuild has no equivalent of. Port before deleting the branch.

**Delete with the branch:** the GUI and its support, the old analyzer, the old
collector, and the dead ML module.

## Ported

### `utils/episode_manager.py` → `bgpmon/episodes.py`

`Episode` / `EpisodeManager`: groups related alerts into an incident by
`(prefix, origin AS)` inside a time window, scores events by severity with
multipliers for critical prefixes / origin changes / RPKI invalidity, and
supports close, cleanup, and `to_dict`.

Field mapping from the old alert dict to today's `Alert`:

| Old field | Today's source | Note |
|---|---|---|
| `prefix` | `Alert.prefix` | direct |
| `origin_as` | `Alert.origin_as` | direct |
| `severity` | `Alert.severity` | direct |
| `reasons` | `Alert.reasons` | direct |
| `is_critical_prefix` | derived | `DetectionEngine._critical` cover test; today's `Alert` carries `is_owned`, not this |
| `previous_origin_as` | **re-based** | see below |

**The one semantic change.** The old matcher keyed an episode on
`(prefix, previous_origin_as)` with a fallback to `(prefix, None)`, because the
old detector compared each announcement against the last origin it saw. That is
the exact antipattern `Logic.md` documents as the reason the rebuild moved to
authorised origins — it fires on every update of a legitimate MOAS prefix.

The rebuild already keeps the better primitive: `PrefixState.origins` is an
`origin AS -> sighting count` map per prefix. An episode is therefore keyed on
**any previously-seen origin for that prefix in this session**, which preserves
the old intent — one incident per origin transition on a prefix — without
reintroducing "compare to last seen". A hijack followed by recovery stays one
episode instead of splitting in two, which is what an operator wants.

Consequence to accept: episodes are session-scoped, like the rest of the
in-memory detector state. A restart mid-incident starts a new episode. Persisting
them is future work and is not implied by the port.

## Deliberately not ported

| Module | Lines | Why |
|---|---|---|
| `utils/security_analyzer.py` | 703 | The analyzer the 2.0 rebuild was a reaction to: 0.2 RPKI lookups/s, 7.08% alert rate, blocking HTTP per update. `bgpmon/detect.py` supersedes it |
| `utils/analysis.py` | 620 | `BGPAnalyzer`, same generation as the above |
| `utils/as_lookup.py` | 381 | `ASLookup`. Superseded by `bgpmon/scope.py` (172 lines, same PeeringDB + RIPEstat sources) |
| `utils/db_manager.py` | 590 | `BGPDatabaseManager`. Superseded by `bgpmon/sinks.py` batched write-behind |
| `utils/notification_manager.py` | 120 | Email alerting. The scope spec decided the SIEM is the system of record; syslog RFC 5424 covers the destination |
| `utils/anomaly_detector.py` | 119 | **Dead code, verified.** `fit()` is called nowhere — line 129 is commented out — so `predict()` always returns `None` at the `if not self.is_fitted` guard on line 124. It imported scikit-learn and produced nothing. The rebuild's decision to remove it rather than ship it inert was correct |
| `utils/data_manager.py` | 145 | CSV alert output. The `SinkSettings.csv_dir` field survives in config but no CSV sink exists |
| `utils/config_manager.py` | 267 | Replaced by `bgpmon/config.py` + `config/*.json` |
| `utils/bgp_utils.py` | 157 | Superseded |
| `src/`, `bgp_collector.py`, `config/collectors.py` | 975 | Old RIS collector. `bgpmon/collector.py` is the replacement with explicit subscription acks and a bounded queue |

## Deleted with the branch (web-only decision)

| File | Lines |
|---|---|
| `gui/main_window.py` | 1 365 |
| `gui/config_dialog.py` | 143 |
| `utils/ui_config_handler.py` | 144 |
| `tests/test_ui/app.py` | 138 |
| `test_ui_config.py` | 48 |

The old UI was a genuine thick client: `tkinter`/`ttk`, 1000×800 window,
`ttk.PanedWindow`, a `ttk.Notebook` for tabs, two `Treeview`s for updates and
alerts, plus `Progressbar`, `Combobox` and `Radiobutton` — driven from `main.py`
with signal handling.

It also contained the defect the rebuild was built to fix: a
`prefix_origin_cache` tracking the last-seen origin per prefix, used by
`check_suspicious_patterns`. That is precisely the comparison `Logic.md` rejects.

## Reproducing anything from this branch

```bash
git show archive/pre-rebuild-master:utils/episode_manager.py
git show archive/pre-rebuild-master:project_summary.txt   # per-file summary
git show archive/pre-rebuild-master:IMPROVEMENT_TRACKER.md
```

After the episode port lands and the branch is deleted, the only thing it still
holds is a full checkout of the above — and the before/after figures already
transcribed into the `README.md` benchmark table.