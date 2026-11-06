# Rearchitecting plan: Subsystem 2 (threat detection)

Status: **P0 and P1-1/P1-5 applied** (2026-11-05); the rest is still proposal.
Every number below was measured against the working tree, not recalled.

| Package | Status |
|---|---|
| P0-1 events carry `t` (LogV1) | **done** — and it turned up that the writer was dead code; now wired |
| P0-2 one `metrics.py` | **done** — 4 implementations → 1 module, 2 explicit policies |
| P0-4 layering test | **done** — 4 tests, verified to fail on a deliberate violation |
| P0-5 window spread beside every mean | **done** — `statemachine.py`, `reporting.py` |
| P0-3 feature_value on median/MAD | **open** — changes published numbers; needs a decision |
| P1-1 split `statemachine.py` | **done** — 789 lines/50 names → 3 modules + 33-line shim |
| P1-5 matplotlib out of module scope | **done** — `import reporting` 0.86 s → 0.32 s |
| P1-4 shared scorer helpers | **done** — `warm_from`/`held_out_scores` moved to `methods.scores` |
| P1-2 `core/` package, P1-3 regrouping | **open** |
| P2, P3, P4 | **open** |

Baseline before any change: `python -m unittest tests` → **259 tests, OK, 12.5 s**.
After P0: **271 tests, OK, 13.6 s**, and the four regenerated experiment CSVs
(`sweep_results`, `detector_comparison`, `feature_value`, `feature_value_wide`) are
**byte-identical** to the pre-change snapshot.

---

## 0. The short version

**The subsystem is in good shape technically. Its problem is presentation, not correctness.**

- The four pipeline layers have **zero layering violations** and a clean one-way
  dependency. That is better than most student subsystems and should be the headline.
- The core is **1,261 lines out of 8,446** (15%). Everything else is experiment,
  presentation, or conversion. A reader currently cannot see that ratio.
- The tests are strong (259, 12.5 s, including real-corpus checks).

**The five things I would fix first**, in order:

1. **The event contract was dead code.** `to_events`/`write_events` were written,
   tested, documented in `EVENT_LOG.md` and consumed by Subsystem 3 — but **nothing
   called them**. `outputs/events.jsonl` was a stale artifact from 27 October. Fixed:
   `pair_demo` now emits them, and the events carry `t` (LogV1) so they can be ordered.
   *This was only found by regenerating and inspecting the file, not by reading the code.*
2. **`statemachine.py` is 789 lines and 50 public names.** Split at a seam that is exact
   to the line (learning 47–328, scoring 331–673, CLI 676–789).
3. **Four copies of the same statistics helpers**, with two different tie policies.
4. **`feature_value` measures features on a baseline the detector doesn't use**
   (mean/std vs median/MAD), so the feature ranking is not comparable to detection.
5. **~37 s of redundant parsing** across three experiments that each re-read all 88 CSVs.

**What I would *not* do:** delete experiments, replace the z-score detector, merge the two
detectors, or rename the public vocabulary. All four would cost more than they save.

---

## 1. The problem, in one paragraph

The *functionality* of this subsystem is small and genuinely good: read packet CSVs,
window them per second, learn what normal looks like, score deviation, flag, report. That
core is **1,261 lines** across four layers with a clean one-way dependency
(`data_io → features → detectors → reporting`) and no layering violations. Around it sit
**977 lines** of experiments, a second 789-line detector, four ad-hoc statistical
helpers, 202 lines of pre-registered verdict rules, and **1,025 lines** of presentation.
The core is buried, not broken. The job of this plan is to make the core obvious again
**without discarding any measurement already taken**.

Measured split of the 8,446 project lines, partitioned so every line is counted exactly
once (`tests.py` 3,144 and `demo.py` 460 are excluded as harness/entry, not architecture):

| Band | Modules | Lines | Share |
|---|---|---:|---:|
| Core (io, windows, detect, policy, report) | data_io, features, detectors, evaluation, reporting | 1,261 | 26.1% |
| Second method | statemachine | 789 | 16.3% |
| Presentation | story, cluster, layout | 1,025 | 21.2% |
| Experiments | sweep, compare, feature_value, flag_scores, windowed_scores, cv_calibration | 977 | 20.2% |
| Verdict rules | flag_verdict, root_verdict, cv_verdict | 202 | 4.2% |
| Conversion | pcap_read, pcap_rows, pcap_diff | 572 | 11.9% |
| Config | local_paths | 6 | 0.1% |
| **Total** | | **4,832** | **100%** |

(Total excludes `tests.py` and `demo.py`; every other `.py` in the tree is in exactly one band.)

The single biggest structural signal:

| Module | Lines | Public names | Distinct concerns |
|---|---:|---:|---|
| `statemachine.py` | 789 | **50** | flow building, encoding, ALERGIA learning, PDFA, two scorers, cutoffs, sweep CLI |

Fifty public names in one file is why a new reader cannot tell what is core.

---

## 2. What is core vs. what is experiment

Measured by tracing who imports whom (call sites, alias-resolved) and what has fan-in.

### Core — what the subsystem *is*

| Concern | Module | Why it stays |
|---|---|---|
| Read captures, resolve paths, manifest | `data_io.py` (162) | fan-in 13; everything touches it |
| Packets → 1-second windows, 13 features | `features.py` (141) | fan-in 5 |
| Detector protocol + z-score | `detectors.py` (316) | fan-in 6; the contract every method obeys |
| Evaluation policy (70/30, bulk labels) | `evaluation.py` (18) | the only place judging rules live |
| Render results → tables/charts/events | `reporting.py` (624) | fan-in 3 |
| PDFA / SEQUENT second method | `statemachine.py` (789) | the only *sequence-aware* detector |

### Experiment — measurements, not product

`sweep.py` (111), `compare.py` (65), `feature_value.py` (116), `flag_scores.py` (262),
`windowed_scores.py` (236), `cv_calibration.py` (187) = **977 lines**, plus **202 lines**
of pre-registered verdicts (`flag_verdict` 47, `root_verdict` 57, `cv_verdict` 98).
`pcap_diff.py` (203) is a proof rather than an experiment and sits with conversion.

### Presentation — one user-facing surface

`story.py` (545) + `cluster.py` (325) + `layout.py` (155) + `story_template/` = **1,025 lines**
to render one page. `demo.py` (460) is a menu that mostly shells out.

### Conversion — independent, already well-isolated

`pcap_read.py` (172) + `pcap_rows.py` (197) + `pcap_diff.py` (203) = 572 lines, no coupling
into the pipeline. Leave as is.

---

## 3. Target layout

```
Threat_Detection/
├── core/                      # THE SUBSYSTEM. 1,261 lines. Read this to understand it.
│   ├── io.py                  #   data_io   (was data_io.py)
│   ├── windows.py             #   features
│   ├── detect.py              #   detectors: protocol + z_score + registry
│   ├── policy.py              #   evaluation: split, bulk labels, warm-up
│   └── report.py              #   reporting: tables, charts, events
├── methods/
│   ├── pdfa.py                # learning: flows, symbols, ALERGIA, PDFA
│   ├── scores.py              # scoring: likelihood + SEQUENT (cumulative & windowed)
│   └── sweep.py               # the PDFA experiment CLI (statemachine.main)
├── metrics.py                 # ONE auroc, ONE detection_at_rate, ONE calibration
├── experiments/               # each is a thin CLI over core/ + metrics
│   ├── sweep.py  compare.py  feature_value.py
│   ├── flag_alphabet.py  windowed.py  cv_calibration.py
├── verdicts/                  # pre-registered rules, unchanged in behaviour
│   ├── flag.py  root_count.py  cv.py
├── story/                     # presentation (optional install)
│   ├── build.py  cluster.py  layout.py  template/
├── convert/                   # pcap → packet rows (unchanged)
│   ├── read.py  rows.py  diff.py
├── demo.py                    # the menu
├── local_paths.py
└── tests/
```

**The rule that makes this work:** `core/` may import `core/` and the standard library
only. Not numpy-of-the-moment, not `metrics`, not `story`. `metrics.py` may import nothing
from the project. Experiments import `core` + `metrics` + `verdicts`. `story/` imports
`core` + `methods`. That is checkable in a test (see §6, P0-4).

### Why a package, not flat files

`data_io.py` is currently a name that reads as "I/O for everything" and, being top-level,
can be shadowed by anything. A `core/` package with an explicit `__init__.py` exporting the
six things a user actually needs gives the subsystem a **front door**:

```python
from core import load_capture, make_windows, build_detector, split_reference
```

Today a newcomer has to read 25 top-level files to discover that.

---

## 4. Ordered work packages

Each package is independently shippable and keeps the suite green. **Order matters**: the
behavioural fixes (P0) go first because they are the ones a reviewer will ask about, and
they are cheap; the move (P1) is mechanical and can be reverted in isolation.

### P0 — Correctness and contract (small, high value)

| # | Change | Evidence | Risk |
|---|---|---|---|
| **P0-1** | **Add `t` to events.** `outputs/events.jsonl` has **51 events, none with a timestamp**; all 51 share one location. Subsystem 3 cannot order, dedupe, or expire them. The window index *is* capture-relative seconds — `annotate()` already has it, `to_events` drops it. **Prototyped**: adding `"t": int(index)` yields `{"version":"LogV1","detector":"z_score","t":3,"severity":"med",...}`, orderable, with the unbounded-score-is-high rule preserved. | `outputs/events.jsonl`, `reporting.to_events` | Low. Bump `LogV0` → `LogV1`. |
| **P0-2** | **One metric module.** Four implementations today: `feature_value.separation_auc` (rank-based, NaN on thin input), `flag_scores.auroc` (pairwise, raises), `detection_at_budget`, `detection_at_benign_rate`. They currently *agree* numerically (verified on random and tie-heavy input), so this is maintainability + one tie policy, not a bug fix. | `feature_value.py:27,39`, `flag_scores.py:33,44` | Low. |
| **P0-3** | **Make `feature_value` use the detector's own baseline.** It z-scores with **mean/std**; the detector uses **median/MAD** (`MAD_TO_SIGMA`). So "what each feature is worth" is measured on a baseline the detector does not use. Route it through `detectors.ZScoreDetector`. | `feature_value.py:42` | **Medium — changes published numbers.** Re-run and state the delta. |
| **P0-4** | **Enforce the layering rule with a test.** Already precedent: `FeatureLayerChecks.test_features_module_does_not_import_local_paths`. Extend it to "core imports nothing outside core". | `tests.py:279` | Low. |
| **P0-5** | **Fix the uneven-denominator reporting** PROGRESS already flags: print window counts beside every mean over strata (a 3-window capture currently weighs the same as an 80-window one). | `PROGRESS.md` §Outstanding | Low. |

### P1 — The move (mechanical, the bulk of the value)

| # | Change | Notes |
|---|---|---|
| **P1-1** | Split `statemachine.py` (789, 50 names) into `methods/pdfa.py` + `methods/scores.py` + `methods/sweep.py`. | The seam is exact, not approximate: **lines 47–328 are learning** (flows → symbols → PTA → ALERGIA → PDFA), **331–673 are scoring** (trace likelihood + both SEQUENT scorers + cutoffs), **676–789 are the sweep CLI**. `fit_model`/`fit_segments` (440–467) bridge the two and go with `pdfa.py`. |
| **P1-2** | Create `core/` package; move the five core modules; re-export a front door in `__init__.py`. | Pure moves + import rewrites. Do it in one commit so `git log` shows a clean rename. |
| **P1-3** | Group experiments under `experiments/`; verdicts under `verdicts/`; story under `story/`; conversion under `convert/`. | Keeps `demo.py` and `local_paths.py` at the top as the entry surface. |
| **P1-4** | Replace the duplicated `warm_from` / `held_out_scores` / `_flags` helpers by importing from `methods.scores`. | `windowed_scores.py:41-62` reimplements what `statemachine` already does. |
| **P1-5** | Move `matplotlib` import out of module scope in `reporting` (keep `Agg`, but import inside the plotting functions). | `import reporting` costs **0.86 s** vs **0.31 s** for the whole core, because it drags in matplotlib. Pure-Python users never need it. |

### P2 — Simplify the front door

| # | Change | Notes |
|---|---|---|
| **P2-1** | Replace the 460-line `demo.py` menu with a thin dispatcher: `python -m demo <experiment>`. | 80 `print()` calls and subprocess shell-outs; it re-implements the CLI of every script. |
| **P2-2** | Make every experiment importable and return a DataFrame; `main()` only prints and writes. | Most already do; finish the ones that print inline. |
| **P2-3** | Retire `print()` from library code in favour of returned rows. | 39 prints in `reporting`, 10 in `flag_scores`, 7 in `cv_calibration`. |

### P3 — Performance (measured, only where it matters)

| # | Change | Expected gain | Evidence |
|---|---|---|---|
| **P3-1** | Load captures lazily / cache parsed windows per `(label, method)`. | A full `load_all_windows` pass over the 88-capture corpus takes **12.3 s** (measured). `sweep`, `compare` and `feature_value` each call it once → **~37 s of redundant parsing** per full run, and the ablation re-parses again per group. | `sweep.py:47`, `compare.py:27`, `feature_value.py:54` |
| **P3-2** | Replace `iterrows()` in `to_events` / `summary_row` with vectorised construction. | small but on the hot path | `reporting.py:197` |
| **P3-3** | `story.py` writes a 3 MB page; the per-trace detail dominates. Make trimming the default, not a fallback. | 3 MB → ~0.7 MB observed when trimmed | `outputs/statemachine_story.html` (3.0 MB) vs a trimmed build (0.7 MB) |

### P4 — Features worth adding (after the above, not before)

These are additive and each is one small module. Listed in order of value-per-risk.

1. **Multi-pod incident correlation.** Every event today names one pod. A real attack
   touches several; grouping flagged windows across vantages by time is the missing link
   to Subsystem 3.
2. **An interface to S1's Prometheus baseline.** PROGRESS records that 7 of 8 original
   features have no source in S1's surface. A small adapter that maps resource metrics
   onto the same 13-feature window shape would answer the open "interface question".
3. **`unique_src_ips` / `unique_src_ports`** — already listed as unread candidates;
   cheap, and the diversity group is currently all-destination.
4. **A `--sensitivity` flag** exposing `THRESHOLD` (2.5) instead of a constant that
   silently changes published numbers — PROGRESS records exactly that failure once already.
5. **Calibration honesty:** report the realised benign rate next to every cutoff (the
   story page already does; the sweeps do not).

---

## 5. What this plan deliberately does **not** do

- **Does not delete the experiments.** They are the evidence for every claim; they move,
  they do not disappear.
- **Does not change any detection result** except P0-3, which is called out and re-measured.
- **Does not replace the z-score detector.** PROGRESS is explicit that nothing measured
  justifies it.
- **Does not merge the two detectors.** The PDFA method answers a different question
  (sequence novelty) and its verdicts are still open.
- **Does not rename the public vocabulary** (`flagged_fraction`, `persistent`,
  `insufficient_data`). The words are load-bearing across `outputs/` and the report.

---

## 6. How each step is verified

1. `python -m unittest tests` stays at 259+ passing after every package.
2. A new test asserting the layering rule (P0-4) and one asserting `core/` imports without
   matplotlib.
3. Every experiment CLI re-run before/after and its CSV diffed — the only expected
   differences are the ones P0-3 and P0-5 name.
4. `demo.py` items 1–11 still produce the same artifacts.

---

## 7. Suggested sequencing for a review meeting

| Stage | Work | Reviewer-facing outcome |
|---|---|---|
| 1 (½ day) | P0-1, P0-2, P0-4, P0-5 | "Events are orderable; the statistics live in one place; the layering is enforced." |
| 2 (1 day) | P0-3 | One number changes, with the delta explained. |
| 3 (1–2 days) | P1-1 … P1-5 | `core/` is 1,261 readable lines; the rest is clearly labelled. |
| 4 (½ day) | P2 | One obvious entry point. |
| 5 (ongoing) | P3, P4 | Speed and new capability, once the shape is stable. |
