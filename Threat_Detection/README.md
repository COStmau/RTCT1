# Subsystem 2: detection and diagnosis

Offline analysis of the KUBEDATA packet captures. Run everything from this folder with
the project virtualenv: `.venv/bin/python`.

## How it fits together

Data flows one way through four layers, and each layer only knows the one below it:

```
packet CSVs ──► data_io ──► features ──► detectors ──► reporting ──► tables, charts, stdout
                load a      1-second    fit / calibrate   print and
                capture     windows     / score / flag    plot
```

`data_io` → `features` → `detectors` → `reporting`. Nothing downstream reaches back
upstream, and none of the four import `local_paths.py`, so they are portable and
testable on their own.

## What each file is

**Layers** — the reusable pipeline. Use these to build something new.

| File | What it does |
|---|---|
| `data_io.py` | The input format and where output goes. Names every capture, reads the packet columns, checks the timebase and snaplen saturation, builds and caches the manifest, resolves `outputs/`. |
| `features.py` | Packets → one row per second. The 13 features, the ablation groups, and the temporal train/held-out split. Stateless: no baseline, no thresholds, no detection. |
| `detectors.py` | Every detection method behind one interface: `fit` → `calibrate` → `score` → `flag`, with optional `explain`. The z-score baseline is median + MAD. Add one by writing a class and adding it to `REGISTRY`. |
| `reporting.py` | Console reports, charts, the `SHOWCASE.md` handover file, and the event log the response side reads. Takes results, renders them; computes no detection logic. Pins matplotlib to `Agg`, so nothing here opens a window. |
| `cluster.py` | The k3s cluster's shape inferred from benign traffic: nodes, pods (including host-network ones), services, conversations and where each capture listened. Used by the story page. |
| `layout.py` | Computed positions for the story page: the prefix tree as an icicle, the learned machine in columns. |

**The one entry point** — everything a person looks at goes through it.

| File | What it does |
|---|---|
| `demo.py` | A menu over the whole subsystem. Items 1-3 are presentations (pair demo, plain-language walkthrough, state machine); 4-7 are the experiments below; 8 regenerates every artifact; 9 runs the tests; 10 builds the interactive state-machine story page. |

**The experiments** — each runs one measurement and writes its own CSV. `demo.py` runs
these as documented; they also run on their own.

| File | What it does |
|---|---|
| `sweep.py` | Every capture against its own matched benign reference. `--groups` runs the feature-group ablation. |
| `compare.py` | Every registered detector on the same windows, reference, and split. |
| `feature_value.py` | Per-feature value: threshold-free separation (auc) and detection at a 5% benign budget. |
| `statemachine.py` | PDFA anomaly detection after Cao et al. (ARES 2022): packet flows to symbols, ALERGIA state merging, trace likelihood flags. A second detection method; `demo.py` item 3 is its presentation. `--flags` adds TCP SYN/RST presence to the symbol; default is the old alphabet. |
| `flag_scores.py` | Per-window anomaly scores under the plain and flag alphabets, plus AUROC and matched-rate detection per stratum. Prints the pre-registered verdict. |
| `windowed_scores.py` | The story page's detector, the windowed SEQUENT score, on every stratum, calibrated exactly as the page is. Quotes the windows each cutoff rests on and the realised benign rate beside every number. Prints the root-count verdict. |
| `cv_calibration.py` | Cross-validated calibration of the windowed score (every benign window scored out of fold) against the split. Prints the pre-registered verdict: drop, so the split stays. |
| `story.py` | The state machine as one interactive page, `outputs/statemachine_story.html`: the inferred cluster, ALERGIA learning step by step, and a replay of held-out benign and every attack through the windowed SEQUENT scorer (the 8 s anomaly clock, forgetting, release). One page carries every steady capture tap (`--vantages` to choose; `--vantage` picks the one it opens on): click a tap on the map or use the header picker to switch the learning and detection acts, and Act 3's *Across taps* view lines one scenario up at every tap on a shared capture-time axis. Self-contained (about 3 MB for the 8 steady taps; past 15 MB the other taps' per-trace breakdown is dropped); opens offline. `demo.py` item 10. The renderer is `story_template/`. Bulk-transfer vantages (`evaluation.BULK_LABELS`) never set a cutoff, so they are left out unless `--allow-bulk`, and the page then marks their verdicts as inspection only. Each cutoff shows how many held-out windows it rests on and how often it actually flags them; capture text is HTML-escaped in the bundle. |

**Supporting files**

| File | What it does |
|---|---|
| `tests.py` | All unit tests. |
| `evaluation.py` | How a result is judged, in one place: the 70/30 split, the six bulk-transfer files that never calibrate, and the warm-up window. |
| `flag_verdict.py` | The keep-or-drop rule for the flag alphabet, committed before the measurement, with `decide()` applying it. |
| `root_verdict.py`, `cv_verdict.py` | The same kind of rule for the start-state training count (kept: entries) and for cross-validated calibration (dropped). |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. Only the entry points read it. |
| `requirements.txt` | The pinned runtime: Python 3.11 with numpy, pandas, matplotlib and scikit-learn at the versions the numbers were measured under. |
| `PROGRESS.md` | Why the design is what it is: decisions, retractions, what is not claimed, what is next. |
| `EVENT_LOG.md` | The detection → response event contract (`LogV0`). |
| `outputs/` | Everything generated. Safe to delete; `demo.py` item 8 rebuilds it. `outputs/SHOWCASE.md` is every measured result as one file. |

## Run it

The virtualenv is built once from the pinned runtime:
`python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt`.

```bash
cd /Users/cos/Documents/school/ECEN403/RTCT1/Threat_Detection
.venv/bin/python demo.py            # menu
.venv/bin/python demo.py 2          # one item, no menu
.venv/bin/python demo.py all        # sweep, ablation, compare, features, then the report
```

The menu, in order:

```
 1  Pair demo       one normal and one attack recording: report and chart
 2  Walkthrough     the same pair narrated plainly, then writes outputs/SHOWCASE.md
 3  State machine   trace scores from a learned automaton, two charts
 4  Sweep           every capture against its own matched benign reference
 5  Ablation        the sweep repeated once per feature group
 6  Compare         z-score against isolation forest and one-class SVM
 7  Feature value   what each measurement is worth on its own
 8  Everything      all of the above, in the order the report needs it
 9  Tests           the unit suite
10  Story           the state machine learned and replayed, as an interactive page
```

Underneath the menu, the same commands run directly:

```bash
.venv/bin/python -m unittest tests                    # 203 tests
.venv/bin/python sweep.py                             # all 88 captures, about 8 seconds
.venv/bin/python sweep.py --groups volume,size_timing,diversity,flags,protocol --out ablation_results.csv
.venv/bin/python compare.py
.venv/bin/python feature_value.py
.venv/bin/python statemachine.py                      # PDFA sweep, 42 rows, about 13 seconds
.venv/bin/python statemachine.py --method ptcp --out statemachine_sweep_ptcp.csv
.venv/bin/python flag_scores.py                       # both alphabets' window scores, AUROC, verdict chart
.venv/bin/python windowed_scores.py                   # the windowed SEQUENT score on every stratum
.venv/bin/python cv_calibration.py                    # cross-validated calibration and its verdict
.venv/bin/python story.py                             # interactive page, every steady tap; --vantage pod-nginx opens on it
```

`sweep.py` writes `outputs/sweep_summary.png` and `outputs/detection_gap.png`; `flag_scores.py`
writes `outputs/alphabet_verdict.png` alongside `flag_auc.csv`.

The two sweeps do not have the same row count, and the gap is not missing captures.
`sweep_results.csv` covers both capture methods and holds 88 rows. `statemachine_sweep.csv`
runs one method per invocation, so 44 strata, and excludes two: the quarantined zero-timestamp
capture (`nginx attack / pod-robot-controller`) and `injection attack / router-flannel`, which
has too few flows left after boundary-crossing segments are dropped. That leaves 42. Run it
twice, once per method, to compare against the 88-row file.

Generated files always land in `Threat_Detection/outputs/`, whichever directory you run
from. Delete `outputs/capture_manifest.csv` after any dataset change, or the sweep scores
the previous inventory.

## Adding a detector

Write one class and add one line to `REGISTRY`:

```python
class MyDetector(Detector):
    name = "my_detector"

    def fit(self, reference): ...          # learn from benign training windows
    def calibrate(self, held_out_benign): ...   # set self.cutoff
    def score(self, windows): ...          # higher = more anomalous; NaN if unscorable
```

Then `build("my_detector")`. `compare.py` picks it up with no changes, because it iterates
the registry. Two rules the protocol guarantees, so a new detector cannot break a
comparison:

- **Higher score means more anomalous.** scikit-learn's `decision_function` runs the other
  way, so learned detectors negate it once in `LearnedDetector.score`.
- **Attribution is optional.** `explain` stays `None` unless your detector can genuinely
  name the feature that moved. The z-score can; a learned model that guessed would make the
  comparison lopsided.

## Rules the code follows

- One second per window. A window with no packets keeps zero counts and leaves the
  averages empty, not zero.
- The reference is learned from benign traffic only, and the last 30% of that capture is
  never used for fitting. That part is the honest check.
- The baseline is a median and a MAD, not a mean and a standard deviation. Six of the 22
  benign captures contain a bulk-transfer regime change, and a mean/std summary is set by
  those windows rather than by normal traffic. `PROGRESS.md` has the reasoning.
- A window is flagged when its score passes the cutoff, and an alert needs
  `PERSISTENCE_WINDOW` flagged windows in a row.
- Missing or mismatched data is reported as insufficient, never as normal.
- Learned models take their cutoff from held-out benign windows, so every detector is
  compared at the same false-alarm budget.
- A capture truncated by the recorder's snaplen is still scored, but `at_snaplen` in the
  manifest records the fraction of packets clipped, and those captures' length-based
  features are not comparable to the unclipped ones.
