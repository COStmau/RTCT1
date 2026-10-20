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

**The one entry point** — everything a person looks at goes through it.

| File | What it does |
|---|---|
| `demo.py` | A menu over the whole subsystem. Items 1-3 are presentations (pair demo, plain-language walkthrough, state machine); 4-7 are the experiments below; 8 regenerates every artifact; 9 runs the tests. |

**The experiments** — each runs one measurement and writes its own CSV. `demo.py` runs
these as documented; they also run on their own.

| File | What it does |
|---|---|
| `sweep.py` | Every capture against its own matched benign reference. `--groups` runs the feature-group ablation. |
| `compare.py` | Every registered detector on the same windows, reference, and split. |
| `feature_value.py` | Per-feature value: threshold-free separation (auc) and detection at a 5% benign budget. |
| `statemachine.py` | PDFA anomaly detection after Cao et al. (ARES 2022): packet flows to symbols, ALERGIA state merging, trace likelihood flags. A second detection method; `demo.py` item 3 is its presentation. |

**Supporting files**

| File | What it does |
|---|---|
| `tests.py` | All unit tests. |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. Only the entry points read it. |
| `PROGRESS.md` | Why the design is what it is: decisions, retractions, what is not claimed, what is next. |
| `EVENT_LOG.md` | The detection → response event contract (`LogV0`). |
| `outputs/` | Everything generated. Safe to delete; `demo.py` item 8 rebuilds it. `outputs/SHOWCASE.md` is every measured result as one file. |

## Run it

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
```

Underneath the menu, the same commands run directly:

```bash
.venv/bin/python -m unittest tests                    # 57 tests
.venv/bin/python sweep.py                             # all 88 captures, about 8 seconds
.venv/bin/python sweep.py --groups volume,size_timing,diversity,flags,protocol --out ablation_results.csv
.venv/bin/python compare.py
.venv/bin/python feature_value.py
.venv/bin/python statemachine.py                      # PDFA sweep, 43 rows, about 13 seconds
.venv/bin/python statemachine.py --method ptcp --out statemachine_sweep_ptcp.csv
```

The two sweeps do not have the same row count, and the gap is not a missing capture.
`sweep_results.csv` covers both capture methods and holds 88 rows. `statemachine_sweep.csv`
runs one method per invocation, so 44 strata, and drops the quarantined zero-timestamp capture
(`nginx attack / pod-robot-controller`), leaving 43. Run it twice, once per method, to compare
against the 88-row file.

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
