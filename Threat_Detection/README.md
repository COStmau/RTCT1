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
| `data_io.py` | The input format and where output goes. Names every capture, reads the packet columns, checks the timebase, builds and caches the manifest, resolves `outputs/`. |
| `features.py` | Packets → one row per second. The 8 features, the ablation groups, and the temporal train/held-out split. Stateless: no baseline, no thresholds, no detection. |
| `detectors.py` | Every detection method behind one interface: `fit` → `calibrate` → `score` → `flag`, with optional `explain`. Add one by writing a class and adding it to `REGISTRY`. |
| `reporting.py` | Console reports and charts. Takes results, renders them; computes no detection logic. |

**Entry points** — the experiments. Each one is now a short script that calls the layers
above in order.

| File | What it does |
|---|---|
| `detector.py` | The single-pair demo: two captures, one report, one chart. |
| `sweep.py` | Every capture against its own matched benign reference. `--groups` runs the feature-group ablation. |
| `compare.py` | Every registered detector on the same windows, reference, and split. |
| `feature_value.py` | Per-feature value: threshold-free separation (auc) and detection at a 5% benign budget. |
| `walkthrough.py` | Plain-language walk-through of one result, for showing someone. |

**Supporting files**

| File | What it does |
|---|---|
| `tests.py` | All unit tests. |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. Only the entry points read it. |
| `PROGRESS.md` | Status, results, what is next. |
| `etc/TA-UPDATE.md` | Two-minute spoken update for the TA. |
| `outputs/` | Everything generated. Safe to delete; the commands below rebuild it. |

## Run it

```bash
cd /Users/cos/Documents/school/ECEN403/RTCT1/Threat_Detection
.venv/bin/python -m unittest -v tests                 # 36 tests
.venv/bin/python detector.py --no-show                # one benign/attack pair
.venv/bin/python sweep.py                             # all 88 captures, about 8 seconds
.venv/bin/python sweep.py --groups volume,size_timing,diversity,flags --out ablation_results.csv
.venv/bin/python compare.py                           # z-score vs Isolation Forest vs One-Class SVM
.venv/bin/python feature_value.py                     # what each single feature is worth
.venv/bin/python walkthrough.py                       # the demo walk-through
```

Generated files always land in `Threat_Detection/outputs/`, whichever directory you run
from.

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
- A window is flagged when its score passes the cutoff, and an alert needs
  `PERSISTENCE_WINDOW` flagged windows in a row.
- Missing or mismatched data is reported as insufficient, never as normal.
- Learned models take their cutoff from held-out benign windows, so every detector is
  compared at the same false-alarm budget.