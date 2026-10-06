# Subsystem 2: detection and diagnosis

Offline analysis of the KUBEDATA packet captures. Run everything from this folder with
the project virtualenv: `.venv/bin/python`.

## What each file is

| File | What it does |
|---|---|
| `detector.py` | The detector: packet CSV -> 1-second windows -> 8 features -> baseline learned from benign traffic -> deviation score -> persistence rule. Also the single-pair demo run. |
| `dataset.py` | Reads the dataset: names every capture (scenario / level / label / method), loads the packet columns, checks the timebase. |
| `sweep.py` | Runs the detector over every capture against its own matched benign reference. `--groups` runs the feature-group ablation. |
| `compare.py` | Same windows, three detectors: z-score, Isolation Forest, One-Class SVM. |
| `walkthrough.py` | Plain-language walk-through of one result, for showing someone. |
| `tests.py` | All unit tests. |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. |
| `PROGRESS.md` | Status, results, what is next. |
| `etc/TA-UPDATE.md` | Two-minute spoken update for the TA. |
| `outputs/` | Everything generated. Safe to delete, the commands below rebuild it. |

## Run it

```bash
cd /Users/cos/Documents/school/ECEN403/RTCT1/Threat_Detection
.venv/bin/python -m unittest -v tests                 # 18 tests
.venv/bin/python detector.py --no-show                # one benign/attack pair
.venv/bin/python sweep.py                             # all 88 captures, about 8 seconds
.venv/bin/python sweep.py --groups volume,size_timing,diversity,flags --out ablation_results.csv
.venv/bin/python compare.py                           # z-score vs Isolation Forest vs One-Class SVM
.venv/bin/python walkthrough.py                       # the demo walk-through
```

## Rules the code follows

- One second per window. A window with no packets keeps zero counts and leaves the
  averages empty, not zero.
- The baseline is learned from benign traffic only, and the last 30% of that capture is
  never used for fitting. That part is the honest check.
- A window is flagged when its largest deviation passes 3 typical spreads, and an alert
  needs 3 flagged windows in a row.
- Missing or mismatched data is reported as insufficient, never as normal.
- Learned models (forest, SVM) take their cutoff from held-out benign windows, so every
  model is compared at the same false-alarm budget.
