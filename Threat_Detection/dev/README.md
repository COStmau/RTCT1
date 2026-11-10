# dev: how the detector was built and judged

Everything here is development material: the measurements, the keep-or-drop rules they were
judged by, the unit suite, and the notes on why the design is what it is. None of it ships.
The shipped code (`core/`, `methods/`, `convert/`, `viz/`, `demo.py`) is mapped in the
[root README](../README.md), and nothing there imports from `dev/`.

Run everything from `Threat_Detection/` with the project virtualenv, `.venv/bin/python`.
Each script puts both the root (`core`, `methods`, `convert`) and `dev/` (`experiments`,
`verdicts`, `statemachine`) on its path, so it also runs from any other directory. Results
land in the shared `Threat_Detection/outputs/`.

```
experiments/   one measurement per module. The evidence.
verdicts/      keep-or-drop rules, committed before the measurement they judge.
tests.py       the unit suite, for the shipped code and for everything here.
statemachine.py  a compatibility re-export of methods/pdfa.py and methods/scores.py.
PROGRESS.md    decisions, retractions, what is not claimed, what is next.
REARCHITECTING.md  the notes from splitting the original modules into layers.
feature_research.ipynb  the exploratory notebook the feature set came from.
```

## The evidence

Each runs one measurement and writes its own CSV. `demo.py` (items 4-7) runs the first four as documented; they
also run on their own, as a script or with `-m`.

| File | What it does |
|---|---|
| `dev/experiments/sweep.py` | Every capture against its own matched benign reference. `--groups` runs the feature-group ablation. |
| `dev/experiments/compare.py` | Every registered detector on the same windows, reference, and split. |
| `dev/experiments/feature_value.py` | Per-feature value: threshold-free separation (auc) and detection at a 5% benign budget. |
| `dev/experiments/flag_scores.py` | Per-window anomaly scores under the plain and flag alphabets, plus AUROC and matched-rate detection per stratum. Prints the pre-registered verdict. |
| `dev/experiments/windowed_scores.py` | The visualization page's detector, the windowed SEQUENT score, on every stratum, calibrated exactly as the page is. Quotes the windows each cutoff rests on and the realised benign rate beside every number. Prints the root-count verdict. |
| `dev/experiments/cv_calibration.py` | Cross-validated calibration of the windowed score (every benign window scored out of fold) against the split. Prints the pre-registered verdict: drop, so the split stays. |
| `dev/experiments/feature_set.py` | All 13 features against the eight without volume and size/timing: persistent alerts, AUROC and detection at a 5% benign budget per scenario. Prints the pre-registered verdict: drop; `--rule hybrid` runs the nine-feature candidate (kept). |
| `dev/experiments/load_behavior.py` | Load channel (z-score) against behavior channel (windowed SEQUENT): does the second gate the first on the bulk taps and the attacks. Prints the pre-registered verdict: drop. |
| `dev/experiments/metrics.py` | One `auroc`, one `detection_at_rate`, one `detection_at_budget`, with the two missing-data policies stated rather than accidental. Imports nothing from the project, so any experiment can use it. |

## The pre-registered rules

Each is a keep-or-drop rule committed before the measurement it judges, with `decide()`
applying it. They exist so a verdict cannot be chosen after seeing the numbers.

| File | What it does |
|---|---|
| `dev/verdicts/flag.py` | The flag-alphabet rule. |
| `dev/verdicts/root_count.py` | The start-state training-count rule (kept: entries). |
| `dev/verdicts/feature_set.py` | The eight-feature rule (dropped). |
| `dev/verdicts/feature_set_hybrid.py` | The eight features plus `packet_count`, judged by the same rule (kept). |
| `dev/verdicts/load_behavior.py` | The load-versus-behavior alert rule (dropped). |
| `dev/verdicts/cv.py` | The cross-validated calibration rule (dropped). |
| `dev/experiments/pdfa_sweep.py` | The PDFA experiment CLI, one `flag_stats` row per capture stratum. `--flags` adds TCP SYN/RST presence to the symbol; default is the old alphabet. |
| `dev/experiments/pcap_diff.py` | Regenerates every sponsor packet CSV from its capture file and diffs the two row for row, plus the window tables. Writes `outputs/pcap_diff.csv`. Reads every capture, so `demo.py` only summarizes the last run. |

## The other files

| File | What it does |
|---|---|
| `dev/tests.py` | All unit tests, for the shipped code and for the experiments and verdicts. Runs from any directory. |
| `dev/statemachine.py` | **A compatibility re-export, not a module with logic.** It keeps the name `statemachine` resolving for the experiments and tests that still use it; the code is `methods/pdfa.py` and `methods/scores.py`, and shipped code imports those directly. Run as a script it is the PDFA sweep. |
| `dev/PROGRESS.md` | Why the design is what it is: decisions, retractions, what is not claimed, what is next. Paths in it are as they were when written. |
| `dev/REARCHITECTING.md` | The plan and record of splitting the original scripts into the four layers. |
| `dev/feature_research.ipynb` | The exploratory notebook behind the feature set. |

## Run it

```bash
cd Threat_Detection
.venv/bin/python dev/tests.py                                       # the unit suite
.venv/bin/python dev/experiments/sweep.py                           # all 88 captures, about 8 seconds
.venv/bin/python dev/experiments/sweep.py --groups volume,size_timing,diversity,flags,protocol --out ablation_results.csv
.venv/bin/python dev/experiments/compare.py
.venv/bin/python dev/experiments/feature_value.py
.venv/bin/python dev/experiments/pdfa_sweep.py                      # PDFA sweep, 42 rows, about 13 seconds
.venv/bin/python dev/experiments/pdfa_sweep.py --method ptcp --out statemachine_sweep_ptcp.csv
.venv/bin/python dev/experiments/flag_scores.py                     # both alphabets' window scores, AUROC, verdict chart
.venv/bin/python dev/experiments/windowed_scores.py                 # the windowed SEQUENT score on every stratum
.venv/bin/python dev/experiments/cv_calibration.py                  # cross-validated calibration and its verdict
.venv/bin/python dev/experiments/feature_set.py [--rule hybrid]     # all 13 features against the candidate set
.venv/bin/python dev/experiments/load_behavior.py                   # load channel against behavior channel

.venv/bin/python dev/experiments/pcap_diff.py                       # all 88 captures regenerated and diffed
.venv/bin/python dev/experiments/pcap_diff.py --max-gb 0.2          # only the 64 captures under 0.2 GB, for quick checks
.venv/bin/python dev/experiments/pcap_diff.py --report              # summary of the last run, no Drive needed
```

`sweep.py` writes `outputs/sweep_summary.png` and `outputs/detection_gap.png`; `flag_scores.py`
writes `outputs/alphabet_verdict.png` alongside `flag_auc.csv`.

The two sweeps do not have the same row count, and the gap is not missing captures.
`sweep_results.csv` covers both capture methods and holds 88 rows. `statemachine_sweep.csv` (from `pdfa_sweep.py`)
runs one method per invocation, so 44 strata, and excludes two: the quarantined zero-timestamp
capture (`nginx attack / pod-robot-controller`; see "Capture to packet rows" for its cause) and `injection attack / router-flannel`, which
has too few flows left after boundary-crossing segments are dropped. That leaves 42. Run it
twice, once per method, to compare against the 88-row file.
