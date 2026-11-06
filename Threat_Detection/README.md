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

`core/data_io.py` → `core/features.py` → `core/detectors.py` → `core/reporting.py`. Nothing
downstream reaches back upstream, and none of the four import `local_paths.py`, so they are
portable and testable on their own. That one-way arrow is enforced by a test, not by
convention: `core/` may not import `methods/`, `experiments/`, `verdicts/`, `viz/`,
`convert/`, `demo`, `metrics`, `statemachine` or `local_paths`.

```
core/          the subsystem. This is what goes into the project.
methods/       the second detection method, a learned automaton.
experiments/   one measurement per module. The evidence.
verdicts/      keep-or-drop rules, committed before the measurement they judge.
viz/           the interactive visualization page.
convert/       capture files -> the sponsor's packet CSVs.
```

## What each file is

**`core/` and `methods/` are the subsystem.** They are what goes into the project; everything
below them is the evidence that it works, the rules it was judged by, and the pages it is
presented on. `core` imports nothing outside itself.

### The subsystem

| File | What it does |
|---|---|
| `core/__init__.py` | The front door, and the whole subsystem in six calls: `load_capture` → `make_windows` → `split_reference` → `build_detector` → `pipeline` → `annotate`. Its docstring is the shortest correct description of this folder. |
| `core/data_io.py` | The input format and where output goes. Names every capture, reads the packet columns, checks the timebase and snaplen saturation, builds and caches the manifest, resolves `outputs/`. |
| `core/features.py` | Packets → one row per second. The 13 features, the ablation groups, and the temporal train/held-out split. Stateless: no baseline, no thresholds, no detection. |
| `core/detectors.py` | Every detection method behind one interface: `fit` → `calibrate` → `score` → `flag`, with optional `explain`. The z-score baseline is median + MAD. Add one by writing a class and adding it to `REGISTRY`. |
| `core/evaluation.py` | How a result is judged, in one place: the 70/30 split, the six bulk-transfer files that never calibrate, and the warm-up window. |
| `core/reporting.py` | Console reports, charts, the `SHOWCASE.md` handover file, and the event log the response side reads. Takes results, renders them; computes no detection logic. Pins matplotlib to `Agg`, so nothing here opens a window. |
| `methods/pdfa.py` | PDFA anomaly detection after Cao et al. (ARES 2022), learning half: packet flows to symbols, the prefix tree, ALERGIA state merging, the automaton. |
| `methods/scores.py` | The scoring half of the same method: trace likelihood, and SEQUENT's cumulative and windowed frequency scores with their cutoffs. |
| `methods/sweep.py` | The PDFA experiment CLI, one `flag_stats` row per capture stratum. `--flags` adds TCP SYN/RST presence to the symbol; default is the old alphabet. |

### The evidence

Each runs one measurement and writes its own CSV. `demo.py` runs these as documented; they
also run on their own, as a script or with `-m`.

| File | What it does |
|---|---|
| `experiments/sweep.py` | Every capture against its own matched benign reference. `--groups` runs the feature-group ablation. |
| `experiments/compare.py` | Every registered detector on the same windows, reference, and split. |
| `experiments/feature_value.py` | Per-feature value: threshold-free separation (auc) and detection at a 5% benign budget. |
| `experiments/flag_scores.py` | Per-window anomaly scores under the plain and flag alphabets, plus AUROC and matched-rate detection per stratum. Prints the pre-registered verdict. |
| `experiments/windowed_scores.py` | The visualization page's detector, the windowed SEQUENT score, on every stratum, calibrated exactly as the page is. Quotes the windows each cutoff rests on and the realised benign rate beside every number. Prints the root-count verdict. |
| `experiments/cv_calibration.py` | Cross-validated calibration of the windowed score (every benign window scored out of fold) against the split. Prints the pre-registered verdict: drop, so the split stays. |
| `experiments/feature_set.py` | All 13 features against the eight without volume and size/timing: persistent alerts, AUROC and detection at a 5% benign budget per scenario. Prints the pre-registered verdict: drop; `--rule hybrid` runs the nine-feature candidate (kept). |
| `experiments/load_behavior.py` | Load channel (z-score) against behavior channel (windowed SEQUENT): does the second gate the first on the bulk taps and the attacks. Prints the pre-registered verdict: drop. |
| `experiments/metrics.py` | One `auroc`, one `detection_at_rate`, one `detection_at_budget`, with the two missing-data policies stated rather than accidental. Imports nothing from the project, so any experiment can use it. |

### The pre-registered rules

Each is a keep-or-drop rule committed before the measurement it judges, with `decide()`
applying it. They exist so a verdict cannot be chosen after seeing the numbers.

| File | What it does |
|---|---|
| `verdicts/flag.py` | The flag-alphabet rule. |
| `verdicts/root_count.py` | The start-state training-count rule (kept: entries). |
| `verdicts/feature_set.py` | The eight-feature rule (dropped). |
| `verdicts/feature_set_hybrid.py` | The eight features plus `packet_count`, judged by the same rule (kept). |
| `verdicts/load_behavior.py` | The load-versus-behavior alert rule (dropped). |
| `verdicts/cv.py` | The cross-validated calibration rule (dropped). |

### The presentation

| File | What it does |
|---|---|
| `viz/page.py` | The state machine as one interactive page, `outputs/state_machine.html`: the inferred cluster, ALERGIA learning step by step, and a replay of held-out benign and every attack through the windowed SEQUENT scorer (the 8 s anomaly clock, forgetting, release). One page carries every steady capture tap (`--vantages` to choose; `--vantage` picks the one it opens on): click a tap on the map or use the header picker to switch the learning and detection acts, and Act 3's *Across taps* view lines one scenario up at every tap on a shared capture-time axis. Self-contained (about 3 MB for the 8 steady taps; past 15 MB the other taps' per-trace breakdown is dropped); opens offline. `demo.py` item 10. The renderer is `viz/template/`. Bulk-transfer vantages (`core/evaluation.BULK_LABELS`) never set a cutoff, so they are left out unless `--allow-bulk`, and the page then marks their verdicts as inspection only. Each cutoff shows how many held-out windows it rests on and how often it actually flags them; capture text is HTML-escaped in the bundle. |
| `viz/cluster.py` | The k3s cluster's shape inferred from benign traffic: nodes, pods (including host-network ones), services, conversations and where each capture listened. |
| `viz/layout.py` | Computed positions for the page: the prefix tree as an icicle, the learned machine in columns. |

### Capture conversion

Capture files to the packet CSVs `core/data_io.py` reads. Upstream of the subsystem and
independent of it; see "Capture to packet rows" below.

| File | What it does |
|---|---|
| `convert/read.py` | The two capture containers (pcap, pcapng) to raw frames. Format from the magic number, never the extension. Reads at most 256 bytes of each frame. |
| `convert/rows.py` | Frames to the sponsor's 34-column packet rows, written as their CSV. Copies the sponsor's own quirks on purpose; `SPONSOR_QUIRKS` in its docstring lists them. |
| `convert/diff.py` | Regenerates every sponsor packet CSV from its capture file and diffs the two row for row, plus the window tables. Writes `outputs/pcap_diff.csv`. Reads every capture, so `demo.py` only summarizes the last run. |

### The entry surface

| File | What it does |
|---|---|
| `demo.py` | A menu over the whole subsystem. Items 1-3 are presentations (pair demo, plain-language walkthrough, state machine); 4-7 are the experiments above; 8 regenerates every artifact; 9 runs the tests; 10 builds the interactive state-machine visualization page; 11 summarizes the last capture-conversion diff. |
| `statemachine.py` | **A compatibility re-export, not a module with logic.** It exists so the name `statemachine` keeps resolving for older callers; the code is `methods/pdfa.py` and `methods/scores.py`. New code imports those. |
| `tests.py` | All unit tests. |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. Only the entry points and experiments read it, never `core/`. |
| `requirements.txt` | The pinned runtime: Python 3.11 with numpy, pandas, matplotlib and scikit-learn at the versions the numbers were measured under. |
| `PROGRESS.md` | Why the design is what it is: decisions, retractions, what is not claimed, what is next. |
| `EVENT_LOG.md` | The detection → response event contract (`LogV1`, carries the capture-relative second). |
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
10  Visualization   the state machine learned and replayed, as an interactive page
11  Pcap diff       regenerated packet rows against the sponsor CSVs (last run's summary)
```

Underneath the menu, the same commands run directly:

```bash
.venv/bin/python -m unittest tests                              # 276 tests
.venv/bin/python experiments/sweep.py                           # all 88 captures, about 8 seconds
.venv/bin/python experiments/sweep.py --groups volume,size_timing,diversity,flags,protocol --out ablation_results.csv
.venv/bin/python experiments/compare.py
.venv/bin/python experiments/feature_value.py
.venv/bin/python statemachine.py                                # PDFA sweep, 42 rows, about 13 seconds
.venv/bin/python statemachine.py --method ptcp --out statemachine_sweep_ptcp.csv
.venv/bin/python experiments/flag_scores.py                     # both alphabets' window scores, AUROC, verdict chart
.venv/bin/python experiments/windowed_scores.py                 # the windowed SEQUENT score on every stratum
.venv/bin/python experiments/cv_calibration.py                  # cross-validated calibration and its verdict
.venv/bin/python viz/page.py                                    # interactive page, every steady tap; --vantage pod-nginx opens on it

.venv/bin/python convert/diff.py                                # all 88 captures regenerated and diffed
.venv/bin/python convert/diff.py --max-gb 0.2                   # only the 64 captures under 0.2 GB, for quick checks
.venv/bin/python convert/diff.py --report                       # summary of the last run, no Drive needed
```

`sweep.py` writes `outputs/sweep_summary.png` and `outputs/detection_gap.png`; `flag_scores.py`
writes `outputs/alphabet_verdict.png` alongside `flag_auc.csv`.

The two sweeps do not have the same row count, and the gap is not missing captures.
`sweep_results.csv` covers both capture methods and holds 88 rows. `statemachine_sweep.csv`
runs one method per invocation, so 44 strata, and excludes two: the quarantined zero-timestamp
capture (`nginx attack / pod-robot-controller`; see "Capture to packet rows" for its cause) and `injection attack / router-flannel`, which
has too few flows left after boundary-crossing segments are dropped. That leaves 42. Run it
twice, once per method, to compare against the 88-row file.

Generated files always land in `Threat_Detection/outputs/`, whichever directory you run
from. Delete `outputs/capture_manifest.csv` after any dataset change, or the sweep scores
the previous inventory.

## Capture to packet rows

`pcap_read.py` and `pcap_rows.py` turn a capture file into the same 34-column packet CSV
the sponsor supplied, so a capture taken today can be windowed and scored with no dataset in
between. `pcap_diff.py` is the proof: it regenerates every sponsor CSV from its capture and
diffs the two.

What the corpus actually is, read from the files rather than their names:

- Every capture is named `.pcapng`, but only the 44 ptcp ones are pcapng (ptcpdump v0.37.0,
  Ethernet link layer, nanosecond timestamps). The 44 tcp ones are classic pcap (Linux cooked
  capture v2, microsecond timestamps). The reader goes by the magic number.
- `benign/` and `injection attack/` keep their captures flat under `pcapng files/`; the
  other two nest them under `{tcp,ptcp}/<level> level/`.
- 14 capture files end mid-record, their tails filled with zeros. In
  `injection attack/node-child4-ptcp` the real data stops at 4.58 GB of a 10.8 GB file. The
  sponsor's CSVs were made from these same cut files.

The converter copies the sponsor's conversion where it is surprising rather than correcting
it, so the rows match; `SPONSOR_QUIRKS` in `pcap_rows.py` lists each rule with its evidence.
The one deliberate exception is a zero-filled tail, which the reader stops at instead of
reading zeros as packets.
The ones that change a counted feature: `is_http` matches port 80 or 8080 on either side, and
an ICMP error message takes its ports from the packet it quotes.

Measured 2026-11-03 over all 88 captures, 461 seconds: every regenerated row identical, cell
for cell, to the sponsor's row at the same position, and the window tables equal on 87.
`pcap_diff.py` counts 74 captures Tier-A exact and 13 "identical but cut short at the source",
because a file cut mid-record is never called complete.

The 88th is the quarantined `nginx attack / pod-robot-controller / tcp`, and the converter
explains it. Its recording ends at frame 155,603, 3.56 GB into a 3.75 GB file; the rest is
zeros. The sponsor's conversion read 64,853 of those zero records as packets with timestamp
0, which is what made the capture unusable. The converter stops at the first zero record, so
its version of this capture is 155,603 real frames and can be windowed.

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
