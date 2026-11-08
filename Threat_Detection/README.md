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
convention: `core/` may not import `methods/`, `viz/`, `convert/`, `demo` or `local_paths`,
nor anything in `dev/` (`experiments`, `verdicts`, `metrics`, `statemachine`).

```
core/          the subsystem. This is what goes into the project.
methods/       the second detection method, a learned automaton.
viz/           the interactive visualization page.
convert/       capture files -> the sponsor's packet CSVs.
dev/           how it was built and judged: experiments, verdicts, tests, design notes.
```

This README covers what ships. Everything under `dev/` (the measurements, the keep-or-drop
rules, the unit suite, the progress log and the rearchitecting notes) is mapped in
[`dev/README.md`](dev/README.md). Nothing outside `dev/` imports from it.

## What each file is

**`core/` and `methods/` are the subsystem.** They are what goes into the project; everything
below them is how it is presented and how captures are fed to it. `core` imports nothing
outside itself.

### The subsystem

| File | What it does |
|---|---|
| `core/__init__.py` | The front door, and the whole subsystem in six calls: `load_capture` → `make_windows` → `split_reference` → `build_detector` → `pipeline` → `annotate`. Its docstring is the shortest correct description of this folder. |
| `core/data_io.py` | The input format and where output goes. Names every capture, reads the packet columns, checks the timebase and snaplen saturation, builds and caches the manifest, resolves `outputs/`. |
| `core/features.py` | Packets → one row per second. The 13 features, the 9 the detectors read by default (`DETECTION_FEATURES`), the ablation groups, and the temporal train/held-out split. Stateless: no baseline, no thresholds, no detection. |
| `core/detectors.py` | Every detection method behind one interface (each reads `DETECTION_FEATURES` unless built with `features=None`): `fit` → `calibrate` → `score` → `flag`, with optional `explain`. The z-score baseline is median + MAD. Add one by writing a class and adding it to `REGISTRY`. |
| `core/evaluation.py` | How a result is judged, in one place: the 70/30 split, the six bulk-transfer files that never calibrate, and the warm-up window. |
| `core/reporting.py` | Console reports, charts, the `SHOWCASE.md` handover file, and the event log the response side reads. Takes results, renders them; computes no detection logic. Pins matplotlib to `Agg`, so nothing here opens a window. |
| `methods/pdfa.py` | PDFA anomaly detection after Cao et al. (ARES 2022), learning half: packet flows to symbols, the prefix tree, ALERGIA state merging, the automaton. |
| `methods/scores.py` | The scoring half of the same method: trace likelihood, and SEQUENT's cumulative and windowed frequency scores with their cutoffs. |

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

### The entry surface

| File | What it does |
|---|---|
| `demo.py` | A menu over the whole subsystem. Items 1-3 are presentations (pair demo, plain-language walkthrough, state machine); 4-7 run experiments from `dev/`; 8 regenerates every artifact; 9 runs the tests (`dev/tests.py`); 10 builds the interactive state-machine visualization page; 11 summarizes the last capture-conversion diff. |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. Only the entry points and experiments read it, never `core/`. |
| `dev/` | Development material, not shipped: experiments, verdicts, tests and design notes. Mapped in `dev/README.md`. |
| `requirements.txt` | The pinned runtime: Python 3.11 with numpy, pandas, matplotlib and scikit-learn at the versions the numbers were measured under. |
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

Items 4-7, 9 and 11 run scripts in `dev/`; in a copy without `dev/` they say so and skip.
The page also builds directly:

```bash
.venv/bin/python viz/page.py        # interactive page, every steady tap; --vantage pod-nginx opens on it
```

The experiments, the tests and the capture diff run from `dev/`; their commands are in
`dev/README.md`.

Generated files always land in `Threat_Detection/outputs/`, whichever directory you run
from. Delete `outputs/capture_manifest.csv` after any dataset change, or the sweep scores
the previous inventory.

## Capture to packet rows

`convert/read.py` and `convert/rows.py` turn a capture file into the same 34-column packet
CSV the sponsor supplied, so a capture taken today can be windowed and scored with no dataset in
between. `dev/experiments/pcap_diff.py` is the proof: it regenerates every sponsor CSV from its
capture and diffs the two.

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
it, so the rows match; `SPONSOR_QUIRKS` in `convert/rows.py` lists each rule with its evidence.
The one deliberate exception is a zero-filled tail, which the reader stops at instead of
reading zeros as packets.
The ones that change a counted feature: `is_http` matches port 80 or 8080 on either side, and
an ICMP error message takes its ports from the packet it quotes.

Measured 2026-11-03 over all 88 captures, 461 seconds: every regenerated row identical, cell
for cell, to the sponsor's row at the same position, and the window tables equal on 87.
`dev/experiments/pcap_diff.py` counts 74 captures Tier-A exact and 13 "identical but cut short at the source",
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

Then `build("my_detector")`. `dev/experiments/compare.py` picks it up with no changes, because it iterates
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
  those windows rather than by normal traffic. `dev/PROGRESS.md` has the reasoning.
- A window is flagged when its score passes the cutoff, and an alert needs
  `PERSISTENCE_WINDOW` flagged windows in a row.
- Missing or mismatched data is reported as insufficient, never as normal.
- Learned models take their cutoff from held-out benign windows, so every detector is
  compared at the same false-alarm budget.
- A capture truncated by the recorder's snaplen is still scored, but `at_snaplen` in the
  manifest records the fraction of packets clipped, and those captures' length-based
  features are not comparable to the unclipped ones.
