# Subsystem 2: why the design is what it is

This file records decisions, corrections, and what is not claimed. It deliberately does
not carry result tables: every measured number is regenerated into `outputs/SHOWCASE.md`
and the CSVs beside it by `demo.py`. Copying numbers into prose is how the two versions
drift apart, and they already did once.

Started 2026-10-09 for the TA checkpoint. Numbers in it were measured at a 3.0 sigma
cutoff; commit d4c73a1 lowered `THRESHOLD` to 2.5, so the figures below are the ones
re-derived at 2.5. Quote this file for reasoning and `outputs/SHOWCASE.md` for values.

## Where the files below live now

This file is a record, so it names modules the way they were named when each decision was
made. The code has since been sorted by role; nothing changed behaviour, only the path.

`data_io` `features` `detectors` `evaluation` `reporting` → `core/<same name>.py`
`statemachine` (the method) → `methods/pdfa.py` + `methods/scores.py`; `statemachine.py` at
the top level is now a re-export shim, so older references to it stay valid.
`sweep` `compare` `feature_value` `flag_scores` `windowed_scores` `cv_calibration` `metrics`
→ `experiments/<same name>.py`
`flag_verdict` → `verdicts/flag.py`; `root_verdict` → `verdicts/root_count.py`;
`cv_verdict` → `verdicts/cv.py`
the old page module → `viz/page.py`; `cluster` `layout` → `viz/<same name>.py`
`pcap_read` `pcap_rows` `pcap_diff` → `convert/read.py` `convert/rows.py` `convert/diff.py`

See `README.md` for the map with descriptions.

## The correction that still stands

Earlier drafts called the high flag rates on a few capture points a calibration problem.
It is not. Three of the eleven benign vantages (`router-any`, `node-child4`,
`pod-robot-controller`) contain a bulk-transfer regime change: normal traffic steps from
tens of KB/s to hundreds of MB/s partway through the recording and stays there. At
`router-any` the change begins at second 52, which is right where the 70/30 temporal split
cuts. A baseline fitted on the first 70% of a recording *should* flag the regime that
begins in the last 30%.

So those fractions are drift detection working, not a false alarm, and the plan to tune a
per-vantage cutoff until they fell was wrong: it would have suppressed a real change in
the cluster. The defensible split is by regime, not by vantage. Current figures, 2.5
sigma, both capture methods: **0.43 of held-out windows on the 16 steady captures (max
0.79), 0.93 on the 6 bulk-transfer captures**, and **0.68 / 0.54 / 0.70 detection on
injection / lidar / nginx** over the steady strata. Name which group produced a number
when you quote it.

## The cutoff change is the newest thing that moved

`THRESHOLD` went from 3.0 to 2.5 in d4c73a1 ("lower detection threshold to 2.5 for higher
sensitivity"). It was not re-measured against the demo pair at the time, and the effect is
large: the single pair the walkthrough narrates (benign `pod-nginx` against the nginx
attack capture) now flags **9 of 19 unseen benign seconds with 3 persistent alerts**, and
**54 of 60 attack seconds with 50 alerts**. At 3.0 the same pair read 3 of 19 with no
alerts. Detection rose, so did the false alarms on that pair, and the pooled totals above
moved with it.

That is the trade the constant buys, and the number to watch if it moves again. Two
consequences worth holding on to: a fixture that sits near a constant goes red silently
when the constant moves (one did, and now passes its own cutoff), and any doc quoting the
old 3.0 figures is stale.

## What changed since the 2026-10-06 version

- **The z-score baseline is now median + MAD, not mean + std** (`detectors.py`,
  `MAD_TO_SIGMA = 1.4826` so the sigma cutoff keeps its meaning). A mean/std summary is
  set by the bulk-transfer windows; median/MAD describes the dominant mode. The mean/std
  version's inflated std (28 MB against a 50 KB median) was accidentally wide enough to
  span both regimes, which is why it looked less alarming and was less honest. Switching
  to robust statistics raised the pooled benign figure because it stopped hiding the drift.
  Robustness is not a general good: on a non-stationary series it discards the evidence
  that the world changed.
- **Snaplen saturation is measured and reported, not assumed** (`data_io.py`,
  `at_snaplen`). 22 of the 88 captures are truncated at the 65535-byte tcpdump ceiling
  (35-59% of packets at the wall); the other 66 are clean. The 22 are the same three
  vantages that carry the regime change. Their length measurements are clipped by the
  capture tool and are not comparable to the other eight vantages. Payload is truncated
  too (65,483 bytes at the wall), so `payload_bytes` fixes overlay overhead, not the
  snaplen.
- **Five features added from the 34-column packet set** (`features.py`): `payload_bytes`,
  `http_count`, `dns_count`, `https_count`, `http_frac`, in a new `protocol` ablation
  group. The CSVs carry 34 fields; the pipeline now reads 12. Protocol identity was a
  CONOPS-named category with zero features before this.
- **`sweep.py` writes `capture_manifest.csv`**, which the previous version's docs claimed
  it wrote but no code did. The sibling scripts read that cache, so a stale one silently
  scores the wrong inventory; delete it or pass `--manifest` after any dataset change.
- **One entry point.** `detector.py`, `walkthrough.py` and `statemachine_demo.py` were
  three files showing the same subsystem from three angles; they are now items 1-3 of
  `demo.py`. The experiments (`sweep.py`, `compare.py`, `feature_value.py`) stay separate
  because each writes one CSV, and the menu runs them unchanged.
- The spike plots shown before 2026-10-06 remain retracted. Every number above is
  regenerated by `demo.py`, item 8.

## Capture inventory

88 captures = 4 scenarios x 11 labels x 2 capture methods. Levels: 20 pod, 16 node, 8
router per method. All 88 parsed; 1 unusable:
`nginx attack/csv files/tcp/pod level/pod-robot-controller-tcp.csv` has 64,853 of its
220,456 rows with `ts = 0.0` (frames 155,604 onward), which makes 1-second binning try to
build ~1.77 billion windows. It is quarantined with a stated reason, not zeroed. That is
why a sweep reports 87 scored captures out of 88.

Capture spans are NOT uniform: benign captures run 51.3-67.7 s, lidar attacks 53.5-68.9 s,
nginx attacks 42.7-87.9 s, injection attacks 2.7-63.6 s. Across all 87 usable captures the
span is 2.7-87.9 s. The short captures are injection attacks, not benign ones, so the
injection column is computed over fewer windows and is not comparable row to row. Window
count is `floor(span_s) + 1` and is derivable from the manifest without re-reading packets.

## Feature set: a candidate pool, now measured

The features were not selected by a requirement or a plan. They trace to Team CONOPS §3.3,
which names the categories to observe — "source and destination addresses, communication
protocols, port usage, packet sizes, and connection frequency", plus traffic volume — and
then delegates the choice: "the specific traffic characteristics used in the analysis will
depend on what is available from the existing telemetry collection system". The dataset's
34 packet columns decide the concrete form.

Of the original 8, five mapped to a CONOPS category and three (`mean_iat`, `syn_count`,
`rst_count`) came from columns rather than the CONOPS list. Communication protocols and the
source side of addresses and ports had no feature at all; the 5 added fill the protocol
gap. The source side (`src_ip`, `src_port`) is still unread.

What the measurement says, in one line each (tables in `outputs/feature_value.csv`, 845
rows; values unchanged by the cutoff move):

1. `rst_count` is the worst ranker (auc 0.49-0.61) and the best single trigger in all three
   scenarios. RST is almost always zero, so any RST is far from normal — a cheap precision
   trigger, not a graded score. Ranking value and trigger value are different measurements.
2. `syn_count` is worthless on both: auc at chance, 0 of 22 strata above 0.75, lowest
   detection. First drop candidate.
3. `mean_iat` ranks below chance on injection (0.291) and flags 0.05 of nginx windows.
   Second drop candidate, though it is mid-pack on lidar (0.545).
4. `unique_dst_ips` is the strongest ranker on nginx (0.791, above 0.75 in all 22 strata)
   and still weak as a lone trigger (0.459); `mean_packet_size` is the most consistent
   single feature across all three scenarios.
5. The new protocol features earn their slot on nginx: `http_count` auc 0.794 and 0.703 of
   nginx windows flagged at the 5% budget, second-best trigger in the set. `http_frac` is
   the vantage-stable form and the one to carry into cross-vantage work. `https_count` does
   not earn a slot — there is little HTTPS in this testbed.
6. `payload_bytes` underperforms `total_bytes` as a ranker and does not reduce false alarms
   on its own. Keep it for cross-vantage comparability, not for detection strength.
7. `packet_count` and `total_bytes` move together and both invert on lidar — a redundancy
   worth measuring before keeping both.

A feature earns its place if it clears the 5% budget test on at least one scenario,
survives the redundancy check, and can be obtained at a vantage worth instrumenting.
Nothing is dropped until all three are measured.

Adding features does not lower the false-alarm rate, measured: `payload_bytes` plus the
protocol features moved the benign mean up, not down, because the non-stationary baseline
is the real driver. And per-vantage calibration is the wrong lever for the same reason: the
ablation localises the false alarm to `volume` and `size_timing` on the three drifting
captures, while `diversity`, `flags` and `protocol` stay low everywhere. The one-command
test of whether detection survives without the length features is
`sweep.py --groups diversity,flags,protocol`.

## What I am not claiming

- Generalization from 60-second captures, or a calibrated false-alarm rate. Each capture is
  ~42-69 s, so ~15-20 held-out benign windows per stratum; at that size a 0/19 result only
  bounds the true rate at roughly 15%.
- That a flag is an attack.
- That the bulk-transfer captures' high flag rate is a defect.
- Cross-vantage comparability of the length-based features.
- Network-origin attribution from resource metrics, or any live connection to Subsystem 1's
  baseline or Subsystem 3's response. Nothing here is wired to S1 or S3.
- That a learned model is needed. At a matched 5% budget the SVM finds more than the
  forest, and the uncalibrated z-score still finds the most while also flagging the most
  benign windows; nothing measured so far justifies replacing the transparent detector.

## Outstanding problems

- **The flagged fractions have uneven denominators.** The state-machine sweep prints a benign
  mean of 0.033 over 11 strata, but the windows behind that mean are not comparable across
  scenarios: 690 benign windows against 240 injection windows in the tcp sweep, because 18 of
  the 22 injection strata are under 32 s and one holds 3 windows. A mean over strata weights a
  3-window capture the same as an 80-window one. Per-scenario window counts belong beside every
  such number, and the injection column is not comparable to the others.

- **`evaluation.py` names three policies the sweeps do not enforce yet.** The visualization page
  (`viz/page.py`) now enforces two of them for the windowed scorer: a `BULK_LABELS` vantage is
  refused unless `--allow-bulk` and then marked inspection only, and an alert is released only
  after `CLEAR_WINDOWS` scored clean windows. Its cold-clock warm-up is the forgetting window
  itself (8 s), not `WARMUP_WINDOWS`, which still has no consumer. The sweeps (`sweep.py`,
  `statemachine_rows`) still score bulk labels and never clear an incident; wiring the rules in
  there drops three labels and changes the numbers, so it lands with the windowed scorer's own
  sweep.

- **The windowed scorer's cutoffs rest on very few windows.** On the eight steady tcp taps the
  cutoff is set from 3 to 16 scored one-second held-out windows (a window with no finished
  trace is no evidence, and the first held-out window, which mixes in training traces, is
  left out), so the 95th-percentile cutoff sits next to the held-out maximum. On those same
  windows it flags between 0% and 33% (router-flannel 1 of 3, node-child2 and node-gchild9
  1 of 8, pod-robot-hardware 0 of 9) against a nominal 5%. The visualization page prints the count and the realised rate beside each
  cutoff. The fix is more benign recording per vantage, the same blocker as calibration in
  general.

- **Resolved: the frequency scorers counted the start state twice in training.** Training
  counts came from `node.visits`, which for the start state includes every trace start that a
  test trace never adds (pod-lidar: 702 against 554 entries). The pre-registered rule kept the
  fix; the scorers now count entries. See "Root-count verdict" below.

## Next: feature selection and the interface question

| Candidate feature | Source column | Status |
|---|---|---|
| packet_count, total_bytes, payload_bytes | `ts`, `frame_len`, `tcp_payload_len`, `udp_length` | implemented; volume carries detection, noisy; payload kept for vantage comparability |
| mean_packet_size, mean_iat | `frame_len`, `iat` | implemented; mean_packet_size is the most consistent, mean_iat is a drop candidate |
| unique_dst_ips, unique_dst_ports | `dst_ip`, `dst_port` | implemented; quiet but weak as lone triggers |
| syn_count, rst_count | `tcp_syn`, `tcp_rst` | implemented; rst is the best trigger, syn is the worst ranker |
| http_count, http_frac | `is_http` | implemented, new; second-best trigger on nginx |
| dns_count | `is_dns` | implemented, new; 0 of 22 strata above 0.75 auc |
| https_count | `is_https` | implemented, new; does not earn a slot, little HTTPS in this testbed |
| unique_src_ips, unique_src_ports | `src_ip`, `src_port` | candidate, still unread |
| proto / icmp shares | `proto`, `icmp_type` | candidate |
| flag mix (fin/psh/ack) | `tcp_fin`, `tcp_psh`, `tcp_ack` | candidate |
| ttl_or_hlim, ip_version | `ttl_or_hlim`, `ip_version` | candidate; expect flat under a flannel overlay |

The question that needs an answer from the sponsor before more features get built: every
feature in that table exists only in the packet-level CSVs. Subsystem 1's Prometheus surface
as configured exposes pod CPU/memory and node memory, with network RX marked removed and
network TX and node CPU needing retest, so the FSR's "baseline to detection" interface has
no source for 7 of the original 8 implemented features. Either the detection path consumes
packet captures at the observation points, or it is limited to coarse resource deviations,
which cannot support network-origin diagnosis.

## Two-minute version, if you have to say it out loud

"What my part does: turn raw traffic into a diagnosis another part can act on. It cuts each
recording into one-second slices, learns what normal looks like from normal traffic only,
and flags seconds that sit far from normal.

Last week I said the alarm level was not calibrated, and that three capture points were
flagging up to eighty-five percent of normal traffic. That framing was wrong. Those three
points are where the recorder hits its own size limit, and where normal traffic changes
character mid-recording, from about fifty kilobytes a second to hundreds of megabytes. A
detector is supposed to notice that. So the honest figure is 0.43 on the sixteen capture
points whose traffic stays steady, and 0.93 on the six that change regime, reported
separately. Detection over the steady points is 0.68 on injection, 0.54 on lidar and 0.70
on the web attack. Lowering the cutoff from three to two-and-a-half bought detection and
cost false alarms: on the single pair I demo, normal seconds flagged went from three of
nineteen to nine, and attack seconds from fifty-one to fifty-four.

What is next: the real blocker is that we have one benign recording per capture point.
Per-point calibration needs several, or there is nothing stationary to calibrate against.
That is a question for the sponsor."

## Flag verdict: the rule was fixed before the measurement (2026-10-20)

The flag alphabet is judged by a rule committed in `1c83add`, before any AUROC existed:

- keep only if `pod-lidar` on `lidar attack` gains at least 0.10 AUROC over the plain
  alphabet, with detection at the plain model's realised benign fraction no worse;
- keep only if neither `router-any` nor `node-child4` on `injection attack` loses more than
  0.05 AUROC;
- a missing stratum is `undecidable`, never a silent keep.

The constants are `KEEP_AUC_GAIN` and `MAX_OTHER_LOSS` in `flag_verdict.py`, and `decide()`
applies them. A near miss is a drop and gets reported as one; the thresholds are not
renegotiated after the numbers arrive.

Measured 2026-10-20 with `flag_scores.py`, 31 strata, tcp: verdict **drop**. Target
`pod-lidar/lidar attack` AUROC 0.868 to 0.868, detection 0.273 to 0.273 at a realised benign
rate of 0.133, so the raw-fraction gain on that stratum (0.531 to 0.578) was a threshold
shift, not better ranking. `node-child4/injection attack` lost 0.035 AUROC and
`router-any/injection attack` lost 0.051, the latter above the 0.05 allowance. One trap the
table shows: `router-any` detection at the matched rate rose 0.188 to 0.469 while its AUROC
fell, because with 26 benign windows a moved threshold can buy detection without better
ranking. That is why the rule is written on AUROC.

Separate measurement, worth keeping: the nominal 5% cutoff is applied to trace scores, but a
window flags when its most anomalous trace clears the cutoff, so the median realised benign
window rate across strata is 0.217, not 0.05. Quote the realised rate beside any detection
number.

## The windowed score, measured on every stratum (2026-11-03)

`viz/page.py` presents the windowed SEQUENT frequency score (the 8 s `FORGET_SECONDS` clock) as
its detector, but until now only the likelihood detector had a sweep. `windowed_scores.py`
writes `outputs/windowed_sweep.csv`: 174 rows, one per (label, scenario, method, training
count source), every label in both capture methods. One stratum is excluded and named:
`nginx attack/pod-robot-controller/tcp`, unusable timebase.

How it is measured, and what that costs:

- **Calibration is the page's, exactly.** The whole benign recording runs through one scorer
  so the clock is warm, and the cutoff is the top 5% of the held-out windows after the one
  the split falls in. A test holds the sweep's cutoff equal to the bundle's.
- **The cutoffs rest on 3-16 scored windows** per steady tap, and the realised benign rate is
  measured on those same windows (one benign recording per tap; there is nothing else). It
  runs **0.000-0.333**, median 0.077 tcp and 0.118 ptcp, against the nominal 0.05. Pooled:
  7 of 86 held-out windows flagged on tcp, 8 of 77 on ptcp. `router-flannel` sets its cutoff
  on 3 windows and flags one of them.
- **Missing is missing.** A window no trace ended in enters no rate and no AUROC; it is
  counted in `missing_windows`. On the steady taps, 75 tcp held-out windows are missing
  beside 86 scored, and up to 63 of 88 windows on an attack capture.
- **Attack clocks start cold.** The first 8 windows of an attack capture are warm-up: they are
  flagged and counted (`warmup_flagged`), but detection and AUROC use only warm windows. Most
  injection captures are shorter than 8 s, so 2 of 8 tcp and 4 of 8 ptcp steady injection
  strata have no warm window and no detection number at all.
- **Bulk taps set no cutoff.** The three `evaluation.BULK_LABELS` taps get an AUROC and no
  flag, detection or benign rate, in group `bulk`, outside every figure below.

Steady taps, training counts from entries (the adopted variant). Detection is pooled over
warm windows, at each tap's own realised benign rate:

| method | scenario | strata with warm windows | warm windows | detection | median AUROC | AUROC < 0.5 |
|---|---|---|---|---|---|---|
| tcp | injection | 6 of 8 | 36 | 0.500 | 0.795 | 1 |
| tcp | lidar | 8 of 8 | 285 | 0.347 | 0.628 | 2 |
| tcp | nginx | 8 of 8 | 297 | 0.172 | 0.514 | 4 |
| ptcp | injection | 4 of 8 | 26 | 0.154 | 0.500 | 2 |
| ptcp | lidar | 8 of 8 | 284 | 0.123 | 0.426 | 5 |
| ptcp | nginx | 8 of 8 | 305 | 0.148 | 0.446 | 5 |

What that says: on tcp the windowed score ranks lidar and injection better than chance, and
nginx at chance. On ptcp it ranks attack windows *below* benign ones in most strata. The
best stratum is the one the clock was sized for: `pod-lidar/lidar attack/tcp`, AUROC 0.908,
detection 0.784 at a realised benign rate of 0.071 on 14 windows. The worst named numbers
rest on almost nothing: `node-child1/injection/tcp` reads AUROC 1.000 on one warm window.
The page's headline detector is a lidar detector on tcp, not a general one, and the injection
column is not comparable to the others.

### Root-count verdict: keep the entries fix

The scorers took each state's training count from `node.visits`. For the start state that
includes one visit per training trace start, which a test trace never adds, so its count was
inflated (tcp `pod-lidar`: 702 visits, 554 entries). The start state *is* re-entered at test
time on every tap (entries are non-zero everywhere), so the inflated count reached scores.

The rule was committed in `0d4e0a7` before either variant's AUROC existed (`root_verdict.py`):
keep entries unless a steady stratum loses more than 0.05 AUROC or the steady mean falls by
more than 0.01; fewer than 10 paired steady strata is undecidable.

Measured: **keep**. 42 paired steady strata, mean AUROC change +0.006, worst −0.029
(`pod-nginx/lidar attack/ptcp`, 0.664 to 0.635). Detection on `pod-lidar/lidar attack/tcp`
rose 0.725 to 0.784 and tcp nginx pooled 0.148 to 0.172, with every tap's realised benign
rate unchanged between the variants. Bulk-tap AUROCs rose more (tcp median 0.500 to 0.552),
but bulk strata decide nothing. `statemachine.TRAIN_COUNTS` is now `"entries"`; `"visits"` stays
selectable and its tests still hold. The visualization page shows the scorer's own training count
per state, so the start state now reads its entries, and the page says the trace starts are
not counted.

## Cross-validated calibration: dropped by its own rule (2026-11-03)

The windowed score's cutoffs rest on 3-16 held-out windows per steady tap, the last 30% of one
benign recording. The candidate fix used every benign window out of fold: the recording cut
into 5 contiguous blocks, each block scored on a warm clock by a machine learned from the
other four (kept as separate segments, so no training trace spans the hole), the cutoff set
from all of them, and one machine learned from the whole recording deployed on the page.

The rule was committed in `274cf63` (`cv_verdict.py`) before any of these numbers existed.
`cv_calibration.py` writes `outputs/cv_calibration.csv`. Verdict: **drop**, on every clause.

- **The sample grew 2.9x, not 5x** (median over steady taps; rule asks 3x). Each block's first
  window mixes in training traces and the recording's first 8 s run on a cold clock, so both
  are left out, and many windows hold no finished trace. Per tap: 9 to 50 windows against 3 to 16.
- **Out of fold, the windowed score flags about 11% of benign windows**: 26 of 231 on tcp, 23 of
  205 on ptcp, each block judged against a cutoff set from the other four. The rule's band is
  2-10%. `router-flannel` flags 3 of 9 in both methods.
- **Fold and full machines do not share a scale.** On attack windows, out of sample for every
  machine, they differ by a median 0.43 of the benign interquartile range (rule: 0.25). A
  machine learned from all the data scores differently from one learned from 80%, so a cutoff
  set by the fold machines cannot be carried to the deployed one.
- **Ranking moved both ways.** Over 42 paired steady strata the mean AUROC rose 0.039 and 23
  strata improved, but 18 lost more than 0.05, the worst `node-child2/injection/tcp` (0.392)
  and `pod-lidar/lidar/tcp` (0.908 to 0.565). Those losses mix two changes, a different
  machine and a benign sample three times larger, so they do not say which one costs.

What stays, and what it is worth:

- The split calibration stays; the page and `windowed_scores.py` are unchanged.
- The out-of-fold rate is the first benign false-alarm rate for this detector measured on
  windows that did not set its cutoff. It is a property of fold machines, not of the deployed
  one, but it says the nominal 5% is optimistic by about a factor of two. Quote 11% beside the
  windowed score's detection numbers until there is a second benign recording per tap.
- `statemachine.fit_segments` (fit on several stretches of one recording with no trace across
  a gap) stays: `fit_model` is now its one-segment case, with every existing test unchanged.

## Pcap converter verdict (2026-11-03)

Built `pcap_read.py`, `pcap_rows.py` and `pcap_diff.py` so a capture file becomes the packet
CSV the pipeline reads without the sponsor's conversion step. Judged by a diff fixed before
the run: Tier A is `frame_number` plus every column the pipeline reads, which must be
identical, with equal window tables; Tier B is the other 22 columns, counted.

Result over all 88 captures: every regenerated row identical, cell for cell, to the
sponsor's row at the same position, in every column; row counts equal on 87; window tables
equal on 87. 74 are called exact and 13 "identical but cut short at the source". The run
takes 461 seconds.

The 88th changes a standing conclusion. `nginx attack / pod-robot-controller / tcp` was
quarantined for 64,853 zero timestamps. They are not packets: the recording ends at frame
155,603, 3.56 GB into a 3.75 GB file, the rest is zeros, and the sponsor's conversion read
64,853 of those zero records as packets. The converter stops at the first one, so this
capture is recoverable: 155,603 real frames that window normally. The quarantine stays in
the sweep until the sweep reads converted captures; that is a decision for later, not made
here.

Found on the way, each now a rule with a test built from the real frame:

- The tcp captures are classic pcap with Linux cooked headers, not pcapng; the extension is
  wrong for half the corpus.
- Sponsor rules the converter copies: HTTP is port 80 or 8080; ICMP errors take the quoted
  packet's ports; ICMPv4 prints zero type/code blank, ICMPv6 prints them; IPv6 extension
  headers are looked behind for the transport while `proto` keeps the first next-header; an
  802.3 length field leaves `eth_type` blank, a zero type field prints `0x0000`.
- 14 capture files are cut mid-record with zero-filled tails, `injection attack /
  node-child4-ptcp` with 6.2 GB of zeros after 4.58 GB of data. The reader ends a capture at
  the first record that cannot be real: a pcapng block whose closing length does not match,
  or a pcap record that is empty, longer than its wire frame, or past the snaplen. Worth
  raising with the sponsor: those files lost data.
- `data_io.at_snaplen` counts 64 KB frames (65535 plus the link header), which are offloaded
  super-frames, not snaplen truncation: the tcp captures have a 262144-byte snaplen. The name
  is misleading; the measurement itself is unchanged here.
