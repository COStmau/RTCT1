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

## Load versus behavior alerts: dropped by its own rule (2026-11-06)

The idea: flag on the z-score ("load"), escalate only when the windowed SEQUENT score
("behavior") also fires. The rule is `verdicts/load_behavior.py`, committed in `4df7dde`
before any number existed; `experiments/load_behavior.py` measures it
(`outputs/load_behavior.csv`, `outputs/load_behavior_bulk.csv`). One fix after the first run,
disclosed: the rule's scenario names did not match the manifest's ("injection" against
"injection attack"), which made claim B read undecidable. No threshold moved.

**Claim A fails (tcp).** On the bulk taps the z-score control sees the step (AUROC
0.97-1.00, onset at second 50-52, found by change point), and the behavior score sees it
too, in the other direction: post-onset AUROC 0.18 (`node-child4`), 0.12
(`pod-robot-controller`), 0.37 (`router-any`, inside the band). The score falls after the
regime change, so it does not flag it, but the rule asked for "quiet", not "does not rise".
The rule is symmetric and the verdict stands; a one-sided rule would be a new rule, written
before it is run on this data again.

**Claim B fails (tcp).** Behavior detection is 0.26 / 0.42 / 0.14 of the z-score's on
injection / lidar / nginx, against the 0.50 bar. It does cost fewer benign windows (0.043
against 0.453 of 161 held-out), but 75 of those 161 windows have no behavior score at all,
and 86 / 157 / 211 warm attack windows are missing, counted as not escalated.

Not part of the verdict, but worth knowing: the two channels are compared above at their own
cutoffs, and the z-score's costs ten times the benign rate. At the benign rate the behavior
cutoff realised, the z-score detects 0.55 / 0.16 / 0.24 against behavior's 0.15 / 0.22 / 0.10,
so behavior is competitive on lidar and worse elsewhere. Behavior ranks better by AUROC on
injection and lidar (0.74 / 0.63 against 0.69 / 0.52) and at chance on nginx. ptcp is worse
on every number. Outcome: no gating; the "tag each alert load-only or behavior-involved"
fallback is still available but rests on a channel that is blank on about half the windows.

## Eight-feature set: dropped by its own rule (2026-11-06)

Candidate: the z-score on `unique_dst_ips`, `unique_dst_ports`, `syn_count`, `rst_count`,
`http_count`, `dns_count`, `https_count`, `http_frac` (no `volume`, no `size_timing`) against
all 13. The rule is `verdicts/feature_set.py`, committed in `d5891e8`; it says in its
docstring that it is not blind (the candidate came from the group ablation and an exploratory
run preceded the rule, and the benign side is optimistic for that reason). Measured by
`experiments/feature_set.py` into `outputs/feature_set.csv`.

**Verdict: drop. Stay on all 13.** One condition fails: `ptcp/injection attack` AUROC fell
0.152 (0.738 to 0.586), above the 0.10 limit. Everything else passed:

| | tcp, all 13 | tcp, 8 features | ptcp, all 13 | ptcp, 8 features |
|---|---|---|---|---|
| persistent alerts on 151 / 141 steady held-out windows | 22 | 3 | 18 | 6 |
| held-out benign windows flagged, steady | 0.424 | 0.185 | 0.454 | 0.234 |
| held-out benign windows flagged, bulk | 0.918 | 0.443 | 0.946 | 0.589 |

Lidar and nginx improve under the candidate in both methods on detection at 5% (tcp lidar
0.076 to 0.206, nginx 0.174 to 0.283); injection loses 0.07 / 0.05 and AUROC 0.07 / 0.15.
The ptcp injection loss comes from two strata of 6 and 11 windows (`node-child1` 0.98 to
0.39, `pod-lidar` 0.98 to 0.35), so it is real under the rule and also thin evidence. A
candidate that keeps one volume feature for injection would be a new candidate and needs a
new rule committed first. `mean_packet_size` and the count-over-packets ratios were tried
exploratorily and did worse on benign flags (0.29 and 0.31 tcp steady), so they are not
candidates.

## Hybrid feature set: kept by its rule (2026-11-06)

After the eight-feature set was dropped on ptcp injection, one more candidate was fixed before
it ran (`7196852`, `verdicts/feature_set_hybrid.py`): the same eight plus `packet_count`, judged
by the previous rule with thresholds imported, not copied. It is the second candidate on the
same recordings and the last one; the module says the false-alarm side is more optimistic than
before. Measured by `experiments/feature_set.py --rule hybrid` into
`outputs/feature_set_hybrid.csv`.

**Verdict: keep.** Every condition passed under both capture methods.

| | tcp, all 13 | tcp, hybrid | ptcp, all 13 | ptcp, hybrid |
|---|---|---|---|---|
| persistent alerts, steady held-out benign (151 / 141 windows) | 22 | 9 | 18 | 9 |
| steady benign windows flagged | 0.424 | 0.272 | 0.454 | 0.312 |
| bulk benign windows flagged | 0.918 | 0.885 | 0.946 | 0.857 |

AUROC / detection at 5% (all 13 to hybrid): tcp injection 0.677 / 0.319 to 0.719 / 0.373, lidar
0.541 / 0.076 to 0.603 / 0.198, nginx 0.620 / 0.174 to 0.657 / 0.275; ptcp injection 0.738 /
0.389 to 0.730 / 0.413, lidar 0.516 / 0.117 to 0.521 / 0.196, nginx 0.620 / 0.217 to 0.643 /
0.292. No scenario loses, and injection, the scenario that sank the eight-feature set, now holds.

What the pass does and does not say. ptcp alerts fall by exactly 0.50, the minimum, so that
condition passes on the line. The bulk taps still flag 0.86-0.89: `packet_count` brings the
regime change back, so this is a steady-tap improvement and not a fix for drift. And the two
candidates were both tried on the same benign recordings, so the benign gain is optimistic;
the attack-side gains are the more trustworthy half. The detector still runs on all 13 in
`core/`; adopting the nine is a separate change that moves every number in `SHOWCASE.md` and
the visualization.

## Nine features adopted (2026-11-06)

`core.features.DETECTION_FEATURES` is now the hybrid set, and every detector in `core/` reads
it by default (`features=None` reads every column it is given, which the ablations and the two
verdict experiments use so their arms stay what they were). `make_windows` still computes all
13; the ranking, the ablations and the reporting read the whole table. A test keeps the list
equal to the candidate `verdicts/feature_set_hybrid.py` judged. `sweep.py --groups all` is
the adopted detector and `--groups full` is the old 13.

Regenerated by `demo.py 8`; the numbers in `outputs/SHOWCASE.md` moved with it: steady benign
windows flagged 0.43 to 0.29 (max 0.79 to 0.53), bulk 0.93 to 0.87; steady attack windows
flagged nginx 0.70 to 0.64, injection 0.68 to 0.59, lidar 0.54 to 0.42. The drop in flagged
fractions is mostly the false-alarm side; the detection gain is in the matched-rate figures
in the hybrid section above, not in these fixed-cutoff fractions. Earlier sections of this
file quote the 13-feature figures and are not rewritten: they describe what was measured then.
The windowed score, the PDFA and the visualization do not use these features and are unchanged.

## Novelty channel: kept by its rule (2026-11-14)

The frequency scorers walk a trace with `trace_states`, which stops at the first transition the
machine lacks. A sequence the machine never learned therefore adds *less* to the windowed score,
and the likelihood flag only sets a status (`unseen`), never an alert. A diagnostic on four tcp
taps showed what that costs: 92-100% of held-out benign traces walk the whole machine, against
45-51% under the nginx attack on `pod-lidar` and `node-child1`.

The candidate is a second channel, `methods.scores.NoveltyScorer`: the number of traces in the
8 s clock that leave the machine, with its own cutoff from the same held-out windows, and a
window flagged when either channel is over. The rule is `verdicts/novelty.py`, committed in
`075b49ca` before any window-level or alert-level number existed; it says it is not blind (the
diagnostic above preceded it). `experiments/novelty.py` writes `outputs/novelty.csv`.

**Verdict: keep, on the line.** The rule reads only tcp taps with 30 or more held-out traces,
which leaves four of the eight steady taps (`node-child2`, `node-gchild9`, `pod-robot-hardware`
and `router-flannel` are left out). On those: 5 to 9 of 12 attack events detected, a gain of 4
against a bar of 4; no persistent alert and 0.069 of 58 held-out windows flagged.

All eight steady taps, an event being one attack recording with a persistent alert in its warm
windows:

| | tcp, frequency | tcp, novelty | tcp, either | ptcp, frequency | ptcp, either |
|---|---|---|---|---|---|
| injection | 1 of 8 | 3 of 8 | 3 of 8 | 1 of 8 | 3 of 8 |
| lidar | 3 of 8 | 3 of 8 | 4 of 8 | 1 of 8 | 4 of 8 |
| nginx | 3 of 8 | 8 of 8 | 8 of 8 | 4 of 8 | 6 of 8 |
| held-out benign windows flagged | 7 of 86 | 1 of 86 | 8 of 86 | 8 of 77 | 11 of 77 |
| held-out benign persistent alerts | 0 | 0 | 0 | 0 | 0 |

These frequency figures are lower than the 2 / 3 / 4 of 8 quoted from `windowed_sweep.csv`
earlier, because that file's `persistent` column counts warm-up windows and this does not.

What the pass does and does not say. Novelty finds the nginx attack at every steady tap, where
the frequency score ranked it at chance; lidar and injection barely move, so those two need
something else (the detector still drops every flow that crosses a second). The benign side is
the same 60 s recordings that set the cutoffs, 3-16 windows a tap, and four taps' novelty
cutoffs are zero: one unseen trace in 8 s flags a window. Nothing here bounds a false-alarm
rate. Wired into `methods.calibration.calibrate` (a `novelty` entry beside `cutoffs`, which the
frozen page publishes and so must not change) and `live.stream.LiveDetector`, whose verdicts now
carry `novelty`, `novelty_cutoff` and `channels`; saved machines are version 3.

## Live sessions on the scoreboard (2026-11-14)

`experiments/scoreboard.py` reads `session-*/events.jsonl` in the units last year's reports
used. Nine existing sessions, all scored by the frequency channel alone: on the local k3d
cluster 24 of 30 labelled attacks raised an alert at a tap that was scoring (the span runs to
`RELEASE_WATCH`, 120 s after the attack, so this is lenient), median 10.5 s; and taps alerted
2,954 times in 3,399 benign tap-minutes, 0.073 of benign windows in alert, `node-agent1` alone
0.250. The lab-cluster sessions have no labelled attack, so they have no detection number.
False alarms on long runs, not missed attacks, are where the live monitor is furthest from last
year's reports, and novelty can only add flags. `Monitor.mark_attack` (`POST /api/attack/mark`)
now labels an attack run by hand, so the next lab session has spans to score against.

## Sliced flows: kept by its rule, not adopted; and the control that reopens novelty (2026-11-15)

`segment_flows` drops a flow that crosses a second; on three taps the kept flows carry 0.2-1.3%
of the bytes. `methods.pdfa.slice_flows` cuts such a flow at the seconds it crosses and marks
each slice new or continuing. The rule is `verdicts/slices.py`, committed in `2bb04103` before a
sliced machine was scored; `experiments/slices.py` writes `outputs/slices.csv`.

**Verdict: keep.** Seven eligible tcp taps (`router-flannel` left out): 14 to 20 of 21 events,
no scenario losing any, no held-out persistent alert, 0.058 of 138 held-out windows flagged.
Over all eight steady tcp taps, flag on either channel: injection 3 to 7 of 8, lidar 4 to 7,
nginx 8 of 8 both; machines grow from 2-8 states to 2-11 and held-out windows from 86 to 141.

**It is not adopted, because the measure it passed on is not sound.** The jump was large
enough to check, and three controls, none of them part of the rule, say that an attack
recording alerting against its benign recording does not show the attack was seen:

- On the local-cluster recordings (`~/rtct-data/lab`, `general`) the whole-flow detector
  already alerts on 32 of 32 and 7 of 8 attack recordings, at nearly every tap, including taps
  an attack has no reason to reach. The event count is saturated there.
- **A second benign recording alerts too.** `experiments/benign_control.py pair`, two benign
  recordings of the same k3d taps 26 minutes apart, each learned from and scored against the
  other (`outputs/benign_control_pair.csv`): with flags on either channel, 9 of 16 recordings
  raise a persistent alert under whole flows and 16 of 18 under slices. The frequency channel
  alone: 7 of 16, 0.030 of windows in alert. The novelty channel alone: 7 of 16, 0.283 in alert.
- **Later benign traffic, 10 minutes learned** (`benign_control.py later`, four pod taps of a
  51-77 minute benign recording, `outputs/benign_control_later.csv`): share of later benign
  windows in alert is 0.010 for the frequency channel on whole flows, 0.021 for novelty, 0.032
  for either; under slices 0.013, 0.042 and 0.055.

What follows. Every per-recording event count in this file, the novelty section's included, is
an upper bound that mixes the attack with the difference between two recording sessions; the
sponsor set has one benign recording per tap, so it cannot separate them. Novelty's verdict
stands as its rule was written, but the rule had no cross-session benign clause and novelty is
what the control hits hardest: learned from about 42 s it puts 28% of another benign recording
in alert, learned from 10 minutes about 2%. The live monitor learns from 60 s by default and
novelty is wired into it, so that default now matters more than it did. Length of benign
learning is the lever on false alarms: the frequency channel at 10 minutes is at 1%, under
last year's 4.65%, where the 60-second live sessions sat at 7.3%.

The test that can decide novelty and slices is one continuous recording with at least 10
minutes of benign learning and labelled attacks inside it, so each attack is judged against
the benign minutes around it. No such recording exists yet; the one recorded session with
labelled attacks has 22 s of benign before the first.

## The labelled session: the incumbent stays, and novelty comes out (2026-11-15)

Recorded on the local k3d `general` cluster, `~/rtct-data/general/live/session-20261115-145028`:
eight taps, 12 minutes of benign traffic, then http-flood, scan, lateral and sensor-flood three
times each, 30 s on and 90 s off. The rule, `verdicts/session.py`, was committed in `33562b1f`
while it was recording. `experiments/session_score.py` learns each tap from its first 10 minutes
and scores the rest (`outputs/session_score.csv`); `pod-redis` has too few whole flows to learn
from and is left out, so 7 taps and 84 attack-at-tap pairs. A detection is an alert newly
raised, none in the 10 s before the attack.

| flow rule / channel | attacks detected | benign windows in alert | rule |
|---|---|---|---|
| whole / frequency (incumbent) | 42 of 84 (0.50) | 0.030 | |
| whole / novelty | 50 of 84 (0.60) | 0.081 | not under 0.0465 |
| whole / either | 49 of 84 (0.58) | 0.111 | not under 0.0465 |
| sliced / frequency | 53 of 84 (0.63) | 0.025 | gain +0.13, below 0.15 |
| sliced / novelty | 60 of 84 (0.71) | 0.068 | not under 0.0465 |
| sliced / either | 56 of 84 (0.67) | 0.094 | not under 0.0465 |

**Verdict: whole flows with the frequency channel stay.** No challenger is both clean and 15
points better. As the rule says, the novelty channel is out of the live detector again:
`live/stream.py`, `live/worker.py`, `live/monitor.py` and `methods/calibration.py` are back to
what they were before `9718b58d` (saved machines are version 2 again), and `NoveltyScorer`,
`slice_flows` and their experiments stay as measured ablations.

What the session says beyond the verdict:

- **Novelty detects more and costs too much.** It finds lateral movement and scans the frequency
  score misses (`pod-worker` 9 of 12 against 3), but it leaves 8% of benign windows in alert
  even after 10 minutes of learning, 15% on `pod-worker` and `node-agent1`. The 60 s recordings
  that passed it had hidden that.
- **Sliced flows with the frequency channel alone are the near miss.** 53 against 42 attacks with
  slightly *less* benign alerting (0.025 against 0.030), two points short of the bar, so by the
  rule it is a drop. Where it is good it is very good: http-flood 16 of 21, scan 15 of 21 (the
  incumbent has 9), sensor-flood 16 of 21 (10); `pod-api`, `pod-store` and `node-server` each
  catch all nine of their flood, scan and sensor-flood attacks, at 0.4-2.5% of benign windows in
  alert. Lateral movement is its hole, 6 of 21. A candidate limited to those three attack
  kinds, or to pod taps, would be a new candidate and needs its own rule and a new session.
- **One tap carries a third of the false alarms.** `node-agent2` has 11-12% of benign windows in
  alert under either flow rule; the other six taps are at 0-3% for the incumbent.
- Median time from attack start to a newly raised alert is about 4 s for both frequency variants.
- This is one session on a single-host cluster, three repeats per attack kind. It decides
  between variants; it is not a detection rate.

## Role machines: a development reading (2026-11-15)

`methods/roles.py` changes three things at once, so `experiments/roles.py` separates two of
them. The unit is an *exchange*: one peer, one service, one second, both directions together,
with how the connection stood (opened, carried on, closed, reset); it is Zeek's connection
record cut at the seconds it crosses. Each peer keeps its own trace, padded at its start.
A role's symbols read what its protocol exchanges, and were fixed from benign traffic alone.
The experiment crosses whose traffic a machine is learned from (`own` tap, or `pooled` over the
role's instances) with its symbols (`flow`, today's, or `role`). The rule is
`verdicts/roles.py`, committed in `103385da` before any role machine was scored on an attack;
it is written for a held-out session, so what follows decides nothing.

Development session `session-20261115-145028` (already seen), the two web-server instances
`pod-frontend` and `pod-api`, 10 minutes learned, 24 attack-at-tap pairs; second benign session
`session-20261113-124619`, two days earlier, never learned from (`outputs/roles.csv`):

| learned from / symbols | attacks detected | later benign in alert | second session in alert |
|---|---|---|---|
| own / flow (the live detector) | 15 of 24 | 0.018 | **0.880** |
| own / role | 12 of 24 | 0.011 | **0.020** |
| pooled / flow | 7 of 24 | 0.006 | 0.827 |
| pooled / role | 4 of 24 | 0.013 | 0.018 |

- **Role symbols carry across sessions and flow symbols do not.** A flow-symbol machine learned
  on the 15th flags 2,384 of 2,388 scored windows of benign traffic from the 13th at `pod-api`;
  the role-symbol machine on the same packets flags 162 and leaves 2% in alert. This is the
  session-difference problem of the benign control, and on these two taps the exchange symbols
  with per-peer traces nearly remove it. Which of the two does it is not separated here.
- **It costs some detection on this session**, 12 against 15: lateral movement at `pod-api`
  goes from 3 of 3 to 0 of 3. Floods and scans hold (http-flood 6 of 6 both ways).
- **Pooling, as defined here, hurts.** One machine and one cutoff for `frontend` and `api`
  makes `pod-frontend` flag nothing at all, attacks included: the busier instance sets the
  cutoff. The two are not the same role in any strict sense (`api` also calls redis and the
  store), so this says the role list was drawn too coarsely, not that pooling cannot work;
  true replicas of one deployment are the fair test and none is tapped yet.
- Nothing here is a verdict. The held-out session (the staged campaign on the `lab` profile,
  where the sensor-publisher role also exists) is what the rule is for.

## Role machines on the held-out campaign: pooled / flow by the rule, and what the rule did not ask (2026-11-15)

The held-out session is `~/rtct-data/lab/live/session-20261115-220300` on the k3d `lab`
profile: 12 minutes benign, then five rounds of the staged campaign (slow scan, lateral
movement, beacon, exfil, HTTP flood, replay; three rounds of 30-second stages, two of 60).
None of its attack kinds was scored while the role symbols were designed. The second benign
session is `session-20261115-214728`, recorded just before it and never learned from. Taps
with a role: `pod-nginx` (web server), `pod-lidar` and `pod-camera` (sensor publisher); 10
minutes learned; 90 attack-at-tap pairs (`outputs/roles_heldout.csv`).

| learned from / symbols | attacks detected | per round | later benign in alert | second session in alert |
|---|---|---|---|---|
| own / flow (the live detector) | 28 of 90 | 6, 5, 5, 7, 5 | 0.018 | **0.445** |
| own / role | 20 of 90 | 5, 3, 4, 3, 5 | 0.001 | **0.002** |
| pooled / flow | 32 of 90 | 6, 6, 6, 7, 7 | 0.005 | 0.126 |
| pooled / role | 16 of 90 | 4, 2, 2, 4, 4 | 0.003 | 0.003 |

**Verdict by `verdicts/roles.py` (committed in `103385da`): pooled / flow.** It is never behind
the incumbent in a round, ahead in total, and quieter on both controls. Both role-symbol
variants fail the first test: fewer attacks than the incumbent.

The verdict stands as written. What it means is narrower than it sounds:

- **Pooled / flow is not a usable detector, and the rule had no way to say so.** The rule
  compares a challenger with the incumbent and sets no ceiling on benign alerts. `pod-nginx`
  is the only web server, so there pooled is the incumbent, identical. The gain is all at the
  publishers, and it is the pathology of the development reading again: one cutoff for lidar
  and camera makes `pod-lidar` flag nothing (0 of 30 attacks, 0.000 benign) while
  `pod-camera` goes from 11 to 20 attacks and stays in alert for 36% of a benign session
  recorded fifteen minutes earlier. It is not wired into the live monitor.
- **The incumbent does not survive a quarter of an hour.** Own / flow at `pod-lidar` is in
  alert for every scored window of the second session (3 states learned), 30% at
  `pod-camera`. With a detector alerting that often, "newly raised" detections are partly
  chance, so the 28 and the 32 are both soft.
- **Role symbols carry across sessions again, now on three taps and a second role**: 0.2% of
  second-session benign in alert against 44.5%. That is the result of the development
  reading, repeated on data it was not designed on.
- **Where role symbols detect, they detect every time**: HTTP flood 5 of 5 and beacon 5 of 5
  at `pod-nginx` (the beacon calls nginx), with no benign window in alert in either control;
  HTTP flood 5 of 5 at `pod-lidar`.
- **Where they miss, the cause is in the design, three of them:**
  1. *Bins saturate.* Exfil from the camera is ten times its normal upload rate and scores 0
     of 15: quantile bins clip at the top bin, so ten times normal reads as "a busy second".
     Flow symbols catch it at the camera 5 of 5.
  2. *A per-peer trace with the frequency score cannot see a new peer.* Slow scan 0 of 5 at
     `pod-nginx` and lateral movement 1 of 15 overall: a peer that sends one unfamiliar symbol
     adds little to a count. This is the Structure channel's question, as planned.
  3. *The wrong vantage point.* Replay goes from a second pod to the controller; neither
     publisher's tap carries it (1 of 15). It needs the controller's tap or the
     Agreement channel.
- **The web-server machine has one state.** The lab nginx has a single client making one
  kind of request, so its contract is a count of one symbol. It works here and says little
  about a server with varied clients.
- **How early.** Flow-symbol variants raise their first alert in the slow scan in all five
  rounds. Own / role does so in three and at the beacon in the other two; pooled / role first
  alerts at the lateral or beacon stage in four rounds. All are before the impact stages.

What follows for the design: the role contract is the quiet half of a detector and needs a
magnitude that does not clip and a notion of a peer that should not be there. The next rule
must carry a ceiling on benign alerts for every variant, the incumbent included.

## A contract that can say a conversation left it: a development reading (2026-11-16)

Two of the three misses on the campaign had one cause. The frequency score counts visits to
learned states, and a trace the machine lacks stops being walked, so it scores *lower*. A
quantity ten times the learned range was clipped into the top bin; a peer doing something
never learned added almost nothing. Two changes to `methods/roles.py`, neither read from an
attack:

- a quantity above the largest value learned is its own symbol, `x`, as zero already is `z`;
- `role_leaving` counts, over the same 8-second clock, the conversations whose trace the
  machine lacks. A window is flagged by the frequency score or by this count, each against
  its own cutoff from the held-out end of the learning stretch.

The rule is `verdicts/leaving.py`, committed in `580e7bdf` before either change was scored.
It has what the last rule lacked: a ceiling on benign alerts (0.0465) for every variant, no
privileged incumbent. Both lab sessions had already been read, so this decides nothing.

Same sessions and taps as the entry above (`outputs/leaving.csv`), each machine learned from
its own tap:

| detector | attacks detected | per round | later benign in alert | second session in alert |
|---|---|---|---|---|
| flow, frequency (the live detector) | 28 of 90 | 6, 5, 5, 7, 5 | 0.017 | **0.442** |
| role, frequency | 18 of 90 | 4, 3, 3, 3, 5 | 0.001 | 0.002 |
| role, frequency or leaving | **37 of 90** | 8, 6, 7, 7, 9 | 0.042 | **0.010** |

- **Detection doubles and the second session stays quiet.** Ahead of today's detector in
  every round, with 1% of an unseen benign session in alert against 44%. The rule would
  name it; a session recorded after this design was frozen has to.
- **What it now sees:** exfil at the camera 0 to 5 of 5 (the `x` symbol), lateral movement
  at the camera 0 to 5 of 5 (the foothold calling services it never calls), slow scan at
  the lidar 2 to 5 of 5, HTTP flood at nginx 3 to 5 of 5 (five unseen clients).
- **What it still does not:** slow scan and lateral movement at `pod-nginx` (0 of 10) and
  replay everywhere (1 of 15). The scan of nginx and the replay to the controller do not
  pass these taps as conversations with the workload; that is the vantage-point gap, not
  this one.
- **The 4.2% of later benign in alert is mostly one tap and probably not benign.** 11% at
  `pod-camera`, against 1.6% on the second session. Its off-contract conversations in
  "benign" windows fall 32 to 49 seconds after each lateral stage ends, with the symbol that
  stage produces, past the 30-second margin the judge allows. The lateral stage outruns its
  label. The recorder has to close that before the next session; the judge is left alone.

**A correction to the entry above.** `own_address` picked the end of a capture seen on most
packets; with a single peer both ends tie, and on the benign-only session it took the client
for `pod-nginx`. Every nginx trace of that session was off the machine, which the frequency
score reads as quiet, so the nginx share of "second session in alert" for the role variants
was vacuous. A tie is now an error and the second session takes the address the first one
found. Rerun, `outputs/roles_heldout.csv`: nginx is still 0.000 on the second session, now
for a reason; own / role is 18 of 90 and pooled / role 14 of 90 (the `x` symbol takes a few
frequency detections away), and the verdict is unchanged. The sessions do not record a pod's
address; they should.
