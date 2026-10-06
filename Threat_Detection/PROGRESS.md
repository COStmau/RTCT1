# Subsystem 2 status: capture sweep, feature check, detector comparison

Written 2026-10-06 for the TA checkpoint and the Friday feature-selection meeting.

## What changed since last week

- The spike plots I showed last week were a mock-up of the shape of the deliverable, not output from the data. They are retracted.
- Everything below comes from the four scenario folders as they are mounted (88 processed CSVs, 22 capture strata × 4 scenarios), read straight from the dataset with no hand-edited numbers.
- One capture turned out to be unusable as stored and is quarantined instead of silently zeroed: `nginx attack/csv files/tcp/pod level/pod-robot-controller-tcp.csv` has 64,853 of its 220,456 rows with `ts = 0.0` (frames 155,604 onward). The existing 1-second binning would have tried to build ~1.77 billion windows from that file.

## Commands that regenerate every artifact

```bash
cd /Users/cos/Documents/school/ECEN403/RTCT1/Threat_Detection
.venv/bin/python -m unittest -v test_mvp                         # 17 tests
.venv/bin/python sweep.py                                        # capture_manifest dependency, sweep_results.csv, sweep_summary.png
.venv/bin/python sweep.py --groups volume,size_timing,diversity,flags --out ablation_results.csv
.venv/bin/python iforest_compare.py                              # detector_comparison.csv + detector_comparison.png
.venv/bin/python test.py --no-show                               # the original single-pair run, still unchanged
```

The sweep reads 88 CSVs / ~53 MB and finishes in about 8 seconds.

## Capture inventory (`capture_manifest.csv`)

88 captures = 4 scenarios × 11 labels × 2 capture methods. Levels: 20 pod, 16 node, 8 router per method.
All 88 parsed; 1 unusable (above). Capture spans are 42–69 s for every usable capture, i.e. roughly 42–69
one-second windows each.

## Sweep result: flagged fraction of windows, `group=all`, tcp captures

Matched benign reference per capture (same label, same capture method), fitted on the first 70% of the benign
windows; the held-out 30% are the benign column below.

```
label                  benign  injection  lidar  nginx
node-child1              0.11       0.73   0.75   0.19
node-child2              0.16       0.76   0.11   0.28
node-child4              0.75       0.84   0.31   0.40
node-gchild9             0.26       0.72   0.14   0.42
pod-camera               0.00       0.20   0.06   0.08
pod-lidar                0.15       0.73   0.77   0.15
pod-nginx                0.00       0.00   0.02   0.80
pod-robot-controller     0.85       1.00   0.32    NaN   (nginx attack capture excluded: bad timebase)
pod-robot-hardware       0.30       0.70   0.16   0.41
router-any               0.81       0.50   0.35   0.48
router-flannel           0.00       0.31   0.11   0.93
```

Three things fall out of this table:

1. An attack is visible at the vantage that serves it. The web flood shows at `pod-nginx` (0.80 flagged, 0.00 on
   held-out benign) and at `router-flannel` (0.93). The lidar replay shows at `pod-lidar` (0.77) and barely at
   `pod-nginx` (0.02). Scoring a sensor-side attack against a web-server baseline is what makes it look
   undetectable.
2. The 3σ default is not calibrated per vantage. Mean benign false-alarm fraction across the 22 strata is
   **0.30**, and it is concentrated: `pod-robot-controller` 0.85, `router-any` 0.81/0.84,
   `node-child4` 0.75/0.78. On the same strata the detector is flagging a third of normal traffic, so any
   detection number from those rows is not trustworthy yet.
3. The injection-attack column (0.50–1.00) is partly the noise floor: several of the same strata already flag
   0.75–0.85 on their own held-out benign windows.

Top features in flagged attack windows: `total_bytes` 9 strata, `unique_dst_ips` 7, `mean_packet_size` 5,
`packet_count` 5, `rst_count` 2, `unique_dst_ports` 2, `mean_iat` 1.

## Feature-group ablation (`ablation_results.csv`, 352 rows)

Mean flagged fraction over the 22 strata, by feature group:

```
group          benign   injection  lidar  nginx
volume          0.249      0.35     0.17   0.26
size_timing     0.280      0.35     0.20   0.26
diversity       0.021      0.16     0.01   0.14
flags           0.014      0.08     0.16   0.05
```

The split is clean and it is the useful finding for Friday: `volume` and `size_timing` carry most of the
detection but false-alarm on a quarter of held-out benign windows, while `diversity` and `flags` barely
false-alarm (0.02) and barely detect anything either. On the clean case the group matters a lot: for
`nginx attack` at `pod-nginx` (tcp), `size_timing` flags 0.77 of windows, `volume` 0.43, `diversity` 0.08,
`flags` 0.00.

## Detector comparison (`detector_comparison.csv`, 261 rows; chart `detector_comparison.png`)

Same windows, same matched benign reference, same 70/30 split, and all three detectors followed by the same
3-window persistence rule. The forest and the SVM take their cutoff from the 5th percentile of held-out benign
scores, so their benign column is 5% by construction and only their detection columns are comparable.

```
detector             benign  injection  lidar  nginx     (flagged fraction)
z_score                0.30       0.56   0.29   0.41
one_class_svm          0.05       0.44   0.18   0.26
isolation_forest       0.05       0.30   0.18   0.12

detector             benign  injection  lidar  nginx     (persistent fraction)
z_score                0.19       0.35   0.18   0.23
one_class_svm          0.00       0.23   0.11   0.18
isolation_forest       0.00       0.16   0.13   0.03
```

At the same 5% budget the SVM finds more than the forest on two of three scenarios (injection 0.44 against 0.30,
nginx 0.26 against 0.12) and ties it on lidar. The z-score still finds the most of the three, but it is running at
a 30% false-alarm fraction, so it is not the same comparison: matching the z-score threshold to a 5% budget and
re-running is the next measurement, not a claim. Nothing here yet justifies replacing the transparent detector,
and nothing here yet justifies claiming a learned model is needed. All three are charted in
`detector_comparison.png`, written by the same command.

## Sample sizes and what I am not claiming

- Each capture is ~42–69 s, so ~15–20 held-out benign windows per stratum. At that size a 0/19 result only
  bounds the true false-alarm rate at roughly 15%; the numbers above are per-capture window fractions, not
  validated rates.
- Four strata have under 10 windows and their rows are noise: `injection attack` ptcp `node-child2` (3 windows),
  `node-child1` (6), `pod-nginx` (7), and tcp `pod-nginx` (9).
- Both learned detectors are calibrated to a 5% held-out benign budget by construction, so their benign column
  is not evidence of anything; only the detection columns at that budget are comparable.
- Both learned detectors drop windows where `mean_packet_size`/`mean_iat` are undefined (empty seconds) while the
  z-score keeps them as `insufficient_data`, so the three are close to, but not exactly, the same window set.
- I am not claiming: generalization from 60-second captures; a calibrated false-alarm rate; that a flag is an
  attack; network-origin attribution from resource metrics; or any live connection to Subsystem 1's baseline or
  Subsystem 3's response. Nothing here is wired to S1 or S3.

## Friday: feature selection and pathways

| Candidate feature | Source column | At pod / node / router captures | Status |
|---|---|---|---|
| packet_count, total_bytes | `ts`, `frame_len` | all three | implemented, carries detection, noisy |
| mean_packet_size, mean_iat | `frame_len`, `iat` | all three | implemented, carries detection, noisy |
| unique_dst_ips, unique_dst_ports | `dst_ip`, `dst_port` | all three | implemented, quiet but weak |
| syn_count, rst_count | `tcp_syn`, `tcp_rst` | all three | implemented, quiet but weak |
| unique_src_ips, unique_src_ports | `src_ip`, `src_port` | all three | candidate, needs adding to `make_features` |
| protocol mix (udp/tcp/icmp shares) | `proto`, `icmp_type` | all three | candidate |
| DNS/HTTP/HTTPS shares | `is_dns`, `is_http`, `is_https` | all three | candidate |
| payload ratio | `tcp_payload_len` / `frame_len` | all three | candidate |
| flag mix (fin/psh/ack ratios) | `tcp_fin`, `tcp_psh`, `tcp_ack` | all three | candidate |

The question that needs an answer from the sponsor before more features get built: every feature in that table
exists only in the packet-level CSVs. Subsystem 1's Prometheus surface as configured exposes pod CPU/memory and
node memory, with network RX marked removed and network TX and node CPU needing retest, so the FSR's "baseline
to detection" interface has no source for 7 of the 8 implemented features. Either the detection path consumes
packet captures at the observation points (T1) or it is limited to coarse resource deviations (T2), which
cannot support network-origin diagnosis.
