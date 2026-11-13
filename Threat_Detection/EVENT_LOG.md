# Event log: detection to response handoff (LogV2)

Detection writes persistent alerts as JSON Lines, one object per line, to
`outputs/events.jsonl`. The full capture sweep can also write one file per scored
adopted-detector stratum with `dev/experiments/sweep.py --events-dir <dir>`.
Those files use `<scenario>__<label>__<method>.jsonl`; spaces become hyphens.
A scored stratum with no persistent alert has an empty file. A quarantined
stratum has no event file and remains in the sweep CSV with its exclusion note.
Each line is one event. Flagged windows that do not
persist remain in `outputs/results.csv`; they do not produce response events.
This contract is a starter and will change; the `version` field marks the
version so both sides can tell.

```json
{"version": "LogV2", "detector": "z_score", "t": 42, "score": 7.0,
 "cutoff": 2.5, "severity": "medium", "persistent": true,
 "reason": {"feature": "rst_count", "group": "flags", "observed": 8.0,
            "expected": 1.0, "z": 7.0},
 "capture": {"label": "pod-nginx", "method": "tcp", "scenario": "nginx attack",
             "start_epoch_s": 1771551277.3},
 "locations": {"type": "pod", "ids": ["pod-nginx"]}}
```

Flagged windows are not response events. On the recorded demo pair, 52 windows
flag and 44 satisfy persistence, so `outputs/events.jsonl` contains 44 events.
The other eight windows remain in `outputs/results.csv` and in the console counts.

`version` names this contract version. `detector` names the method that scored
the window. LogV2 consumers read `locations.type` for the observation level and
`locations.ids` for the non-empty list of capture labels. The type is copied
from `core.data_io.level_from_label(capture.label)` and is one of `pod`, `node`,
or `router`; the event writer does not infer it from network data. Only windows
with `persistent_flag` set produce events, so
`persistent` is always `true`. A flagged window that does not satisfy the
persistence rule remains visible in the result CSV and the console counts.

`reason` copies the detector explanation for that window. `feature` is the
strongest feature, `group` is its entry in `core.features.FEATURE_GROUPS`, and
`observed`, `expected`, and signed `z` come directly from the columns produced
by `annotate()`. The event writer does not calculate these values again.

## What the emitter assumes

Every current writer passes `detector="z_score"`: `demo.py` and
`dev/experiments/sweep.py` each hold a single `DETECTOR` constant. The emitter is
written for a detector that attributes a window to one feature and has a band in
`SEVERITY_BANDS`. Two lookups enforce that, and both fail loudly rather than
writing a half-filled event: `_feature_group` searches `FEATURE_GROUPS` for
`reason.feature` and raises `StopIteration` when the feature belongs to none of
them, and `_severity` raises `KeyError` for a detector name outside the three
bands above. A learned detector attributes no single feature (its `top_feature`
is `nan`), so it cannot write events until the emitter grows a branch for it. Do
not add one to the sweep and assume events follow.

`write_events` copies `reason` values from `annotate()` and never tests them for
finiteness, so whatever the detector puts in the evidence columns is what lands
in the file. `z_score` fills them with real numbers, which is why every event in
`outputs/events.jsonl` parses as strict JSON. A detector that leaves a NaN in an
evidence column would emit the bare token `NaN`, which is not valid JSON; the
reader would have to drop the line.

`capture` identifies the input recording. It holds the capture `label`, capture
`method`, scenario folder, and `start_epoch_s`. `start_epoch_s` is the epoch
second of the capture's first packet. `make_windows` keeps it when it subtracts
the first timestamp to create the relative window index.

`t` is the window's **second inside its capture**, as an integer: 0 is the
first second of the recording. It is what lets a consumer order events, measure
the gap between two of them, and expire an incident. It is capture-relative,
not wall-clock. Absolute time is `capture.start_epoch_s + t`.

`score` is the window's `anomaly_score`, copied from the detector result. `cutoff`
is the calibrated cutoff used for that capture. Both are JSON numbers, or `null`
when unavailable; they are never strings. An emitted event satisfies
`score > cutoff`, which is the strict comparison used by `Detector.flag()`.

`write_events` opens the file for writing, not appending, so a reader that reads
while a sweep or demo is running can see a truncated last line. Drop it rather
than failing on the file.

`severity` is one of `low`, `medium`, or `high`. Each detector uses bands on
its own raw score scale because the values are not interchangeable:

| detector | low | medium | high |
|---|---:|---:|---:|
| `z_score` | below 5 | 5 to below 10 | 10 and above |
| `isolation_forest` | below 0.10 | 0.10 to below 0.20 | 0.20 and above |
| `one_class_svm` | below 0.45 | 0.45 to below 0.55 | 0.55 and above |

An unbounded score counts as high.

## Changes

- **Clarification, not a version change.** This document now states which detector
  writes events today (`z_score` only), the two lookups that refuse any other
  name, that `write_events` does not check evidence values for finiteness, and
  that the file is rewritten rather than appended. The bytes on the wire are
  unchanged; a LogV2 reader needs no change.
- **LogV2** replaces the abbreviated middle severity value with `medium`, so the
  vocabulary is now `low`/`medium`/`high`, and selects bands per detector. This
  breaks LogV1 readers that accept the old abbreviation or apply the z-score
  5/10 bands to learned-model scores. Readers must key on `version` and
  translate or reject LogV1 events.
- **LogV1** adds `t`. LogV0 carried no time at all: a capture's 51 flagged
  windows were indistinguishable from one another, so nothing downstream could
  order them, dedupe them, or decide an incident had cleared. Readers written
  against LogV0 should key on `version`.

Future: absolute (wall-clock) time alongside `t`; indication of continuing,
increasing, or decreasing severity; and grouping several pods into one incident
rather than emitting one event per window per pod.
