# Event log (LogV2)

One JSON object per line in `outputs/events.jsonl`, one line per persistent alert.
`dev/experiments/sweep.py --events-dir <dir>` writes one file per stratum instead:
`<scenario>__<label>__<method>.jsonl`, spaces to hyphens, empty when a stratum has
no persistent alert.

```json
{"version": "LogV2", "detector": "z_score", "t": 42, "score": 7.0,
 "cutoff": 2.5, "severity": "medium", "persistent": true,
 "reason": {"feature": "rst_count", "group": "flags", "observed": 8.0,
            "expected": 1.0, "z": 7.0},
 "capture": {"label": "pod-nginx", "method": "tcp", "scenario": "nginx attack",
             "start_epoch_s": 1771551277.3},
 "locations": {"type": "pod", "ids": ["pod-nginx"]}}
```

| field | |
|---|---|
| `version` | `LogV2`. Key on it: LogV1 used `med` for the middle band. |
| `detector` | Method that scored the window. Only `z_score` writes events today. |
| `t` | Second inside the capture, integer, 0 = first second. Wall clock is `capture.start_epoch_s + t`. |
| `score` | The window's `anomaly_score`. Always `> cutoff`, because `flag()` is strict. |
| `cutoff` | Calibrated cutoff for that capture. JSON number or `null`. |
| `severity` | `low`, `medium` or `high`, banded on that detector's own scale: `z_score` 5/10, `isolation_forest` 0.10/0.20, `one_class_svm` 0.45/0.55. A non-finite score is `high`. |
| `persistent` | Always `true`. Windows that flag without satisfying persistence stay in `outputs/results.csv` and never appear here. |
| `reason.feature` | Strongest feature for the window. |
| `reason.group` | That feature's entry in `FEATURE_GROUPS`. |
| `reason.observed` | Measured value, copied from `annotate()`. |
| `reason.expected` | Baseline value for that feature. |
| `reason.z` | Signed z-score. Positive means above the baseline. |
| `capture.label` | Capture point, e.g. `pod-nginx`. |
| `capture.method` | `tcp` or `ptcp`. |
| `capture.scenario` | Scenario folder, e.g. `nginx attack`. |
| `capture.start_epoch_s` | Epoch second of the capture's first packet. |
| `locations.type` | `pod`, `node` or `router`, from `level_from_label(capture.label)`. |
| `locations.ids` | Capture labels at that level. |

Two things the reader has to tolerate. The file is rewritten, not appended, so a
read during a sweep can see a truncated last line; drop it. And `reason` values
are copied verbatim without a finiteness check, so a detector that leaves a NaN
would emit the bare token `NaN`; `z_score` never does.
