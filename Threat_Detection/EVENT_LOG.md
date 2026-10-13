# Event log: detection to response handoff (v0, temporary)

Detection writes flagged windows as JSON Lines, one object per line, to
`outputs/events.jsonl`. Each line is one event. This contract is a starter and
will change; the `schema` field marks the version so both sides can tell.

```json
{"schema": "rtct1.event.v0", "detector": "z_score", "cutoff": 3.0,
 "location": {"name": "pod-nginx", "level": "pod", "method": "tcp"},
 "score": 9.41, "persistent": false, "status": "anomaly",
 "cause": {"feature": "total_bytes", "observed": 3906.0,
           "expected": 264.0, "spread": 386.96, "z": 9.41}}
```

`schema` names this contract version. `detector` names the method that scored
the window and `cutoff` is the cutoff that was in force, so severity is always
`score` against `cutoff` and no severity buckets are defined here. Only flagged
windows are emitted, so every score sits above its cutoff. Typical z_score
values run 1 to 3 on normal traffic and 4 to 15 on attacks.

`location` says which capture point saw it: the name, the level (pod, node, or
router), and the capture method. The evaluation scenario (benign or attack) is
left out because live traffic has no scenario.

`status` is the window verdict (`anomaly`, or `persistent_anomaly` once
3 flagged windows run in a row) and `persistent` repeats that as a plain bool
so the response side can filter without parsing strings.

`cause` names the feature that moved most, with its observed value, the
baseline it was compared against, and the distance in spreads (`z`). It is null
when the detector cannot attribute: the learned models never name a feature.
Any number that is undefined or unbounded arrives as null so the file stays
strict JSON.
