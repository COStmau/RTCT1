# Event log: detection to response handoff (LogV0, temporary)

Detection writes flagged windows as JSON Lines, one object per line, to
`outputs/events.jsonl`. Each line is one event. This contract is a starter and
will change; the `version` field marks the version so both sides can tell.

```json
{"version": "LogV0", "detector": "z_score", "severity": "med",
 "locations": {"pods": ["pod-nginx"]}}
```

`version` names this contract version. `detector` names the method that scored
the window. `locations` holds the affected pods as a list, so later events can
name more than one. Only flagged windows are emitted, so
every event is already above the 3.0 cutoff.

`severity` buckets the raw score: low below 5, med from 5 to 10, high at 10
and above. Low is borderline and mostly noise, high is far outside normal. An
unbounded score (a feature that never moved in the baseline moved at all)
counts as high.

Future: some sort of time information, indication of continuing, increasing, or decreasing severity.
