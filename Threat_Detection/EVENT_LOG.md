# Event log: detection to response handoff (LogV1)

Detection writes flagged windows as JSON Lines, one object per line, to
`outputs/events.jsonl`. Each line is one event. This contract is a starter and
will change; the `version` field marks the version so both sides can tell.

```json
{"version": "LogV1", "detector": "z_score", "t": 42, "severity": "med",
 "locations": {"pods": ["pod-nginx"]}}
```

`version` names this contract version. `detector` names the method that scored
the window. `locations` holds the affected pods as a list, so later events can
name more than one. Only flagged windows are emitted, so
every event is already above the detector's cutoff.

`t` is the window's **second inside its capture**, as an integer: 0 is the
first second of the recording. It is what lets a consumer order events, measure
the gap between two of them, and expire an incident. It is capture-relative,
not wall-clock; the capture manifest (`outputs/capture_manifest.csv`) carries
each recording's own start time, so absolute time is `capture start + t`.

`severity` buckets the raw score: low below 5, med from 5 to 10, high at 10
and above. Low is borderline and mostly noise, high is far outside normal. An
unbounded score (a feature that never moved in the baseline moved at all)
counts as high.

## Changes

- **LogV1** adds `t`. LogV0 carried no time at all: a capture's 51 flagged
  windows were indistinguishable from one another, so nothing downstream could
  order them, dedupe them, or decide an incident had cleared. Readers written
  against LogV0 should key on `version`.

Future: absolute (wall-clock) time alongside `t`; indication of continuing,
increasing, or decreasing severity; and grouping several pods into one incident
rather than emitting one event per window per pod.
