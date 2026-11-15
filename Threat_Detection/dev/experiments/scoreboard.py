"""Live sessions scored in the units last year's reports used: events, false alarms, latency.

Reads the event log of one or more live-monitor sessions (`session-*/events.jsonl`) and
reports, per tap: how many labelled attacks raised an alert there and how fast, and how often
the tap alerted with no attack running. It measures what the session logged, so it judges the
detector that ran then; replay a recording to judge another.

An attack counts at a tap only if the tap scored a window during it. An alert belongs to an
attack when it is raised from 2 s before the attack's start to RELEASE_WATCH after its end,
the span live/monitor.py itself uses; every other alert is a false alarm. Attacks come from
the log's own `attack` events, so a session with none (an attack run by hand and never
marked) has no detection number at all, only alerts that cannot be told apart.

Run it with:  .venv/bin/python dev/experiments/scoreboard.py ~/rtct-data/general/live/session-*
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

import argparse
import json

import pandas as pd

from core.data_io import resolve_output
from live.monitor import RELEASE_WATCH

SCOREBOARD_CSV = "scoreboard.csv"
LEAD = 2.0     # seconds before an attack's logged start that still belong to it


def read_events(path):
    """A session's events; a line cut short by a crash is dropped."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def attack_spans(events):
    """[(scenario, start, end)] from the log's attack events; an unfinished attack is left out."""
    spans, open_attack = [], None
    for event in events:
        if event.get("kind") != "attack":
            continue
        if event["phase"] == "start":
            open_attack = (event["scenario"], event["wall"])
        elif event["phase"] == "stop" and open_attack:
            spans.append((*open_attack, event["wall"]))
            open_attack = None
    return spans


def session_rows(events, session=""):
    """One row per tap: attacks seen and detected there, latency, and the benign side."""
    spans = attack_spans(events)

    def owner(wall):
        return next((i for i, (_, start, end) in enumerate(spans)
                     if start - LEAD <= wall <= end + RELEASE_WATCH), None)

    rows = []
    for label in sorted({e["label"] for e in events if e.get("kind") == "window"}):
        scored = [e for e in events if e.get("kind") == "window" and e["label"] == label
                  and e.get("peak") is not None]
        alerts = [e["wall"] for e in events if e.get("kind") == "alert" and e["label"] == label]
        seen = {owner(e["wall"]) for e in scored} - {None}
        first = {}
        for wall in alerts:
            if owner(wall) in seen:
                first.setdefault(owner(wall), wall - spans[owner(wall)][1])
        benign = [e for e in scored if owner(e["wall"]) is None]
        rows.append({"session": session, "label": label, "attacks": len(seen), "detected": len(first),
                     "median_latency_s": float(pd.Series(list(first.values())).median()) if first else None,
                     "benign_windows": len(benign),
                     "false_alerts": sum(owner(wall) is None for wall in alerts),
                     "benign_alert_windows": sum(bool(e.get("alert")) for e in benign)})
    return rows


def summarize(frame):
    """Pooled over sessions, per tap and overall, in the units of last year's reports."""
    lines = []
    groups = list(frame.groupby("label")) + [("all taps", frame)]
    for label, rows in groups:
        attacks, detected, windows = rows["attacks"].sum(), rows["detected"].sum(), rows["benign_windows"].sum()
        latency = rows["median_latency_s"].dropna()
        lines.append(
            f"{label:<18} attacks detected {detected}/{attacks}"
            + (f" (median {latency.median():.1f} s)" if len(latency) else "")
            + f" | false alerts {rows['false_alerts'].sum()} in {windows / 60:.1f} benign min"
            + (f", {rows['benign_alert_windows'].sum() / windows:.3f} of benign windows in alert" if windows else ""))
    return lines


def main():
    parser = argparse.ArgumentParser(description="Detection, false alarms and latency of live sessions.")
    parser.add_argument("sessions", nargs="+", help="session directories holding events.jsonl")
    parser.add_argument("--out", default=SCOREBOARD_CSV)
    args = parser.parse_args()
    rows = []
    for session in args.sessions:
        log = Path(session) / "events.jsonl"
        if log.exists():
            rows += session_rows(read_events(log), Path(session).name)
    frame = pd.DataFrame(rows)
    out = resolve_output(args.out)
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows from {frame['session'].nunique() if len(frame) else 0} sessions")
    print("\n".join(summarize(frame)) if len(frame) else "no scored session")


if __name__ == "__main__":
    main()
