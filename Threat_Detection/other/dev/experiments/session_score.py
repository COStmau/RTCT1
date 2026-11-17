"""One continuous labelled session, scored offline by every detector variant.

Reads a live-monitor session recorded with `record=True`: its taps' pcaps and `attacks.json`.
Each tap is learned from its first --train seconds and everything after is scored, under both
flow rules and each channel. An attack is detected at a tap by an alert newly raised (none in
the PRIOR seconds before it starts); benign windows are the scored ones after learning and
outside every attack's margin. The rule this feeds is `verdicts/session.py`.

Run it with:  .venv/bin/python other/dev/experiments/session_score.py ~/rtct-data/general/live/session-<time>
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1]),
                 str(Path(__file__).resolve().parents[3] / "subsystem")]

import argparse
import json

import numpy as np
import pandas as pd

from verdicts import session as session_verdict
from core.data_io import resolve_output
from core.detectors import persistent_mask
from core.features import WINDOW_SIZE
from experiments.benign_control import RULES, later_flags
from live.stream import load_packets

SESSION_CSV = "session_score.csv"
PRIOR = 10      # seconds before an attack that must hold no alert for one to count as raised by it
GRACE = 5       # seconds after an attack's end in which its alert may still be raised
MARGIN = 30     # seconds after an attack's end kept out of the benign windows


def judge(flagged, later, t0, attacks):
    """One benign row and one row per attack for a run of window flags.

    `later` marks the scored windows past the learning stretch; `attacks` is attacks.json.
    An attack is detected by an alert newly raised: one in the attack or GRACE after it, with
    none in the PRIOR seconds before. Benign windows keep MARGIN clear of every attack.
    """
    window = np.arange(len(later))
    spans = [(a["scenario"], (a["started"] - t0) / WINDOW_SIZE, (a["ended"] - t0) / WINDOW_SIZE)
             for a in attacks if "ended" in a]
    away = np.ones(len(later), dtype=bool)
    for _, start, end in spans:
        away &= ~((window >= start - PRIOR) & (window <= end + MARGIN))
    alert = persistent_mask(flagged).to_numpy()
    benign = later & away
    rows = [{"scenario": "benign", "windows": int(benign.sum()), "flagged": int(flagged[benign].sum()),
             "alert_windows": int(alert[benign].sum())}]
    for index, (scenario, start, end) in enumerate(spans):
        during = (window >= start) & (window <= end + GRACE)
        raised = np.flatnonzero(alert & during)
        before = alert[(window >= start - PRIOR) & (window < start)].any()
        rows.append({"scenario": scenario, "attack": index,
                     "scored": bool((later & during).any()), "already_alerting": bool(before),
                     "detected": bool(len(raised) and not before),
                     "latency_s": float(raised[0] - start) if len(raised) and not before else np.nan})
    return rows


def tap_rows(label, packets, attacks, train_seconds):
    """One row per (rule, channel, attack) plus one benign row per (rule, channel)."""
    rows = []
    for rule, flows_of in RULES.items():
        later, flags, _, t0 = later_flags(packets, train_seconds, flows_of)
        for channel, flagged in flags.items():
            rows += [dict(row, label=label, rule=rule, channel=channel)
                     for row in judge(flagged, later, t0, attacks)]
    return rows


def totals(frame):
    """Per variant, pooled over taps: the rows verdicts/session.py reads."""
    out = []
    for (rule, channel), rows in frame.groupby(["rule", "channel"]):
        benign = rows[rows["scenario"].eq("benign")]
        attacks = rows[rows["scenario"].ne("benign") & rows["scored"].eq(True)]
        out.append({"rule": rule, "channel": channel, "attacks": len(attacks),
                    "detected": int(attacks["detected"].sum()),
                    "already_alerting": int(attacks["already_alerting"].sum()),
                    "median_latency_s": float(attacks["latency_s"].median()),
                    "benign_windows": int(benign["windows"].sum()),
                    "benign_alert_windows": int(benign["alert_windows"].sum())})
    return out


def main():
    parser = argparse.ArgumentParser(description="Score a recorded, labelled live session by every variant.")
    parser.add_argument("session")
    parser.add_argument("--train", type=float, default=600.0)
    parser.add_argument("--out", default=SESSION_CSV)
    args = parser.parse_args()
    session = Path(args.session)
    attacks = json.loads((session / "attacks.json").read_text())
    rows = []
    for capture in sorted(session.glob("*/pcapng files/*-tcp.pcap")):
        label = capture.name[:-len("-tcp.pcap")]
        try:
            rows += tap_rows(label, load_packets(capture), attacks, args.train)
        except ValueError as error:
            print(f"  excluded: {label} ({error})")
    frame = pd.DataFrame(rows)
    out = resolve_output(args.out)
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows, {len(attacks)} attacks, {frame['label'].nunique()} taps")
    attack_rows = frame[frame["scenario"].ne("benign") & frame["scored"].eq(True)]
    print(attack_rows.groupby(["rule", "channel", "scenario"])["detected"].agg(["sum", "count"]).unstack("scenario").to_string())
    verdict, reasons = session_verdict.decide(totals(frame))
    print(f"\nSession verdict: {verdict}")
    for reason in reasons:
        print(f"  {reason}")


if __name__ == "__main__":
    main()
