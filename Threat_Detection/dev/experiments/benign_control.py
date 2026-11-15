"""Benign traffic the machine did not learn from: the control every detection number needs.

An attack recording that alerts proves nothing unless a benign recording of the same tap, made
at another time, does not. Two controls, both for the whole-flow and the sliced flow rule and
for each channel:

  later   one long benign recording: learn from its first --train seconds (cutoffs from the
          held-out end of that stretch, as everywhere), then score everything after it.
  pair    two benign recordings of the same taps: learn from one, score the other as if it
          were an attack recording, both ways round. Rows come from experiments/novelty.py,
          so "persistent" is the same event the attack sweeps count.

Run it with, for example:
  .venv/bin/python dev/experiments/benign_control.py later ~/rtct-data/general/live/session-20261113-124619/"live attack/pcapng files"/pod-*-tcp.pcap
  .venv/bin/python dev/experiments/benign_control.py pair <dir of *-tcp.csv> <other dir>
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

import argparse

import numpy as np
import pandas as pd

from core.data_io import resolve_output
from core.detectors import persistent_mask
from core.features import WINDOW_SIZE
from experiments import novelty
from live.stream import load_packets
from methods.pdfa import fit_model, load_flow_packets, slice_flows, split_flows
from methods.scores import FORGET_SECONDS, frequency_cutoff, frequency_scores_by_window, novelty_by_window

RULES = {"whole": novelty.whole_flows, "sliced": slice_flows}


def later_flags(packets, train_seconds, flows_of, forget_seconds=FORGET_SECONDS):
    """Learn from the first `train_seconds`, flag every window after: (later, flags, model, t0).

    `later` marks the scored windows past the training stretch; `flags` is per channel. The
    cutoffs rest on the held-out end of the training stretch, as everywhere.
    """
    t0 = float(packets["ts"].min())
    n = int((float(packets["ts"].max()) - t0) // WINDOW_SIZE) + 1
    flows = flows_of(packets, t0)
    train, holdout = split_flows(flows[flows["start_ts"] - t0 < train_seconds])
    model = fit_model(train)
    scores = {"frequency": frequency_scores_by_window(model, flows, t0, n, forget_seconds),
              "novelty": novelty_by_window(model, flows, t0, n, forget_seconds)}
    held = slice(int((float(holdout["start_ts"].iloc[0]) - t0) // WINDOW_SIZE) + 1, int(train_seconds))
    flags = {name: np.nan_to_num(values, nan=-np.inf) > frequency_cutoff(values[held])
             for name, values in scores.items()}
    flags["either"] = flags["frequency"] | flags["novelty"]
    later = np.isfinite(scores["frequency"])
    later[:int(train_seconds)] = False
    model["held_windows"] = int(np.isfinite(scores["frequency"][held]).sum())
    return later, flags, model, t0


def later_rows(label, packets, train_seconds, forget_seconds=FORGET_SECONDS):
    """Per flow rule and channel: later benign windows scored, flagged and in alert."""
    rows = []
    for rule, flows_of in RULES.items():
        later, flags, model, _ = later_flags(packets, train_seconds, flows_of, forget_seconds)
        for channel, flagged in flags.items():
            rows.append({"control": "later", "label": label, "rule": rule, "channel": channel,
                         "train_seconds": train_seconds, "states": model["pdfa"].n_states,
                         "held_windows": model["held_windows"],
                         "scored_windows": int(later.sum()), "flagged": int(flagged[later].sum()),
                         "persistent": int(persistent_mask(flagged).to_numpy()[later].sum())})
    return rows


def pair_rows(first_dir, second_dir):
    """Each tap both ways round: learn from one recording, score the other benign one."""
    rows = []
    for path in sorted(Path(first_dir).glob("*-tcp.csv")):
        other = Path(second_dir) / path.name
        if not other.exists():
            continue
        label = path.name[:-len("-tcp.csv")]
        recordings = load_flow_packets(path), load_flow_packets(other)
        for rule, flows_of in RULES.items():
            for learned, scored, way in ((*recordings, "first to second"), (*recordings[::-1], "second to first")):
                try:
                    made = novelty.label_rows(label, "tcp", learned, {"other benign": scored}, flows_of=flows_of)
                except ValueError:
                    continue      # too few flows to learn from or to calibrate on
                rows += [{"control": "pair", "label": label, "rule": rule, "channel": r["channel"],
                          "way": way, "states": r["states"], "scored_windows": r["scored_windows"],
                          "flagged": r["flagged"], "persistent": r["persistent"]}
                         for r in made if r["scenario"] != "benign"]
    return rows


def summarize(frame):
    lines = []
    for (rule, channel), rows in frame.groupby(["rule", "channel"]):
        scored = rows["scored_windows"].sum()
        lines.append(f"{rule:<7}{channel:<10} {int(rows['persistent'].gt(0).sum())}/{len(rows)} recordings alert | "
                     f"flagged {rows['flagged'].sum() / scored:.3f}, in alert "
                     f"{rows['persistent'].sum() / scored:.3f} of {scored} windows")
    return lines


def main():
    parser = argparse.ArgumentParser(description="Score benign traffic the machine did not learn from.")
    modes = parser.add_subparsers(dest="mode", required=True)
    later = modes.add_parser("later")
    later.add_argument("captures", nargs="+", help="long benign pcap recordings, one per tap")
    later.add_argument("--train", type=float, default=600.0)
    pair = modes.add_parser("pair")
    pair.add_argument("first")
    pair.add_argument("second")
    args = parser.parse_args()
    if args.mode == "later":
        rows = []
        for capture in args.captures:
            try:
                rows += later_rows(Path(capture).name.split("-tcp")[0], load_packets(capture), args.train)
            except ValueError as error:
                print(f"  excluded: {Path(capture).name} ({error})")
    else:
        rows = pair_rows(args.first, args.second)
    frame = pd.DataFrame(rows)
    out = resolve_output(f"benign_control_{args.mode}.csv")
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows")
    print("\n".join(summarize(frame)))


if __name__ == "__main__":
    main()
