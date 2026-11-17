"""The novelty channel measured beside the windowed frequency score, on every stratum.

Three rows per (label, scenario, method): the frequency score alone (today's detector), the
novelty count alone, and a flag on either. Both cutoffs come from the same held-out benign
windows, each the top BENIGN_QUANTILE of its own score, exactly as windowed_scores.py sets
the frequency cutoff, so the benign rows are measured on the windows that set the cutoffs.

An attack recording is one event, detected when a persistent alert is raised in its warm
windows: the first FORGET_SECONDS run on a cold clock and are never flagged here. A window no
trace ended in is unscored and unflagged. Bulk taps set no cutoff and get no rows.

Run it with:  .venv/bin/python other/dev/experiments/novelty.py
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1]),
                 str(Path(__file__).resolve().parents[3] / "subsystem")]

import argparse

import numpy as np

from verdicts import novelty as novelty_verdict
from core.data_io import MANIFEST_NAME, load_manifest, resolve_output
from core.detectors import flag_stats
from core.evaluation import BULK_LABELS
from core.features import WINDOW_SIZE
from experiments.windowed_scores import sweep
from methods.pdfa import fit_model, make_flows, segment_flows, split_flows
from methods.scores import (FORGET_SECONDS, frequency_cutoff, frequency_scores_by_window,
                            n_windows_for, novelty_by_window, warm_from)

NOVELTY_CSV = "novelty.csv"
CHANNELS = ("frequency", "novelty", "either")


def _over(scores, cutoff):
    return np.nan_to_num(np.asarray(scores, dtype=float), nan=-np.inf) > cutoff


def _channels(frequency, novelty, cutoffs):
    """{channel: flags} for one run of windows."""
    flags = {"frequency": _over(frequency, cutoffs["frequency"]),
             "novelty": _over(novelty, cutoffs["novelty"])}
    return dict(flags, either=flags["frequency"] | flags["novelty"])


def whole_flows(packets, t0):
    """Today's flow rule: a flow that crosses a second is dropped."""
    return segment_flows(make_flows(packets), t0)[0]


def label_rows(label, method, benign, targets, forget_seconds=FORGET_SECONDS, flows_of=whole_flows):
    """Every row for one steady tap: held-out benign and each attack, per channel.

    `flows_of(packets, t0)` is the flow rule; experiments/slices.py passes another.
    """
    if label in BULK_LABELS:
        return []
    t0 = float(benign["ts"].min())
    flows = flows_of(benign, t0)
    train, holdout = split_flows(flows)
    model = fit_model(train)
    n_windows = n_windows_for(benign)
    held = slice(int((float(holdout["start_ts"].iloc[0]) - t0) // WINDOW_SIZE) + 1, None)
    scores = (frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds)[held],
              novelty_by_window(model, flows, t0, n_windows, forget_seconds)[held])
    cutoffs = {"frequency": frequency_cutoff(scores[0]), "novelty": frequency_cutoff(scores[1])}
    common = {"label": label, "method": method, "group": "steady",
              "states": model["pdfa"].n_states,
              "held_traces": max(len(holdout) - model["trace_len"] + 1, 0),
              "frequency_cutoff": cutoffs["frequency"], "novelty_cutoff": cutoffs["novelty"]}
    scored = int(np.isfinite(scores[0]).sum())
    rows = [dict(common, scenario="benign", channel=channel, scored_windows=scored,
                 flagged=int(flags.sum()), persistent=flag_stats(flags)["persistent"])
            for channel, flags in _channels(*scores, cutoffs).items()]
    for scenario, packets in targets.items():
        target_t0 = float(packets["ts"].min())
        target_flows = flows_of(packets, target_t0)
        n = n_windows_for(packets)
        frequency = frequency_scores_by_window(model, target_flows, target_t0, n, forget_seconds)
        novelty = novelty_by_window(model, target_flows, target_t0, n, forget_seconds)
        cold = warm_from(forget_seconds)
        warm_scored = int(np.isfinite(frequency[cold:]).sum())
        for channel, flags in _channels(frequency, novelty, cutoffs).items():
            flags[:cold] = False
            rows.append(dict(common, scenario=scenario, channel=channel, scored_windows=warm_scored,
                             flagged=int(flags.sum()), persistent=flag_stats(flags)["persistent"]))
    return rows


def summarize(frame):
    """Per method and channel: events detected of events, and the held-out benign side."""
    lines = []
    for method, at in frame.groupby("method"):
        for channel in CHANNELS:
            rows = at[at["channel"].eq(channel)]
            benign, attack = rows[rows["scenario"].eq("benign")], rows[rows["scenario"].ne("benign")]
            per = ", ".join(f"{s.split()[0]} {int(g['persistent'].gt(0).sum())}/{len(g)}"
                            for s, g in attack.groupby("scenario"))
            windows = int(benign["scored_windows"].sum())
            lines.append(f"{method:<5}{channel:<10} events: {per} | benign: "
                         f"{int(benign['flagged'].sum())} flagged, {int(benign['persistent'].sum())} "
                         f"persistent of {windows} held-out windows")
    return lines


def main():
    parser = argparse.ArgumentParser(description="Measure the novelty channel beside the windowed "
                                                 "frequency score and print the pre-registered verdict.")
    parser.add_argument("--methods", nargs="+", default=["tcp", "ptcp"], choices=("tcp", "ptcp"))
    parser.add_argument("--out", default=NOVELTY_CSV)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    import local_paths
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    frame, excluded = sweep(manifest, args.methods, rows_for=label_rows)
    out = resolve_output(args.out)
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows")
    for item in excluded:
        print(f"  excluded: {item}")
    print("\n".join(summarize(frame)))
    verdict, reasons = novelty_verdict.decide(frame.to_dict("records"))
    print(f"\nNovelty verdict: {verdict}")
    for reason in reasons:
        print(f"  {reason}")


if __name__ == "__main__":
    main()
