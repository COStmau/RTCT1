"""The windowed SEQUENT score measured on every stratum, calibrated the way story.py draws it.

story.py presents the windowed frequency score (the FORGET_SECONDS clock) as the page's
detector, but only the likelihood detector had a sweep (`statemachine.py main()`). This is
that sweep for the windowed score: one row per (label, scenario, method, training counts).

Calibration is story.build_story's, exactly: the whole benign recording runs through one
windowed scorer so the clock is warm, and the cutoff is the top BENIGN_QUANTILE of the
held-out windows after the one the split falls in. There is one benign recording per tap,
so the realised benign rate is measured on the windows that set the cutoff; with 4-17 of
them it lands anywhere from 0 to 25% against the nominal 5%, and every detection number is
quoted beside it. An attack capture starts its own clock cold, so its first FORGET_SECONDS
of windows are warm-up: they are counted, but they enter no detection rate or AUROC.

A window no trace ended in is missing, never normal: it is counted in `missing_windows` and
left out of every rate and AUROC. A bulk-transfer tap (evaluation.BULK_LABELS) never sets a
cutoff, so its rows carry an AUROC and no flag, detection or benign rate, in group "bulk".

Run it with:  .venv/bin/python windowed_scores.py
"""
import sys
from pathlib import Path

# A script run as `python experiments/windowed_scores.py` gets experiments/ as sys.path[0], so
# the project root has to go back on the path before any project import.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse

import numpy as np
import pandas as pd

from verdicts import root_count as root_verdict
from core.data_io import MANIFEST_NAME, describe_captures, load_manifest, resolve_output, timebase_issues
from core.detectors import flag_stats
from core.evaluation import BULK_LABELS
from core.features import WINDOW_SIZE
from experiments import flag_scores
from experiments.flag_scores import auroc
from methods.scores import (FORGET_SECONDS, TRAIN_COUNTS, held_out_scores, warm_from)
from statemachine import (fit_model, frequency_cutoff, frequency_scores_by_window,
                          load_flow_packets, make_flows, n_windows_for, segment_flows,
                          split_flows, state_train_counts)

WINDOWED_CSV = "windowed_sweep.csv"
VARIANTS = ("visits", "entries")
FLAG_FIELDS = ("windows", "flagged", "flagged_fraction", "persistent", "persistent_fraction")


def _flags(scores, cutoff):
    """Windows above the cutoff; a missing window is not flagged and is not normal either."""
    return np.nan_to_num(np.asarray(scores, dtype=float), nan=-np.inf) > cutoff


def benign_fields(held, cutoff):
    """The held-out row: the windows the cutoff rests on and the fraction it flags among them."""
    held = np.asarray(held, dtype=float)
    scored = np.isfinite(held)
    row = {"scored_windows": int(scored.sum()), "missing_windows": int((~scored).sum()),
           "cutoff_windows": int(scored.sum())}
    if cutoff is None:
        return dict(row, **{field: np.nan for field in FLAG_FIELDS}, realised_benign_rate=np.nan)
    flagged = _flags(held, cutoff)
    return dict(row, **flag_stats(flagged),
                realised_benign_rate=float(flagged[scored].mean()) if scored.any() else np.nan)


def attack_fields(held, attack, cutoff, first_warm):
    """One attack stratum: flags over the whole capture, detection and AUROC on warm windows.

    `held` is the held-out benign side of the AUROC; `first_warm` is the first attack window
    past the cold clock. Missing windows enter neither side and are counted on their own.
    """
    attack = np.asarray(attack, dtype=float)
    scored = np.isfinite(attack)
    warm = attack[first_warm:]
    warm = warm[np.isfinite(warm)]
    cold = attack[:first_warm]
    held = np.asarray(held, dtype=float)
    row = {"scored_windows": int(scored.sum()), "missing_windows": int((~scored).sum()),
           "warmup_windows": int(len(cold)), "warmup_scored": int(np.isfinite(cold).sum()),
           "warm_scored": int(len(warm)),
           "n_benign": int(np.isfinite(held).sum()), "n_attack": int(len(warm)),
           "auroc": (auroc(held, warm) if len(warm) and np.isfinite(held).any() else np.nan)}
    if cutoff is None:
        return dict(row, **{field: np.nan for field in FLAG_FIELDS},
                    warmup_flagged=np.nan, detection=np.nan)
    return dict(row, **flag_stats(_flags(attack, cutoff)),
                warmup_flagged=int(_flags(cold, cutoff).sum()),
                detection=float(np.mean(warm > cutoff)) if len(warm) else np.nan)


def label_rows(label, method, benign, targets, forget_seconds=FORGET_SECONDS,
               variants=VARIANTS):
    """Every row for one tap: its held-out benign and each attack, under each count source.

    `benign` and each `targets[scenario]` are packet frames as load_flow_packets reads them.
    """
    t0 = float(benign["ts"].min())
    flows, dropped = segment_flows(make_flows(benign), t0)
    train, holdout = split_flows(flows)
    model = fit_model(train)
    n_windows = n_windows_for(benign)
    group = "bulk" if label in BULK_LABELS else "steady"
    start = id(model["pdfa"].root)
    attacks = {}
    for scenario, packets in targets.items():
        target_t0 = float(packets["ts"].min())
        target_flows, target_dropped = segment_flows(make_flows(packets), target_t0)
        attacks[scenario] = (target_flows, target_t0, n_windows_for(packets), target_dropped)
    rows = []
    for variant in variants:
        held = held_out_scores(model, flows, holdout, t0, n_windows, forget_seconds, variant)
        cutoff = (frequency_cutoff(held) if group == "steady" and np.isfinite(held).any()
                  else None)
        common = {"detector": "windowed_frequency", "label": label, "method": method,
                  "group": group, "train_counts": variant,
                  "forget_seconds": float(forget_seconds),
                  "states": model["pdfa"].n_states,
                  "start_visits": state_train_counts(model["pdfa"], "visits")[start],
                  "start_entries": state_train_counts(model["pdfa"], "entries")[start],
                  "cutoff": np.nan if cutoff is None else cutoff}
        benign_row = benign_fields(held, cutoff)
        quoted = {"cutoff_windows": benign_row["cutoff_windows"],
                  "realised_benign_rate": benign_row["realised_benign_rate"]}
        rows.append(dict(common, scenario="benign", dropped_segments=dropped, **benign_row))
        for scenario, (target_flows, target_t0, target_windows, target_dropped) in attacks.items():
            scores = frequency_scores_by_window(model, target_flows, target_t0, target_windows,
                                                forget_seconds, variant)
            rows.append(dict(common, scenario=scenario, dropped_segments=target_dropped,
                             **quoted,
                             **attack_fields(held, scores, cutoff, warm_from(forget_seconds))))
    return rows


def _load(path):
    """Flow packets, or None when the capture's timebase is unusable."""
    packets = load_flow_packets(path)
    return packets if timebase_issues(packets)["usable"] else None


def sweep(manifest, methods=("tcp", "ptcp"), forget_seconds=FORGET_SECONDS, rows_for=None):
    """Rows for every (label, scenario, method, count source), and what was excluded.

    `rows_for(label, method, benign, targets, forget_seconds)` makes one tap's rows; it is
    label_rows unless a variant (cv_calibration) supplies its own.
    """
    rows_for = rows_for or label_rows
    if "usable" not in manifest.columns:      # a freshly built manifest carries no verdict
        manifest = describe_captures(manifest)
    rows, excluded = [], []
    for method in methods:
        at_method = manifest[manifest["method"].eq(method)]
        attacks = sorted(s for s in at_method["scenario"].unique() if s != "benign")
        for label in sorted(at_method["label"].unique()):
            by_scenario = {row.scenario: row for row in
                           at_method[at_method["label"].eq(label)].itertuples()}
            if "benign" not in by_scenario:
                excluded.append(f"{label}/{method} (no benign capture)")
                continue
            benign = _load(by_scenario["benign"].path)
            if benign is None:
                excluded.append(f"{label}/{method} (benign timebase unusable)")
                continue
            targets = {}
            for scenario in attacks:
                if scenario not in by_scenario:
                    excluded.append(f"{scenario}/{label}/{method} (no capture)")
                    continue
                packets = _load(by_scenario[scenario].path)
                if packets is None:
                    excluded.append(f"{scenario}/{label}/{method} (timebase unusable)")
                    continue
                targets[scenario] = packets
            try:
                rows += rows_for(label, method, benign, targets, forget_seconds)
            except ValueError as error:
                excluded.append(f"{label}/{method} ({error})")
    frame = pd.DataFrame(rows)
    if not frame.empty:
        order = [c for c in ("method", "group", "label", "scenario", "train_counts",
                             "calibration") if c in frame.columns]
        frame = frame.sort_values(order, kind="stable").reset_index(drop=True)
    return frame, excluded


def main():
    parser = argparse.ArgumentParser(
        description="Measure the windowed SEQUENT score on every stratum, calibrated as the "
                    "story page is, under both start-state training counts.")
    parser.add_argument("--methods", nargs="+", default=["tcp", "ptcp"],
                        choices=("tcp", "ptcp"))
    parser.add_argument("--forget", type=float, default=FORGET_SECONDS)
    parser.add_argument("--out", default=WINDOWED_CSV)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    import local_paths
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    rows, excluded = sweep(manifest, tuple(args.methods), args.forget)
    out = resolve_output(args.out)
    rows.to_csv(out, index=False)
    print(f"Wrote {out} | rows={len(rows)} | forget={args.forget:g}s")
    if excluded:
        print(f"excluded: {len(excluded)} ({', '.join(sorted(excluded))})")

    steady = rows[rows["group"].eq("steady")]
    for (method, variant), group in steady.groupby(["method", "train_counts"]):
        held = group[group["scenario"].eq("benign")]
        print(f"\n{method} | {variant} | steady | cutoffs rest on "
              f"{held['cutoff_windows'].min()}-{held['cutoff_windows'].max()} held-out windows, "
              f"realised benign rate {held['realised_benign_rate'].min():.3f}-"
              f"{held['realised_benign_rate'].max():.3f} "
              f"(median {held['realised_benign_rate'].median():.3f})")
        for scenario, attack in group[~group["scenario"].eq("benign")].groupby("scenario"):
            print(f"  {scenario:<16} detection {attack['detection'].mean():.3f} "
                  f"AUROC {attack['auroc'].mean():.3f} (means over "
                  f"{attack['auroc'].notna().sum()} strata with warm windows of "
                  f"{len(attack)}) | {int(attack['warm_scored'].sum())} warm windows")

    verdict, reasons = root_verdict.decide(rows.to_dict("records"))
    print(f"\nroot-count verdict: {verdict}")
    for reason in reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    main()
