"""Cross-validated calibration of the windowed SEQUENT score, judged by cv_verdict's rule.

The split calibration (story.py, windowed_scores.py) sets the cutoff on the last 30% of one
benign recording: 3-16 scored windows per steady tap. Here every benign window is held out
once instead. The recording is cut into cv_verdict.CV_FOLDS contiguous blocks on window
boundaries; each block is scored, on a warm clock, by a machine learned from the other
blocks (as separate segments, so no training trace spans the hole), and the cutoff is the
95th percentile of all of those out-of-fold windows. The deployed machine learns from the
whole benign recording.

Windows left out of calibration, and why:
  - each block's first window: traces ending there began in the training data before it;
  - the recording's first FORGET_SECONDS: the clock starts cold there, as an attack's does.

What the verdict reads, per tap:
  - cutoff_windows: how many windows the cutoff rests on;
  - oos_flagged / oos_windows: each block judged against a cutoff set from the other blocks
    only, the benign rate measured out of sample;
  - scale_ratio: median |full machine - fold machine| on attack windows (out of sample for
    every machine), over the interquartile range of the benign windows.

Run it with:  .venv/bin/python cv_calibration.py
"""
import argparse

import numpy as np
import pandas as pd

import cv_verdict
import windowed_scores
from core.data_io import MANIFEST_NAME, load_manifest, resolve_output
from core.evaluation import BULK_LABELS
from core.features import WINDOW_SIZE
from statemachine import (FORGET_SECONDS, fit_model, fit_segments, frequency_cutoff,
                          frequency_scores_by_window, make_flows, n_windows_for,
                          segment_flows)

CV_CSV = "cv_calibration.csv"


def fold_blocks(n_windows, folds=cv_verdict.CV_FOLDS):
    """[(first window, end window)] for `folds` contiguous blocks covering the recording."""
    edges = [round(n_windows * k / folds) for k in range(folds + 1)]
    return [(edges[k], edges[k + 1]) for k in range(folds)]


def _window_of(flows, t0):
    return ((flows["start_ts"] - t0) // WINDOW_SIZE).astype(int).to_numpy()


def calibrate(flows, t0, n_windows, forget_seconds=FORGET_SECONDS, folds=cv_verdict.CV_FOLDS):
    """Out-of-fold window scores, the cutoff they give, and the full-recording machine.

    Returns {"model", "folds": [{"block", "model", "windows", "scores"}], "cutoff",
    "cutoff_windows", "oos_flagged", "oos_windows"}. A fold's `scores` are aligned with its
    `windows` and may hold NaN where no trace ended.
    """
    window = _window_of(flows, t0)
    first_warm = windowed_scores.warm_from(forget_seconds)
    results = []
    for start, end in fold_blocks(n_windows, folds):
        held = (window >= start) & (window < end)
        segments = [part for part in (flows[window < start], flows[window >= end])
                    if len(part)]
        model = fit_segments(segments)
        scores = frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds)
        kept = [w for w in range(start + 1, end) if w >= first_warm]
        results.append({"block": (start, end), "model": model, "windows": kept,
                        "scores": scores[kept], "held_flows": int(held.sum())})
    pooled = np.concatenate([fold["scores"] for fold in results])
    flagged = windows = 0
    for k, fold in enumerate(results):
        others = np.concatenate([f["scores"] for j, f in enumerate(results) if j != k])
        if not np.isfinite(others).any():
            continue
        cutoff = frequency_cutoff(others)
        scored = fold["scores"][np.isfinite(fold["scores"])]
        flagged += int((scored > cutoff).sum())
        windows += len(scored)
    return {"model": fit_model(flows), "folds": results,
            "cutoff": frequency_cutoff(pooled) if np.isfinite(pooled).any() else None,
            "cutoff_windows": int(np.isfinite(pooled).sum()),
            "oos_flagged": flagged, "oos_windows": windows}


def scale_ratio(calibration, attack_scores_by_model):
    """Median |full - fold| over attack windows, as a share of the benign windows' IQR.

    `attack_scores_by_model` is a list of (full scores, [fold scores]) per attack capture,
    already restricted to warm windows. Attack windows are out of sample for every machine,
    so a difference there is the scale the fold machines do not share with the full one.
    """
    diffs = []
    for full, fold_scores in attack_scores_by_model:
        for fold in fold_scores:
            both = np.isfinite(full) & np.isfinite(fold)
            diffs.append(np.abs(full[both] - fold[both]))
    diffs = np.concatenate(diffs) if diffs else np.array([])
    pooled = np.concatenate([f["scores"] for f in calibration["folds"]])
    pooled = pooled[np.isfinite(pooled)]
    if not len(diffs) or not len(pooled):
        return np.nan
    spread = np.subtract(*np.percentile(pooled, [75, 25]))
    return float(np.median(diffs) / spread) if spread > 0 else np.inf


def label_rows(label, method, benign, targets, forget_seconds=FORGET_SECONDS):
    """The split rows (as windowed_scores measures them) and the cv5 rows for one tap."""
    split = [dict(row, calibration="split") for row in windowed_scores.label_rows(
        label, method, benign, targets, forget_seconds, variants=("entries",))]
    t0 = float(benign["ts"].min())
    flows, dropped = segment_flows(make_flows(benign), t0)
    n_windows = n_windows_for(benign)
    group = "bulk" if label in BULK_LABELS else "steady"
    cal = calibrate(flows, t0, n_windows, forget_seconds)
    cutoff = cal["cutoff"] if group == "steady" else None
    pooled = np.concatenate([f["scores"] for f in cal["folds"]])
    first_warm = windowed_scores.warm_from(forget_seconds)

    common = {"detector": "windowed_frequency", "label": label, "method": method,
              "group": group, "train_counts": "entries", "calibration": "cv5",
              "forget_seconds": float(forget_seconds), "states": cal["model"]["pdfa"].n_states,
              "cutoff": np.nan if cutoff is None else cutoff}
    attack_rows, by_model = [], []
    for scenario, packets in targets.items():
        target_t0 = float(packets["ts"].min())
        target_flows, target_dropped = segment_flows(make_flows(packets), target_t0)
        target_windows = n_windows_for(packets)
        full = frequency_scores_by_window(cal["model"], target_flows, target_t0, target_windows,
                                          forget_seconds)
        folds = [frequency_scores_by_window(f["model"], target_flows, target_t0,
                                            target_windows, forget_seconds)[first_warm:]
                 for f in cal["folds"]]
        by_model.append((full[first_warm:], folds))
        attack_rows.append(dict(common, scenario=scenario, dropped_segments=target_dropped,
                                **windowed_scores.attack_fields(pooled, full, cutoff, first_warm)))
    benign_row = dict(common, scenario="benign", dropped_segments=dropped,
                      **windowed_scores.benign_fields(pooled, cutoff),
                      oos_flagged=cal["oos_flagged"], oos_windows=cal["oos_windows"],
                      scale_ratio=scale_ratio(cal, by_model))
    quoted = {"cutoff_windows": benign_row["cutoff_windows"],
              "realised_benign_rate": (cal["oos_flagged"] / cal["oos_windows"]
                                       if cal["oos_windows"] else np.nan)}
    return split + [benign_row] + [dict(row, **quoted) for row in attack_rows]


def main():
    parser = argparse.ArgumentParser(
        description="Measure cross-validated calibration of the windowed SEQUENT score "
                    "against the split, and apply the pre-registered verdict.")
    parser.add_argument("--methods", nargs="+", default=["tcp", "ptcp"], choices=("tcp", "ptcp"))
    parser.add_argument("--forget", type=float, default=FORGET_SECONDS)
    parser.add_argument("--out", default=CV_CSV)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    import local_paths
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    rows, excluded = windowed_scores.sweep(manifest, tuple(args.methods), args.forget,
                                           rows_for=label_rows)
    out = resolve_output(args.out)
    rows.to_csv(out, index=False)
    print(f"Wrote {out} | rows={len(rows)}")
    if excluded:
        print(f"excluded: {len(excluded)} ({', '.join(sorted(excluded))})")

    steady = rows[rows["group"].eq("steady")]
    for (method, calibration), group in steady.groupby(["method", "calibration"]):
        held = group[group["scenario"].eq("benign")]
        print(f"\n{method} | {calibration} | cutoffs rest on {held['cutoff_windows'].min()}-"
              f"{held['cutoff_windows'].max()} windows (median {held['cutoff_windows'].median():g})")
        if calibration == "cv5":
            print(f"  out-of-fold benign rate {held['oos_flagged'].sum():.0f} of "
                  f"{held['oos_windows'].sum():.0f}; median scale shift "
                  f"{held['scale_ratio'].median():.3f} of the benign IQR")
        for scenario, attack in group[~group["scenario"].eq("benign")].groupby("scenario"):
            print(f"  {scenario:<16} AUROC median {attack['auroc'].median():.3f} "
                  f"detection mean {attack['detection'].mean():.3f}")

    verdict, reasons = cv_verdict.decide(rows.to_dict("records"))
    print(f"\ncross-validated calibration verdict: {verdict}")
    for reason in reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    main()
