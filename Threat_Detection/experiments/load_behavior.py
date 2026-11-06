"""Load channel against behavior channel, judged by verdicts/load_behavior.py.

The load channel is the z-score detector (all 13 features, fitted on the first 70% of the
benign recording, cutoff THRESHOLD). The behavior channel is the windowed SEQUENT score of
the PDFA at the visualization's calibration. This measures whether the second can gate the
first: see the verdict module for the two claims and the rule, committed before this ran.

Claim A runs on the three bulk-transfer taps' benign recordings, comparing windows after the
regime change against windows before it. The onset is the single change point of
log(total_bytes) that minimises the squared error of two flat segments, each at least
MIN_SEGMENT windows long; it is a measurement of the step, not a label from the sponsor.

Claim B runs on the steady taps. A warm attack window is flagged by a channel when its score is
above that channel's cutoff; a window the behavior score could not score is not flagged. The
per-window cross-tabulation is written beside the counts so the missing column is visible.

Run it with:  .venv/bin/python experiments/load_behavior.py
"""
import sys
from pathlib import Path

# A script run as `python experiments/load_behavior.py` gets experiments/ as sys.path[0].
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse

import numpy as np
import pandas as pd

from core import (BULK_LABELS, build_detector, load_capture, load_manifest, make_windows,
                  resolve_output, split_reference)
from core.data_io import MANIFEST_NAME, describe_captures
from experiments import metrics
from experiments.windowed_scores import _load as _load_flow_packets
from methods.scores import FORGET_SECONDS, warm_from
from statemachine import (fit_model, frequency_cutoff, frequency_scores_by_window,
                          make_flows, n_windows_for, segment_flows, split_flows)
from verdicts import load_behavior as verdict

STEADY_CSV = "load_behavior.csv"
BULK_CSV = "load_behavior_bulk.csv"
MIN_SEGMENT = 8             # windows on each side of a change point


def onset_window(total_bytes):
    """The window where log(total_bytes) steps, or None if no side can hold MIN_SEGMENT windows."""
    series = np.log1p(np.asarray(total_bytes, dtype=float))
    best, best_error = None, np.inf
    for cut in range(MIN_SEGMENT, len(series) - MIN_SEGMENT + 1):
        left, right = series[:cut], series[cut:]
        error = ((left - left.mean()) ** 2).sum() + ((right - right.mean()) ** 2).sum()
        if error < best_error:
            best, best_error = cut, error
    return best


def _load(path):
    """(flow packets, capture packets) for one file, or None when its timebase is unusable.

    The PDFA reads the flow columns and the z-score's windows need `iat`, so each side is
    loaded by the loader that keeps its columns.
    """
    flow = _load_flow_packets(path)
    return None if flow is None else (flow, load_capture(path))


def _flagged(scores, cutoff):
    """Above the cutoff; a missing score is not flagged."""
    return np.nan_to_num(np.asarray(scores, dtype=float), nan=-np.inf) > cutoff


def _auroc(low, high):
    low = np.asarray(low, dtype=float)
    high = np.asarray(high, dtype=float)
    low, high = low[np.isfinite(low)], high[np.isfinite(high)]
    if not len(low) or not len(high):
        return np.nan
    return metrics.auroc(low, high)


def _fit(benign):
    """Everything fitted on one benign recording: windows, z detector, PDFA, flows."""
    benign, captured = benign
    windows = make_windows(captured)
    reference, held = split_reference(windows)
    z = build_detector("z_score", features=None).pipeline(reference, held)   # all 13, as measured
    t0 = float(benign["ts"].min())
    flows, _ = segment_flows(make_flows(benign), t0)
    train, holdout = split_flows(flows)
    model = fit_model(train)
    return {"windows": windows, "z": z, "t0": t0, "flows": flows, "holdout": holdout,
            "model": model, "n_windows": n_windows_for(benign)}


def bulk_row(label, method, benign):
    fit = _fit(benign)
    windows = fit["windows"]
    onset = onset_window(windows["total_bytes"])
    behavior = frequency_scores_by_window(fit["model"], fit["flows"], fit["t0"],
                                          fit["n_windows"], FORGET_SECONDS)
    z = fit["z"].score(windows).to_numpy(dtype=float)
    n = min(len(behavior), len(z))
    first = warm_from(FORGET_SECONDS)
    row = {"label": label, "method": method, "windows": n, "onset": onset,
           "onset_fraction": np.nan if onset is None else onset / n,
           "n_pre": 0, "n_post": 0, "behavior_auroc": np.nan, "z_auroc": np.nan}
    if onset is None or onset <= first + 1:
        return row
    pre_b, post_b = behavior[first:onset], behavior[onset:n]
    row.update(n_pre=int(np.isfinite(pre_b).sum()), n_post=int(np.isfinite(post_b).sum()),
               behavior_auroc=_auroc(pre_b, post_b), z_auroc=_auroc(z[first:onset], z[onset:n]))
    return row


def steady_rows(label, method, benign, targets):
    """Benign counts and one row per attack for one steady tap."""
    fit = _fit(benign)
    windows, z, model = fit["windows"], fit["z"], fit["model"]
    behavior_all = frequency_scores_by_window(model, fit["flows"], fit["t0"],
                                              fit["n_windows"], FORGET_SECONDS)
    first_held = int((float(fit["holdout"]["start_ts"].iloc[0]) - fit["t0"]) // 1.0) + 1
    n = min(len(windows), len(behavior_all))
    held_behavior = behavior_all[first_held:n]
    if not np.isfinite(held_behavior).any():
        raise ValueError("no scored held-out benign window")
    cutoff = frequency_cutoff(held_behavior)
    z_held_score = z.score(windows).to_numpy(dtype=float)[first_held:n]
    z_held = z.flag(windows).to_numpy()[first_held:n]
    behavior_held = _flagged(held_behavior, cutoff)
    rows = [{"label": label, "method": method, "scenario": "benign", "windows": len(z_held),
             "z_flagged": int(z_held.sum()), "behavior_flagged": int(behavior_held.sum()),
             "behavior_missing": int((~np.isfinite(held_behavior)).sum())}]
    warm_start = warm_from(FORGET_SECONDS)
    for scenario, (packets, captured) in targets.items():
        t0 = float(packets["ts"].min())
        flows, _ = segment_flows(make_flows(packets), t0)
        behavior = frequency_scores_by_window(model, flows, t0, n_windows_for(packets),
                                              FORGET_SECONDS)
        target_windows = make_windows(captured)
        z_flags = z.flag(target_windows).to_numpy()
        z_scores = z.score(target_windows).to_numpy(dtype=float)
        m = min(len(behavior), len(z_flags))
        b_warm, z_warm = behavior[warm_start:m], z_flags[warm_start:m]
        if len(b_warm) == 0:
            rows.append({"label": label, "method": method, "scenario": scenario, "warm": 0})
            continue
        b_flags = _flagged(b_warm, cutoff)
        # Supplementary, decides nothing: the z-score at the benign rate the behavior cutoff
        # actually realised, so the two are compared at what they cost rather than at their
        # own cutoffs (the 2.5 sigma cutoff flags ~45% of held-out benign windows).
        scored_held = np.isfinite(held_behavior)
        realised = float(behavior_held[scored_held].mean()) if scored_held.any() else 0.0
        matched = (metrics.detection_at_rate(z_held_score, z_scores[warm_start:m], realised)
                   if realised > 0 else (np.nan, np.nan))
        rows.append({
            "label": label, "method": method, "scenario": scenario, "warm": int(len(b_warm)),
            "z_flagged": int(z_warm.sum()), "behavior_flagged": int(b_flags.sum()),
            "both": int((z_warm & b_flags).sum()), "z_only": int((z_warm & ~b_flags).sum()),
            "behavior_only": int((~z_warm & b_flags).sum()),
            "neither": int((~z_warm & ~b_flags).sum()),
            "z_only_behavior_missing": int((z_warm & ~np.isfinite(b_warm)).sum()),
            "behavior_missing": int((~np.isfinite(b_warm)).sum()),
            "behavior_benign_rate": realised, "z_matched_detection": matched[0],
            "z_matched_benign_rate": matched[1],
            "behavior_auroc": _auroc(held_behavior, b_warm),
            "z_auroc": _auroc(z_held_score, z_scores[warm_start:m])})
    return rows


def sweep(manifest, methods=("tcp", "ptcp")):
    if "usable" not in manifest.columns:
        manifest = describe_captures(manifest)
    bulk, steady, excluded = [], [], []
    for method in methods:
        at_method = manifest[manifest["method"].eq(method)]
        attacks = sorted(s for s in at_method["scenario"].unique() if s != "benign")
        for label in sorted(at_method["label"].unique()):
            by_scenario = {r.scenario: r for r in at_method[at_method["label"].eq(label)].itertuples()}
            benign = _load(by_scenario["benign"].path) if "benign" in by_scenario else None
            if benign is None:
                excluded.append(f"{label}/{method} (no usable benign)")
                continue
            try:
                if label in BULK_LABELS:
                    bulk.append(bulk_row(label, method, benign))
                    continue
                targets = {}
                for scenario in attacks:
                    packets = _load(by_scenario[scenario].path) if scenario in by_scenario else None
                    if packets is None:
                        excluded.append(f"{scenario}/{label}/{method}")
                    else:
                        targets[scenario] = packets
                steady += steady_rows(label, method, benign, targets)
            except ValueError as error:
                excluded.append(f"{label}/{method} ({error})")
    return pd.DataFrame(bulk), pd.DataFrame(steady), excluded


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    import local_paths
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    bulk, steady, excluded = sweep(manifest)
    bulk.to_csv(resolve_output(BULK_CSV), index=False)
    steady.to_csv(resolve_output(STEADY_CSV), index=False)
    print(f"Wrote {BULK_CSV} ({len(bulk)} rows) and {STEADY_CSV} ({len(steady)} rows)")
    if excluded:
        print(f"excluded: {len(excluded)} ({', '.join(sorted(excluded))})")

    print("\nClaim A: bulk taps, benign recording, post-onset against pre-onset (AUROC)")
    print(bulk.round(3).to_string(index=False))

    tcp_bulk = bulk[bulk["method"].eq("tcp")].to_dict("records")
    attack = steady[steady["scenario"].ne("benign") & steady["warm"].gt(0)]
    benign = steady[steady["scenario"].eq("benign")]
    for method in ("tcp", "ptcp"):
        a = attack[attack["method"].eq(method)]
        b = benign[benign["method"].eq(method)]
        print(f"\nClaim B inputs, {method}:")
        for scenario, g in a.groupby("scenario"):
            warm = g["warm"].sum()
            print(f"  {scenario:<10} warm {int(warm):>4} | z {g['z_flagged'].sum() / warm:.3f} "
                  f"behavior {g['behavior_flagged'].sum() / warm:.3f} | both {int(g['both'].sum())} "
                  f"z_only {int(g['z_only'].sum())} behavior_only {int(g['behavior_only'].sum())} "
                  f"neither {int(g['neither'].sum())} | behavior missing "
                  f"{int(g['behavior_missing'].sum())} | z at behavior's benign rate "
                  f"{(g['z_matched_detection'] * g['warm']).sum() / warm:.3f} | AUROC z {g['z_auroc'].mean():.3f} "
                  f"behavior {g['behavior_auroc'].mean():.3f}")
        print(f"  benign     windows {int(b['windows'].sum()):>4} | z "
              f"{b['z_flagged'].sum() / b['windows'].sum():.3f} behavior "
              f"{b['behavior_flagged'].sum() / b['windows'].sum():.3f} "
              f"(behavior missing {int(b['behavior_missing'].sum())})")

    tcp_attack = attack[attack["method"].eq("tcp")].to_dict("records")
    tcp_benign = benign[benign["method"].eq("tcp")].to_dict("records")
    decision, reasons = verdict.decide(tcp_bulk, tcp_attack, tcp_benign)
    print(f"\nload-versus-behavior verdict (tcp decides): {decision}")
    for reason in reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    main()
