"""Per-window anomaly scores for the plain and flag alphabets, and the AUROC summary.

Both models are fitted on the same training flows and scored on the same windows, so the
only difference between them is the symbol alphabet. Scores are oriented so higher always
means more anomalous: the likelihood path negates the mean log probability, which is lower
for unlikely traces.
"""
import argparse

import numpy as np
import pandas as pd

from data_io import describe_captures, load_manifest, resolve_output
from features import WINDOW_SIZE
from statemachine import (fit_model, load_flow_packets, make_flows, n_windows_for,
                          score_cutoff, score_flows, segment_flows, split_flows)

MANIFEST_FILE = "capture_manifest.csv"
WINDOW_CSV = "flag_window_scores.csv"
SUMMARY_CSV = "flag_auc.csv"


def window_scores(scored, t0, n_windows, window_size=WINDOW_SIZE):
    """Most anomalous trace per window; NaN where no trace ends."""
    scores = np.full(n_windows, np.nan)
    for start_ts, score in scored:
        window = int((start_ts - t0) // window_size)
        if 0 <= window < n_windows:
            current = scores[window]
            scores[window] = score if np.isnan(current) else max(current, score)
    return scores


def auroc(benign, attack):
    """Probability an attack window outranks a benign one, ties counted as half."""
    benign = np.asarray([value for value in benign if np.isfinite(value)], dtype=float)
    attack = np.asarray([value for value in attack if np.isfinite(value)], dtype=float)
    if not len(benign) or not len(attack):
        raise ValueError("AUROC needs at least one finite score on each side.")
    greater = (attack[:, None] > benign[None, :]).sum()
    ties = (attack[:, None] == benign[None, :]).sum()
    return float((greater + 0.5 * ties) / (len(attack) * len(benign)))


def detection_at_benign_rate(benign, attack, fraction):
    """(detection, realised benign rate) with the threshold at the k-th largest benign score."""
    benign = np.asarray([value for value in benign if np.isfinite(value)], dtype=float)
    attack = np.asarray([value for value in attack if np.isfinite(value)], dtype=float)
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be within (0, 1].")
    if not len(benign) or not len(attack):
        raise ValueError("Detection needs at least one finite score on each side.")
    k = max(1, int(round(fraction * len(benign))))
    threshold = float(np.sort(benign)[-k])
    return float(np.mean(attack >= threshold)), float(np.mean(benign >= threshold))


def anomaly_scores(model, flows, t0, n_windows):
    """Window anomalies under one model, higher meaning more anomalous."""
    scored = score_flows(model, flows)
    # A likelihood is a mean log probability: negate it so a higher value is worse.
    return window_scores([(ts, -score) for ts, score in scored], t0, n_windows)


def score_label(reference_path, targets):
    """Per-window anomalies for one label's holdout and its attack captures."""
    reference = load_flow_packets(reference_path, flags=True)
    reference_t0 = reference["ts"].min()
    flows, dropped = segment_flows(make_flows(reference), reference_t0)
    train, holdout = split_flows(flows)
    models = {"plain": fit_model(train, flags=False),
              "flags": fit_model(train, flags=True)}
    n_windows = n_windows_for(reference)
    result = {"holdout": {}, "targets": {}, "dropped": dropped}
    for name, model in models.items():
        cutoff = score_cutoff(score_flows(model, holdout))
        result["holdout"][name] = anomaly_scores(model, holdout, reference_t0, n_windows)
        result["holdout"][f"{name}_cutoff"] = cutoff
        for scenario, path, packets in targets:
            target_t0 = packets["ts"].min()
            target_flows, _ = segment_flows(make_flows(packets), target_t0)
            result["targets"][(scenario, name)] = anomaly_scores(
                model, target_flows, target_t0, n_windows_for(packets))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Dump per-window anomaly scores under the plain and flag alphabets.")
    parser.add_argument("--method", default="tcp", choices=("tcp", "ptcp"))
    parser.add_argument("--out", default=WINDOW_CSV)
    parser.add_argument("--summary", default=SUMMARY_CSV)
    parser.add_argument("--manifest", default=MANIFEST_FILE)
    args = parser.parse_args()

    import local_paths
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    if "usable" not in manifest.columns:      # a freshly built manifest carries no verdict
        manifest = describe_captures(manifest)
    at_method = manifest[(manifest["method"] == args.method)
                         & manifest["usable"].astype(bool)]
    attacks = [name for name in sorted(at_method["scenario"].unique()) if name != "benign"]

    windows, summary = [], []
    for label in sorted(at_method["label"].unique()):
        reference = at_method[(at_method["scenario"] == "benign")
                              & (at_method["label"] == label)]
        if reference.empty:
            print(f"skipped {label}: no benign reference")
            continue
        targets = []
        for scenario in attacks:
            row = at_method[(at_method["scenario"] == scenario)
                            & (at_method["label"] == label)]
            if row.empty:
                print(f"skipped {label}/{scenario}: no capture")
                continue
            packets = load_flow_packets(row.iloc[0]["path"], flags=True)
            targets.append((scenario, row.iloc[0]["path"], packets))
        result = score_label(reference.iloc[0]["path"], targets)
        for name, scores in result["holdout"].items():
            if name.endswith("_cutoff"):
                continue
            for window, value in enumerate(scores):
                windows.append({"label": label, "scenario": "benign", "method": args.method,
                                "model": name, "window": window, "anomaly": value})
        for (scenario, name), scores in result["targets"].items():
            for window, value in enumerate(scores):
                windows.append({"label": label, "scenario": scenario, "method": args.method,
                                "model": name, "window": window, "anomaly": value})

        reference_benign = result["holdout"]["plain"]
        # A window flags when its most anomalous trace reaches the negated cutoff.
        plain_rate = float(np.mean(reference_benign[np.isfinite(reference_benign)]
                                   >= -result["holdout"]["plain_cutoff"]))
        for scenario, _, _ in targets:
            benign_plain = result["holdout"]["plain"]
            benign_flags = result["holdout"]["flags"]
            attack_plain = result["targets"][(scenario, "plain")]
            attack_flags = result["targets"][(scenario, "flags")]
            if not (np.isfinite(attack_plain).any() and np.isfinite(attack_flags).any()):
                print(f"skipped {label}/{scenario}: no scored attack windows")
                continue
            if plain_rate <= 0:
                print(f"skipped {label}/{scenario}: plain model flagged no benign window")
                continue
            det_plain, _ = detection_at_benign_rate(benign_plain, attack_plain, plain_rate)
            det_flags, realised = detection_at_benign_rate(benign_flags, attack_flags,
                                                           plain_rate)
            summary.append({
                "label": label, "scenario": scenario, "method": args.method,
                "n_benign_plain": int(np.isfinite(benign_plain).sum()),
                "n_attack_plain": int(np.isfinite(attack_plain).sum()),
                "n_benign_flags": int(np.isfinite(benign_flags).sum()),
                "n_attack_flags": int(np.isfinite(attack_flags).sum()),
                "auc_plain": auroc(benign_plain, attack_plain),
                "auc_flags": auroc(benign_flags, attack_flags),
                "det_plain": det_plain, "det_flags": det_flags,
                "benign_rate_plain": plain_rate, "benign_rate_flags": realised,
            })

    windows_path = resolve_output(args.out)
    pd.DataFrame(windows).to_csv(windows_path, index=False)
    summary_path = resolve_output(args.summary)
    rows = pd.DataFrame(summary)
    rows.to_csv(summary_path, index=False)
    print(f"Wrote {windows_path} | rows={len(windows)}")
    print(f"Wrote {summary_path} | strata={len(rows)}")

    import flag_verdict
    verdict_rows = []
    for label, scenario in flag_verdict.STRATA:
        match = rows[(rows["label"] == label) & (rows["scenario"] == scenario)]
        if match.empty:
            continue
        row = match.iloc[0]
        verdict_rows.append({"label": label, "scenario": scenario,
                             "auc_plain": row["auc_plain"], "auc_flags": row["auc_flags"],
                             "det_plain": row["det_plain"], "det_flags": row["det_flags"]})
    verdict, reasons = flag_verdict.decide(verdict_rows)
    print(f"\nverdict: {verdict}")
    for reason in reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    main()
