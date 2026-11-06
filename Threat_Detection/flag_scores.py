"""Per-window anomaly scores for the plain and flag alphabets, and the AUROC summary.

Both models are fitted on the same training flows and scored on the same windows, so the
only difference between them is the symbol alphabet. Scores are oriented so higher always
means more anomalous: the likelihood path negates the mean log probability, which is lower
for unlikely traces.
"""
import argparse

import numpy as np
import pandas as pd

import metrics

from core.data_io import MANIFEST_NAME, describe_captures, load_manifest, resolve_output
from core.features import WINDOW_SIZE
from statemachine import (fit_model, load_flow_packets, make_flows, n_windows_for,
                          score_cutoff, score_flows, segment_flows, split_flows)

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
    """Probability an attack window outranks a benign one, ties counted as half.

    Delegates to metrics.auroc, the pairwise policy that raises on an empty side: in a sweep
    an empty stratum is a broken measurement, not a thin one.
    """
    return metrics.auroc(benign, attack)


def detection_at_benign_rate(benign, attack, fraction):
    """(detection, realised benign rate) with the threshold at the k-th largest benign score."""
    return metrics.detection_at_rate(benign, attack, fraction)


def anomaly_scores(model, flows, t0, n_windows):
    """Window anomalies under one model, higher meaning more anomalous."""
    scored = score_flows(model, flows)
    # A likelihood is a mean log probability: negate it so a higher value is worse.
    return window_scores([(ts, -score) for ts, score in scored], t0, n_windows)


def verdict_rows(summary):
    """The summary rows the pre-registered rule reads, in the rule's own order."""
    import flag_verdict
    rows = []
    for label, scenario in flag_verdict.STRATA:
        match = summary[(summary["label"] == label) & (summary["scenario"] == scenario)]
        if match.empty:
            continue
        row = match.iloc[0]
        rows.append({"label": label, "scenario": scenario,
                     "auc_plain": row["auc_plain"], "auc_flags": row["auc_flags"],
                     "det_plain": row["det_plain"], "det_flags": row["det_flags"]})
    return rows


def plot_alphabet_slope(summary, path=None):
    """One line per stratum, plain-model AUROC to flag-model AUROC, sorted by the change.

    Green is a gain at or above the rule's keep bar, red a loss at or above the limit it
    allows, grey anything inside the band. The verdict in the title is `flag_verdict`'s,
    not this function's opinion.
    """
    import matplotlib
    matplotlib.use("Agg")   # renders to a file; nothing here opens a window
    import matplotlib.pyplot as plt

    import flag_verdict

    path = resolve_output(path or "alphabet_verdict.png")
    verdict, _ = flag_verdict.decide(verdict_rows(summary))
    view = (summary.assign(gain=summary["auc_flags"] - summary["auc_plain"])
            .sort_values("gain", ascending=False).reset_index(drop=True))
    named = set(flag_verdict.STRATA)

    fig, ax = plt.subplots(figsize=(8.4, 5.25))
    for row, record in view.iterrows():
        if record["gain"] >= flag_verdict.KEEP_AUC_GAIN:
            colour = "#2ca02c"
        elif record["gain"] <= -flag_verdict.MAX_OTHER_LOSS:
            colour = "#d62728"
        else:
            colour = "#7f7f7f"
        ax.plot([record["auc_plain"], record["auc_flags"]], [row, row],
                color=colour, linewidth=2, zorder=2)
        ax.scatter([record["auc_plain"]], [row], s=24, facecolor="white",
                   edgecolors=colour, linewidths=1.5, zorder=3)
        ax.scatter([record["auc_flags"]], [row], s=24, color=colour, zorder=3)
        ax.text(1.03, row, f"{int(record['n_benign_plain'])}/{int(record['n_attack_plain'])}",
                fontsize=6.5, va="center", color="#444444")
    ax.axvline(0.5, color="#bbbbbb", linestyle="--", linewidth=1, zorder=1)

    tick_labels = [f"{record.label} · {record.scenario.replace(' attack', '')}"
                   for record in view.itertuples()]
    ax.set_yticks(range(len(view)))
    ax.set_yticklabels(tick_labels, fontsize=7)
    for tick, record in zip(ax.get_yticklabels(), view.itertuples()):
        if (record.label, record.scenario) in named:
            tick.set_fontweight("bold")
    ax.set_ylim(len(view) - 0.5, -0.5)          # biggest gain on top, smallest at the foot
    ax.set_xlim(-0.02, 1.22)
    ax.set_xticks([0.0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0])
    ax.set_xlabel("AUROC: probability an attack window outranks a benign one", fontsize=9)
    ax.text(1.03, 1.01, "benign/attack windows", fontsize=6.5, color="#444444",
            transform=ax.get_xaxis_transform(), va="bottom")
    caption = (f"AUROC per stratum, plain alphabet against the flag alphabet"
               f" | tcp | {len(view)} strata | same flows, windows and split"
               f"\ngreen: gain at or above the {flag_verdict.KEEP_AUC_GAIN:.2f} keep bar"
               f" | red: loss at or above the {flag_verdict.MAX_OTHER_LOSS:.2f} limit"
               f" | grey: inside it | bold = named by the rule"
               f"\nverdict: {verdict}")
    # Centred on the figure, not on the axes: the row labels push the axes right, and a
    # title anchored there runs off the right edge.
    fig.suptitle(caption, fontsize=8.5, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path


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
    parser.add_argument("--figure", default="alphabet_verdict.png")
    parser.add_argument("--manifest", default=MANIFEST_NAME)
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
    rule_rows = verdict_rows(rows)
    verdict, reasons = flag_verdict.decide(rule_rows)
    print(f"\nverdict: {verdict}")
    for reason in reasons:
        print(f"  - {reason}")
    if len(rule_rows) == len(flag_verdict.STRATA):
        print(f"\nWrote {plot_alphabet_slope(rows, path=args.figure)}")
    else:
        print(f"\nno figure: {len(rule_rows)} of {len(flag_verdict.STRATA)} rule strata measured")


if __name__ == "__main__":
    main()
