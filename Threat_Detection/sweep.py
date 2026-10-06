"""Score every capture against its own matched benign reference.

The reference for a target capture is the benign capture with the same label and
the same capture method, fitted on its first 70% of windows. The remaining 30% are
scored too, so the false-alarm rows come from windows the baseline never saw.
"""
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import manifest
from test import (BENIGN_TRAIN_FRACTION, PERSISTENCE_WINDOW, THRESHOLD, WINDOW_SIZE,
                  build_baseline, detect_anomalies, flag_persistent, make_features)

FEATURE_GROUPS = {
    "volume": ["packet_count", "total_bytes"],
    "size_timing": ["mean_packet_size", "mean_iat"],
    "diversity": ["unique_dst_ips", "unique_dst_ports"],
    "flags": ["syn_count", "rst_count"],
}
MANIFEST_FILE = "capture_manifest.csv"


def split_reference(features, train_fraction=BENIGN_TRAIN_FRACTION):
    """First `train_fraction` of the benign windows fit the reference; the rest are held out."""
    split = int(len(features) * train_fraction)
    if split < 2 or split >= len(features):
        raise ValueError("Insufficient benign windows for a matched reference")
    return features.iloc[:split], features.iloc[split:]


def load_features(described):
    """make_features for every capture; unusable captures get None plus a stated reason."""
    features, notes = {}, {}
    for _, capture in described.iterrows():
        key = (capture["scenario"], capture["label"], capture["method"])
        packets = manifest.load_capture(capture["path"])
        issues = manifest.timebase_issues(packets)
        if not issues["usable"]:
            features[key] = None
            notes[key] = (f"excluded: {issues['bad_ts']} bad timestamps of {issues['rows']} rows,"
                          f" span {issues['span_s']}s")
            continue
        features[key] = make_features(packets)
    return features, notes


def summary_row(scenario, label, method, group, results):
    """One row of evidence for one scored capture."""
    flagged = results["anomaly"].fillna(False).astype(bool)
    finite = results["anomaly_score"].replace([np.inf, -np.inf], np.nan).dropna()
    return {
        "group": group, "scenario": scenario, "label": label, "method": method,
        "windows": int(len(results)),
        "flagged": int(flagged.sum()),
        "persistent": int(results["persistent_flag"].sum()),
        "flagged_fraction": round(float(flagged.mean()), 4) if len(results) else np.nan,
        "peak_score": round(float(finite.max()), 3) if len(finite) else np.nan,
        "top_feature": (results.loc[flagged, "top_feature"].value_counts().idxmax()
                        if flagged.any() else ""),
        "note": "",
    }


def blocked_row(scenario, label, method, group, note):
    """A capture that could not be scored, kept visible with its reason."""
    return {"group": group, "scenario": scenario, "label": label, "method": method,
            "windows": 0, "flagged": 0, "persistent": 0, "flagged_fraction": np.nan,
            "peak_score": np.nan, "top_feature": "", "note": note}


def run_sweep(described, groups=(None,)):
    """Score every (label, method) stratum in every scenario; `groups` selects feature subsets."""
    features, notes = load_features(described)
    attacks = [s for s in sorted(described["scenario"].unique()) if s != "benign"]
    rows = []
    for group in groups:
        columns = None if group in (None, "all") else list(FEATURE_GROUPS[group])
        group_name = "all" if columns is None else group
        for method in sorted(described["method"].unique()):
            for label in sorted(described["label"].unique()):
                reference_features = features.get(("benign", label, method))
                targets = [("benign", None)] + [(s, features.get((s, label, method))) for s in attacks]
                if reference_features is None:
                    for scenario, _ in targets:
                        rows.append(blocked_row(scenario, label, method, group_name,
                                                notes.get((scenario, label, method), "no capture")))
                    continue
                reference, holdout = split_reference(reference_features)
                mean, std = build_baseline(reference if columns is None else reference[columns])
                for scenario, target in targets:
                    target = holdout if scenario == "benign" else target
                    if target is None:
                        rows.append(blocked_row(scenario, label, method, group_name,
                                                notes.get((scenario, label, method), "no capture")))
                        continue
                    scored = target if columns is None else target[columns]
                    results = flag_persistent(detect_anomalies(scored, mean, std))
                    rows.append(summary_row(scenario, label, method, group_name, results))
    return (pd.DataFrame(rows)
            .sort_values(["group", "method", "label", "scenario"])
            .reset_index(drop=True))


def print_matrix(results):
    """One row per capture label, one column per scenario, for each group and capture method."""
    for group in results["group"].unique():
        for method in sorted(results["method"].unique()):
            view = results[results["group"].eq(group) & results["method"].eq(method)]
            table = view.pivot_table(index="label", columns="scenario", values="flagged_fraction")
            print(f"\nFlagged fraction of windows | group={group} | method={method}"
                  f" | {WINDOW_SIZE:g}s windows | alert > {THRESHOLD:g} sigma"
                  f" | {PERSISTENCE_WINDOW}-window persistence")
            print(table.to_string(float_format=lambda value: f"{value:5.2f}"))


def _fraction(view, label, scenario):
    row = view[view["label"].eq(label) & view["scenario"].eq(scenario)]
    return float(row["flagged_fraction"].iloc[0]) if len(row) else np.nan


def plot_summary(results, path="sweep_summary.png"):
    """Grouped bars: flagged fraction per capture label, one series per scenario."""
    view = results[results["group"].eq("all") & results["method"].eq("tcp")]
    scenarios = ["benign"] + [s for s in view["scenario"].unique() if s != "benign"]
    labels = sorted(view["label"].unique())
    positions = np.arange(len(labels))
    width = 0.8 / len(scenarios)
    fig, ax = plt.subplots(figsize=(12, 5))
    for offset, scenario in enumerate(scenarios):
        values = [_fraction(view, label, scenario) for label in labels]
        ax.bar(positions + offset * width, values, width, label=scenario)
    ax.set_xticks(positions + 0.4 - width / 2)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_ylabel("flagged fraction of windows")
    ax.set_ylim(0, 1)
    ax.legend(fontsize=8)
    fig.suptitle(f"Matched benign reference per capture | {WINDOW_SIZE:g}s windows"
                 f" | alert > {THRESHOLD:g} sigma | {PERSISTENCE_WINDOW}-window persistence"
                 f" | tcp captures ({len(labels)} labels)", fontsize=11)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\nWrote {path}")


def main():
    import local_paths
    parser = argparse.ArgumentParser(description="Score every capture against its matched benign reference.")
    parser.add_argument("--groups", default="all",
                        help="'all', or a comma-separated subset of " + ", ".join(FEATURE_GROUPS))
    parser.add_argument("--out", default="sweep_results.csv")
    parser.add_argument("--manifest", default=MANIFEST_FILE)
    args = parser.parse_args()

    described = (pd.read_csv(args.manifest) if Path(args.manifest).exists()
                 else manifest.describe_captures(manifest.build_manifest(local_paths.KUBEDATA_ROOT)))
    groups = [None] if args.groups == "all" else args.groups.split(",")
    results = run_sweep(described, groups=groups)
    results.to_csv(args.out, index=False)
    print_matrix(results)
    excluded = results[results["note"].str.startswith("excluded", na=False)]
    print(f"\nWrote {args.out} | rows={len(results)}"
          f" | excluded captures={excluded['label'].nunique()}")
    print(f"Times are per capture; windows are {WINDOW_SIZE:g}s. Flags are deviations, not confirmed attacks.")
    if len(groups) == 1 and groups[0] is None:
        plot_summary(results)


if __name__ == "__main__":
    main()
