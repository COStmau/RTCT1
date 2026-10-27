"""Score every capture against its own matched benign reference.

The reference for a target capture is the benign capture with the same label and
the same capture method, fitted on its first 70% of windows. The remaining 30% are
scored too, so the false-alarm rows come from windows the baseline never saw.
"""
import argparse

import numpy as np
import pandas as pd

import local_paths
from data_io import MANIFEST_NAME, load_manifest, resolve_output
from detectors import build, flag_stats
from features import FEATURE_GROUPS, WINDOW_SIZE, load_all_windows, split_reference
from reporting import plot_detection_gap, plot_matrix, print_matrix

DETECTOR = "z_score"


def summary_row(scenario, label, method, group, results=None, note=""):
    """One row of evidence for one capture.

    results=None records a capture that could not be scored: the row stays, with the
    reason in `note`, so nothing disappears quietly.
    """
    if results is None:
        return {"group": group, "scenario": scenario, "label": label, "method": method,
                "windows": 0, "flagged": 0, "persistent": 0, "flagged_fraction": np.nan,
                "peak_score": np.nan, "top_feature": "", "note": note}
    flagged = results["anomaly"].fillna(False).astype(bool)
    finite = results["anomaly_score"].replace([np.inf, -np.inf], np.nan).dropna()
    stats = flag_stats(flagged)
    return {
        "group": group, "scenario": scenario, "label": label, "method": method,
        "windows": stats["windows"], "flagged": stats["flagged"], "persistent": stats["persistent"],
        "flagged_fraction": stats["flagged_fraction"],
        "peak_score": round(float(finite.max()), 3) if len(finite) else np.nan,
        "top_feature": (results.loc[flagged, "top_feature"].value_counts().idxmax()
                        if flagged.any() else ""),
        "note": note,
    }


def run_sweep(manifest, groups=(None,)):
    """Score every (label, method) stratum in every scenario; `groups` selects feature subsets."""
    windows, notes = load_all_windows(manifest)
    attacks = [s for s in sorted(manifest["scenario"].unique()) if s != "benign"]
    rows = []
    for group in groups:
        columns = None if group in (None, "all") else list(FEATURE_GROUPS[group])
        group_name = "all" if columns is None else group
        for method in sorted(manifest["method"].unique()):
            for label in sorted(manifest["label"].unique()):
                reference_windows = windows.get(("benign", label, method))
                targets = [("benign", None)] + [(s, windows.get((s, label, method))) for s in attacks]
                if reference_windows is None:
                    for scenario, _ in targets:
                        rows.append(summary_row(scenario, label, method, group_name,
                                                note=notes.get((scenario, label, method), "no capture")))
                    continue
                reference, holdout = split_reference(reference_windows)
                # For z_score, calibrate() installs the fixed design cutoff rather
                # than fitting a quantile, so this is the sweep's original behavior.
                detector = build(DETECTOR).pipeline(reference if columns is None else reference[columns],
                                                     holdout if columns is None else holdout[columns])
                for scenario, target in targets:
                    target = holdout if scenario == "benign" else target
                    if target is None:
                        rows.append(summary_row(scenario, label, method, group_name,
                                                note=notes.get((scenario, label, method), "no capture")))
                        continue
                    scored = target if columns is None else target[columns]
                    rows.append(summary_row(scenario, label, method, group_name,
                                            detector.annotate(scored)))
    return (pd.DataFrame(rows)
            .sort_values(["group", "method", "label", "scenario"])
            .reset_index(drop=True))


def main():
    parser = argparse.ArgumentParser(description="Score every capture against its matched benign reference.")
    parser.add_argument("--groups", default="all",
                        help="'all', or a comma-separated subset of " + ", ".join(FEATURE_GROUPS))
    parser.add_argument("--out", default="sweep_results.csv")
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    groups = [None] if args.groups == "all" else args.groups.split(",")
    results = run_sweep(manifest, groups=groups)
    out_file = resolve_output(args.out)
    results.to_csv(out_file, index=False)
    # Write the inventory this run actually scored, so the sibling scripts
    # (compare.py, feature_value.py) read the same captures rather than re-globbing the
    # Drive. load_manifest prefers a cached file, so a stale one must be deleted or
    # --rebuild passed rather than trusted.
    resolve_output(args.manifest).parent.mkdir(exist_ok=True)
    manifest.to_csv(resolve_output(args.manifest), index=False)
    print_matrix(results)
    excluded = results[results["note"].str.startswith("excluded", na=False)]
    print(f"\nWrote {out_file} | rows={len(results)}"
          f" | excluded captures={excluded['label'].nunique()}")
    print(f"Times are per capture; windows are {WINDOW_SIZE:g}s. Flags are deviations, not confirmed attacks.")
    if len(groups) == 1 and groups[0] is None:
        print(f"\nWrote {plot_matrix(results)}")
        print(f"Wrote {plot_detection_gap(results)}")


if __name__ == "__main__":
    main()