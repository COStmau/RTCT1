"""
Every registered detector on the same windows, the same matched benign reference and the same
split. The forest is fit on benign training windows only; its alert cutoff comes from
held-out benign windows, so the benign false-alarm fraction is set by construction
rather than by looking at the attacks.
"""
import sys
from pathlib import Path

# A script run as `python dev/experiments/compare.py` gets dev/experiments/ as sys.path[0], so the
# Threat_Detection root (core, methods, convert) and dev/ (experiments, verdicts) go back on
# the path before any project import.
sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

import argparse

import pandas as pd

import local_paths
from core.data_io import MANIFEST_NAME, load_manifest, resolve_output
from core.detectors import REGISTRY, build, flag_stats
from core.features import DETECTION_FEATURES, load_all_windows, split_reference
from core.reporting import plot_comparison, print_comparison

# Every registered detector gets compared. Adding one here is the whole change.
DETECTORS = list(REGISTRY)


def compare_detectors(manifest, features=DETECTION_FEATURES):
    """One row per detector per capture stratum: flagged and sustained fractions.

    Same windows, same reference, same split for all three -- that is the only reason
    the numbers are comparable. `features` are the columns every detector reads; None reads all.
    """
    windows, _ = load_all_windows(manifest)
    attacks = [s for s in sorted(manifest["scenario"].unique()) if s != "benign"]
    rows = []
    for method in sorted(manifest["method"].unique()):
        for label in sorted(manifest["label"].unique()):
            reference_windows = windows.get(("benign", label, method))
            if reference_windows is None:
                continue
            reference, holdout = split_reference(reference_windows)
            fitted = {name: build(name, features=features).pipeline(reference, holdout) for name in DETECTORS}
            targets = [("benign", holdout)] + [(s, windows.get((s, label, method))) for s in attacks]
            for scenario, target in targets:
                if target is None:
                    continue
                for name, detector in fitted.items():
                    rows.append({"detector": name, "scenario": scenario, "label": label,
                                 "method": method, **flag_stats(detector.flag(target))})
    return (pd.DataFrame(rows)
            .sort_values(["detector", "label", "method", "scenario"])
            .reset_index(drop=True))


def main():
    parser = argparse.ArgumentParser(description="Compare every registered detector.")
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    parser.add_argument("--out", default="detector_comparison.csv")
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    comparison = compare_detectors(manifest)
    out_file = resolve_output(args.out)
    comparison.to_csv(out_file, index=False)
    print_comparison(comparison)
    print(f"\nWrote {plot_comparison(comparison)}")
    print(f"\nWrote {out_file} | rows={len(comparison)}")


if __name__ == "__main__":
    main()