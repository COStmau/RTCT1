"""Compare the transparent z-score detector with an Isolation Forest on the same windows.

Both detectors see the same windows, the same matched benign reference and the same
split. The forest is fit on benign training windows only; its alert cutoff comes from
held-out benign windows, so the benign false-alarm fraction is set by construction
rather than by looking at the attacks.
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

import manifest
import sweep
from test import (PERSISTENCE_WINDOW, THRESHOLD, build_baseline, detect_anomalies,
                  flag_persistent, persistent_mask)

BENIGN_QUANTILE = 0.05
N_ESTIMATORS = 100
RANDOM_STATE = 0


def fit_isolation(train, columns=None, seed=RANDOM_STATE):
    """Fit Isolation Forest on benign training windows."""
    from sklearn.ensemble import IsolationForest

    values = train if columns is None else train[columns]
    model = IsolationForest(n_estimators=N_ESTIMATORS, random_state=seed)
    model.fit(values.dropna())
    return model


def isolation_cutoff(model, benign_holdout, quantile=BENIGN_QUANTILE):
    """Decision-function cutoff that flags the worst `quantile` of held-out benign windows."""
    values = benign_holdout.dropna()
    if values.empty:
        raise ValueError("No held-out benign windows to calibrate the cutoff")
    return float(np.quantile(model.decision_function(values), quantile))


def isolation_flags(model, target, cutoff):
    """True where the forest scores a window below (more anomalous than) the benign cutoff."""
    values = target.dropna()
    scores = pd.Series(model.decision_function(values), index=values.index)
    return scores.lt(cutoff).reindex(target.index, fill_value=False).fillna(False)


def detection_row(detector, scenario, label, method, flags, windows):
    """One comparison row: flagged and persistent fractions for a detector."""
    flags = pd.Series(flags).fillna(False).astype(bool)
    persistent = persistent_mask(flags, PERSISTENCE_WINDOW)
    return {"detector": detector, "scenario": scenario, "label": label, "method": method,
            "windows": int(windows), "flagged": int(flags.sum()),
            "flagged_fraction": round(float(flags.mean()), 4) if len(flags) else np.nan,
            "persistent": int(persistent.sum()),
            "persistent_fraction": round(float(persistent.mean()), 4) if len(flags) else np.nan}


def compare_detectors(described):
    """Run both detectors over every stratum and return one row per detector per stratum."""
    features, _ = sweep.load_features(described)
    attacks = [s for s in sorted(described["scenario"].unique()) if s != "benign"]
    rows = []
    for method in sorted(described["method"].unique()):
        for label in sorted(described["label"].unique()):
            reference_features = features.get(("benign", label, method))
            if reference_features is None:
                continue
            reference, holdout = sweep.split_reference(reference_features)
            mean, std = build_baseline(reference)
            model = fit_isolation(reference)
            cutoff = isolation_cutoff(model, holdout)
            targets = [("benign", holdout)] + [(s, features.get((s, label, method))) for s in attacks]
            for scenario, target in targets:
                if target is None:
                    continue
                scored = flag_persistent(detect_anomalies(target, mean, std))
                rows.append(detection_row("z_score", scenario, label, method,
                                          scored["anomaly"], len(target)))
                rows.append(detection_row("isolation_forest", scenario, label, method,
                                          isolation_flags(model, target, cutoff), len(target)))
    return (pd.DataFrame(rows)
            .sort_values(["detector", "label", "method", "scenario"])
            .reset_index(drop=True))


def print_summary(comparison):
    """One block per detector: held-out benign false alarms, then detection per scenario."""
    print(f"\n{comparison['detector'].nunique()} detectors | {THRESHOLD:g} sigma z-score alert"
          f" | forest cutoff = {BENIGN_QUANTILE:.0%} of held-out benign scores"
          f" | {PERSISTENCE_WINDOW}-window persistence")
    for detector, view in comparison.groupby("detector"):
        benign = view[view["scenario"].eq("benign")]["flagged_fraction"].mean()
        print(f"\n{detector}: held-out benign flagged fraction {benign:.2f}")
        for scenario in [s for s in view["scenario"].unique() if s != "benign"]:
            attacks = view[view["scenario"].eq(scenario)]
            print(f"   {scenario:<18} mean {attacks['flagged_fraction'].mean():.2f}"
                  f" | persistent {attacks['persistent_fraction'].mean():.2f}"
                  f" | captures {len(attacks)}")


def main():
    import local_paths
    parser = argparse.ArgumentParser(description="Compare z-score and Isolation Forest detection.")
    parser.add_argument("--manifest", default=sweep.MANIFEST_FILE)
    parser.add_argument("--out", default="detector_comparison.csv")
    args = parser.parse_args()
    described = (pd.read_csv(args.manifest) if Path(args.manifest).exists()
                 else manifest.describe_captures(manifest.build_manifest(local_paths.KUBEDATA_ROOT)))
    comparison = compare_detectors(described)
    comparison.to_csv(args.out, index=False)
    print_summary(comparison)
    print(f"\nWrote {args.out} | rows={len(comparison)}")


if __name__ == "__main__":
    main()
