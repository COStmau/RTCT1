"""
detectors see the same windows, the same matched benign reference and the same
split. The forest is fit on benign training windows only; its alert cutoff comes from
held-out benign windows, so the benign false-alarm fraction is set by construction
rather than by looking at the attacks.
"""
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import dataset
import sweep
from detector import (PERSISTENCE_WINDOW, THRESHOLD, WINDOW_SIZE, build_baseline,
                      detect_anomalies, flag_persistent, flag_stats, output_path)

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


SVM_NU = 0.10


def fit_one_class_svm(train, columns=None, nu=SVM_NU):
    """Fit One-Class SVM on benign training windows, scaling inside the pipeline.

    The SVM is scale sensitive, so the StandardScaler is fitted on the same benign
    training windows and lives in the pipeline. Keeping it there means this model
    exposes decision_function on raw feature values, exactly like the forest, so
    detector_cutoff() and detector_flags() work unchanged.
    """
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM

    values = train if columns is None else train[columns]
    model = make_pipeline(StandardScaler(), OneClassSVM(kernel="rbf", gamma="scale", nu=nu))
    model.fit(values.dropna())
    return model


LEARNED_FITTERS = {
    "isolation_forest": fit_isolation,
    "one_class_svm": fit_one_class_svm,
}

# The chart name carries the nu for that run, so two settings never overwrite each other.
CHART_NAME = f"detector_comparison_nu{SVM_NU:g}.png"


def detector_cutoff(model, benign_holdout, quantile=BENIGN_QUANTILE):
    """Decision-function cutoff that flags the worst `quantile` of held-out benign windows.

    Works for any learned detector here, because they all expose decision_function.
    """
    values = benign_holdout.dropna()
    if values.empty:
        raise ValueError("No held-out benign windows to calibrate the cutoff")
    return float(np.quantile(model.decision_function(values), quantile))


def detector_flags(model, target, cutoff):
    """True where the model scores a window below (more anomalous than) the benign cutoff."""
    values = target.dropna()
    scores = pd.Series(model.decision_function(values), index=values.index)
    return scores.lt(cutoff).reindex(target.index, fill_value=False).fillna(False)


def detection_row(detector, scenario, label, method, flags):
    """One comparison row: flagged and sustained fractions for a detector on one set of windows."""
    return {"detector": detector, "scenario": scenario, "label": label, "method": method,
            **flag_stats(flags)}


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
            learned = {name: fitter(reference) for name, fitter in LEARNED_FITTERS.items()}
            cutoffs = {name: detector_cutoff(model, holdout) for name, model in learned.items()}
            targets = [("benign", holdout)] + [(s, features.get((s, label, method))) for s in attacks]
            for scenario, target in targets:
                if target is None:
                    continue
                scored = flag_persistent(detect_anomalies(target, mean, std))
                rows.append(detection_row("z_score", scenario, label, method, scored["anomaly"]))
                for name, model in learned.items():
                    rows.append(detection_row(name, scenario, label, method,
                                              detector_flags(model, target, cutoffs[name])))
    return (pd.DataFrame(rows)
            .sort_values(["detector", "label", "method", "scenario"])
            .reset_index(drop=True))


def print_summary(comparison):
    """One block per detector: held-out benign false alarms, then detection per scenario."""

def plot_comparison(comparison, path=None):
    """Two panels: flagged fraction and sustained fraction, one bar series per detector."""
    path = output_path(path or CHART_NAME)
    detectors = sorted(comparison["detector"].unique())
    scenarios = ["benign"] + sorted(s for s in comparison["scenario"].unique() if s != "benign")
    positions = np.arange(len(scenarios))
    width = 0.8 / len(detectors)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, column, title in [
        (axes[0], "flagged_fraction", "Flagged windows"),
        (axes[1], "persistent_fraction", f"Sustained ({PERSISTENCE_WINDOW} flagged in a row)"),
    ]:
        for offset, detector in enumerate(detectors):
            view = comparison[comparison["detector"].eq(detector)]
            values = [view[view["scenario"].eq(scenario)][column].mean() for scenario in scenarios]
            ax.bar(positions + offset * width, values, width, label=detector)
        ax.set_xticks(positions + 0.4 - width / 2)
        ax.set_xticklabels(scenarios, rotation=20, ha="right")
        ax.set_ylabel("fraction of windows")
        ax.set_ylim(0, 1)
        ax.set_title(title)
        ax.legend(fontsize=8)
    fig.suptitle(f"Same windows and matched benign reference per capture stratum"
                 f" | {WINDOW_SIZE:g}s windows | mean over 22 strata\n"
                 f"forest and SVM cutoffs = {BENIGN_QUANTILE:.0%} of held-out benign"
                 f" | z-score alert > {THRESHOLD:g} sigma"
                 f" | {PERSISTENCE_WINDOW}-window persistence", fontsize=10)
    fig.tight_layout(rect=[0, 0, 1, 0.90])
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\nWrote {path}")
    print(f"\n{comparison['detector'].nunique()} detectors | {THRESHOLD:g} sigma z-score alert"
          f" | forest and SVM cutoffs = {BENIGN_QUANTILE:.0%} of held-out benign scores"
          f" | SVM nu={SVM_NU:g} | {PERSISTENCE_WINDOW}-window persistence")
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
    manifest_file = output_path(args.manifest)
    described = (pd.read_csv(manifest_file) if manifest_file.exists()
                 else dataset.describe_captures(dataset.build_manifest(local_paths.KUBEDATA_ROOT)))
    comparison = compare_detectors(described)
    comparison.to_csv(output_path(args.out), index=False)
    print_summary(comparison)
    plot_comparison(comparison)
    print(f"\nWrote {output_path(args.out)} | rows={len(comparison)}")


if __name__ == "__main__":
    main()
