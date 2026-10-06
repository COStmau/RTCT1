"""Rank features by how well each one separates attack windows from benign windows.

Value has two numbers per feature, per scenario, per capture stratum:

  auc              threshold-free separation (1.0 = perfect, 0.5 = useless). Needs no
                   model and no threshold, so it compares features fairly.
  detection_at_5%  what fraction of attack windows that single feature flags when its
                   cutoff is set to flag 5% of held-out benign windows.

Both are computed against the matched benign reference for the same capture label and
capture method, so a feature is never credited for a vantage effect.

Run it with:  .venv/bin/python feature_value.py
"""
import argparse

import pandas as pd

import dataset
import sweep
from detector import OUTPUT_DIR, output_path

BUDGET = 0.05
STRONG_AUC = 0.75


def separation_auc(benign, attack):
    """Probability that a random attack window ranks above a random benign window."""
    benign = pd.Series(benign).dropna()
    attack = pd.Series(attack).dropna()
    if len(benign) < 2 or len(attack) < 2:
        return float("nan")
    n_b, n_a = len(benign), len(attack)
    ranks = pd.concat([benign, attack]).rank()
    rank_sum = ranks.iloc[n_b:].sum()
    return (rank_sum - n_a * (n_a + 1) / 2) / (n_b * n_a)


def detection_at_budget(benign_train, benign_holdout, attack, budget=BUDGET):
    """Attack-window flag rate when the cutoff flags `budget` of held-out benign windows."""
    train = pd.Series(benign_train).dropna()
    holdout = pd.Series(benign_holdout).dropna()
    target = pd.Series(attack).dropna()
    mean, std = train.mean(), train.std()
    if not len(train) or not len(holdout) or not len(target) or not std or pd.isna(std):
        return float("nan")
    deviation = lambda values: (values - mean).abs() / std
    cutoff = deviation(holdout).quantile(1 - budget)
    return float((deviation(target) >= cutoff).mean())


def rank_features(described):
    """One row per feature x scenario x capture stratum."""
    features, _ = sweep.load_features(described)
    scenarios = [s for s in sorted(described["scenario"].unique()) if s != "benign"]
    rows = []
    for method in sorted(described["method"].unique()):
        for label in sorted(described["label"].unique()):
            reference = features.get(("benign", label, method))
            if reference is None:
                continue
            train, holdout = sweep.split_reference(reference)
            for scenario in scenarios:
                target = features.get((scenario, label, method))
                if target is None:
                    continue
                for feature in reference.columns:
                    rows.append({
                        "feature": feature, "scenario": scenario, "label": label, "method": method,
                        "auc": separation_auc(holdout[feature], target[feature]),
                        "detection_at_5pct": detection_at_budget(train[feature], holdout[feature],
                                                                 target[feature]),
                        "benign_windows": int(holdout[feature].notna().sum()),
                        "attack_windows": int(target[feature].notna().sum()),
                    })
    return pd.DataFrame(rows)


def print_ranking(values):
    """Mean value per feature and scenario, plus how many strata back it."""
    for column, title in [("auc", f"Separation (AUC > {STRONG_AUC} counts as strong)"),
                          ("detection_at_5pct", f"Attack windows flagged at a {BUDGET:.0%} benign budget")]:
        table = values.pivot_table(index="feature", columns="scenario", values=column, aggfunc="mean")
        if column == "auc":
            table["strata_auc>%.2f" % STRONG_AUC] = (values.assign(hit=values["auc"].ge(STRONG_AUC))
                                                    .groupby("feature")["hit"].sum())
        print(f"\n{title}" + (" (of 22 capture strata per scenario)" if column == "auc" else ""))
        print(table.sort_values(by=table.columns[0], ascending=False).round(3).to_string())
    benign = values["benign_windows"].mean()
    print(f"\nBudget check: each stratum has {benign:.0f} held-out benign windows on average,")
    print("so the 5% cutoff flags about 1 of them. Differences under 0.1 here are not measured.")


def main():
    parser = argparse.ArgumentParser(description="Rank features by measured separation value.")
    parser.add_argument("--manifest", default=sweep.MANIFEST_FILE)
    parser.add_argument("--out", default="feature_value.csv")
    args = parser.parse_args()

    import local_paths
    manifest_file = output_path(args.manifest)
    described = (pd.read_csv(manifest_file) if manifest_file.exists()
                 else dataset.describe_captures(dataset.build_manifest(local_paths.KUBEDATA_ROOT)))
    values = rank_features(described)
    values.to_csv(output_path(args.out), index=False)
    print_ranking(values)
    print(f"\nWrote {output_path(args.out)} | rows={len(values)}")


if __name__ == "__main__":
    main()
