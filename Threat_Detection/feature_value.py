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

import metrics

import local_paths
from core.data_io import load_manifest, resolve_output
from core.features import load_all_windows, split_reference

BUDGET = 0.05
STRONG_AUC = 0.75


def separation_auc(benign, attack):
    """Probability that a random attack window ranks above a random benign window.

    Delegates to metrics.auroc_ranked, which returns NaN when a stratum has fewer than two
    finite windows on either side -- a 1-vs-1 stratum would otherwise score 1.0 by chance.
    """
    return metrics.auroc_ranked(benign, attack)


def detection_at_budget(benign_train, benign_holdout, attack, budget=BUDGET):
    """Attack-window flag rate when the cutoff flags `budget` of held-out benign windows."""
    return metrics.detection_at_budget(benign_train, benign_holdout, attack, budget)


def rank_features(manifest):
    """One row per feature x scenario x capture stratum."""
    windows, _ = load_all_windows(manifest)
    scenarios = [s for s in sorted(manifest["scenario"].unique()) if s != "benign"]
    rows = []
    for method in sorted(manifest["method"].unique()):
        for label in sorted(manifest["label"].unique()):
            reference = windows.get(("benign", label, method))
            if reference is None:
                continue
            train, holdout = split_reference(reference)
            for scenario in scenarios:
                target = windows.get((scenario, label, method))
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
    # Counted from the data, and labeled for what it counts: STRONG_AUC hits pooled across
    # all scenarios, so it is NOT comparable to a single scenario's mean in the table.
    strata = values.groupby(["label", "method"]).ngroups
    per_feature = values.groupby("feature").size().max()
    scenarios = values["scenario"].nunique()
    for column, title in [("auc", f"Separation (mean per scenario; {STRONG_AUC} counts as strong)"),
                          ("detection_at_5pct", f"Attack windows flagged at a {BUDGET:.0%} benign budget")]:
        table = values.pivot_table(index="feature", columns="scenario", values=column, aggfunc="mean")
        if column == "auc":
            table[f"hits>={STRONG_AUC:g} (pooled)"] = (values.assign(hit=values["auc"].ge(STRONG_AUC))
                                                      .groupby("feature")["hit"].sum())
        print(f"\n{title}")
        print(table.sort_values(by=table.columns[0], ascending=False).round(3).to_string())
    print(f"\nThe pooled hit count sums {scenarios} scenarios x {strata} capture strata"
          f" = {per_feature} rows per feature, so it is not per-scenario.")
    benign = values["benign_windows"].mean()
    print(f"\nBudget check: each stratum has {benign:.0f} held-out benign windows on average,")
    print("so the 5% cutoff flags about 1 of them. Differences under 0.1 here are not measured.")


def main():
    parser = argparse.ArgumentParser(description="Rank features by measured separation value.")
    parser.add_argument("--manifest", default="capture_manifest.csv")
    parser.add_argument("--out", default="feature_value.csv")
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    values = rank_features(manifest)
    out_file = resolve_output(args.out)
    values.to_csv(out_file, index=False)
    print_ranking(values)
    print(f"\nWrote {out_file} | rows={len(values)}")


if __name__ == "__main__":
    main()
