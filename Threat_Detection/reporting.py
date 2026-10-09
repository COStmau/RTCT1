"""Everything that shows a human something. Takes results, renders them.

No detection logic lives here. Each function takes already-scored results and writes stdout
or an image; none of them re-derives a number another module already computed.
"""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data_io import resolve_output
from detectors import (BENIGN_QUANTILE, PERSISTENCE_WINDOW, SVM_NU, THRESHOLD, WINDOW_SIZE,
                       flag_stats, persistent_mask)
from features import FEATURE_LABELS

__all__ = ["flag_stats", "persistent_mask", "print_detection_summary", "threshold_table",
           "plot_detection", "print_matrix", "plot_matrix", "plot_comparison",
           "print_comparison", "summarize_flags"]


# --- one capture, printed and plotted ---------------------------------------------

def summarize_flags(results, benign_results, baseline_windows, evaluation_note):
    """The console report for a single benign/attack pair."""
    print("\n" + "=" * 76)
    print("THREAT DETECTION  |  Offline traffic analysis")
    print("=" * 76)
    print("\n1. BUILD THE REFERENCE")
    print(f"   {baseline_windows} benign windows define normal behavior.")
    print(f"   {evaluation_note}")
    print("   The reference stays fixed during evaluation.")
    print("\n2. COMPARE EACH WINDOW")
    print(f"   Window: {WINDOW_SIZE:g} s  |  Features: {len(FEATURE_LABELS)}")
    print(f"   Flag when score > {THRESHOLD:g}")
    print("   Score = the largest absolute feature deviation, in standard deviations.")
    print()
    print(f"   {'Capture':<20} {'Windows':>7} {'Flagged':>8} {'Unknown':>8} {'Peak score':>11}")
    print("   " + "-" * 58)
    for label, frame in [("Held-out benign", benign_results), ("Attack scenario", results)]:
        peak = frame["anomaly_score"].max()
        peak_text = "unknown" if pd.isna(peak) else f"{peak:.2f}"
        print(f"   {label:<20} {len(frame):>7} {int(frame['anomaly'].fillna(False).sum()):>8}"
              f" {int(frame['anomaly'].isna().sum()):>8} {peak_text:>11}")
    print("\n   Empty windows are included; unavailable scores are marked unknown.")
    print(f"\n   Requiring {PERSISTENCE_WINDOW} consecutive flagged windows")
    print(f"   cuts this to {int(benign_results['persistent_flag'].sum())} persistent on benign,"
          f" {int(results['persistent_flag'].sum())} on attack")
    threshold_table(results, benign_results)
    print("\n3. EXPLAIN THE ALERTS")
    flagged = results.loc[results["anomaly"].fillna(False)]
    if flagged.empty:
        print("   No scored window exceeded the cutoff.")
    else:
        first = flagged.index[0]
        strongest = flagged["anomaly_score"].idxmax()
        examples = [("First flag", first)]
        if strongest != first:
            examples.append(("Strongest flag", strongest))
        for label, index in examples:
            row = flagged.loc[index]
            name, unit = FEATURE_LABELS[row["top_feature"]]
            time = (index - results.index.min()) * WINDOW_SIZE
            print(f"\n   {label} at {time:g} s  |  score {row['anomaly_score']:.2f}")
            print(f"   {name}: {row['observed_value']:,.2f} {unit}")
            print(f"   Baseline mean: {row['expected_mean']:,.2f} {unit}"
                  f"  |  std: {row['expected_std']:,.2f}")
            if row["expected_std"] == 0:
                print("   This feature changed from a constant baseline (infinite score).")
            else:
                direction = "above" if row["feature_z_score"] > 0 else "below"
                print(f"   {abs(row['feature_z_score']):.2f} standard deviations {direction} the mean.")
        print("\n   Strongest feature in each flagged window:")
        for feature, count in flagged["top_feature"].value_counts().items():
            print(f"   - {FEATURE_LABELS[feature][0]}: {count} windows")
    persistent = results.loc[results["persistent_flag"]]
    if not persistent.empty:
        span = (persistent.index.max() - persistent.index.min()) * WINDOW_SIZE
        print(f"\n   Longest sustained deviation lasts about {span:g} s.")
    print("\n   Times are relative to each evaluation segment, not a shared timeline.")
    print("   Flags indicate deviations, not confirmed attacks or detection accuracy.")
    print("\nOUTPUTS  outputs/anomaly_results.png | outputs/results.csv | outputs/benign_results.csv")
    print("=" * 76)


def threshold_table(results, benign_results, thresholds=(1.5, 2.0, 3.0, 4.0)):
    """Flag counts at a few cutoffs, to sanity-check the 3-sigma default."""
    print(f"\n   {'Threshold':>9} {'Benign flags':>13} {'Attack flags':>13}")
    for threshold in thresholds:
        benign_flags = int(benign_results["anomaly_score"].gt(threshold).sum())
        attack_flags = int(results["anomaly_score"].gt(threshold).sum())
        print(f"   {threshold:>9.1f} {benign_flags:>13} {attack_flags:>13}")


def plot_detection(results, benign_results, mean, std, baseline_windows, path=None, show=True):
    """Two score traces plus the strongest feature against its baseline band."""
    path = resolve_output(path or "anomaly_results.png")
    fig = plt.figure(figsize=(12, 7))
    ax_benign = fig.add_subplot(2, 2, 1)
    ax_attack = fig.add_subplot(2, 2, 2)
    ax_feature = fig.add_subplot(2, 1, 2)

    fig.suptitle(f"Anomaly scores per {WINDOW_SIZE:g}s window "
                 f"(baseline: {baseline_windows} benign windows, alert > {THRESHOLD:g} sigma)",
                 fontsize=12, fontweight="bold")

    for ax, frame, title in [
        (ax_benign, benign_results, "Held-out benign"),
        (ax_attack, results, "Attack scenario"),
    ]:
        times = (frame.index - frame.index.min()) * WINDOW_SIZE
        scores = frame["anomaly_score"]
        finite = scores[np.isfinite(scores)]
        displayed = scores.replace(np.inf, finite.max() * 1.1 if len(finite) else THRESHOLD)
        flagged = frame["anomaly"].fillna(False)
        ax.plot(times, displayed, color="#1f77b4", linewidth=1.2)
        ax.scatter(times[flagged], displayed[flagged], color="#d62728", s=15,
                   zorder=3, label="flagged")
        ax.axhline(THRESHOLD, color="gray", linestyle="--", linewidth=1,
                   label=f"threshold = {THRESHOLD:g}")
        ax.set_title(f"{title} — {int(flagged.sum())}/{len(frame)} flagged",
                     fontsize=10, fontweight="bold")
        ax.set_xlabel("seconds", fontsize=9, fontweight="bold")
        ax.set_ylabel("score (max |z|)", fontsize=9, fontweight="bold")
        ax.legend(fontsize=8, prop={"weight": "bold"})

    scored = results.loc[results["anomaly_score"].notna()]
    if scored.empty:
        ax_feature.text(0.5, 0.5, "no scored windows", transform=ax_feature.transAxes,
                        ha="center", fontsize=11, fontweight="bold")
        ax_feature.set_axis_off()
    else:
        index = scored["anomaly_score"].idxmax()
        row = scored.loc[index]
        feature = row["top_feature"]
        name, unit = FEATURE_LABELS[feature]
        times = (results.index - results.index.min()) * WINDOW_SIZE
        time = (index - results.index.min()) * WINDOW_SIZE
        ax_feature.plot(times, results[feature], color="#1f77b4", linewidth=1.2,
                        marker=".", markersize=3)
        ax_feature.axhspan(mean[feature] - THRESHOLD * std[feature],
                           mean[feature] + THRESHOLD * std[feature],
                           color="#deebf7", label=f"baseline ± {THRESHOLD:g} std")
        ax_feature.scatter([time], [row["observed_value"]], color="#d62728", s=60,
                           zorder=5, label=f"max score ({time:g}s)")
        ax_feature.set_title(f"{name} — observed vs baseline",
                             fontsize=10, fontweight="bold")
        ax_feature.set_xlabel("seconds", fontsize=9, fontweight="bold")
        ax_feature.set_ylabel(f"{name} ({unit})", fontsize=9, fontweight="bold")
        ax_feature.legend(fontsize=8, prop={"weight": "bold"})

    for ax in fig.axes:
        for label in ax.get_xticklabels() + ax.get_yticklabels():
            label.set_fontweight("bold")

    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(path, dpi=150)
    if show:
        plt.show()
    plt.close(fig)
    return path


# --- every capture ----------------------------------------------------------------

def print_matrix(results):
    """One row per capture label, one column per scenario, for each group and method."""
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


def plot_matrix(results, path=None):
    """Grouped bars: flagged fraction per capture label, one series per scenario."""
    path = resolve_output(path or "sweep_summary.png")
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
    return path


# --- detector comparison ----------------------------------------------------------

def print_comparison(comparison):
    """One block per detector: held-out benign false alarms, then detection per scenario."""
    print(f"\n{comparison['detector'].nunique()} detectors | {THRESHOLD:g} sigma z-score alert"
          f" | learned cutoffs = {BENIGN_QUANTILE:.0%} of held-out benign scores"
          f" | SVM nu={SVM_NU:g} | {PERSISTENCE_WINDOW}-window persistence")
    for detector, view in comparison.groupby("detector"):
        benign = view[view["scenario"].eq("benign")]["flagged_fraction"].mean()
        print(f"\n{detector}: held-out benign flagged fraction {benign:.2f}")
        for scenario in [s for s in view["scenario"].unique() if s != "benign"]:
            attacks = view[view["scenario"].eq(scenario)]
            print(f"   {scenario:<18} mean {attacks['flagged_fraction'].mean():.2f}"
                  f" | persistent {attacks['persistent_fraction'].mean():.2f}"
                  f" | captures {len(attacks)}")


def plot_comparison(comparison, path=None):
    """Two panels: flagged fraction and sustained fraction, one bar series per detector."""
    path = resolve_output(path or f"detector_comparison_nu{SVM_NU:g}.png")
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
                 f" | {WINDOW_SIZE:g}s windows | mean over strata\n"
                 f"forest and SVM cutoffs = {BENIGN_QUANTILE:.0%} of held-out benign"
                 f" | z-score alert > {THRESHOLD:g} sigma"
                 f" | {PERSISTENCE_WINDOW}-window persistence", fontsize=10)
    fig.tight_layout(rect=[0, 0, 1, 0.90])
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path