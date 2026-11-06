"""Everything that shows a human something. Takes results, renders them.

No detection logic. Each function takes already-scored results and writes stdout
or an image; none of them re-derives a number another module already computed.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # before pyplot: this subsystem renders to files, never a window
import json

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data_io import SNAPLEN_CEILINGS, SNAPLEN_REPORT_AT, resolve_output
from evaluation import BULK_LABELS, TRAIN_FRACTION
from detectors import (BENIGN_QUANTILE, PERSISTENCE_WINDOW, SVM_NU, THRESHOLD,
                       flag_stats, persistent_mask)
from features import FEATURE_LABELS, WINDOW_SIZE

__all__ = ["flag_stats", "persistent_mask", "summarize_flags", "threshold_table",
           "plot_detection", "print_matrix", "plot_matrix", "plot_detection_gap",
           "plot_comparison", "print_comparison", "plot_regime_split", "plot_snaplen",
           "write_report", "to_events", "write_events"]

# LogV1 adds `t`, the capture-relative second, so a consumer can order and expire events.
# LogV0 carried no time at all: 51 events on one capture were indistinguishable.
EVENT_VERSION = "LogV1"

# Incident lifetime: consecutive clean windows before a flag may clear. Nothing enforces it
# yet; the rule belongs to the event stream this module writes, not to the detector.
CLEAR_WINDOWS = 3

# Severity bands on the raw z_score. Only flagged windows reach here, so every
# score sits above the detector's cutoff: low is borderline, high is far outside normal.
SEVERITY_LOW_BELOW = 5.0
SEVERITY_MED_BELOW = 10.0


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


def threshold_table(results, benign_results, thresholds=(1.5, 2.0, THRESHOLD, 3.0, 4.0)):
    """Flag counts at a few cutoffs, including the one this run alerted at."""
    print(f"\n   {'Threshold':>9} {'Benign flags':>13} {'Attack flags':>13}")
    for threshold in sorted(set(thresholds)):
        benign_flags = int(benign_results["anomaly_score"].gt(threshold).sum())
        attack_flags = int(results["anomaly_score"].gt(threshold).sum())
        mark = "  <- alert cutoff" if threshold == THRESHOLD else ""
        print(f"   {threshold:>9.1f} {benign_flags:>13} {attack_flags:>13}{mark}")


def plot_detection(results, benign_results, mean, std, baseline_windows, path=None):
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
    plt.close(fig)
    return path


# --- event log (starter contract for the response subsystem) --------------------------

def _severity(score):
    """Bucket a raw score: low below 5, med below 10, high at or above."""
    if not np.isfinite(score):  # flagged and unbounded beats any band
        return "high"
    if score < SEVERITY_LOW_BELOW:
        return "low"
    if score < SEVERITY_MED_BELOW:
        return "med"
    return "high"


def to_events(results, *, detector, pods):
    """One dict per flagged window: version, detector, time, severity, locations.

    `t` is the window's second inside its capture -- the index of the windowed table, which
    annotate() builds from the capture's first packet. Without it a consumer can tell which
    windows flagged but not in what order or how far apart, so it cannot dedupe or expire
    an incident. It is capture-relative, not wall-clock: the manifest carries the capture's
    own start time for that.
    """
    events = []
    flagged = results[results["anomaly"].fillna(False)].sort_index()
    for t, row in flagged.iterrows():
        events.append({"version": EVENT_VERSION,
                       "detector": detector,
                       "t": int(t),
                       "severity": _severity(row.get("anomaly_score")),
                       "locations": {"pods": list(pods)}})
    return events


def write_events(events, path=None):
    """Write events as JSON Lines, one object per line. Returns the path."""
    path = Path(resolve_output(path or "events.jsonl"))
    with open(path, "w") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
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


def plot_detection_gap(results, path=None):
    """Flagged fraction above each capture's own benign rate, one column per scenario.

    A raw fraction puts the noisiest capture at the top of the chart, so the benign
    column is subtracted out and carried in the row label instead: the cell says what
    the detector found, the row says what it costs to run there. Steady vantages sit
    above the C2 bulk-transfer vantages so the saturated baselines are grouped visually.
    """
    path = resolve_output(path or "detection_gap.png")
    view = results[results["group"].eq("all") & results["method"].eq("tcp")]
    fractions = view.pivot_table(index="label", columns="scenario", values="flagged_fraction",
                                 dropna=False)
    windows = view.pivot_table(index="label", columns="scenario", values="windows",
                               dropna=False)
    scenarios = sorted(name for name in fractions.columns if name != "benign")
    steady_labels = sorted(
        [name for name in fractions.index if name not in BULK_LABELS],
        key=lambda name: float(np.nanmax(fractions.loc[name, scenarios] - fractions.loc[name, "benign"])),
        reverse=True,
    )
    bulk_labels = sorted(name for name in fractions.index if name in BULK_LABELS)
    labels = steady_labels + bulk_labels
    benign = fractions["benign"].reindex(labels)
    gaps = fractions[scenarios].reindex(labels).sub(benign, axis=0)

    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    cmap = plt.get_cmap("RdBu_r").with_extremes(bad="#eeeeee")
    image = ax.imshow(gaps.to_numpy(dtype=float), cmap=cmap, vmin=-0.8, vmax=0.8, aspect="auto")
    for row, label in enumerate(labels):
        for column, scenario in enumerate(scenarios):
            gap = float(gaps.loc[label, scenario])
            win_count = windows.loc[label, scenario]
            if np.isnan(gap) or pd.isna(win_count) or int(win_count) == 0:
                ax.text(column, row, "quarantined\n(corrupt ts)",
                        ha="center", va="center", fontsize=8.5, style="italic", color="#555555")
            else:
                ax.text(column, row, f"{gap:+.2f}\n{int(win_count)} windows",
                        ha="center", va="center", fontsize=9,
                        fontweight="bold" if gap >= 0.30 else "normal",
                        color="white" if abs(gap) > 0.45 else "#111111")

    if steady_labels and bulk_labels:
        sep_y = len(steady_labels) - 0.5
        ax.axhline(sep_y, color="#222222", linewidth=2.2, linestyle="--")

    scenario_titles = {
        "injection": "Injection Attack\n(Sidecar Recon)",
        "lidar": "LiDAR Attack\n(Sensor Replay)",
        "nginx": "NGINX Attack\n(Web Flood)",
    }
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels(
        [scenario_titles.get(name.replace(" attack", ""), name.replace(" attack", ""))
         for name in scenarios],
        fontsize=10.5, fontweight="bold",
    )
    ax.set_yticks(range(len(labels)))
    row_labels = [
        f"[C2 bulk] {label}  (benign: {benign[label]:.2f})" if label in BULK_LABELS
        else f"{label}  (benign: {benign[label]:.2f})"
        for label in labels
    ]
    ax.set_yticklabels(row_labels, fontsize=9.5)
    for tick, label in zip(ax.get_yticklabels(), labels):
        if label in BULK_LABELS:
            tick.set_color("#8c1d18")
        elif float(np.nanmax(gaps.loc[label])) >= 0.40:
            tick.set_fontweight("bold")

    ax.set_xticks(np.arange(-0.5, len(scenarios)), minor=True)
    ax.set_yticks(np.arange(-0.5, len(labels)), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.8)
    ax.tick_params(which="minor", length=0)
    bar = fig.colorbar(image, ax=ax, fraction=0.035, pad=0.02)
    bar.set_label("Attack flag rate minus benign flag rate (+ = clear detection)", fontsize=9.5)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path


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
            # A mean over captures weights a 3-window capture like an 80-window one, so the
            # window spread is printed beside it; the mean is not over a common pool.
            windows = attacks["windows"]
            print(f"   {scenario:<18} mean {attacks['flagged_fraction'].mean():.2f}"
                  f" | persistent {attacks['persistent_fraction'].mean():.2f}"
                  f" | captures {len(attacks)}"
                  f" | windows {int(windows.sum())} ({int(windows.min())}-{int(windows.max())}"
                  f" each)")


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
    # Strata count from the data, not a number typed in by hand.
    strata = comparison.groupby(["label", "method"]).ngroups
    windows = comparison["windows"]
    fig.suptitle(f"Same windows and matched benign reference per capture stratum"
                 f" | {WINDOW_SIZE:g}s windows | mean over {strata} strata,"
                 f" {int(windows.min())}-{int(windows.max())} windows each\n"
                 f"forest and SVM cutoffs = {BENIGN_QUANTILE:.0%} of held-out benign"
                 f" | z-score alert > {THRESHOLD:g} sigma"
                 f" | {PERSISTENCE_WINDOW}-window persistence", fontsize=10)
    fig.tight_layout(rect=[0, 0, 1, 0.90])
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


# --- showcase report ----------------------------------------------------------------

def _bulk_view(sweep):
    """Sweep rows split into the steady benign captures and the ones that change regime."""
    view = sweep[sweep["scenario"].eq("benign")].copy()
    view["regime"] = np.where(view["label"].isin(BULK_LABELS), "bulk", "steady")
    return view


def plot_regime_split(bulk_view, steady_mean, bulk_mean, path=None):
    """Benign flag fraction per capture: the steady ones against the three that drift."""
    path = resolve_output(path or "steady_bulk_split.png")
    view = bulk_view[bulk_view["method"].eq("tcp")]
    steady = view[view["regime"].eq("steady")].sort_values("flagged_fraction")
    drifting = view[view["regime"].eq("bulk")].sort_values("flagged_fraction")
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.barh([f"steady {label}" for label in steady["label"]], steady["flagged_fraction"],
            color="#1f77b4", label=f"steady (mean {steady_mean:.2f})")
    ax.barh([f"bulk   {label}" for label in drifting["label"]], drifting["flagged_fraction"],
            color="#d62728", label=f"bulk-transfer (mean {bulk_mean:.2f})")
    ax.set_xlabel("flagged fraction of held-out benign windows")
    ax.set_xlim(0, 1)
    ax.legend(fontsize=8)
    ax.set_title(f"Benign traffic: {len(steady)} steady captures against "
                 f"{len(drifting)} that change regime mid-recording", fontsize=11)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_snaplen(manifest, n_truncated, n_total, path=None):
    """What share of each capture's packets hit the recorder's size ceiling."""
    path = resolve_output(path or "capture_manifest_at_snaplen.png")
    view = manifest[manifest["method"].eq("tcp")].sort_values("at_snaplen")
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.barh(view["label"], view["at_snaplen"],
            color=["#d62728" if value >= SNAPLEN_REPORT_AT else "#9ecae1"
                   for value in view["at_snaplen"]])
    ax.set_xlabel("fraction of packets clipped at the capture size limit")
    ax.set_xlim(0, max(0.05, float(view["at_snaplen"].max()) * 1.15))
    ax.set_title(f"{n_truncated} of {n_total} captures hit the recorder's "
                 f"{SNAPLEN_CEILINGS[0]}-byte ceiling", fontsize=11)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _figure_refs(sweep, manifest, comparison, chart_dir, steady_mean, bulk_mean):
    """Render the charts the report embeds, and return (markdown caption, filename) pairs.

    Each name comes from the function that wrote the file, so a reference in the prose and
    the file on disk cannot drift apart. The two means are passed in rather than recomputed,
    so the chart titles and the report text cannot disagree.
    """
    chart_dir = Path(chart_dir)
    bulk = _bulk_view(sweep)
    truncated = manifest[manifest["at_snaplen"] >= SNAPLEN_REPORT_AT]

    refs = [
        ("Benign flag fraction per capture: steady against bulk-transfer",
         Path(plot_regime_split(bulk, steady_mean, bulk_mean,
                                path=chart_dir / "steady_bulk_split.png")).name),
        ("Fraction of each capture's packets clipped at the recorder's size limit",
         Path(plot_snaplen(manifest, len(truncated), len(manifest),
                           path=chart_dir / "capture_manifest_at_snaplen.png")).name),
        (_CHART_CAPTIONS["sweep_summary.png"],
         Path(plot_matrix(sweep, path=chart_dir / "sweep_summary.png")).name),
        (_CHART_CAPTIONS[f"detector_comparison_nu{SVM_NU:g}.png"],
         Path(plot_comparison(comparison,
                              path=chart_dir / f"detector_comparison_nu{SVM_NU:g}.png")).name),
    ]
    # anomaly_results.png comes from a single scored capture pair, which this function is
    # not given. Referenced only when it is already on disk, never claimed otherwise.
    if (chart_dir / "anomaly_results.png").exists():
        refs.append((_CHART_CAPTIONS["anomaly_results.png"], "anomaly_results.png"))
    return refs


def write_report(sweep, ablation, manifest, comparison, chart_dir=None, path=None):
    """Write the showcase Markdown: every measured result, with the charts it refers to.

    Takes already-scored frames and recomputes nothing another module owns. Every figure
    in the file is written here, so an embedded image cannot reference a stale chart.
    """
    # resolve_output() with no name returns the manifest path, so take its parent: the
    # default chart directory is outputs/, wherever that is anchored.
    chart_dir = Path(chart_dir) if chart_dir is not None else Path(resolve_output()).parent
    chart_dir.mkdir(parents=True, exist_ok=True)
    path = Path(path) if path is not None else chart_dir / "SHOWCASE.md"

    bulk = _bulk_view(sweep)
    steady = bulk[bulk["regime"].eq("steady")]
    drifting = bulk[bulk["regime"].eq("bulk")]
    steady_mean = float(steady["flagged_fraction"].mean())
    steady_max = float(steady["flagged_fraction"].max())
    bulk_mean = float(drifting["flagged_fraction"].mean())
    # Vantage counts, not capture counts: each vantage appears once per capture method.
    n_bulk_labels = drifting["label"].nunique()
    n_steady_labels = steady["label"].nunique()

    truncated = manifest[manifest["at_snaplen"] >= SNAPLEN_REPORT_AT]
    n_truncated, n_total = len(truncated), len(manifest)
    snaplen_worst = float(truncated["at_snaplen"].max()) if len(truncated) else 0.0

    tcp = ablation[ablation["method"].eq("tcp")]
    steady_labels = sorted(set(steady["label"]))
    ab_steady = tcp[tcp["label"].isin(steady_labels)]
    ab_bulk = tcp[tcp["label"].isin(BULK_LABELS)]
    all_col = tcp.groupby("group")["flagged_fraction"].mean()
    steady_col = ab_steady.groupby("group")["flagged_fraction"].mean()
    bulk_col = ab_bulk.groupby("group")["flagged_fraction"].mean()
    groups = list(all_col.index)

    attack = sweep[sweep["scenario"].ne("benign") & sweep["label"].isin(steady_labels)]
    by_scenario = attack.groupby("scenario")["flagged_fraction"].mean()

    refs = _figure_refs(sweep, manifest, comparison, chart_dir, steady_mean, bulk_mean)
    images = {name: caption for caption, name in refs}

    lines = []
    add = lines.append

    add("# Threat detection on the offline captures")
    add("")

    # 1. The correction first: it retracts a claim every other number would otherwise repeat.
    add("## The correction that changes how these numbers read")
    add("")
    add(f"Earlier drafts called the high flag rates on a few capture points a calibration "
        f"problem. It is not. {n_bulk_labels} of {n_bulk_labels + n_steady_labels} benign "
        f"vantages contain a bulk-transfer regime change: normal traffic steps from tens of "
        f"KB/s to hundreds of MB/s partway through the recording and stays there. Across both "
        f"capture methods the detector flags {bulk_mean:.2f} of held-out windows on those "
        f"captures and {steady_mean:.2f} on the other {n_steady_labels} "
        f"(max {steady_max:.2f}). A step change in normal traffic is something the detector is "
        f"supposed to notice, so a per-vantage cutoff would suppress a real change in the "
        f"cluster rather than remove a false alarm.")
    add("")
    if "steady_bulk_split.png" in images:
        add(f"![{images['steady_bulk_split.png']}](steady_bulk_split.png)")
        add("")

    # 2. Which measurements misfire, and what that rules out.
    volume_groups = [g for g in ("volume", "size_timing") if g in groups]
    quiet_groups = [g for g in groups if g not in volume_groups]
    quiet_worst = max(float(bulk_col[g]) for g in quiet_groups) if quiet_groups else 0.0
    add("## Which measurements carry the false alarms")
    add("")
    add("Mean flagged fraction per feature group, tcp captures, held-out benign windows.")
    add("")
    header = ["group", f"benign all {n_bulk_labels + n_steady_labels}",
              f"benign steady ({n_steady_labels})", f"benign bulk-transfer ({n_bulk_labels})"]
    add("| " + " | ".join(header) + " |")
    add("|" + "|".join(["---"] * len(header)) + "|")
    for group in groups:
        add(f"| {group} | {all_col[group]:.2f} | "
            f"{steady_col.get(group, float('nan')):.2f} | {bulk_col.get(group, float('nan')):.2f} |")
    add("")
    add(f"`{'` and `'.join(volume_groups)}` carry the detection and all of the false alarm. "
        f"Every other group stays at or below {quiet_worst:.2f} on the drifting captures. "
        f"That is a property of raw byte counts rather than of the cutoff, so recalibrating "
        f"the threshold would not fix it. The scale-free measurements already in the feature "
        f"set — `http_frac`, `mean_packet_size` — do not have this failure mode, and "
        f"`sweep.py --groups diversity,flags,protocol` is the one-command test of whether "
        f"detection survives without the length features. Per-capture numbers: "
        f"`outputs/ablation_results.csv`.")
    add("")

    # 3. Detection, held to the steady captures so it is not inflated by the drifting ones.
    add("## Detection per scenario")
    add("")
    add(f"Steady captures only, {WINDOW_SIZE:g}s windows, alert above {THRESHOLD:g} sigma. "
        f"Per capture: `outputs/sweep_results.csv`.")
    add("")
    add("| scenario | flagged fraction |")
    add("|---|---|")
    for scenario, value in by_scenario.sort_values(ascending=False).items():
        add(f"| {scenario} | {value:.2f} |")
    add("")
    for name in ("sweep_summary.png", f"detector_comparison_nu{SVM_NU:g}.png"):
        if name in images:
            add(f"![{images[name]}]({name})")
            add("")

    # 4. The recorder artifact.
    add("## The recorder's size limit")
    add("")
    add(f"{n_truncated} of {n_total} captures have at least "
        f"{SNAPLEN_REPORT_AT:.0%} of their packets sitting on the recorder's "
        f"{SNAPLEN_CEILINGS[0]}-byte ceiling, up to {snaplen_worst:.0%} of packets clipped. "
        f"Those captures are exactly the three vantages that change regime, so their "
        f"length-based measurements are not comparable to the other "
        f"{n_total - n_truncated}. They stay in the results, with the clipped share recorded "
        f"per capture as `at_snaplen` in `outputs/capture_manifest.csv` rather than scored as "
        f"if intact.")
    add("")
    if "capture_manifest_at_snaplen.png" in images:
        add(f"![{images['capture_manifest_at_snaplen.png']}](capture_manifest_at_snaplen.png)")
        add("")

    # 5. One capture end to end.
    if "anomaly_results.png" in images:
        add("## One capture end to end")
        add("")
        add(f"![{images['anomaly_results.png']}](anomaly_results.png)")
        add("")

    add("## Method")
    add("")
    add(f"Each recording is cut into {WINDOW_SIZE:g}-second slices and summarised by "
        f"{len(FEATURE_LABELS)} measurements. What normal looks like is learned from a benign "
        f"recording only, with its last {1 - TRAIN_FRACTION:.0%} held back as an honest check, "
        f"so no detector is "
        f"graded on the seconds it learned from. Each slice is scored by its largest deviation "
        f"from that baseline, and an alert requires {PERSISTENCE_WINDOW} flagged slices in a "
        f"row. The baseline is a median and a MAD rather than a mean and standard deviation: a "
        f"mean/std pair is set by the bulk-transfer windows instead of by normal traffic. "
        f"Regenerate everything in this file with `demo.py`, which runs the sweep, the "
        f"ablation, the comparison and this report in order.")
    add("")

    path.write_text("\n".join(lines) + "\n")
    return path


_CHART_CAPTIONS = {
    "anomaly_results.png": "Anomaly scores per window, and the strongest measurement "
                            "against its baseline band",
    "sweep_summary.png": "Flagged fraction per capture point, one series per scenario",
    f"detector_comparison_nu{SVM_NU:g}.png": "Three detectors at a matched false-alarm budget",
}