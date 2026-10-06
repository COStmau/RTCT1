"""The detector: packet CSV -> 1-second windows -> baseline -> deviation score -> persistence.

Run it with:  .venv/bin/python detector.py --no-show
"""
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import local_paths


WINDOW_SIZE = 1.0
THRESHOLD = 3.0
BENIGN_TRAIN_FRACTION = 0.7
FEATURE_LABELS = {
    "packet_count": ("Packet count", "packets/window"),
    "total_bytes": ("Total bytes", "bytes/window"),
    "mean_packet_size": ("Mean packet size", "bytes"),
    "mean_iat": ("Mean interarrival time", "seconds"),
    "unique_dst_ips": ("Distinct destination IPs", "IPs/window"),
    "unique_dst_ports": ("Distinct destination ports", "ports/window"),
    "syn_count": ("TCP SYN count", "flags/window"),
    "rst_count": ("TCP RST count", "flags/window"),
}

# Packet columns this pipeline needs, one row per packet. load_data() reads a whole
# file; dataset.load_capture() reads only these columns.
PACKET_COLUMNS = ["ts", "iat", "frame_len", "dst_ip", "dst_port", "tcp_syn", "tcp_rst"]

# Every generated file goes here, so the folder stays readable.
OUTPUT_DIR = Path("outputs")


def output_path(name):
    """Path inside outputs/, created on first use. A name with a folder in it is used as given."""
    path = Path(name)
    if path.parent != Path("."):
        return path
    OUTPUT_DIR.mkdir(exist_ok=True)
    return OUTPUT_DIR / path


def load_data(path):
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
    return df


def make_features(df):
    """Summarize every window between the first and last observed packets.

    Assume the capture was continuous. Empty windows have zero counts, but
    packet-size and interarrival averages are undefined without packets.
    """
    required = {"ts", "frame_len", "iat", "dst_ip", "dst_port"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing packet columns: {', '.join(sorted(missing))}")
    if df.empty:
        raise ValueError("No packets available to determine the capture interval.")
    if not np.isfinite(WINDOW_SIZE) or WINDOW_SIZE <= 0:
        raise ValueError("WINDOW_SIZE must be positive and finite.")

    df = df.copy()
    for col in ["ts", "frame_len", "iat", "tcp_syn", "tcp_rst"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="raise")
            if not np.isfinite(df[col]).all():
                raise ValueError(f"Packet column {col} contains missing or nonfinite values.")

    df["time_bin"] = ((df["ts"] - df["ts"].min()) // WINDOW_SIZE).astype(int)
    grouped = df.groupby("time_bin")
    features = grouped.agg(
        packet_count=("ts", "count"),
        total_bytes=("frame_len", "sum"),
        mean_packet_size=("frame_len", "mean"),
        mean_iat=("iat", "mean"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
    )
    for flag, feature in [("tcp_syn", "syn_count"), ("tcp_rst", "rst_count")]:
        if flag in df.columns:
            features[feature] = grouped[flag].sum()

    features = features.reindex(range(int(df["time_bin"].max()) + 1))
    counts = features.columns.difference(["mean_packet_size", "mean_iat"])
    features[counts] = features[counts].fillna(0)
    return features


def split_benign(features):
    """Reserve later windows for evaluation; never fit on those windows."""
    split = int(len(features) * BENIGN_TRAIN_FRACTION)
    if split < 2 or split >= len(features):
        raise ValueError("Insufficient benign data for baseline and held-out evaluation.")
    return features.iloc[:split].copy(), features.iloc[split:].copy()


def build_baseline(benign):
    """Temporary Subsystem 1 stand-in: return feature means and deviations.

    Subsystem 2 consumes this fixed reference through detect_anomalies(); it
    does not update the reference from evaluation or attack-scenario traffic.
    """
    if benign.empty or benign.count().lt(2).any():
        raise ValueError("Insufficient baseline data: each feature needs at least two observations.")
    mean, std = benign.mean(), benign.std()
    if not np.isfinite(mean).all() or not np.isfinite(std).all():
        raise ValueError("Baseline statistics must be finite.")
    return mean, std


def detect_anomalies(features, mean, std):
    """Score against a fixed baseline and retain the strongest evidence."""
    if set(features.columns) != set(mean.index) or set(mean.index) != set(std.index):
        raise ValueError("Evaluation features must match the baseline feature names.")
    if not np.isfinite(mean).all() or not np.isfinite(std).all() or std.lt(0).any():
        raise ValueError("Baseline statistics must be finite, with nonnegative deviations.")
    if np.isinf(features.to_numpy()).any():
        raise ValueError("Evaluation features contain infinite values.")

    delta = features - mean
    # A constant baseline feature scores 0 when unchanged and +/- infinity
    # when changed. Missing observations stay undefined, not falsely normal.
    z_scores = delta.div(std).mask(delta.eq(0), 0.0)
    absolute_scores = z_scores.abs()
    score = absolute_scores.max(axis=1)
    top_feature = pd.Series(pd.NA, index=features.index, dtype="string")
    available = absolute_scores.notna().any(axis=1)
    top_feature.loc[available] = absolute_scores.loc[available].idxmax(axis=1)

    results = features.copy()
    results["anomaly_score"] = score
    results["anomaly"] = score.gt(THRESHOLD).astype("boolean").mask(score.isna())
    results["status"] = "normal"
    results.loc[score.gt(THRESHOLD), "status"] = "anomaly"
    results.loc[score.isna(), "status"] = "insufficient_data"
    results["top_feature"] = top_feature
    results["observed_value"] = np.nan
    results["expected_mean"] = top_feature.map(mean)
    results["expected_std"] = top_feature.map(std)
    results["feature_z_score"] = np.nan
    for col in features.columns:
        selected = top_feature.eq(col).fillna(False)
        results.loc[selected, "observed_value"] = features.loc[selected, col]
        results.loc[selected, "feature_z_score"] = z_scores.loc[selected, col]
    return results


PERSISTENCE_WINDOW = 3


def persistent_mask(flags, min_consecutive=PERSISTENCE_WINDOW):
    """Mark flags that sit inside a run of >= min_consecutive consecutive flags.

    Uses a running count within each run: transform("sum") would return the whole
    run length for every row and escalate the first windows of a run too.
    """
    flags = pd.Series(flags).fillna(False).astype(bool)
    run_id = (flags != flags.shift()).cumsum()
    run_len = flags.groupby(run_id).cumsum()
    return flags & run_len.ge(min_consecutive)


def flag_persistent(results, min_consecutive=PERSISTENCE_WINDOW):
    """Count consecutive flags so alerts need sustained deviations, not one-off spikes."""
    results = results.copy()
    results["persistent_flag"] = persistent_mask(results["anomaly"], min_consecutive)
    results["status"] = results["status"].mask(results["persistent_flag"], "persistent_anomaly")
    return results


def flag_stats(flags, min_consecutive=PERSISTENCE_WINDOW):
    """Flagged and sustained counts/fractions for one set of windows.

    Shared by sweep.py and compare.py so both report the same numbers.
    """
    flags = pd.Series(flags).fillna(False).astype(bool)
    persistent = persistent_mask(flags, min_consecutive)
    total = len(flags)
    return {
        "windows": int(total),
        "flagged": int(flags.sum()),
        "flagged_fraction": round(float(flags.mean()), 4) if total else float("nan"),
        "persistent": int(persistent.sum()),
        "persistent_fraction": round(float(persistent.mean()), 4) if total else float("nan"),
    }


def sweep_thresholds(results, benign_results, thresholds=(1.5, 2.0, 3.0, 4.0)):
    """Flag counts at a few cutoffs, to sanity-check the 3-sigma default."""
    print(f"\n   {'Threshold':>9} {'Benign flags':>13} {'Attack flags':>13}")
    for t in thresholds:
        b = int(benign_results["anomaly_score"].gt(t).sum())
        a = int(results["anomaly_score"].gt(t).sum())
        print(f"   {t:>9.1f} {b:>13} {a:>13}")


def print_summary(results, benign_results, baseline_features, evaluation_note):
    print("\n" + "=" * 76)
    print("THREAT DETECTION MVP  |  Offline traffic analysis")
    print("=" * 76)
    print("\n1. BUILD THE REFERENCE")
    print(f"   {len(baseline_features)} benign windows define normal behavior.")
    print(f"   {evaluation_note}")
    print("   The reference stays fixed during evaluation.")
    print("\n2. COMPARE EACH WINDOW")
    print(f"   Window: {WINDOW_SIZE:g} s  |  Features: {len(baseline_features.columns)}"
          f"  |  Flag when score > {THRESHOLD:g}")
    print("   Score = the largest absolute feature deviation, in standard deviations.")
    print()
    print(f"   {'Capture':<20} {'Windows':>7} {'Flagged':>8} {'Unknown':>8} {'Peak score':>11}")
    print("   " + "-" * 58)
    for label, frame in [("Held-out benign", benign_results), ("Attack scenario", results)]:
        peak = frame["anomaly_score"].max()
        peak_text = "unknown" if pd.isna(peak) else f"{peak:.2f}"
        print(f"   {label:<20} {len(frame):>7} {int(frame['anomaly'].sum()):>8}"
              f" {int(frame['anomaly'].isna().sum()):>8} {peak_text:>11}")
    print("\n   Empty windows are included; unavailable scores are marked unknown.")
    print(f"\n   Requiring {PERSISTENCE_WINDOW} consecutive flagged windows")
    print(f"   cuts this to {int(benign_results['persistent_flag'].sum())} persistent on benign,"
          f" {int(results['persistent_flag'].sum())} on attack")
    sweep_thresholds(results, benign_results)
    print("\n3. EXPLAIN THE ATTACK-SCENARIO ALERTS")
    flagged = results.loc[results["anomaly"].fillna(False)]
    if flagged.empty:
        print("   No scored attack-scenario window exceeded the cutoff.")
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


def plot_results(results, benign_results, mean, std, baseline_windows, show=True):
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
        ax_feature.set_title(f"{name} — attack scenario vs baseline",
                             fontsize=10, fontweight="bold")
        ax_feature.set_xlabel("seconds", fontsize=9, fontweight="bold")
        ax_feature.set_ylabel(f"{name} ({unit})", fontsize=9, fontweight="bold")
        ax_feature.legend(fontsize=8, prop={"weight": "bold"})

    for ax in fig.axes:
        for label in ax.get_xticklabels() + ax.get_yticklabels():
            label.set_fontweight("bold")

    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(output_path("anomaly_results.png"), dpi=150)
    if show:
        plt.show()
    plt.close(fig)


def main(show_plot=True):
    if not local_paths.BENIGN_CSV or not local_paths.ATTACK_CSV:
        raise ValueError("Set BENIGN_CSV and ATTACK_CSV in local_paths.py.")

    benign_features = make_features(load_data(local_paths.BENIGN_CSV))
    evaluation_path = getattr(local_paths, "BENIGN_EVAL_CSV", "")
    if evaluation_path:
        if Path(evaluation_path).resolve() == Path(local_paths.BENIGN_CSV).resolve():
            raise ValueError("BENIGN_EVAL_CSV must differ from the baseline capture.")
        baseline_features = benign_features
        benign_evaluation = make_features(load_data(evaluation_path))
        evaluation_note = "Benign evaluation uses a separate capture, excluded from fitting."
    else:
        baseline_features, benign_evaluation = split_benign(benign_features)
        evaluation_note = (f"First {len(baseline_features)} windows fit the reference; "
                           f"the next {len(benign_evaluation)} are held out.")

    mean, std = build_baseline(baseline_features)
    attack_features = make_features(load_data(local_paths.ATTACK_CSV))
    benign_results = flag_persistent(detect_anomalies(benign_evaluation, mean, std))
    results = flag_persistent(detect_anomalies(attack_features, mean, std))
    results.to_csv(output_path("results.csv"))
    benign_results.to_csv(output_path("benign_results.csv"))

    print_summary(results, benign_results, baseline_features, evaluation_note)
    plot_results(results, benign_results, mean, std, len(baseline_features), show=show_plot)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the offline threat detection demo.")
    parser.add_argument("--no-show", action="store_true", help="Save the chart without opening a window.")
    args = parser.parse_args()
    try:
        main(show_plot=not args.no_show)
    except (ValueError, OSError) as error:
        raise SystemExit(f"Unable to run detector: {error}")
