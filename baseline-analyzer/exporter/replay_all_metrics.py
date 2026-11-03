"""
replay_all_metrics.py

Replay multiple processed benign datasets through one Prometheus
metrics endpoint.

Instead of starting a separate exporter for nginx, camera, lidar, etc.,
this script reads the batch manifest created by process_all_benign.py
and loads every successfully processed source.

Each source keeps its own Prometheus label:

    source="pod-nginx"
    source="pod-camera"
    source="pod-lidar"

All sources are exposed through one /metrics endpoint.

When available, load per-source frozen robust baselines from data/baseline/robust.
The baseline center is always the median; scale is 1.4826*MAD unless MAD == 0,
when it falls back to sample standard deviation. A constant feature (both zero)
remains unscorable. Accepts compact and extended batch manifest schemas.
"""

import argparse
import time
from pathlib import Path

import pandas as pd
from prometheus_client import Gauge, start_http_server


# =========================================================
# Replay metrics
# =========================================================

packets_per_second = Gauge(
    "benign_replay_packets_per_second",
    "Recorded benign packets per second",
    ["source"]
)

bytes_per_second = Gauge(
    "benign_replay_bytes_per_second",
    "Recorded benign bytes per second",
    ["source"]
)

mean_packet_size = Gauge(
    "benign_replay_mean_packet_size_bytes",
    "Mean packet size in the current benign replay window",
    ["source"]
)

mean_iat = Gauge(
    "benign_replay_mean_iat_seconds",
    "Mean packet inter-arrival time in seconds",
    ["source"]
)

tcp_syn_per_second = Gauge(
    "benign_replay_tcp_syn_per_second",
    "Recorded TCP SYN packets per second",
    ["source"]
)

tcp_rst_per_second = Gauge(
    "benign_replay_tcp_rst_per_second",
    "Recorded TCP RST packets per second",
    ["source"]
)

unique_src_ips = Gauge(
    "benign_replay_unique_src_ips",
    "Number of unique source IP addresses in the replay window",
    ["source"]
)

unique_dst_ports = Gauge(
    "benign_replay_unique_dst_ports",
    "Number of unique destination ports in the replay window",
    ["source"]
)

source_timestamp = Gauge(
    "benign_replay_source_timestamp_seconds",
    "Original timestamp of the replayed benign data",
    ["source"]
)

replay_row = Gauge(
    "benign_replay_row",
    "Current row number in the benign replay",
    ["source"]
)

replay_active = Gauge(
    "benign_replay_active",
    "1 while replay is active",
    ["source"]
)


# =========================================================
# Frozen robust baseline metrics (median/MAD, std fallback)
# =========================================================

baseline_median = Gauge("benign_baseline_median", "Frozen benign training median", ["source", "metric"])
baseline_mad = Gauge("benign_baseline_mad", "Unscaled median absolute deviation", ["source", "metric"])
baseline_scale = Gauge("benign_baseline_scale", "1.4826 * MAD, or sample std dev when MAD is zero", ["source", "metric"])
baseline_sample_stddev = Gauge("benign_baseline_sample_stddev", "Training sample standard deviation (fallback diagnostic)", ["source", "metric"])
baseline_lower = Gauge("benign_baseline_lower_3scale", "Median minus 3 times selected scale", ["source", "metric"])
baseline_upper = Gauge("benign_baseline_upper_3scale", "Median plus 3 times selected scale", ["source", "metric"])
baseline_std_fallback = Gauge("benign_baseline_std_fallback_used", "1 if MAD was zero and sample std dev was used", ["source", "metric"])
baseline_scale_available = Gauge("benign_baseline_scale_available", "1 if the fitted scale is valid and positive", ["source", "metric"])
replay_robust_score = Gauge("benign_replay_robust_score", "(current - training median) / selected scale", ["source", "metric"])
replay_outside_baseline = Gauge("benign_replay_outside_baseline", "1 if abs(robust score) exceeds 3; candidate only", ["source", "metric"])


# These columns must exist in every processed replay CSV.
REQUIRED_COLUMNS = [
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size",
    "mean_iat",
    "tcp_syn_per_second",
    "tcp_rst_per_second",
    "unique_src_ips",
    "unique_dst_ports",
]


def set_gauge(gauge, source, value):
    """
    Publish a value for one source.

    Undefined values remain NaN instead of being changed to zero.
    This is important for statistics such as mean packet size during
    completely idle windows.
    """

    if pd.isna(value):
        gauge.labels(
            source=source
        ).set(float("nan"))
    else:
        gauge.labels(
            source=source
        ).set(float(value))


def load_baseline_stats(baseline_file, source):
    """Publish a frozen robust baseline and return scales for replay scoring.

    The old mean/standard-deviation file format is rejected deliberately;
    robust baselines must be trained with build_robust_baselines.py.
    """
    import math

    df = pd.read_csv(baseline_file)
    required = ["feature", "median", "mad", "std_dev", "scale", "scale_method",
                "lower_3scale", "upper_3scale"]
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"{baseline_file} is not a robust baseline; missing {missing}")

    if df["feature"].isna().any() or df["feature"].duplicated().any():
        raise ValueError(f"Invalid or duplicate feature names in {baseline_file}")

    # Prevalidate everything before writing any gauges, avoiding partial baselines.
    stats = {}
    for _, row in df.iterrows():
        feature = str(row["feature"])
        if feature not in REQUIRED_COLUMNS:
            continue
        median = float(row["median"])
        scale = float(row["scale"])
        method = str(row["scale_method"])
        if method not in {"scaled_mad", "std_fallback", "zero_variance", "insufficient_data"}:
            raise ValueError(f"Unknown scale method {method!r} for {feature}")
        available = math.isfinite(median) and math.isfinite(scale) and scale > 0
        if method in ("scaled_mad", "std_fallback") and not available:
            raise ValueError(f"Invalid scale for {feature} in {baseline_file}")
        stats[feature] = {"median": median, "scale": scale, "method": method,
                          "mad": float(row["mad"]), "std_dev": float(row["std_dev"]),
                          "lower": float(row["lower_3scale"]), "upper": float(row["upper_3scale"]),
                          "available": available}

    for feature, item in stats.items():
        labels = {"source": source, "metric": feature}
        baseline_median.labels(**labels).set(item["median"])
        baseline_mad.labels(**labels).set(item["mad"])
        baseline_scale.labels(**labels).set(item["scale"])
        baseline_sample_stddev.labels(**labels).set(item["std_dev"])
        baseline_lower.labels(**labels).set(item["lower"])
        baseline_upper.labels(**labels).set(item["upper"])
        baseline_std_fallback.labels(**labels).set(int(item["method"] == "std_fallback"))
        baseline_scale_available.labels(**labels).set(int(item["available"]))
    return stats


def load_source(source, processed_file, baseline_file=None):
    """Load a source's processed windows and optional frozen baseline."""
    print()
    print(f"Loading source: {source}")
    print(f"Processed file: {processed_file}")

    df = pd.read_csv(processed_file)
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"{processed_file} is missing required columns: {missing}")
    if df.empty:
        raise ValueError(f"{processed_file} contains no replay windows.")

    # Replaying the observations does not require a trained baseline.
    # Baseline series are emitted only if actual frozen statistics exist.
    baseline_stats = {}
    if baseline_file is not None and baseline_file.is_file():
        try:
            baseline_stats = load_baseline_stats(baseline_file, source)
            print(f"Frozen baseline loaded: {baseline_file}")
        except (ValueError, KeyError, OSError) as error:
            print(f"WARNING: frozen baseline for {source} could not be loaded: {error}")
            print("         Replay will continue without baseline metrics for this source.")
    else:
        print(f"WARNING: no frozen baseline available for {source}; replay metrics only.")

    print(f"Loaded {len(df)} windows")
    return {
        "source": source,
        "data": df,
        "position": 0,
        "finished": False,
        "baseline_stats": baseline_stats,
    }


def load_manifest(manifest_file, baseline_dir):
    """Load all processed sources from either supported manifest format.

    Compact manifest generated by process_all_benign.py:
        source,path,window_seconds
    Extended manifest:
        source,processed_file,baseline_file,status

    Missing robust baselines are permitted during exporter validation.
    Extended-manifest baseline_file is deliberately ignored; robust baselines
    are read only from baseline_dir to avoid mixing old mean/std statistics.
    """
    manifest = pd.read_csv(manifest_file)

    if "source" not in manifest.columns:
        raise ValueError("Manifest must include a 'source' column")

    file_column = (
        "processed_file" if "processed_file" in manifest.columns
        else "path" if "path" in manifest.columns else None
    )
    if file_column is None:
        raise ValueError("Manifest must include either 'path' or 'processed_file'")

    if "status" in manifest.columns:
        successful = manifest.loc[
            manifest["status"].fillna("").str.lower() == "success"
        ]
    else:
        successful = manifest

    if successful.empty:
        raise ValueError("Manifest contains no successfully processed datasets")

    sources = []
    seen = set()
    for _, row in successful.iterrows():
        source = str(row["source"]).strip()
        if not source or source == "nan":
            print("WARNING: skipping manifest row with empty source")
            continue
        if source in seen:
            print(f"WARNING: duplicate source {source!r}; skipping repeated entry")
            continue
        seen.add(source)

        processed_file = Path(str(row[file_column]))
        if not processed_file.is_file():
            print(f"WARNING: missing processed CSV for {source}: {processed_file}")
            continue

        # Always use the dedicated robust-baseline directory by default.
        # This prevents accidentally loading legacy mean/std files.
        baseline_file = baseline_dir / f"{source}_baseline_stats.csv"

        try:
            sources.append(load_source(source, processed_file, baseline_file))
        except (ValueError, KeyError, OSError) as error:
            print(f"WARNING: unable to load {source}: {error}")

    if not sources:
        raise ValueError("No valid replay sources could be loaded")
    return sources


def publish_row(source_state):
    """
    Publish the current row for one source to Prometheus.
    """

    source = source_state["source"]
    df = source_state["data"]
    position = source_state["position"]

    row = df.iloc[position]

    set_gauge(
        packets_per_second,
        source,
        row["packets_per_second"]
    )

    set_gauge(
        bytes_per_second,
        source,
        row["bytes_per_second"]
    )

    set_gauge(
        mean_packet_size,
        source,
        row["mean_packet_size"]
    )

    set_gauge(
        mean_iat,
        source,
        row["mean_iat"]
    )

    set_gauge(
        tcp_syn_per_second,
        source,
        row["tcp_syn_per_second"]
    )

    set_gauge(
        tcp_rst_per_second,
        source,
        row["tcp_rst_per_second"]
    )

    set_gauge(
        unique_src_ips,
        source,
        row["unique_src_ips"]
    )

    set_gauge(
        unique_dst_ports,
        source,
        row["unique_dst_ports"]
    )

    if "window_start" in df.columns:
        set_gauge(
            source_timestamp,
            source,
            row["window_start"]
        )

    # Publish robust scores for trained metrics. These are *candidate* signals,
    # not persistent anomaly alerts. Missing / constant features are unscorable.
    import math
    for feature, trained in source_state["baseline_stats"].items():
        labels = {"source": source, "metric": feature}
        observed = pd.to_numeric(row[feature], errors="coerce")
        if trained["available"] and pd.notna(observed) and math.isfinite(float(observed)):
            score = (float(observed) - trained["median"]) / trained["scale"]
            replay_robust_score.labels(**labels).set(score)
            replay_outside_baseline.labels(**labels).set(float(abs(score) > 3.0))
        else:
            replay_robust_score.labels(**labels).set(float("nan"))
            replay_outside_baseline.labels(**labels).set(float("nan"))

    replay_row.labels(
        source=source
    ).set(position)

    replay_active.labels(
        source=source
    ).set(1)

    print(
        f"source={source:<24} "
        f"row={position:<5} "
        f"pps={row['packets_per_second']:<8.2f} "
        f"mean_size={row['mean_packet_size']:<10.2f} "
        f"dst_ports={row['unique_dst_ports']}"
    )


def replay_all(sources, interval, loop):
    """
    Replay all loaded sources at the same configured interval.

    Every replay cycle publishes one new window from every active
    source, then waits before moving to the next set of observations.
    """

    print()
    print("=" * 70)
    print("Starting multi-source replay")
    print("=" * 70)
    print(f"Sources loaded: {len(sources)}")
    print(f"Replay interval: {interval} seconds")
    print()

    try:

        while True:

            active_sources = 0

            # Publish one row from every source during this cycle.
            for source_state in sources:

                if source_state["finished"]:
                    continue

                source = source_state["source"]
                df = source_state["data"]

                publish_row(source_state)

                active_sources += 1

                # Advance this source to its next observation.
                source_state["position"] += 1

                # Handle the end of this individual dataset.
                if source_state["position"] >= len(df):

                    if loop:

                        print(
                            f"Restarting source: {source}"
                        )

                        source_state["position"] = 0

                    else:

                        source_state["finished"] = True

                        replay_active.labels(
                            source=source
                        ).set(0)

            # If every source has completed and looping is disabled,
            # the exporter can stop replaying.
            if active_sources == 0:
                break

            print("-" * 70)

            # Wait once per cycle rather than once per source.
            #
            # This means 10 sources still advance every 5 seconds,
            # rather than taking 50 seconds to complete one cycle.
            time.sleep(interval)

    finally:

        # Ensure all source status metrics are reset when the exporter
        # stops or is interrupted.
        for source_state in sources:

            replay_active.labels(
                source=source_state["source"]
            ).set(0)


def main():
    """
    Start the Prometheus server, load the batch manifest,
    and begin multi-source replay.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Replay all successfully processed benign sources "
            "through one Prometheus exporter."
        )
    )

    parser.add_argument(
        "manifest_file",
        help="batch_manifest.csv created by process_all_benign.py"
    )

    parser.add_argument(
        "--baseline-dir", type=Path, default=Path("data/baseline/robust"),
        help="Directory containing frozen median/MAD baseline files"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5,
        help="Seconds between replay windows (default: 5)"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Prometheus exporter port (default: 8000)"
    )

    parser.add_argument(
        "--loop",
        action="store_true",
        help="Restart each dataset after it reaches the end"
    )

    args = parser.parse_args()

    if args.interval <= 0:
        raise ValueError(
            "Replay interval must be greater than zero."
        )

    manifest_file = Path(args.manifest_file)

    if not manifest_file.exists():
        raise FileNotFoundError(
            f"Manifest file not found: {manifest_file}"
        )

    # Validate the manifest and CSV data before binding an HTTP port.
    sources = load_manifest(manifest_file, args.baseline_dir)

    # One HTTP endpoint serves all loaded sources.
    print(f"Starting multi-source exporter on port {args.port}")
    start_http_server(args.port, addr="0.0.0.0")
    print(f"Metrics endpoint: http://localhost:{args.port}/metrics")

    print()
    print("Loaded sources:")

    for source_state in sources:
        print(
            f"  {source_state['source']}"
        )

    # Start replaying all sources together.
    replay_all(
        sources=sources,
        interval=args.interval,
        loop=args.loop
    )


if __name__ == "__main__":
    main()