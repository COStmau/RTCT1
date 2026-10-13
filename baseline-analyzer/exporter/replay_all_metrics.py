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

The exporter also loads the frozen baseline associated with each source.
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
# Frozen baseline metrics
# =========================================================

baseline_mean = Gauge(
    "benign_baseline_mean",
    "Frozen benign baseline mean",
    ["source", "metric"]
)

baseline_stddev = Gauge(
    "benign_baseline_stddev",
    "Frozen benign baseline standard deviation",
    ["source", "metric"]
)

baseline_lower = Gauge(
    "benign_baseline_lower_3sigma",
    "Frozen benign baseline lower 3-sigma boundary",
    ["source", "metric"]
)

baseline_upper = Gauge(
    "benign_baseline_upper_3sigma",
    "Frozen benign baseline upper 3-sigma boundary",
    ["source", "metric"]
)


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
    """
    Load one source's frozen baseline into Prometheus.

    These values remain constant throughout replay.
    """

    baseline_df = pd.read_csv(baseline_file)

    required_baseline_columns = [
        "feature",
        "mean",
        "std_dev",
        "lower_3sigma",
        "upper_3sigma",
    ]

    missing = [
        column
        for column in required_baseline_columns
        if column not in baseline_df.columns
    ]

    if missing:
        raise ValueError(
            f"{baseline_file} is missing baseline columns: {missing}"
        )

    for _, row in baseline_df.iterrows():

        metric = row["feature"]

        baseline_mean.labels(
            source=source,
            metric=metric
        ).set(
            float(row["mean"])
        )

        baseline_stddev.labels(
            source=source,
            metric=metric
        ).set(
            float(row["std_dev"])
        )

        baseline_lower.labels(
            source=source,
            metric=metric
        ).set(
            float(row["lower_3sigma"])
        )

        baseline_upper.labels(
            source=source,
            metric=metric
        ).set(
            float(row["upper_3sigma"])
        )


def load_source(source, processed_file, baseline_file):
    """
    Load one processed dataset and its frozen baseline.

    Returns a dictionary containing the dataframe and the source's
    current replay position.
    """

    print()
    print(f"Loading source: {source}")
    print(f"Processed file: {processed_file}")
    print(f"Baseline file:  {baseline_file}")

    df = pd.read_csv(processed_file)

    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"{processed_file} is missing required columns: {missing}"
        )

    if len(df) == 0:
        raise ValueError(
            f"{processed_file} contains no replay windows."
        )

    # Load this source's frozen statistics before replay starts.
    load_baseline_stats(
        baseline_file=baseline_file,
        source=source
    )

    print(f"Loaded {len(df)} windows")

    return {
        "source": source,
        "data": df,
        "position": 0,
        "finished": False,
    }


def load_manifest(manifest_file):
    """
    Read the batch-processing manifest and load all successful sources.

    Failed preprocessing jobs are ignored so one bad dataset does not
    prevent valid sources from being replayed.
    """

    manifest = pd.read_csv(manifest_file)

    required_manifest_columns = [
        "source",
        "processed_file",
        "baseline_file",
        "status",
    ]

    missing = [
        column
        for column in required_manifest_columns
        if column not in manifest.columns
    ]

    if missing:
        raise ValueError(
            f"Manifest is missing required columns: {missing}"
        )

    # Only use datasets that completed preprocessing successfully.
    successful = manifest[
        manifest["status"] == "success"
    ].copy()

    if successful.empty:
        raise ValueError(
            "Manifest does not contain any successful datasets."
        )

    sources = []

    for _, row in successful.iterrows():

        source = str(row["source"])
        processed_file = Path(str(row["processed_file"]))
        baseline_file = Path(str(row["baseline_file"]))

        if not processed_file.exists():
            print(
                f"WARNING: processed file not found for "
                f"{source}: {processed_file}"
            )
            continue

        if not baseline_file.exists():
            print(
                f"WARNING: baseline file not found for "
                f"{source}: {baseline_file}"
            )
            continue

        try:
            source_state = load_source(
                source=source,
                processed_file=processed_file,
                baseline_file=baseline_file,
            )

            sources.append(source_state)

        except Exception as error:
            print(
                f"WARNING: unable to load {source}: {error}"
            )

    if not sources:
        raise ValueError(
            "No valid replay sources could be loaded."
        )

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

    # One HTTP endpoint now serves every source.
    print(
        f"Starting multi-source exporter on port {args.port}"
    )

    start_http_server(
        args.port,
        addr="0.0.0.0"
    )

    print(
        f"Metrics endpoint: "
        f"http://localhost:{args.port}/metrics"
    )

    # Load every successful dataset listed in the manifest.
    sources = load_manifest(
        manifest_file
    )

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