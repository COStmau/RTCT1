"""
replay_metrics.py

Replay processed benign network traffic as Prometheus metrics.

The Baseline Analyzer currently works with recorded benign traffic.
This script makes that historical dataset behave like a live stream by
publishing one processed time window at a time.

Prometheus can then scrape these values and Grafana can visualize them.

The script also loads the previously trained frozen baseline so that
the current replay values can be compared against fixed benign mean
and standard-deviation values.
"""

import argparse
import time

import pandas as pd
from prometheus_client import Gauge, start_http_server


# =========================================================
# Replay Prometheus metrics
# =========================================================
#
# Each replay metric contains a "source" label.
#
# Example:
#
# benign_replay_packets_per_second{source="pod-nginx"}
#
# This allows multiple workloads to have separate metrics
# without creating a completely different metric name for each pod.


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


# Preserve the timestamp from the original recording.
#
# Prometheus will still use the current scrape time for the sample,
# but this metric allows us to know which historical source window
# is currently being replayed.
source_timestamp = Gauge(
    "benign_replay_source_timestamp_seconds",
    "Original timestamp of the replayed benign data",
    ["source"]
)


# Track which row in the processed CSV is currently being replayed.
# This is mainly useful for debugging.
replay_row = Gauge(
    "benign_replay_row",
    "Current row number in the benign replay",
    ["source"]
)


# 1 indicates that this source is actively replaying.
# 0 indicates that replay has stopped.
replay_active = Gauge(
    "benign_replay_active",
    "1 while replay is active",
    ["source"]
)


# =========================================================
# Frozen baseline Prometheus metrics
# =========================================================
#
# Unlike the replay metrics above, these values do not change as
# new observations are replayed.
#
# The baseline was previously calculated from known-benign training
# data by build_baseline.py.


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


# Columns that must exist in the processed replay CSV.
#
# These include both the three current primary features and several
# supporting metrics that are still useful for visualization.
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


def load_baseline_stats(baseline_file, source):
    """
    Load frozen baseline statistics and publish them to Prometheus.

    The baseline CSV contains one row per trained feature. These values
    remain constant during the replay and act as the fixed definition
    of normal benign behavior.
    """

    baseline_df = pd.read_csv(baseline_file)

    for _, row in baseline_df.iterrows():

        metric = row["feature"]

        # Frozen average benign value.
        baseline_mean.labels(
            source=source,
            metric=metric
        ).set(
            float(row["mean"])
        )

        # Frozen amount of normal variation.
        baseline_stddev.labels(
            source=source,
            metric=metric
        ).set(
            float(row["std_dev"])
        )

        # Lower candidate normal boundary.
        baseline_lower.labels(
            source=source,
            metric=metric
        ).set(
            float(row["lower_3sigma"])
        )

        # Upper candidate normal boundary.
        baseline_upper.labels(
            source=source,
            metric=metric
        ).set(
            float(row["upper_3sigma"])
        )


def set_gauge(gauge, source, value):
    """
    Publish a replay value using the correct source label.

    Some statistics, such as mean packet size, can be undefined during
    a completely idle window. Those values remain NaN instead of being
    incorrectly converted to zero.
    """

    if pd.isna(value):

        gauge.labels(
            source=source
        ).set(
            float("nan")
        )

    else:

        gauge.labels(
            source=source
        ).set(
            float(value)
        )


def replay(csv_file, source, interval, loop):
    """
    Replay a processed benign CSV one window at a time.

    Each dataframe row represents one previously aggregated time window.
    The values are copied into Prometheus gauges and then the program
    waits for the configured interval before publishing the next row.

    When --loop is enabled, the replay restarts after the last row.
    """

    print(f"Reading: {csv_file}")
    print(f"Source:  {source}")

    # Load the processed feature windows.
    df = pd.read_csv(csv_file)

    # Verify that the exporter has all of the features it expects.
    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"CSV is missing required columns: {missing}"
        )

    print(f"Loaded {len(df)} replay windows")
    print(f"Replay interval: {interval} seconds")
    print()

    # Tell Prometheus that replay for this source is active.
    replay_active.labels(
        source=source
    ).set(1)

    try:

        # Continue indefinitely when loop mode is enabled.
        while True:

            # Each dataframe row represents one aggregated observation.
            for index, row in df.iterrows():

                # -------------------------------------------------
                # Publish the current replay metrics
                # -------------------------------------------------

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

                # Publish the original dataset timestamp if it exists.
                if "window_start" in df.columns:

                    set_gauge(
                        source_timestamp,
                        source,
                        row["window_start"]
                    )

                # Publish the current row number for debugging.
                replay_row.labels(
                    source=source
                ).set(index)

                # Display a small status line in the terminal so the
                # replay can also be monitored without Grafana.
                print(
                    f"source={source:<18} "
                    f"row={index:<4} "
                    f"pps={row['packets_per_second']:<8.2f} "
                    f"Bps={row['bytes_per_second']:<10.2f} "
                    f"dst_ports={row['unique_dst_ports']}"
                )

                # Simulate real-time observations by waiting before
                # publishing the next historical window.
                time.sleep(interval)

            # Stop after one pass unless --loop was requested.
            if not loop:
                break

            print()
            print(
                f"End of {source} dataset. Restarting..."
            )
            print()

    finally:

        # Ensure Prometheus knows the replay is no longer active
        # if the program stops normally or is interrupted.
        replay_active.labels(
            source=source
        ).set(0)


def main():
    """
    Parse command-line arguments, start the Prometheus endpoint,
    load the frozen baseline, and begin replay.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Replay processed benign CSV metrics for Prometheus."
        )
    )

    # Processed 5-second network feature CSV.
    parser.add_argument(
        "csv_file",
        help="Processed benign CSV file"
    )

    # Statistics previously created by build_baseline.py.
    parser.add_argument(
        "--baseline-file",
        required=True,
        help="Frozen baseline statistics CSV"
    )

    # Source becomes the Prometheus label identifying this workload.
    parser.add_argument(
        "--source",
        required=True,
        help='Source label, for example "pod-nginx"'
    )

    # Number of seconds between historical observations.
    parser.add_argument(
        "--interval",
        type=float,
        default=5,
        help="Seconds between replay rows"
    )

    # Port where /metrics will be exposed.
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Prometheus exporter port"
    )

    # Restart at the first row after reaching the end of the CSV.
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Restart from the beginning when the file ends"
    )

    args = parser.parse_args()

    if args.interval <= 0:
        raise ValueError(
            "Replay interval must be greater than zero."
        )

    # Start an HTTP endpoint that Prometheus can scrape.
    print(
        f"Starting exporter on port {args.port}"
    )

    start_http_server(
        args.port,
        addr="0.0.0.0"
    )

    print(
        f"Metrics endpoint: "
        f"http://localhost:{args.port}/metrics"
    )

    print()

    # Load the frozen statistics once.
    #
    # These baseline values remain constant while replay values
    # change over time.
    load_baseline_stats(
        baseline_file=args.baseline_file,
        source=args.source
    )

    # Begin publishing the historical observations.
    replay(
        csv_file=args.csv_file,
        source=args.source,
        interval=args.interval,
        loop=args.loop
    )


if __name__ == "__main__":
    main()