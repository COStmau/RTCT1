import argparse
import time

import pandas as pd
from prometheus_client import Gauge, start_http_server


# ---------------------------------------------------------
# Prometheus metrics
# Every metric now has a "source" label.
# ---------------------------------------------------------

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
    Publish the value using the correct source label.

    Undefined source values remain NaN instead of being
    incorrectly replaced with zero.
    """
    if pd.isna(value):
        gauge.labels(source=source).set(float("nan"))
    else:
        gauge.labels(source=source).set(float(value))


def replay(csv_file, source, interval, loop):
    print(f"Reading: {csv_file}")
    print(f"Source:  {source}")

    df = pd.read_csv(csv_file)

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

    replay_active.labels(source=source).set(1)

    try:
        while True:
            for index, row in df.iterrows():

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

                replay_row.labels(source=source).set(index)

                print(
                    f"source={source:<18} "
                    f"row={index:<4} "
                    f"pps={row['packets_per_second']:<8.2f} "
                    f"Bps={row['bytes_per_second']:<10.2f} "
                    f"dst_ports={row['unique_dst_ports']}"
                )

                time.sleep(interval)

            if not loop:
                break

            print()
            print(f"End of {source} dataset. Restarting...")
            print()

    finally:
        replay_active.labels(source=source).set(0)


def main():
    parser = argparse.ArgumentParser(
        description="Replay processed benign CSV metrics for Prometheus."
    )

    parser.add_argument(
        "csv_file",
        help="Processed benign CSV file"
    )

    parser.add_argument(
        "--source",
        required=True,
        help='Source label, for example "pod-nginx"'
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5,
        help="Seconds between replay rows"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Prometheus exporter port"
    )

    parser.add_argument(
        "--loop",
        action="store_true",
        help="Restart from the beginning when the file ends"
    )

    args = parser.parse_args()

    if args.interval <= 0:
        raise ValueError("Replay interval must be greater than zero.")

    print(f"Starting exporter on port {args.port}")
    start_http_server(args.port, addr="0.0.0.0")

    print(f"Metrics endpoint: http://localhost:{args.port}/metrics")
    print()

    replay(
        csv_file=args.csv_file,
        source=args.source,
        interval=args.interval,
        loop=args.loop
    )


if __name__ == "__main__":
    main()