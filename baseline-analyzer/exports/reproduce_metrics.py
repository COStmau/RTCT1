import argparse
import math
import time

import pandas as pd
from prometheus_client import Gauge, start_http_server


# ---------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------

packets_per_second = Gauge(
    "benign_replay_packets_per_second",
    "Recorded benign packets per second"
)

bytes_per_second = Gauge(
    "benign_replay_bytes_per_second",
    "Recorded benign bytes per second"
)

mean_packet_size = Gauge(
    "benign_replay_mean_packet_size_bytes",
    "Mean packet size in the current benign replay window"
)

mean_iat = Gauge(
    "benign_replay_mean_iat_seconds",
    "Mean packet inter-arrival time in seconds"
)

tcp_syn_per_second = Gauge(
    "benign_replay_tcp_syn_per_second",
    "Recorded TCP SYN packets per second"
)

tcp_rst_per_second = Gauge(
    "benign_replay_tcp_rst_per_second",
    "Recorded TCP RST packets per second"
)

unique_src_ips = Gauge(
    "benign_replay_unique_src_ips",
    "Number of unique source IP addresses in the replay window"
)

unique_dst_ports = Gauge(
    "benign_replay_unique_dst_ports",
    "Number of unique destination ports in the replay window"
)

source_timestamp = Gauge(
    "benign_replay_source_timestamp_seconds",
    "Original timestamp of the replayed benign data"
)

replay_row = Gauge(
    "benign_replay_row",
    "Current row number in the benign replay"
)

replay_active = Gauge(
    "benign_replay_active",
    "1 while replay is active"
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


def set_gauge(gauge, value):
    """
    Set a Prometheus gauge.

    If the source value is undefined/NaN, publish NaN rather
    than incorrectly replacing it with zero or a mean.
    """
    if pd.isna(value):
        gauge.set(float("nan"))
    else:
        gauge.set(float(value))


def replay(csv_file, interval, loop):
    print(f"Reading {csv_file}")

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

    replay_active.set(1)

    try:
        while True:
            for index, row in df.iterrows():

                set_gauge(
                    packets_per_second,
                    row["packets_per_second"]
                )

                set_gauge(
                    bytes_per_second,
                    row["bytes_per_second"]
                )

                set_gauge(
                    mean_packet_size,
                    row["mean_packet_size"]
                )

                set_gauge(
                    mean_iat,
                    row["mean_iat"]
                )

                set_gauge(
                    tcp_syn_per_second,
                    row["tcp_syn_per_second"]
                )

                set_gauge(
                    tcp_rst_per_second,
                    row["tcp_rst_per_second"]
                )

                set_gauge(
                    unique_src_ips,
                    row["unique_src_ips"]
                )

                set_gauge(
                    unique_dst_ports,
                    row["unique_dst_ports"]
                )

                if "window_start" in df.columns:
                    set_gauge(
                        source_timestamp,
                        row["window_start"]
                    )

                replay_row.set(index)

                print(
                    f"row={index:<4} "
                    f"pps={row['packets_per_second']:<8.2f} "
                    f"Bps={row['bytes_per_second']:<10.2f} "
                    f"SYN/s={row['tcp_syn_per_second']:<6.2f} "
                    f"RST/s={row['tcp_rst_per_second']:<6.2f}"
                )

                time.sleep(interval)

            if not loop:
                break

            print()
            print("End of dataset reached. Restarting replay...")
            print()

    finally:
        replay_active.set(0)


def main():
    parser = argparse.ArgumentParser(
        description="Replay processed benign CSV metrics for Prometheus."
    )

    parser.add_argument(
        "csv_file",
        help="Processed benign CSV file"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5,
        help="Seconds between replay rows (default: 5)"
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
        help="Restart from the beginning when the file ends"
    )

    args = parser.parse_args()

    if args.interval <= 0:
        raise ValueError("Replay interval must be greater than zero.")

    print(f"Starting Prometheus exporter on port {args.port}")
    start_http_server(args.port, addr="0.0.0.0")

    print(
        f"Metrics endpoint: http://localhost:{args.port}/metrics"
    )
    print()

    replay(
        csv_file=args.csv_file,
        interval=args.interval,
        loop=args.loop
    )


if __name__ == "__main__":
    main()