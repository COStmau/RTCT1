import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def numeric_column(df, column):
    """
    Return a numeric version of a column.
    Missing/non-numeric values become NaN.
    """
    if column not in df.columns:
        return pd.Series(np.nan, index=df.index)

    return pd.to_numeric(df[column], errors="coerce")


def indicator_column(df, column):
    """
    Convert a 0/1-style column to numeric values.
    Missing values become 0.
    """
    if column not in df.columns:
        return pd.Series(0, index=df.index, dtype=float)

    return pd.to_numeric(df[column], errors="coerce").fillna(0)


def aggregate_benign(input_file, output_file, window_seconds=1):
    print(f"Reading: {input_file}")

    df = pd.read_csv(input_file)

    if "ts" not in df.columns:
        raise ValueError("CSV must contain a 'ts' timestamp column.")

    # Ensure timestamps are numeric Unix timestamps.
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"])

    # Sort chronologically.
    df = df.sort_values("ts").reset_index(drop=True)

    # Assign each packet to a fixed time bucket.
    #
    # Example for 1-second windows:
    # 100.1 -> 100
    # 100.8 -> 100
    # 101.2 -> 101
    df["window_start"] = (
        np.floor(df["ts"] / window_seconds) * window_seconds
    )

    # Convert useful packet fields to numeric form.
    df["frame_len_num"] = numeric_column(df, "frame_len")
    df["iat_num"] = numeric_column(df, "iat")
    df["tcp_payload_len_num"] = numeric_column(df, "tcp_payload_len")
    df["udp_length_num"] = numeric_column(df, "udp_length")

    # Boolean / indicator fields.
    indicator_fields = [
        "tcp_syn",
        "tcp_fin",
        "tcp_rst",
        "tcp_psh",
        "tcp_ack",
        "is_dns",
        "is_http",
        "is_https",
    ]

    for column in indicator_fields:
        df[f"{column}_num"] = indicator_column(df, column)

    grouped = df.groupby("window_start")

    output = pd.DataFrame(index=grouped.size().index)

    # ---------------------------------------------------------
    # Basic traffic-rate features
    # ---------------------------------------------------------

    output["packet_count"] = grouped.size()

    output["packets_per_second"] = (
        output["packet_count"] / window_seconds
    )

    output["total_bytes"] = grouped["frame_len_num"].sum()

    output["bytes_per_second"] = (
        output["total_bytes"] / window_seconds
    )

    # ---------------------------------------------------------
    # Packet-size characteristics
    # ---------------------------------------------------------

    output["mean_packet_size"] = grouped["frame_len_num"].mean()
    output["std_packet_size"] = grouped["frame_len_num"].std()
    output["max_packet_size"] = grouped["frame_len_num"].max()
    output["min_packet_size"] = grouped["frame_len_num"].min()

    # ---------------------------------------------------------
    # Packet timing / inter-arrival characteristics
    # ---------------------------------------------------------

    output["mean_iat"] = grouped["iat_num"].mean()
    output["std_iat"] = grouped["iat_num"].std()
    output["max_iat"] = grouped["iat_num"].max()

    # ---------------------------------------------------------
    # TCP behavior
    # ---------------------------------------------------------

    output["tcp_syn_per_second"] = (
        grouped["tcp_syn_num"].sum() / window_seconds
    )

    output["tcp_fin_per_second"] = (
        grouped["tcp_fin_num"].sum() / window_seconds
    )

    output["tcp_rst_per_second"] = (
        grouped["tcp_rst_num"].sum() / window_seconds
    )

    output["tcp_psh_per_second"] = (
        grouped["tcp_psh_num"].sum() / window_seconds
    )

    output["tcp_ack_per_second"] = (
        grouped["tcp_ack_num"].sum() / window_seconds
    )

    # ---------------------------------------------------------
    # Application/protocol behavior
    # ---------------------------------------------------------

    output["dns_packets_per_second"] = (
        grouped["is_dns_num"].sum() / window_seconds
    )

    output["http_packets_per_second"] = (
        grouped["is_http_num"].sum() / window_seconds
    )

    output["https_packets_per_second"] = (
        grouped["is_https_num"].sum() / window_seconds
    )

    # ---------------------------------------------------------
    # Payload behavior
    # ---------------------------------------------------------

    output["tcp_payload_bytes_per_second"] = (
        grouped["tcp_payload_len_num"].sum() / window_seconds
    )

    output["udp_bytes_per_second"] = (
        grouped["udp_length_num"].sum() / window_seconds
    )

    # ---------------------------------------------------------
    # Diversity / fan-out features
    # ---------------------------------------------------------

    if "src_ip" in df.columns:
        output["unique_src_ips"] = grouped["src_ip"].nunique()

    if "dst_ip" in df.columns:
        output["unique_dst_ips"] = grouped["dst_ip"].nunique()

    if "src_port" in df.columns:
        output["unique_src_ports"] = grouped["src_port"].nunique()

    if "dst_port" in df.columns:
        output["unique_dst_ports"] = grouped["dst_port"].nunique()

    if "proto" in df.columns:
        output["unique_protocols"] = grouped["proto"].nunique()




        # ---------------------------------------------------------
        # Add missing time windows
        # ---------------------------------------------------------

        start_window = int(output.index.min())
        end_window = int(output.index.max())

        all_windows = np.arange(
            start_window,
            end_window + window_seconds,
            window_seconds
        )

        # Add rows for windows where no packets were recorded
        output = output.reindex(all_windows)
        output.index.name = "window_start"

        # These features should genuinely be zero when there is no traffic
        zero_when_idle = [
            "packet_count",
            "packets_per_second",
            "total_bytes",
            "bytes_per_second",

            "tcp_syn_per_second",
            "tcp_fin_per_second",
            "tcp_rst_per_second",
            "tcp_psh_per_second",
            "tcp_ack_per_second",

            "dns_packets_per_second",
            "http_packets_per_second",
            "https_packets_per_second",

            "tcp_payload_bytes_per_second",
            "udp_bytes_per_second",

            "unique_src_ips",
            "unique_dst_ips",
            "unique_src_ports",
            "unique_dst_ports",
            "unique_protocols",
        ]

        for column in zero_when_idle:
            if column in output.columns:
                output[column] = output[column].fillna(0)

                
    # Restore timestamp as a normal column.
    output = output.reset_index()

    # Optional readable timestamp for debugging / visualization.
    output["datetime_utc"] = pd.to_datetime(
        output["window_start"],
        unit="s",
        utc=True
    )

    # Keep readable datetime near the beginning.
    columns = list(output.columns)
    columns.remove("datetime_utc")
    columns.insert(1, "datetime_utc")
    output = output[columns]

    # Save.
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(output_file, index=False)

    print()
    print("Aggregation complete.")
    print(f"Input packets: {len(df):,}")
    print(f"Output windows: {len(output):,}")
    print(f"Window size: {window_seconds} second(s)")
    print(f"Saved to: {output_file}")

    print()
    print("First five rows:")
    print(output.head().to_string(index=False))


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate benign packet-level CSV data into time-series features."
    )

    parser.add_argument(
        "input",
        help="Input packet-level CSV file"
    )

    parser.add_argument(
        "output",
        help="Output aggregated CSV file"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=1,
        help="Aggregation window in seconds (default: 1)"
    )

    args = parser.parse_args()

    if args.window <= 0:
        raise ValueError("Window size must be greater than zero.")

    aggregate_benign(
        input_file=args.input,
        output_file=args.output,
        window_seconds=args.window
    )


if __name__ == "__main__":
    main()