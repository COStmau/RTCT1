import argparse
from pathlib import Path
"""
aggregate_benign_1s.py

Convert packet-level benign network traffic into fixed-duration
time-series feature windows.

The raw CSV contains one row per captured packet. This script groups
those packets into configurable time windows and calculates features
that can later be used to train the benign baseline.

Although the filename contains "1s", the window size is configurable.
The current Baseline Analyzer primarily uses 5-second windows.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def numeric_column(df, column):
    """
    Convert a dataframe column to numeric values.

    Missing or invalid values become NaN. Returning NaN is useful for
    statistics such as packet size or IAT because those values should
    remain undefined if they were not present in the original data.
    """
    if column not in df.columns:
        return pd.Series(np.nan, index=df.index)

    return pd.to_numeric(df[column], errors="coerce")


def indicator_column(df, column):
    """
    Convert a 0/1 indicator column to numeric values.

    Indicator fields represent events such as TCP SYN, TCP RST, or DNS.
    If the column is missing or a value cannot be read, treat it as 0.
    """
    if column not in df.columns:
        return pd.Series(0, index=df.index, dtype=float)

    return pd.to_numeric(df[column], errors="coerce").fillna(0)


def aggregate_benign(input_file, output_file, window_seconds=1):
    """
    Aggregate raw packet rows into fixed-duration network feature windows.

    Parameters
    ----------
    input_file:
        Packet-level benign CSV file.

    output_file:
        Location where the processed feature CSV will be saved.

    window_seconds:
        Size of each aggregation window in seconds.
    """

    print(f"Reading: {input_file}")

    # Load the packet-level capture.
    df = pd.read_csv(input_file)

    # The timestamp is required because all feature calculations depend
    # on assigning packets to the correct time window.
    if "ts" not in df.columns:
        raise ValueError("CSV must contain a 'ts' timestamp column.")

    # Convert timestamps to numeric Unix timestamps.
    # Invalid timestamps are removed because they cannot be placed
    # into a time window.
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"])

    # Keep packets in chronological order before aggregation.
    df = df.sort_values("ts").reset_index(drop=True)

    # Assign every packet to the beginning of its fixed time window.
    #
    # Example using 1-second windows:
    #   100.1 -> window 100
    #   100.8 -> window 100
    #   101.2 -> window 101
    #
    # With 5-second windows, packets between 100 and 104.999...
    # would all belong to the same window.
    df["window_start"] = (
        np.floor(df["ts"] / window_seconds) * window_seconds
    )

    # Convert packet fields that will be used for mathematical
    # calculations into numeric values.
    df["frame_len_num"] = numeric_column(df, "frame_len")
    df["iat_num"] = numeric_column(df, "iat")
    df["tcp_payload_len_num"] = numeric_column(df, "tcp_payload_len")
    df["udp_length_num"] = numeric_column(df, "udp_length")

    # These columns behave like boolean indicators.
    # Each 1 represents that the packet contained the corresponding
    # flag or protocol characteristic.
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

    # Group all packets belonging to the same time window.
    grouped = df.groupby("window_start")

    # Each output row represents one aggregated time window.
    output = pd.DataFrame(index=grouped.size().index)

    # ---------------------------------------------------------
    # Traffic volume / rate
    # ---------------------------------------------------------

    # Total packets observed in each window.
    output["packet_count"] = grouped.size()

    # Normalize by the window length so this metric can still be
    # interpreted as packets per second.
    output["packets_per_second"] = (
        output["packet_count"] / window_seconds
    )

    # Total number of captured bytes in the window.
    output["total_bytes"] = grouped["frame_len_num"].sum()

    output["bytes_per_second"] = (
        output["total_bytes"] / window_seconds
    )

    # ---------------------------------------------------------
    # Packet-size behavior
    # ---------------------------------------------------------

    # These features describe the size distribution of packets
    # observed during each time window.
    output["mean_packet_size"] = grouped["frame_len_num"].mean()
    output["std_packet_size"] = grouped["frame_len_num"].std()
    output["max_packet_size"] = grouped["frame_len_num"].max()
    output["min_packet_size"] = grouped["frame_len_num"].min()

    # ---------------------------------------------------------
    # Packet timing behavior
    # ---------------------------------------------------------

    # IAT = inter-arrival time between packets.
    # These values describe how regularly packets arrive.
    output["mean_iat"] = grouped["iat_num"].mean()
    output["std_iat"] = grouped["iat_num"].std()
    output["max_iat"] = grouped["iat_num"].max()

    # ---------------------------------------------------------
    # TCP flag behavior
    # ---------------------------------------------------------

    # Count each TCP flag in the window and normalize the count
    # into a per-second rate.
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
    # Application / protocol behavior
    # ---------------------------------------------------------

    # These metrics describe how much application-specific traffic
    # occurs inside each window.
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
    # Communication diversity / fan-out
    # ---------------------------------------------------------

    # Unique counts help describe who the workload communicates
    # with and how many different ports or protocols are involved.
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
    # Restore windows where no packets were observed
    # ---------------------------------------------------------

    # groupby() only creates windows containing at least one packet.
    # For baseline analysis, true inactivity is meaningful behavior,
    # so missing time intervals must also exist in the processed data.
    start_window = int(output.index.min())
    end_window = int(output.index.max())

    all_windows = np.arange(
        start_window,
        end_window + window_seconds,
        window_seconds
    )

    # Insert rows for any completely idle windows.
    output = output.reindex(all_windows)
    output.index.name = "window_start"

    # Count and rate metrics genuinely equal zero when no traffic exists.
    #
    # Packet-size and IAT statistics are intentionally NOT included here.
    # If no packets exist, there is no meaningful average packet size or
    # inter-arrival time, so those values should remain NaN.
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

    # Restore window_start as a normal dataframe column.
    output = output.reset_index()

    # Add a readable UTC timestamp in addition to the Unix timestamp.
    # This is useful when inspecting the processed CSV manually.
    output["datetime_utc"] = pd.to_datetime(
        output["window_start"],
        unit="s",
        utc=True
    )

    # Place the human-readable datetime near the start of the CSV.
    columns = list(output.columns)
    columns.remove("datetime_utc")
    columns.insert(1, "datetime_utc")
    output = output[columns]

    # Create the destination directory if it does not already exist.
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    # Save the processed time-series features.
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
    """
    Parse command-line arguments and start the aggregation process.
    """

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