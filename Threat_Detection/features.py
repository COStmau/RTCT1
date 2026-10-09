"""Packets in, one row per second out. Stateless: no baseline, no thresholds, no detection.

`make_windows` is the only thing that reads packet rows. It knows the window size and the
feature set, and nothing about what counts as an anomaly.
"""
import numpy as np
import pandas as pd

from data_io import PACKET_COLUMNS  # noqa: F401  re-exported: callers ask features for the format

WINDOW_SIZE = 1.0

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

# Groups used by the ablation. Every feature label belongs to exactly one group.
FEATURE_GROUPS = {
    "volume": ["packet_count", "total_bytes"],
    "size_timing": ["mean_packet_size", "mean_iat"],
    "diversity": ["unique_dst_ips", "unique_dst_ports"],
    "flags": ["syn_count", "rst_count"],
}

# Columns the aggregator cannot do without, regardless of which features are asked for.
REQUIRED_COLUMNS = {"ts", "frame_len", "iat", "dst_ip", "dst_port"}

BENIGN_TRAIN_FRACTION = 0.7


def make_windows(packets, window_size=WINDOW_SIZE):
    """Summarize every window between the first and last observed packets.

    Assume the capture was continuous. Empty windows have zero counts, but packet-size and
    interarrival averages are undefined without packets -- NaN, never zero, so the detection
    layer can report them as insufficient_data rather than normal.
    """
    missing = REQUIRED_COLUMNS - set(packets.columns)
    if missing:
        raise ValueError(f"Missing packet columns: {', '.join(sorted(missing))}")
    if packets.empty:
        raise ValueError("No packets available to determine the capture interval.")
    if not np.isfinite(window_size) or window_size <= 0:
        raise ValueError("window_size must be positive and finite.")

    frame = packets.copy()
    for column in ("ts", "frame_len", "iat", "tcp_syn", "tcp_rst"):
        if column in frame.columns:
            frame[column] = pd.to_numeric(frame[column], errors="raise")
            if not np.isfinite(frame[column]).all():
                raise ValueError(f"Packet column {column} contains missing or nonfinite values.")

    frame["time_bin"] = ((frame["ts"] - frame["ts"].min()) // window_size).astype(int)
    grouped = frame.groupby("time_bin")
    windows = grouped.agg(
        packet_count=("ts", "count"),
        total_bytes=("frame_len", "sum"),
        mean_packet_size=("frame_len", "mean"),
        mean_iat=("iat", "mean"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
    )
    for flag, feature in (("tcp_syn", "syn_count"), ("tcp_rst", "rst_count")):
        if flag in frame.columns:
            windows[feature] = grouped[flag].sum()

    # Seconds between two packets with no traffic still count, as zeros.
    windows = windows.reindex(range(int(frame["time_bin"].max()) + 1))
    counts = windows.columns.difference(["mean_packet_size", "mean_iat"])
    windows[counts] = windows[counts].fillna(0)
    return windows


def split_reference(windows, train_fraction=BENIGN_TRAIN_FRACTION):
    """First `train_fraction` of the benign windows fit the reference; the rest are held out.

    The split is temporal, never random: a random split would put the same second on both
    sides and let the detector be graded on what it learned.
    """
    split = int(len(windows) * train_fraction)
    if split < 2 or split >= len(windows):
        raise ValueError("Insufficient benign windows for a matched reference")
    return windows.iloc[:split], windows.iloc[split:]