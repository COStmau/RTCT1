"""Packets in, one row per second out. Stateless: no baseline, no thresholds, no detection.

`make_windows` is the only thing that reads packet rows. It knows the window size and the
feature set, and nothing about what counts as an anomaly.
"""
import numpy as np
import pandas as pd

import core.evaluation as evaluation
from core.data_io import load_capture, timebase_issues

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
    "payload_bytes": ("Payload bytes", "bytes/window"),
    "http_count": ("HTTP packets", "packets/window"),
    "dns_count": ("DNS packets", "packets/window"),
    "https_count": ("HTTPS packets", "packets/window"),
    "http_frac": ("HTTP share of packets", "fraction"),
}

# What the detectors read. make_windows still computes all 13 measurements, because the
# ablations, the feature ranking and the reporting read the whole table; a detector built with
# its default uses only these nine. They are the eight measurements that do not move with load
# (destination diversity, TCP flags, protocol mix) plus packet_count, which was put back
# because without a volume term injection attacks lose ranking. The reasoning and the numbers
# are in PROGRESS.md ("Eight-feature set", "Hybrid feature set"); a test keeps this list equal
# to the candidate verdicts/feature_set_hybrid.py judged.
DETECTION_FEATURES = ("packet_count", "unique_dst_ips", "unique_dst_ports", "syn_count",
                      "rst_count", "http_count", "dns_count", "https_count", "http_frac")

# Groups used by the ablation. Every feature label belongs to exactly one group.
FEATURE_GROUPS = {
    "volume": ["packet_count", "total_bytes", "payload_bytes"],
    "size_timing": ["mean_packet_size", "mean_iat"],
    "diversity": ["unique_dst_ips", "unique_dst_ports"],
    "flags": ["syn_count", "rst_count"],
    "protocol": ["http_count", "dns_count", "https_count", "http_frac"],
}

# Packet columns this pipeline reads are named once, in data_io.PACKET_COLUMNS: tcp_payload_len
# and udp_length are the encapsulation-free volume, because frame_len is inflated by a different
# overlay overhead at every vantage, so total_bytes is not comparable between pod, node and router.

# Columns the aggregator cannot do without, regardless of which features are asked for. A subset
# of data_io.PACKET_REQUIRED: that one is the load-time gate, this one is what a window needs.
WINDOW_COLUMNS = {"ts", "frame_len", "iat", "dst_ip", "dst_port"}

BENIGN_TRAIN_FRACTION = evaluation.TRAIN_FRACTION


def make_windows(packets, window_size=WINDOW_SIZE):
    """Summarize every window between the first and last observed packets.

    Assume the capture was continuous. Empty windows have zero counts, but packet-size and
    interarrival averages are undefined without packets -- NaN, never zero, so the detection
    layer can report them as insufficient_data rather than normal.
    """
    missing = WINDOW_COLUMNS - set(packets.columns)
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
    # Payload volume, summing the two length columns that are present. Absent columns count
    # as zero rather than being invented, and NaN in one column is skipped by the sum.
    payload_columns = [c for c in ("tcp_payload_len", "udp_length") if c in frame.columns]
    if payload_columns:
        # Per-column group sums added together, not a single grouped axis-sum: GroupBy.sum
        # takes no axis. min_count=1 keeps an all-NaN window as NaN rather than 0.0.
        payload = sum(grouped[c].sum(min_count=1) for c in payload_columns)
        windows["payload_bytes"] = payload
    for column, feature in (("is_http", "http_count"), ("is_dns", "dns_count"),
                            ("is_https", "https_count")):
        if column in frame.columns:
            windows[feature] = grouped[column].sum()
    # Protocol mix as a fraction of the window's packets. A ratio, not a count: the share
    # is comparable between a quiet pod and a busy router, the count is not.
    for count_feature, frac_feature in (("http_count", "http_frac"),):
        if count_feature in windows.columns:
            windows[frac_feature] = windows[count_feature] / windows["packet_count"]

    # Seconds between two packets with no traffic still count, as zeros.
    windows = windows.reindex(range(int(frame["time_bin"].max()) + 1))
    counts = windows.columns.difference(["mean_packet_size", "mean_iat"])
    windows[counts] = windows[counts].fillna(0)
    return windows


def load_all_windows(manifest):
    """Window every capture in the manifest. Key is (scenario, label, method).

    An unusable capture comes back as None plus a stated reason, so nothing disappears
    quietly: callers keep the row and print the reason. This lives here rather than in
    data_io because it is the seam between the two -- data_io knows the CSV format, this
    knows the window shape, and data_io must not have to know what a window is.
    """
    windows, notes = {}, {}
    for _, capture in manifest.iterrows():
        key = (capture["scenario"], capture["label"], capture["method"])
        packets = load_capture(capture["path"])
        issues = timebase_issues(packets)
        if not issues["usable"]:
            windows[key] = None
            notes[key] = (f"excluded: {issues['bad_ts']} bad timestamps of {issues['rows']} rows,"
                          f" span {issues['span_s']}s")
            continue
        windows[key] = make_windows(packets)
    return windows, notes


def split_reference(windows, train_fraction=BENIGN_TRAIN_FRACTION):
    """First `train_fraction` of the benign windows fit the reference; the rest are held out.

    The split is temporal, never random: a random split would put the same second on both
    sides and let the detector be graded on what it learned.
    """
    split = int(len(windows) * train_fraction)
    if split < 2 or split >= len(windows):
        raise ValueError("Insufficient benign windows for a matched reference")
    return windows.iloc[:split], windows.iloc[split:]