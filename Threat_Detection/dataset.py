"""Read the KUBEDATA captures: name every stratum, load packet columns, check the timebase.

A pod capture, a node capture and a router capture are different measurements of
the same traffic, so each one keeps its own scenario, level, label and method.
"""
from pathlib import Path

import pandas as pd

from detector import PACKET_COLUMNS

LEVELS = ("pod", "node", "router")
METHODS = ("ptcp", "tcp")  # ptcp first: "pod-nginx-ptcp.csv" also ends with "-tcp.csv"
MAX_CAPTURE_SPAN_S = 600.0


def parse_capture(path):
    """Return (label, method) for a processed CSV name such as pod-nginx-tcp.csv."""
    stem = Path(path).stem
    for method in METHODS:
        if stem.endswith("-" + method):
            return stem[: -len(method) - 1], method
    raise ValueError(f"Unrecognised capture file: {path}")


def level_from_label(label):
    """Map a capture label to its observation level: pod, node, or router."""
    for level in LEVELS:
        if label.startswith(level + "-"):
            return level
    raise ValueError(f"Unrecognised capture label: {label}")


def load_capture(path):
    """Read only the packet columns the detector uses, so mixed-type text columns stay out."""
    return pd.read_csv(path, usecols=PACKET_COLUMNS, low_memory=False)


def timebase_issues(packets, gap_limit=MAX_CAPTURE_SPAN_S):
    """Report timestamps that would corrupt 1-second binning."""
    ts = pd.to_numeric(packets["ts"], errors="coerce")
    span = float(ts.max() - ts.min()) if len(ts) else 0.0
    issues = {
        "rows": int(len(ts)),
        "bad_ts": int((ts.isna() | ts.le(0)).sum()),
        "span_s": round(span, 3),
    }
    issues["usable"] = issues["bad_ts"] == 0 and 0.0 < issues["span_s"] <= gap_limit
    return issues


def build_manifest(root):
    """One row per processed CSV under <root>/<scenario>/csv files/**."""
    root = Path(root)
    rows = []
    for path in sorted(root.glob("*/csv files/**/*.csv")):
        label, method = parse_capture(path)
        rows.append({
            "scenario": path.relative_to(root).parts[0],
            "level": level_from_label(label),
            "label": label,
            "method": method,
            "path": str(path),
        })
    manifest_frame = (pd.DataFrame(rows)
                      .sort_values(["scenario", "method", "level", "label"])
                      .reset_index(drop=True))
    if manifest_frame.empty:
        raise ValueError(f"No processed CSVs found under {root}")
    if manifest_frame.duplicated(["scenario", "label", "method"]).any():
        raise ValueError("Duplicate scenario/label/method captures in the manifest")
    return manifest_frame


def describe_captures(manifest_frame):
    """Add packet count, capture span and timebase usability to every manifest row."""
    described = manifest_frame.copy()
    for column in ("rows", "bad_ts", "span_s", "usable"):
        described[column] = pd.NA
    for index, path in described["path"].items():
        issues = timebase_issues(load_capture(path))
        for column, value in issues.items():
            described.at[index, column] = value
    return described
