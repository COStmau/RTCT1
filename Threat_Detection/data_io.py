"""Read and write everything the pipeline touches. Knows file formats, nothing else.

Three jobs:
  load_capture(path)    one packet CSV -> a frame with the columns the features need
  load_manifest(...)    the list of captures, from cache or built fresh from the dataset root
  resolve_output(name)  a path inside outputs/, next to this module no matter the cwd

Nothing here reads local_paths. Callers pass an explicit dataset root; entry-point scripts
resolve that from local_paths, so this module imports on any machine.
"""
from pathlib import Path

import pandas as pd

# The packet columns the feature layer reads, one row per packet. This describes the input
# format, so it lives here rather than in a detector. The CSVs carry 34 fields; these are
# the ones turned into features. Order matters only for readability.
PACKET_COLUMNS = ["ts", "iat", "frame_len", "dst_ip", "dst_port", "tcp_syn", "tcp_rst",
                  "tcp_payload_len", "udp_length", "is_http", "is_dns", "is_https"]

# The subset without which a capture cannot be windowed at all. Everything else in
# PACKET_COLUMNS enriches the features but is not needed to produce a window.
PACKET_REQUIRED = ["ts", "iat", "frame_len", "dst_ip", "dst_port", "tcp_syn", "tcp_rst"]

# Capture names end in the method, so ptcp is tried first: "pod-nginx-ptcp.csv" also ends "-tcp.csv".
METHODS = ("ptcp", "tcp")
LEVELS = ("pod", "node", "router")
MAX_CAPTURE_SPAN_S = 600.0

MANIFEST_NAME = "capture_manifest.csv"

# Every generated file lands here, next to this module. Anchored to __file__ so a run started
# from any directory still writes into Threat_Detection/outputs/.
OUTPUT_DIR = Path(__file__).resolve().parent / "outputs"


def resolve_output(name=None):
    """Path inside outputs/. A name carrying a folder is used as given."""
    if name is None:
        name = MANIFEST_NAME
    path = Path(name)
    if path.parent != Path("."):
        return path
    OUTPUT_DIR.mkdir(exist_ok=True)
    return OUTPUT_DIR / path


def normalize_columns(frame):
    """One header convention for every reader: trimmed, lowercase, spaces to underscores."""
    frame.columns = frame.columns.str.strip().str.lower().str.replace(" ", "_")
    return frame


def load_capture(path):
    """Read one capture's packet columns.

    The header is read first and normalized, so a synced capture whose columns arrive as
    'Dst IP' or 'Frame Len' works here and in the demo path alike. Only the needed columns
    are kept, so mixed-type text columns never reach the feature layer.

    PACKET_REQUIRED must be present or the capture is unreadable. The optional columns are
    read when the file has them and simply left out when it does not, so a capture without
    payload or app-protocol fields still loads -- it just yields fewer features, which is
    a narrower measurement rather than a wrong one.
    """
    written = list(pd.read_csv(path, nrows=0, low_memory=False).columns)
    # usecols matches the header as written, so map each needed column back to its original
    # spelling. normalize_columns edits in place, so snapshot the raw names first.
    original = dict(zip(normalize_columns(pd.DataFrame(columns=written)).columns, written))
    missing = [column for column in PACKET_REQUIRED if column not in original]
    if missing:
        raise ValueError(f"Missing packet columns: {', '.join(missing)}")
    present = [column for column in PACKET_COLUMNS if column in original]
    frame = pd.read_csv(path, usecols=[original[c] for c in present], low_memory=False)
    return normalize_columns(frame)[present]


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


def build_manifest(root):
    """One row per processed CSV under <root>/<scenario>/csv files/**.

    pathlib's ** matches zero directories, so this covers the flat `injection attack`
    layout and the nested <method>/<vantage> one in a single pattern.
    """
    root = Path(root)
    rows = []
    for path in sorted(root.glob("*/csv files/**/*.csv")):
        label, method = parse_capture(path)
        rows.append({"scenario": path.relative_to(root).parts[0],
                     "level": level_from_label(label),
                     "label": label, "method": method, "path": str(path)})
    manifest = pd.DataFrame(rows).sort_values(["scenario", "method", "level", "label"])
    manifest = manifest.reset_index(drop=True)
    if manifest.empty:
        raise ValueError(f"No processed CSVs found under {root}")
    if manifest.duplicated(["scenario", "label", "method"]).any():
        raise ValueError("Duplicate scenario/label/method captures in the manifest")
    return manifest


SNAPLEN_CEILINGS = (65535, 65549, 65555)   # tcpdump default 65535 + eth header/FCS variants
SNAPLEN_REPORT_AT = 0.01                   # >=1% of packets at the wall counts as truncated


def timebase_issues(packets, gap_limit=MAX_CAPTURE_SPAN_S):
    """Report timestamps that would corrupt 1-second binning, and snaplen saturation.

    A capture truncated by the capture snaplen is still usable -- the packets are real --
    but its size features are clipped, so the fraction at the ceiling is reported and the
    reader decides. Silently scoring clipped lengths as if they were measured is what
    makes a truncated vantage look like a false-alarming one.
    """
    ts = pd.to_numeric(packets["ts"], errors="coerce")
    span = float(ts.max() - ts.min()) if len(ts) else 0.0
    frame_len = pd.to_numeric(packets.get("frame_len", pd.Series(dtype=float)), errors="coerce")
    issues = {"rows": int(len(ts)),
              "bad_ts": int((ts.isna() | ts.le(0)).sum()),
              "span_s": round(span, 3),
              "at_snaplen": round(float(frame_len.isin(SNAPLEN_CEILINGS).mean()), 4) if len(frame_len) else 0.0}
    issues["usable"] = issues["bad_ts"] == 0 and 0.0 < issues["span_s"] <= gap_limit
    return issues


def describe_captures(manifest):
    """Add packet count, capture span, timebase usability and snaplen saturation to every row."""
    described = manifest.copy()
    for column in ("rows", "bad_ts", "span_s", "at_snaplen", "usable"):
        described[column] = pd.NA
    for index, path in described["path"].items():
        for column, value in timebase_issues(load_capture(path)).items():
            described.at[index, column] = value
    return described


def load_manifest(dataset_root=None, name=None, rebuild=False):
    """The capture inventory: outputs/<name>.csv when it exists, else built from the root.

    A cached manifest is a hazard. Delete it or pass rebuild=True after the dataset changes,
    or the run scores a stale inventory.
    """
    path = resolve_output(name or MANIFEST_NAME)
    if path.exists() and not rebuild:
        return pd.read_csv(path)
    if not dataset_root:
        raise ValueError("No cached manifest and no dataset_root to build one from.")
    return describe_captures(build_manifest(dataset_root))