#!/usr/bin/env python3
r"""Independent, read-only verification of frozen Subsystem 1 median/MAD baselines.

Run from the baseline-analyzer project root:
  python .\preprocessing\audit_robust_reproducibility.py .\data\baseline\batch_manifest.csv

Requires Python standard library only. Does not change any baseline files.
"""

import argparse
import csv
import math
from pathlib import Path
import statistics
import sys

FEATURES = (
    "packets_per_second", "bytes_per_second", "mean_packet_size", "mean_iat",
    "tcp_syn_per_second", "tcp_rst_per_second", "unique_src_ips", "unique_dst_ports",
)
NUMERIC_FIELDS = (
    "median", "mad", "std_dev", "scale", "lower_3scale", "upper_3scale",
)


def read_rows(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        return list(reader), reader.fieldnames or []


def to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def matches(expected, actual):
    if math.isnan(expected):
        return math.isnan(actual)
    return math.isfinite(actual) and math.isclose(
        expected, actual, rel_tol=1e-7, abs_tol=1e-9
    )


def independent_stats(raw_values):
    values = [to_float(v) for v in raw_values]
    values = [v for v in values if math.isfinite(v)]
    result = {key: float("nan") for key in NUMERIC_FIELDS}
    result["n_samples"] = len(values)
    result["scale_method"] = "insufficient_data"
    if len(values) < 2:
        return result

    median = statistics.median(values)
    mad = statistics.median([abs(x - median) for x in values])
    std_dev = statistics.stdev(values)  # Sample std. dev. (n-1 denominator)

    if mad > 0:
        scale, method = 1.4826 * mad, "scaled_mad"
    elif std_dev > 0:
        scale, method = std_dev, "std_fallback"
    else:
        scale, method = float("nan"), "zero_variance"

    result.update({
        "median": median, "mad": mad, "std_dev": std_dev,
        "scale": scale, "scale_method": method,
        # Match the actual frozen CSV computation (unclamped mathematical bound).
        "lower_3scale": median - 3.0 * scale,
        "upper_3scale": median + 3.0 * scale,
    })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--baseline-dir", type=Path, default=Path("data/baseline/robust"))
    args = parser.parse_args()

    if not args.manifest.is_file():
        parser.error(f"Manifest not found: {args.manifest}")
    manifest, headings = read_rows(args.manifest)
    file_key = "processed_file" if "processed_file" in headings else "path"
    if "source" not in headings or file_key not in headings:
        parser.error("Manifest must have source and path (or processed_file) columns")
    if "status" in headings:
        manifest = [r for r in manifest if r["status"].lower() == "success"]
    if not manifest:
        parser.error("No manifest sources")

    totals = {"pods": 0, "features": 0, "passed": 0, "failed": 0}
    seen = set()
    for item in manifest:
        source = item["source"].strip()
        if not source or source in seen or any(x in source for x in "/\\"):
            parser.error(f"Duplicate/invalid source: {source!r}")
        seen.add(source)
        processed = Path(item[file_key])
        baseline = args.baseline_dir / f"{source}_baseline_stats.csv"
        if not processed.is_file() or not baseline.is_file():
            print(f"FAIL {source}: missing input: {processed} or {baseline}")
            totals["failed"] += 1
            continue

        data, data_columns = read_rows(processed)
        stats_rows, baseline_columns = read_rows(baseline)
        if "window_start" in data_columns:
            data.sort(key=lambda r: to_float(r["window_start"]))
        stats = {r.get("feature", ""): r for r in stats_rows}
        missing = [f for f in FEATURES if f not in data_columns or f not in stats]
        required_stats = set(NUMERIC_FIELDS) | {"n_samples", "train_rows", "rows_total", "scale_method"}
        if missing or not required_stats.issubset(baseline_columns):
            print(f"FAIL {source}: missing features {missing} or baseline columns")
            totals["failed"] += 1
            continue

        totals["pods"] += 1
        pod_fails = []
        for feature in FEATURES:
            record = stats[feature]
            try:
                count = int(record["train_rows"])
                original_total = int(record["rows_total"])
            except (ValueError, TypeError):
                pod_fails.append(f"{feature}: invalid row-count metadata")
                continue
            if not (2 <= count <= len(data)) or original_total != len(data):
                pod_fails.append(f"{feature}: incorrect train_rows / rows_total")
                continue

            expected = independent_stats([r[feature] for r in data[:count]])
            errors = []
            if record["scale_method"] != expected["scale_method"]:
                errors.append("scale_method")
            if to_float(record["n_samples"]) != expected["n_samples"]:
                errors.append("n_samples")
            for field in NUMERIC_FIELDS:
                if not matches(expected[field], to_float(record.get(field))):
                    errors.append(field)
            totals["features"] += 1
            if errors:
                totals["failed"] += 1
                pod_fails.append(f"{feature}: mismatch in {', '.join(errors)}")
            else:
                totals["passed"] += 1
        if pod_fails:
            print(f"FAIL {source}")
            for fail in pod_fails:
                print(f"  - {fail}")
        else:
            print(f"PASS {source}: all 8 features reproduced")

    print(f"\nSummary: {totals['passed']}/{totals['features']} checked features matched; "
          f"{totals['pods']} source(s) evaluated; "
          f"{totals['failed']} feature/input error(s)")
    print("Read-only check: original processed CSVs and frozen baselines were not modified.")
    print("Note: this checks mathematical reproducibility, not benign representativeness.")
    return 1 if totals["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
