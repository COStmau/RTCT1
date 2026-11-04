#!/usr/bin/env python3
r"""Train per-source frozen median/MAD baselines from processed benign CSVs.

Run from the baseline-analyzer repository root:
    python .\preprocessing\build_robust_baselines.py .\data\baseline\batch_manifest.csv --train-fraction 0.7

Writes data/baseline/robust/<source>_baseline_stats.csv without replacing
legacy mean/std-dev baseline files. Only the *training portion* of each benign
capture is used. This tool does NOT replay or score attack data.
"""

import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd


FEATURES = (
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size",
    "mean_iat",
    "tcp_syn_per_second",
    "tcp_rst_per_second",
    "unique_src_ips",
    "unique_dst_ports",
)
MAD_NORMAL_SCALE = 1.4826
THRESHOLD_MULTIPLIER = 3.0


def fit_feature(raw_series: pd.Series, train_rows: int, total_rows: int, feature: str) -> dict:
    """Compute median and MAD, using sample std dev when MAD == 0.

    A constant training feature has MAD=0 and std_dev=0. It cannot support a
    standardized score, so scale/bounds are NaN and method=zero_variance.
    Missing and nonfinite numeric values are excluded before fitting.
    """
    series = pd.to_numeric(raw_series, errors="coerce")
    values = series.to_numpy(dtype=float)
    values = values[np.isfinite(values)]
    n = int(values.size)
    result = {
        "feature": feature,
        "median": float("nan"),
        "mad": float("nan"),
        "std_dev": float("nan"),
        "scale": float("nan"),
        "scale_method": "insufficient_data",
        "lower_3scale": float("nan"),
        "upper_3scale": float("nan"),
        "n_samples": n,
        "train_rows": train_rows,
        "rows_total": total_rows,
    }
    if n < 2:
        # Not enough samples for a defensible fallback sample standard deviation.
        return result

    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    std_dev = float(np.std(values, ddof=1))  # sample std deviation for fallback
    if mad > 0.0:
        scale = MAD_NORMAL_SCALE * mad
        method = "scaled_mad"
    elif std_dev > 0.0:
        scale = std_dev
        method = "std_fallback"
    else:
        scale = float("nan")
        method = "zero_variance"

    result.update({
        "median": median,
        "mad": mad,
        "std_dev": std_dev,
        "scale": scale,
        "scale_method": method,
        "lower_3scale": median - THRESHOLD_MULTIPLIER * scale,
        "upper_3scale": median + THRESHOLD_MULTIPLIER * scale,
    })
    return result


def main():
    parser = argparse.ArgumentParser(description="Train per-pod median/MAD baseline with std fallback")
    parser.add_argument("manifest", type=Path, help="Batch manifest (source,path,window_seconds)")
    parser.add_argument("--output-dir", type=Path, default=Path("data/baseline/robust"),
                        help="Separate directory for new robust baseline files")
    parser.add_argument("--train-fraction", type=float, default=0.7,
                        help="Fraction of windows used in chronological training (default: 0.7)")
    args = parser.parse_args()
    if not 0 < args.train_fraction <= 1:
        parser.error("--train-fraction must be in (0, 1]")
    manifest = pd.read_csv(args.manifest)
    if "source" not in manifest.columns:
        parser.error("Manifest must contain source column")
    col = "processed_file" if "processed_file" in manifest.columns else "path"
    if col not in manifest.columns:
        parser.error("Manifest must contain path or processed_file column")
    if "status" in manifest.columns:
        manifest = manifest[manifest["status"].astype(str).str.lower() == "success"]
    if manifest.empty:
        parser.error("No sources found in manifest")
    if manifest["source"].isna().any() or manifest["source"].duplicated().any():
        parser.error("All source labels must be nonblank and unique")

    # Validate source file paths before creating or updating baseline outputs.
    datasets = []
    for _, entry in manifest.iterrows():
        source = str(entry["source"]).strip()
        if not source or "/" in source or "\\" in source or source in (".", ".."):
            parser.error(f"Invalid source label: {source!r}")
        path = Path(str(entry[col]))
        if not path.is_file():
            parser.error(f"Processed CSV not found: {path} (source={source})")
        df = pd.read_csv(path)
        missing = [f for f in FEATURES if f not in df.columns]
        if missing:
            parser.error(f"{path} missing required features: {missing}")
        if len(df) < 2:
            parser.error(f"{path} needs at least 2 rows")
        if "window_start" in df.columns:
            df = df.sort_values("window_start", kind="stable").reset_index(drop=True)
        datasets.append((source, df))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for source, df in datasets:
        total = len(df)
        count = max(2, min(total, int(math.floor(total * args.train_fraction))))
        training = df.iloc[:count]
        statistics = [fit_feature(training[f], count, total, f) for f in FEATURES]
        out = args.output_dir / f"{source}_baseline_stats.csv"
        pd.DataFrame(statistics).to_csv(out, index=False)
        methods = pd.Series([s["scale_method"] for s in statistics]).value_counts().to_dict()
        print(f"{source}: {count}/{total} training windows -> {out}")
        print(f"  Scale methods: {methods}")
    print(f"Finished training robust baselines for {len(datasets)} source(s).")
    print("Original mean/std-dev baselines were NOT overwritten.")


if __name__ == "__main__":
    main()
