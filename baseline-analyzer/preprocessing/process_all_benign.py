"""
process_all_benign.py

Batch-process benign network CSV files for the Baseline Analyzer.

For every matching raw CSV, this script:

1. Converts packet-level data into fixed-duration feature windows.
2. Builds a frozen benign baseline.
3. Performs held-out benign validation.
4. Saves a manifest showing which datasets succeeded or failed.

This removes the need to manually preprocess and train a baseline for
each individual Kubernetes workload.
"""

import argparse
from pathlib import Path

import pandas as pd

# Reuse the functions that already exist in this project.
from aggregate_benign_1s import aggregate_benign
from build_baseline import build_baseline


CAPTURE_SUFFIXES = ("-tcp", "-ptcp")


def infer_source(file_path, strip_capture_suffix=False):
    """
    Determine the source label from the input filename.

    Examples:

        pod-nginx-tcp.csv

    normally becomes:

        pod-nginx-tcp

    If --strip-capture-suffix is used, it becomes:

        pod-nginx

    Stripping the suffix is useful for the current TCP-only dashboards.
    Do not strip it if both TCP and PTCP versions of the same workload
    are being processed together, because they would have the same name.
    """

    source = file_path.stem

    if strip_capture_suffix:
        for suffix in CAPTURE_SUFFIXES:
            if source.endswith(suffix):
                source = source[:-len(suffix)]
                break

    return source


def find_raw_files(raw_dir, pattern):
    """
    Find all matching CSV files under the raw-data directory.

    rglob() searches recursively, so files can eventually be organized
    into subdirectories such as pod/, node/, router/, tcp/, etc.
    """

    raw_dir = Path(raw_dir)

    if not raw_dir.exists():
        raise FileNotFoundError(
            f"Raw data directory does not exist: {raw_dir}"
        )

    return sorted(
        path
        for path in raw_dir.rglob(pattern)
        if path.is_file() and path.suffix.lower() == ".csv"
    )


def check_for_source_collisions(files, strip_capture_suffix):
    """
    Make sure two datasets will not accidentally create the same
    baseline filename.

    This is especially important if both TCP and PTCP files exist.
    """

    source_files = {}

    for file_path in files:
        source = infer_source(
            file_path,
            strip_capture_suffix
        )

        source_files.setdefault(
            source,
            []
        ).append(file_path)

    duplicates = {
        source: paths
        for source, paths in source_files.items()
        if len(paths) > 1
    }

    if duplicates:
        print("\nSource-name collision detected:")

        for source, paths in duplicates.items():
            print(f"\n{source}")

            for path in paths:
                print(f"  {path}")

        raise ValueError(
            "\nMultiple files would create the same baseline. "
            "Do not use --strip-capture-suffix when processing "
            "TCP and PTCP files together."
        )


def process_file(
    raw_file,
    processed_dir,
    baseline_dir,
    window_seconds,
    train_fraction,
    threshold,
    strip_capture_suffix,
):
    """
    Run the complete preprocessing + baseline pipeline for one CSV.
    """

    source = infer_source(
        raw_file,
        strip_capture_suffix
    )

    # Example:
    #
    # pod-camera-tcp.csv
    #       ->
    # pod-camera-tcp-5s.csv
    processed_file = (
        Path(processed_dir)
        / f"{raw_file.stem}-{window_seconds}s.csv"
    )

    print()
    print("=" * 70)
    print(f"Processing: {raw_file.name}")
    print(f"Source:     {source}")
    print("=" * 70)

    # ---------------------------------------------------------
    # Step 1: Packet-level CSV -> fixed-window feature CSV
    # ---------------------------------------------------------

    aggregate_benign(
        input_file=raw_file,
        output_file=processed_file,
        window_seconds=window_seconds
    )

    # ---------------------------------------------------------
    # Step 2: Processed features -> frozen benign baseline
    # ---------------------------------------------------------

    build_baseline(
        input_file=processed_file,
        source=source,
        output_dir=baseline_dir,
        train_fraction=train_fraction,
        threshold=threshold
    )

    baseline_file = (
        Path(baseline_dir)
        / f"{source}_baseline_stats.csv"
    )

    validation_file = (
        Path(baseline_dir)
        / f"{source}_heldout_validation.csv"
    )

    # Information returned here will be written to the batch manifest.
    return {
        "raw_file": str(raw_file),
        "source": source,
        "processed_file": str(processed_file),
        "baseline_file": str(baseline_file),
        "validation_file": str(validation_file),
        "status": "success",
        "error": "",
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Process multiple benign packet CSVs and build "
            "a frozen baseline for each source."
        )
    )

    parser.add_argument(
        "--raw-dir",
        default=r".\data\raw",
        help="Directory containing raw benign CSV files"
    )

    parser.add_argument(
        "--processed-dir",
        default=r".\data\processed",
        help="Directory for processed feature CSV files"
    )

    parser.add_argument(
        "--baseline-dir",
        default=r".\data\baseline",
        help="Directory for frozen baseline files"
    )

    parser.add_argument(
        "--pattern",
        default="*.csv",
        help=(
            "Filename pattern to process. "
            'Examples: "*.csv", "*-tcp.csv", "pod-*.csv"'
        )
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Aggregation window in seconds (default: 5)"
    )

    parser.add_argument(
        "--train-fraction",
        type=float,
        default=0.70,
        help="Fraction of windows used for baseline training"
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=3.0,
        help="Absolute z-score threshold (default: 3)"
    )

    parser.add_argument(
        "--strip-capture-suffix",
        action="store_true",
        help=(
            "Remove -tcp or -ptcp from the source label. "
            "Example: pod-nginx-tcp -> pod-nginx"
        )
    )

    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop immediately if one dataset fails"
    )

    args = parser.parse_args()

    # Basic argument validation.
    if args.window <= 0:
        raise ValueError(
            "Window size must be greater than zero."
        )

    if not 0 < args.train_fraction < 1:
        raise ValueError(
            "train-fraction must be between 0 and 1."
        )

    processed_dir = Path(args.processed_dir)
    baseline_dir = Path(args.baseline_dir)

    processed_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    baseline_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    # ---------------------------------------------------------
    # Discover all datasets that should be processed
    # ---------------------------------------------------------

    raw_files = find_raw_files(
        raw_dir=args.raw_dir,
        pattern=args.pattern
    )

    if not raw_files:
        print(
            f'No files matching "{args.pattern}" '
            f"were found in {args.raw_dir}"
        )
        return

    print(
        f"Found {len(raw_files)} raw benign CSV file(s)."
    )

    # Check source names before writing anything.
    check_for_source_collisions(
        raw_files,
        args.strip_capture_suffix
    )

    results = []

    # ---------------------------------------------------------
    # Process each benign dataset
    # ---------------------------------------------------------

    for raw_file in raw_files:

        try:
            result = process_file(
                raw_file=raw_file,
                processed_dir=processed_dir,
                baseline_dir=baseline_dir,
                window_seconds=args.window,
                train_fraction=args.train_fraction,
                threshold=args.threshold,
                strip_capture_suffix=args.strip_capture_suffix,
            )

            results.append(result)

        except Exception as error:

            source = infer_source(
                raw_file,
                args.strip_capture_suffix
            )

            print()
            print(
                f"ERROR processing {raw_file.name}: "
                f"{error}"
            )

            # Record the failure without losing the results from
            # datasets that were already processed successfully.
            results.append({
                "raw_file": str(raw_file),
                "source": source,
                "processed_file": "",
                "baseline_file": "",
                "validation_file": "",
                "status": "failed",
                "error": str(error),
            })

            if args.stop_on_error:
                break

    # ---------------------------------------------------------
    # Save a record of the complete batch run
    # ---------------------------------------------------------

    results_df = pd.DataFrame(results)

    manifest_file = (
        baseline_dir
        / "batch_manifest.csv"
    )

    results_df.to_csv(
        manifest_file,
        index=False
    )

    success_count = int(
        (results_df["status"] == "success").sum()
    )

    failed_count = int(
        (results_df["status"] == "failed").sum()
    )

    print()
    print("=" * 70)
    print("Batch processing complete")
    print("=" * 70)

    print(f"Successful datasets: {success_count}")
    print(f"Failed datasets:     {failed_count}")
    print(f"Manifest:            {manifest_file}")

    if failed_count > 0:

        print()
        print("Failed datasets:")

        print(
            results_df.loc[
                results_df["status"] == "failed",
                ["raw_file", "error"]
            ].to_string(index=False)
        )


if __name__ == "__main__":
    main()