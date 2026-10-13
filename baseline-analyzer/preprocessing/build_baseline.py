import argparse
from pathlib import Path

import numpy as np
import pandas as pd


FEATURES = [
    "packets_per_second",
    "mean_packet_size",
    "unique_dst_ports",
]

def build_baseline(
    input_file,
    source,
    output_dir,
    train_fraction=0.70,
    threshold=3.0,
):
    df = pd.read_csv(input_file)

    # Make sure required features exist
    missing = [feature for feature in FEATURES if feature not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Keep chronological order
    if "window_start" in df.columns:
        df = df.sort_values("window_start").reset_index(drop=True)
    else:
        df = df.reset_index(drop=True)

    total_rows = len(df)

    if total_rows < 4:
        raise ValueError("Not enough rows to create training and held-out sets.")

    split_index = int(total_rows * train_fraction)

    if split_index <= 0 or split_index >= total_rows:
        raise ValueError("Training split leaves no data for one of the sets.")

    train_df = df.iloc[:split_index].copy()
    test_df = df.iloc[split_index:].copy()

    print(f"\nSource: {source}")
    print(f"Total windows: {total_rows}")
    print(f"Training windows: {len(train_df)}")
    print(f"Held-out windows: {len(test_df)}")
    print(f"Threshold: |z| >= {threshold}")
    print()

    # -----------------------------------------------------
    # Build frozen baseline
    # -----------------------------------------------------

    baseline_rows = []

    baseline = {}

    for feature in FEATURES:
        train_values = pd.to_numeric(
            train_df[feature],
            errors="coerce"
        ).dropna()

        mean = train_values.mean()

        # Population standard deviation of training baseline
        std = train_values.std(ddof=0)

        baseline[feature] = {
            "mean": mean,
            "std": std,
        }

        baseline_rows.append({
            "source": source,
            "feature": feature,
            "mean": mean,
            "std_dev": std,
            "lower_3sigma": max(0, mean - threshold * std),
            "upper_3sigma": mean + threshold * std,
            "training_samples": len(train_values),
        })

    baseline_df = pd.DataFrame(baseline_rows)

    # -----------------------------------------------------
    # Score held-out benign data
    # -----------------------------------------------------

    validation = test_df.copy()

    z_columns = []

    for feature in FEATURES:
        mean = baseline[feature]["mean"]
        std = baseline[feature]["std"]

        values = pd.to_numeric(
            validation[feature],
            errors="coerce"
        )

        z_column = f"{feature}_z"

        # Prevent division by zero for perfectly constant features
        if std == 0 or pd.isna(std):
            validation[z_column] = np.where(
                values == mean,
                0.0,
                np.inf
            )
        else:
            validation[z_column] = (values - mean) / std

        z_columns.append(z_column)

    # Maximum absolute z-score across the three baseline features
    validation["max_abs_z"] = (
        validation[z_columns]
        .abs()
        .max(axis=1)
    )

    validation["flagged"] = (
        validation["max_abs_z"] >= threshold
    )

    flagged_count = int(validation["flagged"].sum())
    test_count = len(validation)

    false_positive_rate = (
        flagged_count / test_count * 100
        if test_count > 0
        else 0
    )

    # -----------------------------------------------------
    # Save results
    # -----------------------------------------------------

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    baseline_file = output_path / f"{source}_baseline_stats.csv"
    validation_file = output_path / f"{source}_heldout_validation.csv"

    baseline_df.to_csv(baseline_file, index=False)
    validation.to_csv(validation_file, index=False)

    # -----------------------------------------------------
    # Print summary
    # -----------------------------------------------------

    print("Frozen baseline:")
    print(
        baseline_df[
            [
                "feature",
                "mean",
                "std_dev",
                "lower_3sigma",
                "upper_3sigma"
            ]
        ].to_string(index=False)
    )

    print()
    print("Held-out benign validation:")
    print(f"Flagged: {flagged_count}/{test_count}")
    print(f"False positive rate: {false_positive_rate:.2f}%")

    print()
    print(f"Baseline saved to: {baseline_file}")
    print(f"Validation saved to: {validation_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Build a frozen benign baseline and validate held-out benign data."
    )

    parser.add_argument(
        "input_file",
        help="Processed 5-second benign CSV"
    )

    parser.add_argument(
        "--source",
        required=True,
        help='Source name such as "pod-nginx" or "pod-camera"'
    )

    parser.add_argument(
        "--output-dir",
        default=r".\data\baseline",
        help="Directory for baseline and validation results"
    )

    parser.add_argument(
        "--train-fraction",
        type=float,
        default=0.70,
        help="Fraction used for training (default: 0.70)"
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=3.0,
        help="Absolute z-score threshold (default: 3)"
    )

    args = parser.parse_args()

    if not 0 < args.train_fraction < 1:
        raise ValueError("train-fraction must be between 0 and 1.")

    build_baseline(
        input_file=args.input_file,
        source=args.source,
        output_dir=args.output_dir,
        train_fraction=args.train_fraction,
        threshold=args.threshold,
    )


if __name__ == "__main__":
    main()