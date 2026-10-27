"""
build_baseline.py

Train a frozen statistical baseline from known-benign network traffic.

The processed dataset is divided chronologically into:
    1. Training data
    2. Held-out benign validation data

Only the training portion is used to calculate the baseline mean and
standard deviation. These statistics are then frozen and used to score
the held-out data with z-scores.

This prevents future observations from changing the definition of
"normal" while they are being evaluated.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


# Primary features currently used to describe benign behavior.
#
# packets_per_second:
#     Traffic frequency / volume.
#
# mean_packet_size:
#     Structure and typical size of network packets.
#
# unique_dst_ports:
#     Communication diversity across destination services.
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
    """
    Build a frozen baseline and validate it using held-out benign data.

    Parameters
    ----------
    input_file:
        Processed time-window CSV, normally using 5-second windows.

    source:
        Name of the monitored workload, such as pod-nginx or pod-camera.

    output_dir:
        Directory where baseline and validation CSVs will be saved.

    train_fraction:
        Fraction of the dataset used to train the frozen baseline.

    threshold:
        Absolute z-score required for an observation to be flagged.
    """

    # Load previously aggregated benign feature windows.
    df = pd.read_csv(input_file)

    # The baseline cannot be calculated if one of the required
    # primary features is missing.
    missing = [
        feature
        for feature in FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Keep the original chronological ordering.
    #
    # This is important because we want the validation set to represent
    # later observations rather than randomly mixing past and future data.
    if "window_start" in df.columns:
        df = df.sort_values("window_start").reset_index(drop=True)
    else:
        df = df.reset_index(drop=True)

    total_rows = len(df)

    # A minimum amount of data is required so both the training
    # and validation portions contain observations.
    if total_rows < 4:
        raise ValueError(
            "Not enough rows to create training and held-out sets."
        )

    # Determine where the chronological training period ends.
    split_index = int(total_rows * train_fraction)

    if split_index <= 0 or split_index >= total_rows:
        raise ValueError(
            "Training split leaves no data for one of the sets."
        )

    # Earlier observations train the model.
    train_df = df.iloc[:split_index].copy()

    # Later observations are not used during training.
    # They are reserved for benign validation.
    test_df = df.iloc[split_index:].copy()

    print(f"\nSource: {source}")
    print(f"Total windows: {total_rows}")
    print(f"Training windows: {len(train_df)}")
    print(f"Held-out windows: {len(test_df)}")
    print(f"Threshold: |z| >= {threshold}")
    print()

    # -----------------------------------------------------
    # Build the frozen benign baseline
    # -----------------------------------------------------

    # baseline_rows will eventually become the CSV that can
    # be loaded by the Prometheus replay exporter.
    baseline_rows = []

    # This dictionary keeps the trained statistics available
    # while scoring the held-out portion below.
    baseline = {}

    for feature in FEATURES:

        # Convert the selected training feature to numeric values.
        # Undefined values such as mean packet size during an idle
        # window are removed from the calculation.
        train_values = pd.to_numeric(
            train_df[feature],
            errors="coerce"
        ).dropna()

        # Mean represents the center of normal benign behavior.
        mean = train_values.mean()

        # Population standard deviation describes the normal
        # amount of variation in the training baseline.
        #
        # ddof=0 requests population standard deviation.
        std = train_values.std(ddof=0)

        baseline[feature] = {
            "mean": mean,
            "std": std,
        }

        # Store the frozen statistics for later use.
        baseline_rows.append({
            "source": source,
            "feature": feature,
            "mean": mean,
            "std_dev": std,

            # The baseline currently uses ±3 standard deviations.
            # Lower bounds are clamped at zero because the selected
            # network metrics cannot physically become negative.
            "lower_3sigma": max(
                0,
                mean - threshold * std
            ),

            "upper_3sigma": (
                mean + threshold * std
            ),

            # Record how many valid observations contributed to
            # the baseline for reproducibility.
            "training_samples": len(train_values),
        })

    baseline_df = pd.DataFrame(baseline_rows)

    # -----------------------------------------------------
    # Score held-out benign data
    # -----------------------------------------------------

    # The held-out section was not used to calculate the baseline.
    # It provides a preliminary test of whether future normal traffic
    # would be incorrectly identified as anomalous.
    validation = test_df.copy()

    z_columns = []

    for feature in FEATURES:

        # Retrieve the frozen training statistics.
        mean = baseline[feature]["mean"]
        std = baseline[feature]["std"]

        values = pd.to_numeric(
            validation[feature],
            errors="coerce"
        )

        z_column = f"{feature}_z"

        # Z-score:
        #
        #     current value - benign mean
        # z = ---------------------------
        #          benign std dev
        #
        # The score represents how many standard deviations the
        # observation is away from normal benign behavior.

        # A perfectly constant training feature has standard deviation 0.
        # Division by zero would make a normal z-score calculation invalid.
        if std == 0 or pd.isna(std):

            # If the observation is exactly equal to the constant
            # baseline value, the deviation is zero.
            #
            # Otherwise treat the deviation as infinitely large.
            validation[z_column] = np.where(
                values == mean,
                0.0,
                np.inf
            )

        else:
            validation[z_column] = (
                values - mean
            ) / std

        z_columns.append(z_column)

    # Use the most extreme feature as the overall deviation score.
    #
    # Example:
    # packets z-score      = 0.5
    # packet-size z-score  = 3.4
    # destination-port z   = 1.2
    #
    # max_abs_z = 3.4
    validation["max_abs_z"] = (
        validation[z_columns]
        .abs()
        .max(axis=1)
    )

    # Flag a window if at least one primary feature reaches
    # the configured z-score threshold.
    validation["flagged"] = (
        validation["max_abs_z"] >= threshold
    )

    flagged_count = int(
        validation["flagged"].sum()
    )

    test_count = len(validation)

    # Because this validation set contains benign traffic,
    # any flagged observation is treated as a false positive.
    false_positive_rate = (
        flagged_count / test_count * 100
        if test_count > 0
        else 0
    )

    # -----------------------------------------------------
    # Save results
    # -----------------------------------------------------

    output_path = Path(output_dir)

    # Create the baseline directory if necessary.
    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    baseline_file = (
        output_path
        / f"{source}_baseline_stats.csv"
    )

    validation_file = (
        output_path
        / f"{source}_heldout_validation.csv"
    )

    # Save the frozen statistics.
    baseline_df.to_csv(
        baseline_file,
        index=False
    )

    # Save the held-out observations and their z-scores.
    validation.to_csv(
        validation_file,
        index=False
    )

    # -----------------------------------------------------
    # Print a short summary for the user
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
    print(
        f"False positive rate: "
        f"{false_positive_rate:.2f}%"
    )

    print()
    print(f"Baseline saved to: {baseline_file}")
    print(f"Validation saved to: {validation_file}")


def main():
    """
    Parse command-line options and start baseline training.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Build a frozen benign baseline and "
            "validate held-out benign data."
        )
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

    # Training fraction must leave some data for both training
    # and held-out validation.
    if not 0 < args.train_fraction < 1:
        raise ValueError(
            "train-fraction must be between 0 and 1."
        )

    build_baseline(
        input_file=args.input_file,
        source=args.source,
        output_dir=args.output_dir,
        train_fraction=args.train_fraction,
        threshold=args.threshold,
    )


if __name__ == "__main__":
    main()