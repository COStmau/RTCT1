"""
compare_intervals.py

Compare different time-window sizes used by the Baseline Analyzer.

The goal is to determine whether a smaller or larger aggregation
interval provides a more stable representation of normal network
behavior.

The current comparison evaluates 1-second and 5-second windows for
several network features.
"""

import pandas as pd
import numpy as np


# Processed datasets being compared.
#
# Both files contain the same general type of benign network
# observations, but they were aggregated using different window sizes.
files = {
    "1s": r".\data\processed\pod-nginx-tcp-1s.csv",
    "5s": r".\data\processed\pod-nginx-tcp-5s.csv",
}


# Candidate network features used to compare the two window sizes.
features = [
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size",
    "mean_iat",
    "tcp_syn_per_second",
    "tcp_rst_per_second",
    "unique_src_ips",
    "unique_dst_ports",
]


# Each feature/window comparison will be stored here before
# being converted into the final dataframe.
results = []


# Analyze each aggregation window independently.
for window_name, file_path in files.items():

    print(f"Reading {window_name} dataset: {file_path}")

    df = pd.read_csv(file_path)

    for feature in features:

        # Skip features that do not exist in the processed file.
        if feature not in df.columns:
            continue

        # Convert values to numeric form and ignore undefined entries.
        series = pd.to_numeric(
            df[feature],
            errors="coerce"
        ).dropna()

        # Basic descriptive statistics.
        mean = series.mean()
        std = series.std()

        # Coefficient of variation:
        #
        #           standard deviation
        # CV = -----------------------------
        #                 mean
        #
        # CV allows variability to be compared between features that
        # have very different numerical scales.
        #
        # A smaller CV generally indicates that the feature is more
        # stable relative to its average value.
        cv = (
            std / mean
            if mean != 0
            else np.nan
        )

        # Percentage of windows in which the feature was exactly zero.
        #
        # For traffic metrics this can help show how frequently the
        # chosen window size produces completely inactive observations.
        zero_percent = (
            (series == 0).mean() * 100
        )

        results.append({
            "window": window_name,
            "feature": feature,
            "mean": mean,
            "std_dev": std,
            "min": series.min(),
            "max": series.max(),
            "coefficient_of_variation": cv,
            "zero_percent": zero_percent,
        })


# Convert all comparison results into a table.
results_df = pd.DataFrame(results)


# Print the complete comparison for quick inspection in the terminal.
print()
print(results_df.to_string(index=False))


# Save the results so they can be reviewed later or included
# in documentation.
output_file = (
    r".\data\processed\window_comparison.csv"
)

results_df.to_csv(
    output_file,
    index=False
)


print("\nSaved comparison to:")
print(output_file)