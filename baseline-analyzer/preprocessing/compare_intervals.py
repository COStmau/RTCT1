import pandas as pd
import numpy as np

files = {
    "1s": r".\data\processed\pod-nginx-tcp-1s.csv",
    "5s": r".\data\processed\pod-nginx-tcp-5s.csv",
}

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

results = []

for window_name, file_path in files.items():
    df = pd.read_csv(file_path)

    for feature in features:
        if feature not in df.columns:
            continue

        series = pd.to_numeric(df[feature], errors="coerce").dropna()

        mean = series.mean()
        std = series.std()

        cv = std / mean if mean != 0 else np.nan
        zero_percent = (series == 0).mean() * 100

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

results_df = pd.DataFrame(results)

print(results_df.to_string(index=False))

results_df.to_csv(
    r".\data\processed\window_comparison.csv",
    index=False
)

print("\nSaved comparison to:")
print(r".\data\processed\window_comparison.csv")