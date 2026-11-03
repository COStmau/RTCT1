#!/usr/bin/env python3
r"""Read-only benign baseline validation for ECEN403 Subsystem 1.

Requires the existing frozen robust baseline files produced by
build_robust_baselines.py (median, MAD, sample-std fallback). Never fits new
thresholds to held-out data, modifies baselines, or controls Kubernetes.

Run from baseline-analyzer root:
  python .\preprocessing\validate_benign_baselines.py .\data\baseline\batch_manifest.csv
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path

FEATURES = (
    "packets_per_second", "bytes_per_second", "mean_packet_size", "mean_iat",
    "tcp_syn_per_second", "tcp_rst_per_second", "unique_src_ips", "unique_dst_ports",
)
MULTIPLIERS = (2.0, 3.0, 4.0, 5.0)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, records: list[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def number(value) -> float:
    try:
        v = float(value)
    except (ValueError, TypeError):
        return math.nan
    return v if math.isfinite(v) else math.nan


def sort_windows(rows: list[dict]) -> list[dict]:
    # Match the stable window_start sort in build_robust_baselines.py.
    if rows and "window_start" in rows[0]:
        return sorted(rows, key=lambda r: (not math.isfinite(number(r.get("window_start"))),
                                           number(r.get("window_start")) if math.isfinite(number(r.get("window_start"))) else 0))
    return rows


def classify(value: float, median: float, scale: float, multiplier: float) -> str:
    if not (math.isfinite(value) and math.isfinite(median) and math.isfinite(scale) and scale > 0):
        return "unscorable"
    if value < 0:  # All eight selected traffic features should be nonnegative.
        return "invalid_negative"
    lower = max(0.0, median - multiplier * scale)
    upper = median + multiplier * scale
    return "high" if value > upper else "low" if value < lower else "normal"


def sequence_metrics(labels: list[str], required: int = 3) -> tuple[int, int, int]:
    """Count flagged windows, longest run, and new >=required streak episodes."""
    flagged = longest = streak = episodes = 0
    for label in labels:
        if label in ("high", "low"):
            flagged += 1
            streak += 1
            longest = max(longest, streak)
            if streak == required:
                episodes += 1
        else:
            streak = 0
    return flagged, longest, episodes


def first_window_flag(labels_by_feature: list[list[str]], i: int) -> str:
    values = [labels[i] for labels in labels_by_feature]
    if "high" in values or "low" in values:
        return "high"  # Generic 'outside' state for any-feature status.
    if "normal" in values:
        return "normal"
    return "unscorable"


def validate(manifest: Path, baseline_dir: Path, output_dir: Path) -> None:
    if not manifest.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest}")
    sources = read_csv(manifest)
    if not sources:
        raise ValueError("Manifest has no source rows")
    path_column = "processed_file" if "processed_file" in sources[0] else "path"
    if not {"source", path_column}.issubset(sources[0]):
        raise ValueError("Manifest must contain source and path/processed_file")
    if "status" in sources[0]:
        sources = [r for r in sources if r.get("status", "").lower() == "success"]
    if not sources:
        raise ValueError("No successful manifest sources")

    seen = set()
    summary = []
    source_summary = []
    trace = []
    warnings = []
    for entry in sources:
        source = entry.get("source", "").strip()
        if not source or source in seen or "/" in source or "\\" in source:
            raise ValueError(f"Blank, duplicate, or unsafe source: {source!r}")
        seen.add(source)
        source_file = Path(entry[path_column])
        if not source_file.exists():
            # Also handle a manifest with paths relative to its own directory.
            alternate = manifest.parent / source_file
            source_file = alternate if alternate.exists() else source_file
        base_file = baseline_dir / f"{source}_baseline_stats.csv"
        if not source_file.is_file():
            warnings.append(f"{source}: processed file missing ({source_file})")
            continue
        if not base_file.is_file():
            warnings.append(f"{source}: frozen robust baseline missing ({base_file})")
            continue
        rows = sort_windows(read_csv(source_file))
        stats = read_csv(base_file)
        if not rows or not stats:
            warnings.append(f"{source}: empty processed data or baseline")
            continue
        if not set(FEATURES).issubset(rows[0]):
            warnings.append(f"{source}: processed CSV missing one or more required features")
            continue
        baseline_by_metric = {r.get("feature", ""): r for r in stats}
        if not set(FEATURES).issubset(baseline_by_metric):
            warnings.append(f"{source}: frozen baseline missing one or more required features")
            continue
        train_count = int(number(stats[0].get("train_rows"))) if math.isfinite(number(stats[0].get("train_rows"))) else -1
        total = len(rows)
        if not 2 <= train_count <= total:
            warnings.append(f"{source}: invalid train_rows in baseline ({train_count})")
            continue
        if any(int(number(s.get("train_rows"))) != train_count for s in stats if math.isfinite(number(s.get("train_rows")))):
            warnings.append(f"{source}: inconsistent baseline train_rows; skipping")
            continue
        if any(math.isfinite(number(s.get("rows_total"))) and int(number(s.get("rows_total"))) != total for s in stats):
            warnings.append(f"{source}: baseline rows_total differs from processed CSV; skipping to avoid stale statistics")
            continue
        heldout = rows[train_count:]
        if len(heldout) < 10:
            warnings.append(f"{source}: only {len(heldout)} held-out windows; results are descriptive, NOT reliable FPR estimates")
        metrics_results = {}
        for feature in FEATURES:
            s = baseline_by_metric[feature]
            center, scale = number(s.get("median")), number(s.get("scale"))
            method = s.get("scale_method", "")
            valid_scale = method in ("scaled_mad", "std_fallback") and math.isfinite(center) and math.isfinite(scale) and scale > 0
            if not valid_scale:
                warnings.append(f"{source}/{feature}: {method or 'unknown'}; this feature cannot be statistically scored")
            elif method == "std_fallback":
                warnings.append(f"{source}/{feature}: MAD=0, using sample standard deviation fallback")
            for mult in MULTIPLIERS:
                observed = [number(r.get(feature)) for r in heldout]
                labels = [classify(v, center, scale, mult) if valid_scale else "unscorable" for v in observed]
                flagged, longest, episodes = sequence_metrics(labels)
                valid = sum(v in ("high", "low", "normal") for v in labels)
                high = labels.count("high")
                low = labels.count("low")
                invalid = labels.count("invalid_negative")
                metrics_results[(feature, mult)] = labels
                summary.append({
                    "source": source, "feature": feature, "multiplier": mult,
                    "scale_method": method, "median": center, "mad": s.get("mad", ""),
                    "scale": scale, "train_windows": train_count, "heldout_windows": len(heldout),
                    "valid_scored": valid, "not_scored": len(heldout) - valid,
                    "invalid_negative": invalid, "above_upper": high, "below_lower": low,
                    "flagged_windows": flagged,
                    "flagged_fraction": round(flagged / valid, 6) if valid else "",
                    "longest_consecutive_flagged": longest,
                    "candidate_3window_episodes": episodes,
                })

        for mult in MULTIPLIERS:
            by_feature = [metrics_results[(feature, mult)] for feature in FEATURES]
            states = [first_window_flag(by_feature, i) for i in range(len(heldout))]
            flagged, longest, episodes = sequence_metrics(states)
            valid = states.count("normal") + states.count("high")
            source_summary.append({
                "source": source, "multiplier": mult, "train_windows": train_count,
                "heldout_windows": len(heldout), "scorable_windows": valid,
                "any_feature_flagged": flagged,
                "any_feature_fraction": round(flagged / valid, 6) if valid else "",
                "longest_consecutive_flagged": longest,
                "candidate_3window_episodes": episodes,
            })
        packet_stat = baseline_by_metric["packets_per_second"]
        center = number(packet_stat.get("median"))
        scale = number(packet_stat.get("scale"))
        for index, row in enumerate(rows):
            v = number(row.get("packets_per_second"))
            state = classify(v, center, scale, 3.0)
            trace.append({
                "source": source, "row_index": index,
                "window_start": row.get("window_start", ""),
                "partition": "train" if index < train_count else "heldout",
                "packets_per_second": v,
                "median": center,
                "lower_3scale_clamped": max(0.0, center - 3 * scale) if math.isfinite(scale) else "",
                "upper_3scale": center + 3 * scale if math.isfinite(scale) else "",
                "threshold_result_diagnostic_only": state if index < train_count else "",
                "heldout_threshold_result": state if index >= train_count else "",
            })
        print(f"{source}: training={train_count}, held-out={len(heldout)}; "
              f"packet windows outside 3-scale="
              f"{next(r['flagged_windows'] for r in summary if r['source']==source and r['feature']=='packets_per_second' and r['multiplier']==3)}")

    if not summary:
        raise RuntimeError("No valid sources could be evaluated; see warnings / input paths")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "per_metric_sensitivity.csv", summary, list(summary[0]))
    write_csv(output_dir / "per_pod_sensitivity.csv", source_summary, list(source_summary[0]))
    write_csv(output_dir / "packet_window_trace.csv", trace, list(trace[0]))
    (output_dir / "validation_notes.txt").write_text(
        "ECEN403 Subsystem 1: BENIGN-ONLY baseline evaluation\n"
        "All captures are assumed benign according to supplied dataset labels.\n"
        "Baseline files were READ, not retrained or modified.\n"
        "Only chronological held-out windows were scored for rate calculations.\n"
        "Rates are candidate window-level threshold-exceedance fractions of known-benign data.\n"
        "Comparing 2/3/4/5 multipliers on this held-out set is exploratory; if selecting\n"
        "a threshold using these results, evaluate it again on NEW independent benign data.\n"
        "Not a real-time attack detector; no detection sensitivity/attack recall established.\n"
        "3-window episodes count distinct consecutive held-out flagged windows offline,\n"
        "not Prometheus 'for' time and not validated threat/response events.\n"
        "A source's 'any-feature' threshold rate is not an attack false-alarm rate.\n"
        "An unscorable zero-variance feature is not a passed test.\n"
        "Lower bounds clamped to zero for these nonnegative traffic metrics.\n\n"
        "WARNINGS:\n" + "\n".join(f"- {w}" for w in warnings) + "\n",
        encoding="utf-8")
    print(f"\nSaved read-only validation reports in: {output_dir}")
    print("  per_metric_sensitivity.csv | per_pod_sensitivity.csv | packet_window_trace.csv")
    print(f"  validation_notes.txt ({len(warnings)} notes/warnings)")


def main():
    parser = argparse.ArgumentParser(description="Validate frozen benign-only baselines; does not modify baselines")
    parser.add_argument("manifest", type=Path, help="batch_manifest.csv created by the preprocessing pipeline")
    parser.add_argument("--baseline-dir", type=Path, default=Path("data/baseline/robust"))
    parser.add_argument("--output-dir", type=Path, default=Path("reports/benign_baseline_validation"))
    args = parser.parse_args()
    validate(args.manifest, args.baseline_dir, args.output_dir)


if __name__ == "__main__":
    main()
