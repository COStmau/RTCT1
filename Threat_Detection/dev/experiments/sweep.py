"""Score every capture against its own matched benign reference.

The reference for a target capture is the benign capture with the same label and
the same capture method, fitted on its first 70% of windows. The remaining 30% are
scored too, so the false-alarm rows come from windows the baseline never saw.
"""
import sys
from pathlib import Path

# A script run as `python dev/experiments/sweep.py` gets dev/experiments/ as sys.path[0], so the
# Threat_Detection root (core, methods, convert) and dev/ (experiments, verdicts) go back on
# the path before any project import.
sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

import argparse

import numpy as np
import pandas as pd

import local_paths
from core.data_io import MANIFEST_NAME, load_capture, load_manifest, resolve_output
from core.detectors import build, flag_stats
from core.features import FEATURE_GROUPS, WINDOW_SIZE, load_all_windows, split_reference
from core.reporting import plot_detection_gap, plot_matrix, print_matrix, to_events, write_events

DETECTOR = "z_score"


def summary_row(scenario, label, method, group, results=None, note=""):
    """One row of evidence for one capture.

    results=None records a capture that could not be scored: the row stays, with the
    reason in `note`, so nothing disappears quietly.
    """
    if results is None:
        return {"group": group, "scenario": scenario, "label": label, "method": method,
                "windows": 0, "flagged": 0, "persistent": 0, "flagged_fraction": np.nan,
                "peak_score": np.nan, "top_feature": "", "note": note}
    flagged = results["anomaly"].fillna(False).astype(bool)
    finite = results["anomaly_score"].replace([np.inf, -np.inf], np.nan).dropna()
    stats = flag_stats(flagged)
    return {
        "group": group, "scenario": scenario, "label": label, "method": method,
        "windows": stats["windows"], "flagged": stats["flagged"], "persistent": stats["persistent"],
        "flagged_fraction": stats["flagged_fraction"],
        "peak_score": round(float(finite.max()), 3) if len(finite) else np.nan,
        "top_feature": (results.loc[flagged, "top_feature"].value_counts().idxmax()
                        if flagged.any() else ""),
        "note": note,
    }


def _event_filename(scenario, label, method):
    """Stable capture identity as a filesystem-safe JSON Lines name."""
    return "__".join(str(value).replace(" ", "-") for value in (scenario, label, method)) + ".jsonl"


def write_sweep_events(scored, events_dir):
    """Write one event file for each scored adopted-detector capture."""
    events_dir = Path(events_dir)
    events_dir.mkdir(parents=True, exist_ok=True)
    files = event_count = 0
    for capture, results, cutoff in scored:
        events = to_events(results, detector=DETECTOR, cutoff=cutoff, capture=capture)
        write_events(events, path=events_dir / _event_filename(
            capture["scenario"], capture["label"], capture["method"]))
        files += 1
        event_count += len(events)
    return files, event_count


def run_sweep(manifest, groups=(None,), events_dir=None):
    """Score every stratum; optionally write events for the adopted `all` group."""
    windows, notes = load_all_windows(manifest)
    attacks = [s for s in sorted(manifest["scenario"].unique()) if s != "benign"]
    rows, event_frames = [], []
    for group in groups:
        # "all" is the adopted detector (its own feature list); "full" is every one of the 13
        # measurements, the old baseline; a named group is that group alone.
        columns = None if group in (None, "all", "full") else list(FEATURE_GROUPS[group])
        group_name = "all" if group is None else group
        for method in sorted(manifest["method"].unique()):
            for label in sorted(manifest["label"].unique()):
                reference_windows = windows.get(("benign", label, method))
                targets = [("benign", None)] + [(s, windows.get((s, label, method))) for s in attacks]
                if reference_windows is None:
                    for scenario, _ in targets:
                        rows.append(summary_row(scenario, label, method, group_name,
                                                note=notes.get((scenario, label, method), "no capture")))
                    continue
                reference, holdout = split_reference(reference_windows)
                # For z_score, calibrate() installs the fixed design cutoff rather
                # than fitting a quantile, so this is the sweep's original behavior.
                detector = (build(DETECTOR) if group in (None, "all") else build(DETECTOR, features=None)).pipeline(reference if columns is None else reference[columns],
                                                     holdout if columns is None else holdout[columns])
                for scenario, target in targets:
                    target = holdout if scenario == "benign" else target
                    if target is None:
                        rows.append(summary_row(scenario, label, method, group_name,
                                                note=notes.get((scenario, label, method), "no capture")))
                        continue
                    scored = target if columns is None else target[columns]
                    annotated = detector.annotate(scored)
                    rows.append(summary_row(scenario, label, method, group_name, annotated))
                    if events_dir is not None and group_name == "all":
                        start_epoch_s = annotated.attrs.get("start_epoch_s")
                        if start_epoch_s is None or pd.isna(start_epoch_s):
                            capture_row = manifest[
                                manifest["scenario"].eq(scenario)
                                & manifest["label"].eq(label)
                                & manifest["method"].eq(method)
                            ].iloc[0]
                            annotated.attrs["start_epoch_s"] = float(
                                pd.to_numeric(load_capture(capture_row["path"])["ts"], errors="raise").iloc[0])
                        event_frames.append((
                            {"scenario": scenario, "label": label, "method": method},
                            annotated,
                            detector.cutoff))
    results = (pd.DataFrame(rows)
               .sort_values(["group", "method", "label", "scenario"])
               .reset_index(drop=True))
    if events_dir is not None:
        results.attrs["event_counts"] = write_sweep_events(event_frames, events_dir)
    return results


def main():
    parser = argparse.ArgumentParser(description="Score every capture against its matched benign reference.")
    parser.add_argument("--groups", default="all",
                        help="'all' (the adopted detector), 'full' (all 13 measurements), or a "
                             "comma-separated subset of " + ", ".join(FEATURE_GROUPS))
    parser.add_argument("--out", default="sweep_results.csv")
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    parser.add_argument("--events-dir",
                        help="write one JSON Lines event file per scored `all` stratum")
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    groups = [None] if args.groups == "all" else args.groups.split(",")
    results = run_sweep(manifest, groups=groups, events_dir=args.events_dir)
    out_file = resolve_output(args.out)
    results.to_csv(out_file, index=False)
    # Write the inventory this run actually scored, so the sibling scripts
    # (compare.py, feature_value.py) read the same captures rather than re-globbing the
    # Drive. load_manifest prefers a cached file, so a stale one must be deleted or
    # --rebuild passed rather than trusted.
    resolve_output(args.manifest).parent.mkdir(exist_ok=True)
    manifest.to_csv(resolve_output(args.manifest), index=False)
    print_matrix(results)
    excluded = results[results["note"].str.startswith("excluded", na=False)]
    print(f"\nWrote {out_file} | rows={len(results)}"
          f" | excluded captures={excluded['label'].nunique()}")
    if args.events_dir is not None:
        files, events = results.attrs["event_counts"]
        print(f"Wrote {files} event files | events={events} | directory={args.events_dir}")
    print(f"Times are per capture; windows are {WINDOW_SIZE:g}s. Flags are deviations, not confirmed attacks.")
    if len(groups) == 1 and groups[0] is None:
        print(f"\nWrote {plot_matrix(results)}")
        print(f"Wrote {plot_detection_gap(results)}")


if __name__ == "__main__":
    main()