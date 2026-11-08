"""The PDFA experiment: one flag_stats row per capture stratum.

Run with:  .venv/bin/python dev/experiments/pdfa_sweep.py
           .venv/bin/python dev/statemachine.py      (same thing, kept as the old entry point)
"""
import sys
from pathlib import Path

# A script run as `python dev/experiments/pdfa_sweep.py` gets dev/experiments/ as sys.path[0], so the
# Threat_Detection root (core, methods, convert) and dev/ (experiments, verdicts) go back on
# the path before any project import.
sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

import numpy as np

from core.data_io import MANIFEST_NAME, load_manifest, resolve_output
from core.features import WINDOW_SIZE
from methods.pdfa import encode, fit_model, load_flow_packets, make_flows, segment_flows, split_flows
from methods.scores import (FORGET_SECONDS, flags_for_windows, n_windows_for, score_cutoff,
                            score_flows, statemachine_rows)

SWEEP_CSV = "statemachine_sweep.csv"


def main():
    """Write one flag_stats row per stratum: the sweep behind the pair demo.

    Same shape as sweep.py's output, so the two detectors can be compared row by row.
    """
    import argparse

    import local_paths

    parser = argparse.ArgumentParser(
        description="Score every capture against its matched benign reference with the "
                    "state machine. One row per stratum.")
    parser.add_argument("--method", default="tcp", choices=("tcp", "ptcp"),
                        help="capture method; tcp and ptcp are separate measurements")
    parser.add_argument("--encoding", default="percentile",
                        choices=("percentile", "frequency"))
    parser.add_argument("--flags", action="store_true",
                        help="add TCP SYN/RST presence to the symbol alphabet")
    parser.add_argument("--out", default=SWEEP_CSV)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    rows = statemachine_rows(manifest, method=args.method, encoding=args.encoding,
                             flag_bits=args.flags)
    out_file = resolve_output(args.out)
    rows.to_csv(out_file, index=False)

    print(f"Wrote {out_file} | rows={len(rows)} | method={args.method} "
          f"| encoding={args.encoding} | flags={args.flags}")
    for scenario, group in rows.groupby("scenario"):
        # A mean over strata weights a 3-window capture the same as an 80-window one, so
        # state the window spread beside it rather than letting the reader assume a pool.
        windows = group["windows"]
        print(f"  {scenario:<16} flagged fraction {group['flagged_fraction'].mean():.3f} "
              f"(mean over {len(group)} strata, {int(windows.sum())} windows: "
              f"{int(windows.min())}-{int(windows.max())} per stratum)")
    print(f"Windows are {WINDOW_SIZE:g}s. Flags are deviations, not confirmed attacks.")


if __name__ == "__main__":
    main()
