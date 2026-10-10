"""The z-score demo: two captures in, a report and a chart out.

Run it with:  .venv/bin/python detector.py

This file is only an entry point. Everything it does lives in the four layers:

    data_io      read a capture CSV, resolve where output goes
    features     packets -> 1-second windows
    detectors    score windows against a benign reference, flag them
    reporting    print the story, draw the chart

so the same steps are available to sweep.py, compare.py, and feature_value.py.
"""
import argparse
from pathlib import Path

import local_paths
from data_io import load_capture, resolve_output
from detectors import build
from features import make_windows, split_reference
from reporting import plot_detection, summarize_flags

DETECTOR = "z_score"


def resolve_reference(benign_windows):
    """Pick the reference windows and the held-out windows from one benign capture.

    Two honest options. With a second benign capture set as BENIGN_EVAL_CSV, the whole
    first capture fits the reference and the separate capture is the evaluation -- no
    window ever does both jobs. Without one, the capture is split by time and the later
    windows are held out. Either way the reference never sees evaluation traffic.
    """
    evaluation_path = getattr(local_paths, "BENIGN_EVAL_CSV", "")
    if evaluation_path:
        if Path(evaluation_path).resolve() == Path(local_paths.BENIGN_CSV).resolve():
            raise ValueError("BENIGN_EVAL_CSV must differ from the baseline capture.")
        reference = benign_windows
        held_out = make_windows(load_capture(evaluation_path))
        note = "Benign evaluation uses a separate capture, excluded from fitting."
    else:
        reference, held_out = split_reference(benign_windows)
        note = (f"First {len(reference)} windows fit the reference; "
                f"the next {len(held_out)} are held out.")
    return reference, held_out, note


def main():
    if not local_paths.BENIGN_CSV or not local_paths.ATTACK_CSV:
        raise ValueError("Set BENIGN_CSV and ATTACK_CSV in local_paths.py.")

    reference, held_out, note = resolve_reference(
        make_windows(load_capture(local_paths.BENIGN_CSV)))
    detector = build(DETECTOR).pipeline(reference, held_out)

    benign_results = detector.annotate(held_out)
    results = detector.annotate(make_windows(load_capture(local_paths.ATTACK_CSV)))

    results.to_csv(resolve_output("results.csv"))
    benign_results.to_csv(resolve_output("benign_results.csv"))

    summarize_flags(results, benign_results, len(reference), note)
    plot_detection(results, benign_results, detector.mean, detector.std, len(reference))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the offline threat detection demo.")
    args = parser.parse_args()
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(f"Unable to run detector: {error}")