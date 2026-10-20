"""Per-window anomaly scores for the plain and flag alphabets, and the AUROC summary.

Both models are fitted on the same training flows and scored on the same windows, so the
only difference between them is the symbol alphabet. Scores are oriented so higher always
means more anomalous: the likelihood path negates the mean log probability, which is lower
for unlikely traces.
"""
import argparse

import numpy as np
import pandas as pd

from data_io import describe_captures, load_manifest, resolve_output
from features import WINDOW_SIZE
from statemachine import (fit_model, load_flow_packets, make_flows, n_windows_for,
                          score_cutoff, score_flows, segment_flows, split_flows)

MANIFEST_FILE = "capture_manifest.csv"
WINDOW_CSV = "flag_window_scores.csv"
SUMMARY_CSV = "flag_auc.csv"


def window_scores(scored, t0, n_windows, window_size=WINDOW_SIZE):
    """Most anomalous trace per window; NaN where no trace ends."""
    scores = np.full(n_windows, np.nan)
    for start_ts, score in scored:
        window = int((start_ts - t0) // window_size)
        if 0 <= window < n_windows:
            current = scores[window]
            scores[window] = score if np.isnan(current) else max(current, score)
    return scores


def auroc(benign, attack):
    """Probability an attack window outranks a benign one, ties counted as half."""
    benign = np.asarray([value for value in benign if np.isfinite(value)], dtype=float)
    attack = np.asarray([value for value in attack if np.isfinite(value)], dtype=float)
    if not len(benign) or not len(attack):
        raise ValueError("AUROC needs at least one finite score on each side.")
    greater = (attack[:, None] > benign[None, :]).sum()
    ties = (attack[:, None] == benign[None, :]).sum()
    return float((greater + 0.5 * ties) / (len(attack) * len(benign)))


def detection_at_benign_rate(benign, attack, fraction):
    """(detection, realised benign rate) with the threshold at the k-th largest benign score."""
    benign = np.asarray([value for value in benign if np.isfinite(value)], dtype=float)
    attack = np.asarray([value for value in attack if np.isfinite(value)], dtype=float)
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be within (0, 1].")
    if not len(benign) or not len(attack):
        raise ValueError("Detection needs at least one finite score on each side.")
    k = max(1, int(round(fraction * len(benign))))
    threshold = float(np.sort(benign)[-k])
    return float(np.mean(attack >= threshold)), float(np.mean(benign >= threshold))
