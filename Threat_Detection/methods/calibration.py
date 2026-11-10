"""The detector both the demo page and the live monitor use: one calibration, one rule set.

calibrate(benign)   the learned machine and its cutoffs from one benign packet frame
WindowRules         alert / release / status, one 1-second window at a time

viz/page.py (recordings) and live/stream.py (streams) both import these, so a recording and a
live tap can never disagree about what a tap's normal is or when an alert opens and closes.
"""
import numpy as np
import pandas as pd

from core.detectors import BENIGN_QUANTILE, PERSISTENCE_WINDOW
from core.features import WINDOW_SIZE
from core.reporting import CLEAR_WINDOWS
from methods.pdfa import fit_model, make_flows, segment_flows, split_flows
from methods.scores import (FORGET_SECONDS, frequency_cutoff, frequency_scores_by_window,
                            n_windows_for, score_cutoff, score_flows)

# strongest first; "warmup" and "nodata" are insufficient evidence, never "normal"
WINDOW_STATUSES = ("alert", "flagged", "unseen", "nodata", "warmup", "released", "normal")
RELEASE_SHOWN = 2           # windows after a release that still say "released"


def calibrate(benign, forget_seconds=FORGET_SECONDS, flows=None):
    """The learned machine and its cutoffs from one benign packet frame.

    The one calibration both the page (viz/page.py) and the live monitor (live/stream.py) use, so they can
    never disagree about what a tap's normal is. The windowed cutoff comes from the held-out
    windows scored on a warm clock (the training flows run first, as they did in the
    recording); the cumulative score gets a by-age reference instead of a single cutoff.

    `flows` replaces the offline flow rule (segment_flows) with flows already cut another
    way: the live monitor passes the flows its own causal rule makes (live/stream.py), so a
    tap is trained on exactly the kind of flows it will be scored on.
    """
    t0 = float(benign["ts"].min())
    if flows is None:
        flows, dropped = segment_flows(make_flows(benign), t0)
    else:
        dropped = 0
    train, holdout = split_flows(flows)
    events = []
    model = fit_model(train, trace=events)
    n_windows = n_windows_for(benign)
    first_held = int((float(holdout["start_ts"].iloc[0]) - t0) // WINDOW_SIZE)
    warm = frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds)
    by_age = frequency_scores_by_window(model, flows, t0, n_windows, None)
    held_traces = score_flows(model, holdout)
    held_windows = warm[first_held + 1:]
    held_windows = held_windows[np.isfinite(held_windows)]
    cutoffs = {
        "likelihood": score_cutoff(held_traces),
        "windowed": frequency_cutoff(held_windows),
        "cumulative_reference": list(pd.Series(by_age).cummax().to_numpy()),
    }
    # what each cutoff rests on: a 95th percentile of a dozen windows sits next to their
    # maximum, so the page shows the sample size and the share of held-out benign it flags
    cutoffs["calibration"] = {
        "nominal_rate": BENIGN_QUANTILE,
        "windowed_windows": int(len(held_windows)),
        "windowed_benign_rate": float(np.mean(held_windows > cutoffs["windowed"])),
        "likelihood_traces": len(held_traces),
        "likelihood_benign_rate": float(np.mean([v < cutoffs["likelihood"] for _, v in held_traces])),
    }
    return {"t0": t0, "flows": flows, "dropped": dropped, "train": train, "holdout": holdout,
            "model": model, "events": events, "cutoffs": cutoffs, "n_windows": n_windows}


class WindowRules:
    """The window rules one window at a time, so a live stream and a replay share them.

    `step` takes one window's evidence in order and returns its alert, release, status and
    forgetting flag. An alert is the PERSISTENCE_WINDOW-th flag in a row (the running count
    core.detectors.persistent_mask uses); it is released after CLEAR_WINDOWS scored,
    unflagged windows; a window with no trace neither counts toward that run nor resets it.
    """

    def __init__(self, warmup_s=0.0):
        self.warmup_s = float(warmup_s)
        self.run = 0                  # consecutive flagged windows
        self.pending = False          # an alert is open
        self.clean = 0                # scored, unflagged windows since the last flag
        self.since_release = None
        self.alerted = False

    def step(self, w, scored, flagged, unlikely=False, held=False):
        self.run = self.run + 1 if flagged else 0
        alert = flagged and self.run >= PERSISTENCE_WINDOW
        self.pending = self.pending or alert
        self.clean = 0 if flagged else self.clean + 1 if scored else self.clean
        released = self.pending and scored and self.clean >= CLEAR_WINDOWS
        if released:
            self.pending, self.since_release = False, 0
        elif self.since_release is not None:
            self.since_release = self.since_release + 1 if self.clean else None
        status = ("alert" if alert else "flagged" if flagged else "unseen" if unlikely
                  else "nodata" if not scored else "warmup" if w * WINDOW_SIZE < self.warmup_s
                  else "released" if self.since_release is not None
                  and self.since_release <= RELEASE_SHOWN
                  else "normal")
        verdict = {"alert": bool(alert), "released": bool(released), "status": status,
                   "forgetting_shown": bool(self.alerted and scored and not flagged and held)}
        self.alerted = self.alerted or bool(alert)
        return verdict
