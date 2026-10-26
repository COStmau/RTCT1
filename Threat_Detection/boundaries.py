"""Evaluation boundaries in one place, so every scoring path reads the same policy.

Fit and calibration stay vantage-matched: there is one benign capture per vantage per
capture method, so the split has to run inside that capture rather than across captures.
The bulk-transfer recordings change regime mid-capture; they are scored and reported, but
they never set a cutoff, because a cutoff fitted there learns the drift.
"""

TRAIN_FRACTION = 0.7          # first 70% of a capture fits, the last 30% is held out

# Three vantages whose traffic steps from tens of KB/s to hundreds of MB/s mid-recording,
# in both capture methods, so six files. Matched on the label, not the file name.
BULK_LABELS = frozenset({"router-any", "node-child4", "pod-robot-controller"})

WARMUP_WINDOWS = 5            # a scorer that needs a full trace cannot judge its prefix

# The anomaly clock. A state visit counts only while it is inside this trailing window of
# observed seconds, so an attack's excess visits expire instead of accumulating forever.
# Sized against the dataset: captures run 51-69 s, so a 25 s window would hold an attack
# past the end of most recordings and release could never be observed inside one. 8 s holds
# a 5 s LiDAR replay loop and leaves room for CLEAR_WINDOWS of runway after it.
FORGET_SECONDS = 8.0
CLEAR_WINDOWS = 3             # consecutive clean windows before an incident may clear
