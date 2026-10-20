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
