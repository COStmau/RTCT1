"""Every way of deciding that a window is abnormal, behind one interface.

A detector is four steps and nothing else:

    fit(reference)      learn from benign training windows only
    calibrate(benign)   a cutoff on this detector's own scale, from held-out benign windows
    score(windows)      higher = MORE anomalous, NaN where the window cannot be scored
    flag(windows)       score > cutoff
    explain(windows)    OPTIONAL: which feature drove it, or None

Direction is part of the contract. scikit-learn's decision_function runs the opposite way
(lower = more anomalous), so the learned detectors negate it once, here, and no caller ever
has to know which is which.

Attribution is deliberately optional. Only the z-score can name the feature that moved; the
learned models return None so that a comparison between them is not quietly biased toward
the detector that explains itself.
"""
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
import pandas as pd

from features import WINDOW_SIZE  # noqa: F401  re-exported: chart titles and split logic need it

# Detection policy. These constants are the whole tuning surface.
THRESHOLD = 2.5 ##Changed from 3
PERSISTENCE_WINDOW = 3
BENIGN_QUANTILE = 0.05

# Scales MAD to a consistent estimator of sigma for normal data, so the 3-sigma cutoff
# means the same thing on a median/MAD baseline as on a mean/std one.
MAD_TO_SIGMA = 1.4826

# Learned-model hyperparameters.
N_ESTIMATORS = 100
RANDOM_STATE = 0
SVM_NU = 0.10


@dataclass
class ScoreResult:
    """What one detector says about a set of windows."""
    score: pd.Series
    cutoff: float
    evidence: pd.DataFrame | None = None   # present only when explain() is implemented


class Detector:
    """Base class: holds the calibrated cutoff and the shared train -> calibrate -> flag order."""

    name = "detector"

    # Capability slot. None on detectors that cannot attribute a flag; a bound method on
    # those that can. Checked as `detector.explain is not None`, never called on the base.
    # Typed with ... so a bound method (self already applied) satisfies it.
    explain: Callable[..., pd.DataFrame] | None = None

    def __init__(self):
        self.cutoff = None

    def fit(self, reference):
        raise NotImplementedError

    def calibrate(self, held_out_benign):
        raise NotImplementedError

    def score(self, windows):
        raise NotImplementedError

    def flag(self, windows):
        """True where the window scores above the calibrated cutoff. Unscorable -> False."""
        if self.cutoff is None:
            raise RuntimeError(f"{self.name}: call calibrate() before flag()")
        return self.score(windows).gt(self.cutoff).fillna(False).astype(bool)

    def pipeline(self, reference, held_out_benign):
        """The two steps that must happen in this order, in one call."""
        return self.fit(reference).calibrate(held_out_benign)

    def annotate(self, windows):
        """A full results table for one capture: features, score, flag, status, evidence.

        The per-window result shape lives here so every script reports the same columns
        and the same status vocabulary. An unscorable window is marked insufficient_data
        rather than normal -- a NaN flag is deliberate, and .fillna(False) is what turns
        it into a "not flagged" count at the call site.
        """
        score = self.score(windows)
        results = windows.copy()
        results["anomaly_score"] = score
        results["anomaly"] = score.gt(self.cutoff).mask(score.isna())
        results["status"] = "normal"
        results.loc[score.gt(self.cutoff), "status"] = "anomaly"
        results.loc[score.isna(), "status"] = "insufficient_data"

        evidence = self.explain(windows) if self.explain is not None else None
        if evidence is not None:
            for column in evidence.columns:
                results[column] = evidence[column]
        else:
            for column in ("top_feature", "observed_value", "expected_mean",
                           "expected_std", "feature_z_score"):
                results[column] = np.nan

        results["persistent_flag"] = persistent_mask(results["anomaly"])
        results["status"] = results["status"].mask(results["persistent_flag"], "persistent_anomaly")
        return results


class ZScoreDetector(Detector):
    """Largest absolute standardized deviation across features. Transparent by design.

    The baseline is a robust centre and spread -- median and MAD -- not mean and standard
    deviation. A captured workload mixes idle web traffic with a few enormous bulk-transfer
    windows, and on the KUBEDATA captures 8 of 47 benign windows at router-any carry the
    entire dynamic range (up to 146 MB against a 50 KB median). A mean/std summary is set by
    those windows, so a held-out window sitting in the dominant quiet mode still lands 3
    sigma away and a third of normal traffic flags. Median/MAD ignores them.

    Where MAD is 0 -- a feature that is genuinely constant in the reference -- the standard
    deviation is used instead, because a zero divisor would flag every window. `degenerate`
    records which features took that fallback, so the caller can see it rather than infer it.
    """

    name = "z_score"

    def __init__(self, threshold=THRESHOLD):
        super().__init__()
        self.threshold = threshold
        self.mean = None
        self.std = None
        self.degenerate = None

    def fit(self, reference):
        if reference.empty or reference.count().lt(2).any():
            raise ValueError("Insufficient baseline data: each feature needs at least two observations.")
        # 1.4826 scales MAD to be a consistent estimator of sigma for normal data, so the
        # 3-sigma cutoff keeps the same meaning it has on a mean/std baseline.
        mad = (reference - reference.median()).abs().median() * MAD_TO_SIGMA
        std = reference.std()
        if not np.isfinite(mad).all() or not np.isfinite(std).all():
            raise ValueError("Baseline statistics must be finite.")
        # A constant feature has MAD 0. Standard deviation is 0 too, and a zero divisor
        # flags every window, so the deviation for that feature is defined as 0 when the
        # observation matches the centre and infinite when it does not (see _z).
        self.degenerate = mad.le(0)
        spread = mad.where(~self.degenerate, std)
        self.mean, self.std = reference.median(), spread
        return self

    def calibrate(self, held_out_benign):
        """A design constant, not a fitted quantile: the 3-sigma default from the FSR."""
        self.cutoff = float(self.threshold)
        return self

    def _z(self, windows):
        if self.mean is None or self.std is None:
            raise ValueError("Baseline statistics are unset; call fit() first.")
        if not np.isfinite(self.mean).all() or not np.isfinite(self.std).all() or self.std.lt(0).any():
            raise ValueError("Baseline statistics must be finite, with nonnegative deviations.")
        if set(windows.columns) != set(self.mean.index) or set(self.mean.index) != set(self.std.index):
            raise ValueError("Evaluation features must match the baseline feature names.")
        if np.isinf(windows.to_numpy()).any():
            raise ValueError("Evaluation features contain infinite values.")
        delta = windows - self.mean
        # A degenerate feature (MAD 0 and std 0) has no meaningful scale, and dividing by its
        # zero spread would flag every window. It is scored as: exactly the centre -> 0.0,
        # any movement at all -> +/-infinity, keeping the sign of the movement. NaN is not
        # the right answer here -- it means insufficient_data, but this observation is not
        # missing, it is unscaleable. The sign matters because score() takes abs() of the
        # row max, and explain() reports the signed z.
        zero_spread = self.std.eq(0.0)
        z = delta.div(self.std.where(~zero_spread, 1.0))
        return z.mask(delta.eq(0), 0.0).mask(zero_spread & delta.ne(0), np.sign(delta) * np.inf)

    def score(self, windows):
        return self._z(windows).abs().max(axis=1)

    def explain(self, windows):
        """Name the feature with the largest absolute z, and its observed and baseline values.

        A window where every feature is undefined has no strongest feature; it gets NA
        rather than an arbitrary pick, which is also why idxmax is only asked of the rows
        that have at least one usable feature.
        """
        z = self._z(windows)
        magnitudes = z.abs()
        strongest = pd.Series(pd.NA, index=windows.index, dtype="object")
        # idxmax only over rows with at least one usable feature: asked of an all-NA row it
        # raises rather than answering.
        available = magnitudes.notna().any(axis=1)
        if available.any():
            strongest.loc[available] = magnitudes.loc[available].idxmax(axis=1)

        evidence = pd.DataFrame(index=windows.index)
        evidence["top_feature"] = strongest.astype("string")
        named = strongest.notna()
        evidence["observed_value"] = np.nan
        evidence["expected_mean"] = np.nan
        evidence["expected_std"] = np.nan
        evidence["feature_z_score"] = np.nan
        for feature in strongest.dropna().unique():
            rows = named & strongest.eq(feature)
            evidence.loc[rows, "observed_value"] = windows.loc[rows, feature]
            evidence.loc[rows, "expected_mean"] = self.mean[feature]
            evidence.loc[rows, "expected_std"] = self.std[feature]
            evidence.loc[rows, "feature_z_score"] = z.loc[rows, feature]
        return evidence


class LearnedDetector(Detector):
    """Shared plumbing for the scikit-learn models.

    Subclasses only build `self.model` in fit(); the score sign flip and the held-out
    quantile cutoff live here so both learned detectors behave identically.
    """

    def _build(self):                      # pragma: no cover - overridden
        raise NotImplementedError

    def fit(self, reference):
        if reference.empty or reference.count().lt(2).any():
            raise ValueError("Insufficient baseline data: each feature needs at least two observations.")
        self.model = self._build()
        self.model.fit(reference.dropna())
        return self

    def score(self, windows):
        """Negated decision_function, so a HIGHER score means MORE anomalous everywhere.

        Windows with any undefined feature stay NaN rather than being scored on partial
        evidence, which is also why this detector's window set is not identical to the
        z-score's.
        """
        scored = windows.dropna()
        raw = pd.Series(-self.model.decision_function(scored), index=scored.index)
        return raw.reindex(windows.index)

    def calibrate(self, held_out_benign):
        values = held_out_benign.dropna()
        if values.empty:
            raise ValueError("No held-out benign windows to calibrate the cutoff")
        # The score is negated, so the worst BENIGN_QUANTILE now sits high, not low.
        # Taking quantile(1 - budget) is the same decision as the old
        # quantile(decision_function, budget) + "< cutoff" on the un-negated scale.
        self.cutoff = float(self.score(values).quantile(1 - BENIGN_QUANTILE))
        return self


class IsolationForestDetector(LearnedDetector):
    """Isolation Forest: random-axis partitions that isolate outliers in few splits."""

    name = "isolation_forest"

    def _build(self):
        from sklearn.ensemble import IsolationForest

        return IsolationForest(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE)


class OneClassSvmDetector(LearnedDetector):
    """One-Class SVM. Scale sensitive, so the StandardScaler lives inside the pipeline.

    Keeping it there means decision_function still takes raw feature values, exactly like the
    forest, so score() is the same one-liner for both.
    """

    name = "one_class_svm"

    def __init__(self, nu=SVM_NU):
        super().__init__()
        self.nu = nu

    def _build(self):
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.svm import OneClassSVM

        return make_pipeline(StandardScaler(),
                             OneClassSVM(kernel="rbf", gamma="scale", nu=self.nu))


# Adding a detector is one class plus one line here. No caller changes.
REGISTRY = {
    "z_score": ZScoreDetector,
    "isolation_forest": IsolationForestDetector,
    "one_class_svm": OneClassSvmDetector,
}


def build(name, **kwargs):
    """Instantiate a registered detector by name."""
    if name not in REGISTRY:
        raise KeyError(f"Unknown detector {name!r}; available: {', '.join(sorted(REGISTRY))}")
    return REGISTRY[name](**kwargs)


def persistent_mask(flags, min_consecutive=PERSISTENCE_WINDOW):
    """Mark flags that sit inside a run of >= min_consecutive consecutive flags.

    Uses a running count within each run: transform("sum") would return the whole run
    length for every row and escalate the first windows of a run too.
    """
    flags = pd.Series(flags).fillna(False).astype(bool)
    run_id = (flags != flags.shift()).cumsum()
    run_len = flags.groupby(run_id).cumsum()
    return flags & run_len.ge(min_consecutive)


def flag_stats(flags, min_consecutive=PERSISTENCE_WINDOW):
    """Flagged and sustained counts/fractions for one set of windows.

    Shared by every experiment script so they all report the same numbers.
    """
    flags = pd.Series(flags).fillna(False).astype(bool)
    persistent = persistent_mask(flags, min_consecutive)
    total = len(flags)
    return {
        "windows": int(total),
        "flagged": int(flags.sum()),
        "flagged_fraction": round(float(flags.mean()), 4) if total else float("nan"),
        "persistent": int(persistent.sum()),
        "persistent_fraction": round(float(persistent.mean()), 4) if total else float("nan"),
    }