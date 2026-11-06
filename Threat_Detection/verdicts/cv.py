"""The cross-validated calibration verdict, fixed before the measurement that judges it.

The windowed score's cutoff is the 95th percentile of the held-out benign windows: the last
30% of one benign recording, 3-16 scored windows per steady tap, so the cutoff sits next to
their maximum. The candidate ("cv5") uses every benign window out of fold instead: the
recording is cut into CV_FOLDS contiguous blocks on window boundaries, each block is scored
by a machine learned from the others, and the cutoff is the 95th percentile of all of them.
The page and the sweep then use one machine learned from the whole benign recording.

That has a cost the rule has to see: the fold machines learned from 80% of the data and the
deployed one from all of it, so their scores need not share a scale. Attack windows are the
one place every machine is out of sample, so the scale check is made there.

These constants and `decide()` are the rule. They were committed before any cv5 number was
computed, so moving a threshold later means editing a committed file, not recalling an
intention. `cv_calibration.py` produces the rows this reads. "keep" means adopt cv5.
"""

CV_FOLDS = 5              # contiguous blocks; each is held out once
MIN_STRATA = 10           # fewer paired steady attack strata than this is undecidable
MIN_SAMPLE_GAIN = 3.0     # median (cv5 cutoff windows / split cutoff windows) over steady taps
RATE_BAND = (0.02, 0.10)  # pooled out-of-fold benign rate per method must land in this band
MAX_TAP_RATE = 0.25       # no steady tap's out-of-fold benign rate may exceed this
MAX_SCALE_RATIO = 0.25    # median |full - fold| attack-window shift / pooled benign IQR
MAX_STRATUM_LOSS = 0.05   # no steady attack stratum may lose more AUROC than this under cv5
MAX_MEAN_LOSS = 0.01      # the mean AUROC change over steady attack strata may not fall below -this
TOLERANCE = 1e-9          # float slack so a value written as 0.05 compares equal


def _finite(value):
    return value is not None and value == value


def decide(rows):
    """('keep' | 'drop' | 'undecidable', reasons) from calibration rows.

    Every row has `label`, `method`, `group`, `scenario` and `calibration` ("split" or
    "cv5"). Benign rows carry `cutoff_windows`; cv5 benign rows also carry `oos_flagged` and
    `oos_windows` (out-of-fold windows over a cutoff set without them) and `scale_ratio`.
    Attack rows carry `auroc`. Only the steady group decides anything.
    """
    steady = [r for r in rows if r.get("group") == "steady"]
    benign = {}
    attack = {}
    for row in steady:
        key = (row["label"], row["method"])
        if row["scenario"] == "benign":
            benign.setdefault(key, {})[row["calibration"]] = row
        elif _finite(row.get("auroc")):
            attack.setdefault(key + (row["scenario"],), {})[row["calibration"]] = float(row["auroc"])
    pairs = {k: v for k, v in attack.items() if {"split", "cv5"} <= set(v)}
    if len(pairs) < MIN_STRATA:
        return "undecidable", [f"{len(pairs)} paired steady attack strata, fewer than {MIN_STRATA}"]

    taps = {k: v for k, v in benign.items() if {"split", "cv5"} <= set(v)}
    reasons = []

    gains = sorted(v["cv5"]["cutoff_windows"] / v["split"]["cutoff_windows"]
                   for v in taps.values() if v["split"]["cutoff_windows"])
    gain = gains[len(gains) // 2] if gains else 0.0
    if gain < MIN_SAMPLE_GAIN - TOLERANCE:
        reasons.append(f"median sample gain {gain:.2f}x, below {MIN_SAMPLE_GAIN:.1f}x")

    for method in sorted({m for _, m in taps}):
        cv = [v["cv5"] for (_, m), v in taps.items() if m == method]
        flagged = sum(r["oos_flagged"] for r in cv)
        windows = sum(r["oos_windows"] for r in cv)
        rate = flagged / windows if windows else float("nan")
        if not (RATE_BAND[0] - TOLERANCE <= rate <= RATE_BAND[1] + TOLERANCE):
            reasons.append(f"{method} pooled out-of-fold benign rate {rate:.3f} "
                           f"({flagged} of {windows}) outside {RATE_BAND[0]:.2f}-{RATE_BAND[1]:.2f}")
    for (label, method), v in sorted(taps.items()):
        cv = v["cv5"]
        if cv["oos_windows"] and cv["oos_flagged"] / cv["oos_windows"] > MAX_TAP_RATE + TOLERANCE:
            reasons.append(f"{label}/{method} out-of-fold benign rate "
                           f"{cv['oos_flagged']}/{cv['oos_windows']} above {MAX_TAP_RATE:.2f}")

    ratios = sorted(v["cv5"]["scale_ratio"] for v in taps.values()
                    if _finite(v["cv5"].get("scale_ratio")))
    ratio = ratios[len(ratios) // 2] if ratios else float("inf")
    if ratio > MAX_SCALE_RATIO + TOLERANCE:
        reasons.append(f"median fold-to-full scale shift {ratio:.3f} of the benign IQR, "
                       f"above {MAX_SCALE_RATIO:.2f}")

    changes = {k: v["cv5"] - v["split"] for k, v in sorted(pairs.items())}
    mean = sum(changes.values()) / len(changes)
    for (label, method, scenario), change in changes.items():
        if -change > MAX_STRATUM_LOSS + TOLERANCE:
            reasons.append(f"{label}/{scenario}/{method} lost {-change:.3f} AUROC, "
                           f"above {MAX_STRATUM_LOSS:.2f}")
    if mean < -MAX_MEAN_LOSS - TOLERANCE:
        reasons.append(f"mean AUROC change {mean:+.3f} below -{MAX_MEAN_LOSS:.2f}")

    if reasons:
        return "drop", reasons
    return "keep", [f"{len(changes)} paired steady strata, mean AUROC change {mean:+.4f}, "
                    f"worst {min(changes.values()):+.4f}; median sample gain {gain:.1f}x; "
                    f"median scale shift {ratio:.3f} of the benign IQR"]
