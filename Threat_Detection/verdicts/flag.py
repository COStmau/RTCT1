"""The flag-alphabet verdict, fixed before the measurement that judges it.

These constants and `decide()` are the rule. They were committed before any AUROC was
computed, so moving a threshold later means editing a committed file, not recalling an
intention. `statemachine.py --flags` produces the rows this reads.
"""

TARGET = ("pod-lidar", "lidar attack")
OTHERS = (("router-any", "injection attack"), ("node-child4", "injection attack"))
STRATA = (TARGET,) + OTHERS

KEEP_AUC_GAIN = 0.10      # the target stratum's AUROC must rise by at least this
MAX_OTHER_LOSS = 0.05     # no other stratum may lose more than this
TOLERANCE = 1e-9          # float slack so a value written as 0.10 compares equal


def decide(rows):
    """('keep' | 'drop' | 'undecidable', reasons) from per-stratum AUC and detection rows.

    A row is a mapping with `label`, `scenario`, `auc_plain`, `auc_flags`, `det_plain`,
    `det_flags`. Detection is the flagged fraction of attack windows at the cutoff that
    reproduces the plain model's realised benign fraction.
    """
    by_key = {(row["label"], row["scenario"]): row for row in rows}
    missing = [f"{label}/{scenario}" for label, scenario in STRATA
               if (label, scenario) not in by_key]
    if missing:
        return "undecidable", [f"missing stratum: {name}" for name in missing]

    target = by_key[TARGET]
    gain = target["auc_flags"] - target["auc_plain"]
    reasons = []
    if gain < KEEP_AUC_GAIN - TOLERANCE:
        reasons.append(f"target AUC gain {gain:.3f} below {KEEP_AUC_GAIN:.2f}")
    if target["det_flags"] < target["det_plain"] - TOLERANCE:
        reasons.append(f"target detection fell {target['det_plain']:.3f} "
                       f"to {target['det_flags']:.3f}")
    for key in OTHERS:
        row = by_key[key]
        loss = row["auc_plain"] - row["auc_flags"]
        if loss > MAX_OTHER_LOSS + TOLERANCE:
            reasons.append(f"{key[0]}/{key[1]} lost {loss:.3f} AUC, "
                           f"above {MAX_OTHER_LOSS:.2f}")
    if reasons:
        return "drop", reasons
    return "keep", [f"target AUC gain {gain:.3f}, no other stratum above "
                    f"{MAX_OTHER_LOSS:.2f} loss"]
