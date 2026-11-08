"""The start-state training-count verdict, fixed before the measurement that judges it.

The frequency scorers take each state's training count from `node.visits`. For the start
state that includes one visit per training trace start, which a test trace never adds
(`trace_states` lists the states a trace walks into, not the state it starts in), so the
start state's training count is inflated. The candidate fix counts entries instead:
transitions into the state, which is what a test trace's visits count.

These constants and `decide()` are the rule. They were committed before any AUROC of either
variant was computed, so moving a threshold later means editing a committed file, not
recalling an intention. `windowed_scores.py` produces the rows this reads.

The fix is a consistency correction, so the burden is on harm: it is kept unless the steady
strata measurably lose ranking. AUROC, not detection, because each variant's cutoff rests on
4-17 held-out windows and a moved threshold can buy detection without better ranking.
"""

MAX_STRATUM_LOSS = 0.05   # no steady stratum may lose more AUROC than this under entries
MAX_MEAN_LOSS = 0.01      # the mean AUROC change over steady strata may not fall below -this
MIN_STRATA = 10           # fewer paired steady strata than this is undecidable
TOLERANCE = 1e-9          # float slack so a value written as 0.05 compares equal


def decide(rows):
    """('keep' | 'drop' | 'undecidable', reasons) from per-stratum windowed-score rows.

    A row is a mapping with `label`, `scenario`, `method`, `group`, `train_counts` and
    `auroc`. Only attack rows of the steady group with a finite AUROC under both "visits"
    and "entries" are paired; bulk strata never decide anything. "keep" means adopt entries.
    """
    by_variant = {}
    for row in rows:
        if row.get("group") != "steady" or row.get("scenario") == "benign":
            continue
        auroc = row.get("auroc")
        if auroc is None or auroc != auroc:      # NaN: no AUROC for this stratum
            continue
        key = (row["label"], row["scenario"], row["method"])
        by_variant.setdefault(key, {})[row["train_counts"]] = float(auroc)
    pairs = {key: v for key, v in by_variant.items() if {"visits", "entries"} <= set(v)}
    if len(pairs) < MIN_STRATA:
        return "undecidable", [f"{len(pairs)} paired steady strata, fewer than {MIN_STRATA}"]

    changes = {key: v["entries"] - v["visits"] for key, v in sorted(pairs.items())}
    mean = sum(changes.values()) / len(changes)
    reasons = []
    for (label, scenario, method), change in changes.items():
        if -change > MAX_STRATUM_LOSS + TOLERANCE:
            reasons.append(f"{label}/{scenario}/{method} lost {-change:.3f} AUROC, "
                           f"above {MAX_STRATUM_LOSS:.2f}")
    if mean < -MAX_MEAN_LOSS - TOLERANCE:
        reasons.append(f"mean AUROC change {mean:+.3f} below -{MAX_MEAN_LOSS:.2f}")
    if reasons:
        return "drop", reasons
    worst = min(changes.values())
    return "keep", [f"{len(changes)} paired steady strata, mean AUROC change {mean:+.4f}, "
                    f"worst {worst:+.4f}"]
