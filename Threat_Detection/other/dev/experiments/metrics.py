"""How good a score is at telling attack windows from benign ones. One implementation each.

Every experiment used to carry its own copy of these, and they had drifted: the rank-based
version returned NaN on a thin stratum where the pairwise version returned 1.0 (one attack
point beats one benign point by construction), and one raised where the other returned NaN.
The two disagreeing about *missing* is the hazard -- a NaN and a 1.0 look the same to a
mean over strata, and one of them flatters the result.

So the two policies are explicit here rather than accidental:

  auroc_ranked    returns NaN when either side has fewer than `min_per_side` finite
                   scores. For ranking features, where a 1-vs-1 stratum is noise.
  auroc            raises when either side is empty. For a sweep that is expected to have
                   data, where an empty side is a bug rather than a thin stratum.

Both are the same statistic: P(a random attack window outranks a random benign window),
ties counted as half. Higher is better, and 0.5 is chance.

Nothing here imports the rest of the project, so every layer and every experiment can use it.
"""
import numpy as np

__all__ = ["auroc_ranked", "auroc", "detection_at_rate", "detection_at_budget"]

MIN_PER_SIDE = 2


def _finite(values):
    """The finite values of a sequence, as a float array. NaN and inf are not scores."""
    return np.asarray([v for v in values if np.isfinite(v)], dtype=float)


def auroc_ranked(benign, attack, min_per_side=MIN_PER_SIDE):
    """P(attack outranks benign), or NaN when either side is too thin to rank.

    Rank-based (Mann-Whitney U). Ties count as half by the rank average, so this agrees
    with `auroc` to floating point on every input both accept.
    """
    benign, attack = _finite(benign), _finite(attack)
    if len(benign) < min_per_side or len(attack) < min_per_side:
        return float("nan")
    n_b, n_a = len(benign), len(attack)
    ranks = np.concatenate([benign, attack])
    ranks = _average_ranks(ranks)
    return float((ranks[n_b:].sum() - n_a * (n_a + 1) / 2) / (n_b * n_a))


def _average_ranks(values):
    """1-based ranks, tied values sharing the average of the positions they span."""
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    ordered = values[order]
    start = 0
    while start < len(values):
        stop = start + 1
        while stop < len(values) and ordered[stop] == ordered[start]:
            stop += 1
        ranks[order[start:stop]] = (start + stop + 1) / 2.0   # mean of 1-based positions
        start = stop
    return ranks


def auroc(benign, attack):
    """P(attack outranks benign), ties counted as half; raises if either side is empty.

    Pairwise, and explicit about the tie rule, for the sweeps where an empty side means a
    broken stratum rather than a thin one.
    """
    benign, attack = _finite(benign), _finite(attack)
    if not len(benign) or not len(attack):
        raise ValueError("AUROC needs at least one finite score on each side.")
    greater = (attack[:, None] > benign[None, :]).sum()
    ties = (attack[:, None] == benign[None, :]).sum()
    return float((greater + 0.5 * ties) / (len(attack) * len(benign)))


def detection_at_rate(benign, attack, fraction):
    """(detection, realised benign rate) with the cutoff at the k-th largest benign score.

    `realised` is returned beside `detection` on purpose: a nominal 5% budget on a handful
    of windows is not 5%, and quoting detection without the rate it actually cost flatters it.
    """
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be within (0, 1].")
    benign, attack = _finite(benign), _finite(attack)
    if not len(benign) or not len(attack):
        raise ValueError("Detection needs at least one finite score on each side.")
    k = max(1, int(round(fraction * len(benign))))
    threshold = float(np.sort(benign)[-k])
    return float(np.mean(attack >= threshold)), float(np.mean(benign >= threshold))


def detection_at_budget(benign_train, benign_holdout, attack, budget=0.05):
    """One feature's attack-window flag rate at a `budget` benign rate, on a z-score.

    The feature ranking asks what a single measurement is worth alone, so it standardizes
    with the mean and standard deviation of the training windows -- the same summary the
    old per-feature path used, kept here so the ranking stays comparable to itself. It is
    deliberately *not* the detector's median/MAD baseline; see feature_value.py.
    """
    train = np.asarray([v for v in benign_train if np.isfinite(v)], dtype=float)
    holdout = _finite(benign_holdout)
    target = _finite(attack)
    if not len(train) or not len(holdout) or not len(target):
        return float("nan")
    mean, std = train.mean(), train.std()
    if not std or np.isnan(std):
        return float("nan")

    def deviation(values):
        return np.abs(values - mean) / std

    cutoff = np.quantile(deviation(holdout), 1 - budget)
    return float((deviation(target) >= cutoff).mean())
