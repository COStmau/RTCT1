"""The detection feature-set verdict, fixed before the experiment that judges it.

The ablation showed `volume` and `size_timing` carrying most of the false alarms, because raw
byte and packet counts drift with load. The candidate is the z-score detector on the other
eight measurements (`unique_dst_ips`, `unique_dst_ports`, `syn_count`, `rst_count`,
`http_count`, `dns_count`, `https_count`, `http_frac`) against today's all-13.

Disclosure: this rule is NOT blind. The candidate was chosen after the group ablation, and a
first exploratory run of both sets existed before this file did. The thresholds below are
round numbers fixed now, for the committed experiment, and the benign side of the comparison
is optimistic because the same benign recordings pointed at the candidate and now judge it.
The attack side does not depend on that choice. There is no unused benign data to hold out:
tcp and ptcp are two captures of the same traffic, so ptcp is a consistency check, not an
independent confirmation.

The rule is two-sided because dropping features can only lower the false-alarm rate by
construction (a max over fewer features is never larger); what has to be shown is that the
attacks are still seen.

  alerts   Persistent alerts per benign window on the steady taps fall by at least
           MIN_ALERT_REDUCTION, relative to the 13-feature set.
  ranking  In every attack scenario, pooled over steady strata, AUROC under the candidate
           is no more than MAX_AUROC_LOSS below the 13-feature set's.
  budget   In every attack scenario, detection at a 5% benign budget is no more than
           MAX_DETECTION_LOSS below the 13-feature set's.
  methods  Both capture methods, tcp and ptcp, must satisfy all three.

"keep" means adopt the candidate, "drop" means stay on all 13. `decide()` takes the pooled
summaries `experiments/feature_set.py` writes.
"""

MIN_ALERT_REDUCTION = 0.50   # candidate alerts <= (1 - this) * baseline alerts
MAX_AUROC_LOSS = 0.10
MAX_DETECTION_LOSS = 0.10
MIN_BENIGN_WINDOWS = 100     # pooled steady held-out windows needed per method
SCENARIOS = ("injection attack", "lidar attack", "nginx attack")
METHODS = ("tcp", "ptcp")
TOLERANCE = 1e-9


def decide(summary):
    """('keep' | 'drop' | 'undecidable', reasons) from pooled summaries.

    `summary[method]` has `benign_windows`, `persistent` = {"all": n, "candidate": n}, and
    for each scenario `auroc` = {"all": x, "candidate": x} and `detection` = the same.
    """
    reasons = []
    for method in METHODS:
        s = summary.get(method)
        if s is None or s.get("benign_windows", 0) < MIN_BENIGN_WINDOWS:
            return "undecidable", [f"{method}: fewer than {MIN_BENIGN_WINDOWS} steady benign windows"]
        base, cand = s["persistent"]["all"], s["persistent"]["candidate"]
        if base <= 0:
            return "undecidable", [f"{method}: the baseline raised no persistent alerts"]
        reduction = 1 - cand / base
        if reduction < MIN_ALERT_REDUCTION - TOLERANCE:
            reasons.append(f"{method}: persistent alerts fell {reduction:.2f}, "
                           f"below {MIN_ALERT_REDUCTION:.2f}")
        for scenario in SCENARIOS:
            row = s.get(scenario)
            if row is None:
                return "undecidable", [f"{method}: no {scenario} strata"]
            for key, limit, name in (("auroc", MAX_AUROC_LOSS, "AUROC"),
                                     ("detection", MAX_DETECTION_LOSS, "detection at 5%")):
                loss = row[key]["all"] - row[key]["candidate"]
                if loss > limit + TOLERANCE:
                    reasons.append(f"{method}/{scenario}: {name} fell {loss:.3f}, above {limit:.2f}")
    if reasons:
        return "drop", reasons
    return "keep", ["every scenario holds within the loss limits and persistent alerts fall "
                    f"by at least {MIN_ALERT_REDUCTION:.2f} under both methods"]
