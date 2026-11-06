"""The load-versus-behavior alert verdict, fixed before the measurement that judges it.

The idea: keep two channels. The load channel is the z-score detector (volume, size, timing,
protocol mix). The behavior channel is the windowed SEQUENT score of the PDFA, which sees the
order and shape of conversations. A load-only flag is informational; a behavior flag
escalates. That only works if two things hold, and they are judged separately.

Claim A (bulk taps). On the three bulk-transfer taps the behavior score stays quiet through
the regime change while the z-score does not. Measured as the AUROC of "post-onset window
versus pre-onset window" on the benign recording: the z-score is the control and must see the
step; the behavior score must not.

Claim B (steady taps). Escalating only on the behavior channel does not give up the attacks
the z-score catches, and it does cost fewer benign windows. Measured on the tcp method (the
one the visualization presents), over warm attack windows, with a window the behavior score
could not score counted as "not escalated", never dropped.

These constants and `decide()` were committed before any number of this comparison existed,
so moving a threshold later means editing a committed file, not recalling an intention.
`experiments/load_behavior.py` produces the rows this reads. The deciding behavior score is
the windowed SEQUENT score at the page's calibration; the trace-likelihood detector is
reported beside it and decides nothing.

Outcomes: "separate" (A and B hold: gate escalation on behavior), "tag" (A holds, B fails:
suppress nothing, label each alert load-only or behavior-involved), "drop" (A fails), and
"undecidable" (too little data to judge A).
"""

# Claim A
QUIET_BAND = 0.15           # behavior |AUROC - 0.5| at most this on a bulk tap is "quiet"
CONTROL_MIN_AUROC = 0.80    # the z-score must separate post from pre at least this well, or the
                            # tap tells us nothing (the step was not visible to the control)
MIN_SIDE_WINDOWS = 5        # scored windows needed on each side of the onset
MIN_DECIDABLE_TAPS = 2      # decidable bulk taps needed for a verdict on A

# Claim B
MIN_DETECTION_RATIO = 0.50  # behavior detection / z-score detection, in every scenario
MIN_WARM_WINDOWS = 30       # pooled warm attack windows a scenario needs to be judged
SCENARIOS = ("injection attack", "lidar attack", "nginx attack")   # the manifest's names


def claim_a(bulk):
    """('pass' | 'fail' | 'undecidable', reasons) from per-bulk-tap rows.

    A row has `label`, `behavior_auroc`, `z_auroc`, `n_pre`, `n_post`: the AUROC of post
    versus pre-onset windows for each channel, and the scored behavior windows on each side.
    A tap whose control cannot see the step, or with too few windows, is set aside by name.
    """
    decidable, reasons, loud = [], [], []
    for row in bulk:
        label = row.get("label")
        behavior, control = row.get("behavior_auroc"), row.get("z_auroc")
        if min(row.get("n_pre", 0), row.get("n_post", 0)) < MIN_SIDE_WINDOWS:
            reasons.append(f"{label}: fewer than {MIN_SIDE_WINDOWS} scored windows on a side")
        elif behavior is None or behavior != behavior or control is None or control != control:
            reasons.append(f"{label}: no AUROC")
        elif control < CONTROL_MIN_AUROC:
            reasons.append(f"{label}: z-score control AUROC {control:.3f} below "
                           f"{CONTROL_MIN_AUROC:.2f}, step not visible")
        else:
            decidable.append(row)
            if abs(behavior - 0.5) > QUIET_BAND:
                loud.append(f"{label}: behavior AUROC {behavior:.3f} is outside "
                            f"0.5 +/- {QUIET_BAND:.2f}")
    if loud:
        return "fail", loud
    if len(decidable) < MIN_DECIDABLE_TAPS:
        return "undecidable", reasons + [f"{len(decidable)} decidable bulk taps, fewer than "
                                         f"{MIN_DECIDABLE_TAPS}"]
    return "pass", [f"{len(decidable)} decidable bulk taps, all within 0.5 +/- {QUIET_BAND:.2f}"]


def claim_b(attacks, benign):
    """('pass' | 'fail' | 'undecidable', reasons) from pooled steady tcp counts.

    `attacks`: rows with `scenario`, `warm` (warm attack windows), `z_flagged`,
    `behavior_flagged` (windows flagged, missing counted as not flagged).
    `benign`: rows with `windows`, `z_flagged`, `behavior_flagged` over the held-out windows.
    """
    reasons = []
    for scenario in SCENARIOS:
        rows = [r for r in attacks if r.get("scenario") == scenario]
        warm = sum(r["warm"] for r in rows)
        if warm < MIN_WARM_WINDOWS:
            return "undecidable", [f"{scenario}: {warm} warm windows, fewer than "
                                   f"{MIN_WARM_WINDOWS}"]
        z = sum(r["z_flagged"] for r in rows) / warm
        behavior = sum(r["behavior_flagged"] for r in rows) / warm
        if z <= 0 or behavior / z < MIN_DETECTION_RATIO:
            reasons.append(f"{scenario}: behavior detection {behavior:.3f} is "
                           f"{(behavior / z if z else 0):.2f} of the z-score's {z:.3f}, "
                           f"below {MIN_DETECTION_RATIO:.2f}")
    windows = sum(r["windows"] for r in benign)
    if windows == 0:
        return "undecidable", ["no held-out benign windows"]
    z_rate = sum(r["z_flagged"] for r in benign) / windows
    behavior_rate = sum(r["behavior_flagged"] for r in benign) / windows
    if behavior_rate >= z_rate:
        reasons.append(f"benign: behavior flags {behavior_rate:.3f} of held-out windows, "
                       f"not fewer than the z-score's {z_rate:.3f}")
    if reasons:
        return "fail", reasons
    return "pass", [f"every scenario keeps at least {MIN_DETECTION_RATIO:.2f} of the z-score's "
                    f"detection, benign rate {behavior_rate:.3f} against {z_rate:.3f}"]


def decide(bulk, attacks, benign):
    """('separate' | 'tag' | 'drop' | 'undecidable', reasons), with each claim's verdict."""
    a, a_reasons = claim_a(bulk)
    b, b_reasons = claim_b(attacks, benign)
    reasons = [f"claim A {a}: " + "; ".join(a_reasons), f"claim B {b}: " + "; ".join(b_reasons)]
    if a == "fail":
        return "drop", reasons
    if a == "undecidable" or b == "undecidable":
        return "undecidable", reasons
    return ("separate" if b == "pass" else "tag"), reasons
