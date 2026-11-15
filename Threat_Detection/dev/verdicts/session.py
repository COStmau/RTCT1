"""Which detector the live monitor should run, decided on one continuous labelled session.

The per-recording sweeps cannot tell an attack from the difference between two recording
sessions (`experiments/benign_control.py`), so the novelty channel and the sliced flow rule
are judged again here, on a recording that holds its own control: benign traffic learned from,
more benign traffic, and labelled attacks inside it. `experiments/session_score.py` learns
from the first minutes of each tap and scores the rest.

These constants and `decide()` are the rule, committed while the session it will first judge
(local k3d, 12 minutes benign, then 12 attacks) was still being recorded, before any of it
was read.

A variant is a flow rule and a channel. The incumbent is whole flows with the frequency
channel, the detector before 2026-11-14. An attack counts at a tap only if the tap scored a
window during it, and it is detected only by an alert *newly raised*: a persistent alert in
the attack or just after it, with none in the seconds before, so a tap that was already
alerting gets no credit. Benign windows are the scored ones after learning and away from
every attack.

A challenger replaces the incumbent only if it is clean enough and clearly better. Clean
enough is last year's best stated false-positive figure, which is stricter than FSR 3.2.1.4.
Clearly better is an absolute gain in the share of attacks detected. Among challengers that
qualify, the one that detects most wins; none qualifying leaves the incumbent, and then the
novelty channel comes out of the live detector.
"""

INCUMBENT = ("whole", "frequency")
MAX_BENIGN_ALERT = 0.0465   # share of benign windows in alert; last year's best stated FPR
MIN_GAIN = 0.15             # absolute gain in share of attacks detected, over the incumbent
MIN_ATTACKS = 20            # fewer attack-at-tap pairs than this for the incumbent is undecidable
MIN_BENIGN_WINDOWS = 1000


def decide(rows):
    """((rule, channel) | 'undecidable', reasons) from experiments/session_score.py totals.

    A row is a mapping with `rule`, `channel`, `attacks`, `detected`, `benign_windows` and
    `benign_alert_windows`, one per variant, pooled over taps.
    """
    by = {(r["rule"], r["channel"]): r for r in rows}
    base = by.get(INCUMBENT)
    if base is None or base["attacks"] < MIN_ATTACKS or base["benign_windows"] < MIN_BENIGN_WINDOWS:
        return "undecidable", [f"incumbent needs {MIN_ATTACKS} attacks and {MIN_BENIGN_WINDOWS} benign windows"]
    rate = lambda r: r["detected"] / r["attacks"]
    quiet = lambda r: r["benign_alert_windows"] / r["benign_windows"]
    reasons, qualified = [], []
    for variant, row in sorted(by.items()):
        note = (f"{variant[0]}/{variant[1]}: {row['detected']}/{row['attacks']} attacks ({rate(row):.2f}), "
                f"benign in alert {quiet(row):.4f}")
        if variant != INCUMBENT and row["attacks"] >= MIN_ATTACKS and row["benign_windows"] >= MIN_BENIGN_WINDOWS:
            if quiet(row) >= MAX_BENIGN_ALERT:
                note += f" - not under {MAX_BENIGN_ALERT}"
            elif rate(row) - rate(base) < MIN_GAIN:
                note += f" - gain {rate(row) - rate(base):+.2f}, below {MIN_GAIN}"
            else:
                qualified.append((rate(row), -quiet(row), variant))
        reasons.append(note)
    return (max(qualified)[2] if qualified else INCUMBENT), reasons
