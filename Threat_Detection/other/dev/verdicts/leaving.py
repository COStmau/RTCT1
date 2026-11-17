"""Which detector a role's taps should run, once a contract can say a conversation left it.

The held-out campaign (dev/PROGRESS.md, 2026-11-15) showed the role contract quiet across
sessions and blind in two places, both for one reason: the frequency score counts visits to
learned states, so a conversation that leaves the machine scores lower, not higher. A quantity
beyond anything learned was clipped into the top bin, and a peer that should not be there
added little to a count. `methods/roles.py` now gives a quantity above the learned range its
own symbol and counts the conversations that leave the contract; `experiments/leaving.py`
scores the variants.

These constants and `decide()` are the rule, committed before the change was scored on
anything. Both lab sessions of 2026-11-15 have been read, so a run on them is a development
reading that decides nothing; the rule is for a session recorded after the design is frozen.

The last rule compared a challenger with the incumbent and had no ceiling, so it chose a
detector in alert for an eighth of a benign session. Here no variant is privileged:

  - a variant is eligible only if its share of benign windows in alert is under
    MAX_BENIGN_ALERT in both controls (later in the session, and a second session);
  - an eligible variant wins if, against every other eligible variant, it detects at least
    as many attacks in every repeat of the suite and more in total;
  - no such variant means no winner, and what runs today stays.

Every attack at every tap counts, by alerts newly raised (experiments/session_score.judge).
"""

MAX_BENIGN_ALERT = 0.0465  # share of benign windows in alert; last year's best stated FPR
MIN_ATTACKS = 20           # attack-at-tap pairs each variant must have been scored on
MIN_BENIGN_WINDOWS = 1000  # in each benign control
MIN_ROUNDS = 3


def decide(rows):
    """(variant | 'none' | 'undecidable', reasons) from experiments/leaving.py totals.

    A row is one variant: `variant`, `rounds` (a list of (attacks, detected) per repeat),
    `benign_windows`, `benign_alert_windows`, and the same two with a `second_` prefix.
    """
    if not rows or any(len(r["rounds"]) < MIN_ROUNDS or sum(a for a, _ in r["rounds"]) < MIN_ATTACKS
                       or min(r["benign_windows"], r["second_benign_windows"]) < MIN_BENIGN_WINDOWS for r in rows):
        return "undecidable", [f"every variant needs {MIN_ROUNDS} rounds, {MIN_ATTACKS} attacks and "
                               f"{MIN_BENIGN_WINDOWS} benign windows in each control"]
    quiet = lambda r, p="": r[p + "benign_alert_windows"] / r[p + "benign_windows"]
    hits = lambda r: [d for _, d in r["rounds"]]
    eligible = [r for r in rows if max(quiet(r), quiet(r, "second_")) < MAX_BENIGN_ALERT]
    reasons = [f"{r['variant']}: {sum(hits(r))}/{sum(a for a, _ in r['rounds'])} attacks, per round {hits(r)}; "
               f"benign in alert {quiet(r):.4f}, second session {quiet(r, 'second_'):.4f}"
               + ("" if r in eligible else f" - not under {MAX_BENIGN_ALERT}") for r in rows]
    beats = lambda a, b: all(x >= y for x, y in zip(hits(a), hits(b))) and sum(hits(a)) > sum(hits(b))
    winners = [a["variant"] for a in eligible if all(beats(a, b) for b in eligible if b is not a)]
    return (winners[0] if winners else "none"), reasons
