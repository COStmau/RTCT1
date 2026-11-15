"""Whether a role machine replaces a tap's own machine, decided on attacks the design never saw.

`methods/roles.py` learns one machine per role, pooled over the role's instances, with symbols
that read what the role's protocol exchanges. `experiments/roles.py` crosses the two choices
on a labelled session: whose traffic the machine is learned from ("own" tap or "pooled" role)
and what its symbols are ("flow", today's, or "role"). The incumbent is own / flow.

These constants and `decide()` are the rule. It was committed before any role machine was
scored on an attack; the role symbols were fixed from benign traffic alone. It is meant to be
applied to a *held-out* session (attack kinds not used while designing: the staged campaign).
Run on a development session it prints a reading that decides nothing.

Every attack at every tap of a role counts, pooled; nothing is limited to the attacks aimed
at the role. There is no fixed points bar. A challenger must:

  - detect at least as many attacks as the incumbent in every repeat of the attack suite, and
    more in total, so the gain is not one lucky round;
  - leave no larger a share of benign windows in alert, both later in the same session and in
    a second session recorded at another time, within TOLERANCE.

Detection counts alerts newly raised (experiments/session_score.judge). Among challengers
that qualify, the most attacks detected wins, then the quieter. None qualifying keeps the
incumbent.
"""

INCUMBENT = ("own", "flow")
TOLERANCE = 0.005          # share of benign windows in alert a challenger may exceed the incumbent by
MIN_ATTACKS = 20           # attack-at-tap pairs the incumbent must have been scored on
MIN_BENIGN_WINDOWS = 1000  # in each benign control
MIN_ROUNDS = 3


def decide(rows):
    """((source, symbols) | 'undecidable', reasons) from experiments/roles.py totals.

    A row is one variant: `source`, `symbols`, `rounds` (a list of (attacks, detected) per
    repeat), `benign_windows`, `benign_alert_windows`, and the same two with a `second_` prefix.
    """
    by = {(r["source"], r["symbols"]): r for r in rows}
    base = by.get(INCUMBENT)
    enough = (base is not None and len(base["rounds"]) >= MIN_ROUNDS
              and sum(a for a, _ in base["rounds"]) >= MIN_ATTACKS
              and min(base["benign_windows"], base["second_benign_windows"]) >= MIN_BENIGN_WINDOWS)
    if not enough:
        return "undecidable", [f"incumbent needs {MIN_ROUNDS} rounds, {MIN_ATTACKS} attacks and "
                               f"{MIN_BENIGN_WINDOWS} benign windows in each control"]
    quiet = lambda r, p="": r[p + "benign_alert_windows"] / r[p + "benign_windows"]
    total = lambda r: sum(d for _, d in r["rounds"])
    reasons, qualified = [], []
    for variant, row in sorted(by.items()):
        note = (f"{variant[0]}/{variant[1]}: {total(row)}/{sum(a for a, _ in row['rounds'])} attacks, per round "
                f"{[d for _, d in row['rounds']]}; benign in alert {quiet(row):.4f}, second session "
                f"{quiet(row, 'second_'):.4f}")
        if variant != INCUMBENT:
            behind = [i + 1 for i, ((_, d), (_, b)) in enumerate(zip(row["rounds"], base["rounds"])) if d < b]
            if behind or total(row) <= total(base):
                note += f" - no consistent gain (behind in rounds {behind})" if behind else " - no gain"
            elif quiet(row) > quiet(base) + TOLERANCE:
                note += " - louder on later benign"
            elif quiet(row, "second_") > quiet(base, "second_") + TOLERANCE:
                note += " - louder on the second session"
            else:
                qualified.append((total(row), -quiet(row), variant))
        reasons.append(note)
    return (max(qualified)[2] if qualified else INCUMBENT), reasons
