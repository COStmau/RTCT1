"""The sliced-flow verdict, fixed before the measurement that judges it.

`segment_flows` drops a flow that crosses a one-second boundary. On `pod-lidar`, `node-child1`
and `node-child2` the flows it keeps carry 0.2-1.3% of the bytes, so the machine never sees
the long streams. The candidate, `methods.pdfa.slice_flows`, cuts such a flow at the
boundaries instead and marks each slice new or continuing. "whole" is today's flow rule,
"sliced" the candidate; both are judged on the adopted detector, a flag on either channel
(`verdicts/novelty.py`).

These constants and `decide()` are the rule, committed before any score of a sliced machine
existed. What preceded it is the dropped-bytes diagnostic above and nothing else.
`experiments/slices.py` produces the rows.

Only tcp decides, and bulk taps decide nothing, for the reasons in `verdicts/novelty.py`. The
unit is the same event: a steady tap's attack recording with a persistent alert in its warm
windows. A tap is eligible when the sliced rule gives it MIN_HELD_TRACES held-out traces; the
whole-flow detector is read on those same taps, thin or not, because it is the incumbent
there. Slicing can lose events as well as gain them, so one clause protects the scenario the
detector is already good at.
"""

MIN_GAIN = 3               # more detected events under "sliced" than "whole"
MAX_SCENARIO_LOSS = 1      # no scenario may lose more events than this
MAX_BENIGN_ALERTS = 0.10   # FSR 3.2.1.4: persistent alerts per scored held-out benign window
MAX_BENIGN_FLAGGED = 0.20  # pooled share of scored held-out benign windows flagged
MIN_HELD_TRACES = 30
MIN_EVENTS = 10
DECIDING_METHOD = "tcp"
CHANNEL = "either"


def decide(rows):
    """('keep' | 'drop' | 'undecidable', reasons) from experiments/slices.py rows.

    A row is an experiments/novelty.py row plus `rule` ("whole" or "sliced").
    """
    rows = [r for r in rows if r["method"] == DECIDING_METHOD and r["group"] == "steady"
            and r["channel"] == CHANNEL]
    eligible = {r["label"] for r in rows if r["rule"] == "sliced" and r["held_traces"] >= MIN_HELD_TRACES}
    thin = sorted({r["label"] for r in rows} - eligible)
    rows = [r for r in rows if r["label"] in eligible]
    left_out = [f"left out, under {MIN_HELD_TRACES} sliced held-out traces: {', '.join(thin)}"] if thin else []

    def detected(rule):
        hits = {}
        for r in rows:
            if r["rule"] == rule and r["scenario"] != "benign":
                hits.setdefault(r["scenario"], set())
                if r["persistent"] > 0:
                    hits[r["scenario"]].add(r["label"])
        return hits

    whole, sliced = detected("whole"), detected("sliced")
    n_events = sum(1 for r in rows if r["rule"] == "sliced" and r["scenario"] != "benign")
    if n_events < MIN_EVENTS or set(whole) != set(sliced):
        return "undecidable", left_out + [f"{n_events} paired attack events, fewer than {MIN_EVENTS} "
                                          "or scenarios unpaired"]
    benign = [r for r in rows if r["rule"] == "sliced" and r["scenario"] == "benign"]
    windows = sum(r["scored_windows"] for r in benign)
    if not windows:
        return "undecidable", left_out + ["no scored held-out benign window"]

    before, after = sum(map(len, whole.values())), sum(map(len, sliced.values()))
    alerts = sum(r["persistent"] for r in benign) / windows
    flagged = sum(r["flagged"] for r in benign) / windows
    summary = (f"{before} -> {after} of {n_events} events detected; benign alerts {alerts:.3f}, "
               f"flagged {flagged:.3f} of {windows} held-out windows")
    reasons = []
    if after - before < MIN_GAIN:
        reasons.append(f"gain {after - before} events, below {MIN_GAIN}")
    for scenario in sorted(whole):
        loss = len(whole[scenario]) - len(sliced[scenario])
        if loss > MAX_SCENARIO_LOSS:
            reasons.append(f"{scenario} lost {loss} events, above {MAX_SCENARIO_LOSS}")
    if alerts >= MAX_BENIGN_ALERTS:
        reasons.append(f"benign alerts {alerts:.3f}, not under {MAX_BENIGN_ALERTS:.2f}")
    if flagged > MAX_BENIGN_FLAGGED:
        reasons.append(f"benign flagged {flagged:.3f}, above {MAX_BENIGN_FLAGGED:.2f}")
    return ("drop" if reasons else "keep"), left_out + [summary] + reasons
