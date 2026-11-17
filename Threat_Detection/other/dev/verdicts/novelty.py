"""The novelty-channel verdict, fixed before the measurement that judges it.

The windowed frequency score cannot see a sequence the machine never learned: `trace_states`
stops at the first missing transition, so such a trace adds less to the score. The candidate
adds a second channel, `methods.scores.NoveltyScorer` (off-machine traces in the 8 s clock),
with its own cutoff from the same held-out benign windows, and flags a window when either
channel is over its cutoff. "frequency" is today's detector, "either" the candidate.

These constants and `decide()` are the rule, committed before any window-level or alert-level
number of the candidate existed. It is not blind: a diagnostic on four tcp taps (the share of
traces that walk the whole machine, benign against attack) is what suggested the channel, so
the attack side is optimistic for those taps. `experiments/novelty.py` produces the rows.

Only tcp decides. The live monitor reads classic pcap, which is the tcp capture method, so a
ptcp result changes nothing that is deployed; ptcp rows are reported and judge nothing. Bulk
taps set no cutoff and decide nothing, as everywhere else.

The unit is the one FSR 3.2.1.5 now uses: a steady tap's attack recording is one event,
detected when a persistent alert is raised in its warm windows. An OR of two channels cannot
detect fewer events than one, so the gain clause asks for a real one, and the benign clauses
are where the candidate can fail.
"""

MIN_GAIN = 4               # more detected (tap, scenario) events under "either" than "frequency"
MAX_BENIGN_ALERTS = 0.10   # FSR 3.2.1.4: persistent alerts per scored held-out benign window
MAX_BENIGN_FLAGGED = 0.20  # pooled share of scored held-out benign windows flagged
MIN_HELD_TRACES = 30       # a tap with fewer held-out traces is left out and named
MIN_EVENTS = 10            # fewer eligible attack events than this is undecidable
DECIDING_METHOD = "tcp"


def decide(rows):
    """('keep' | 'drop' | 'undecidable', reasons) from experiments/novelty.py rows.

    A row is a mapping with `label`, `scenario`, `method`, `group`, `channel`, `held_traces`,
    `scored_windows`, `flagged` and `persistent`. "keep" means flag on either channel.
    """
    rows = [r for r in rows if r["method"] == DECIDING_METHOD and r["group"] == "steady"]
    thin = sorted({r["label"] for r in rows if r["held_traces"] < MIN_HELD_TRACES})
    rows = [r for r in rows if r["label"] not in thin]
    left_out = [f"left out, under {MIN_HELD_TRACES} held-out traces: {', '.join(thin)}"] if thin else []

    def cell(channel, benign):
        return [r for r in rows if r["channel"] == channel and (r["scenario"] == "benign") == benign]

    events = {c: {(r["label"], r["scenario"]) for r in cell(c, False) if r["persistent"] > 0}
              for c in ("frequency", "either")}
    n_events = len(cell("either", False))
    if n_events < MIN_EVENTS:
        return "undecidable", left_out + [f"{n_events} eligible attack events, fewer than {MIN_EVENTS}"]
    benign = cell("either", True)
    windows = sum(r["scored_windows"] for r in benign)
    if not windows:
        return "undecidable", left_out + ["no scored held-out benign window"]

    gain = len(events["either"]) - len(events["frequency"])
    alerts = sum(r["persistent"] for r in benign) / windows
    flagged = sum(r["flagged"] for r in benign) / windows
    summary = (f"{len(events['frequency'])} -> {len(events['either'])} of {n_events} events detected; "
               f"benign alerts {alerts:.3f}, flagged {flagged:.3f} of {windows} held-out windows")
    reasons = []
    if gain < MIN_GAIN:
        reasons.append(f"gain {gain} events, below {MIN_GAIN}")
    if alerts >= MAX_BENIGN_ALERTS:
        reasons.append(f"benign alerts {alerts:.3f}, not under {MAX_BENIGN_ALERTS:.2f}")
    if flagged > MAX_BENIGN_FLAGGED:
        reasons.append(f"benign flagged {flagged:.3f}, above {MAX_BENIGN_FLAGGED:.2f}")
    return ("drop" if reasons else "keep"), left_out + [summary] + reasons
