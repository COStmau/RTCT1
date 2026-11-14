"""Scoring: how anomalous a trace is, and how anomalous a window is.

Two questions, both answered here. How unlikely is this trace under the learned machine
(``trace_score``)? And how much more often does it visit states than training said it would
(SEQUENT's frequency score), counted either cumulatively or over a trailing ``FORGET_SECONDS``
clock so a burst expires instead of accumulating forever.

Every score is oriented so higher means more anomalous, the same convention the detectors in
``detectors`` use.
"""
from collections import Counter, deque

import numpy as np
import pandas as pd

from core.data_io import load_capture, resolve_output, timebase_issues
from core.detectors import BENIGN_QUANTILE, flag_stats
from core.features import WINDOW_SIZE
from methods.pdfa import (MISSING_PROB, PDFA, TRACE_LEN, encode, fit_model,
                          load_flow_packets, make_flows, segment_flows, split_flows)

# The anomaly clock: a state visit counts only while it is inside this trailing window of
# observed seconds, so an attack's excess visits expire instead of accumulating forever.
# Sized against the dataset: captures run 51-69 s, so a 25 s window would hold an attack
# past the end of most recordings and release could never be observed inside one. 8 s holds
# a 5 s LiDAR replay loop and leaves room for a few clean windows of runway after it.
FORGET_SECONDS = 8.0

# Where a frequency scorer's training count per state comes from. "visits" counts the start
# state once per training trace start, which a test trace never adds; "entries" counts only
# transitions into a state, the same thing a test trace's visits count. Entries won under the
# rule root_verdict.py fixed before measuring (windowed_scores.py, PROGRESS.md 2026-11-03).
TRAIN_COUNTS = "entries"

PAIR_CSV = "statemachine_pair.csv"


def trace_score(pdfa, trace):
    """Mean log transition probability; unseen symbols take the floor."""
    if not trace:
        return float("-inf")
    node = pdfa.root
    total = 0.0
    for symbol in trace:
        if node is None:
            total += np.log(MISSING_PROB)
            continue
        child, probability = pdfa.transition(node, symbol)
        if child is None:
            total += np.log(MISSING_PROB)
            node = None
        else:
            total += np.log(probability)
            node = child
    return total / len(trace)


def pdfa_states_in_order(pdfa):
    """States breadth-first from the start state, so ids are deterministic."""
    order, queue, seen = [], [pdfa.root], {id(pdfa.root)}
    while queue:
        node = queue.pop(0)
        order.append(node)
        for symbol in sorted(pdfa.probs[id(node)][1]):
            child = pdfa.probs[id(node)][1][symbol][0]
            if id(child) not in seen:
                seen.add(id(child))
                queue.append(child)
    return order


def pdfa_graph(pdfa):
    """The machine as JSON for a live viewer: states (id, visits) and edges (src, dst, symbol, prob).

    `pdfa_states_in_order` fixes the ids breadth-first from the root, so state 0 is the start
    state and the layout is stable across calls. `prob` is the transition probability; `symbol`
    is the flow symbol that walks it.
    """
    order = pdfa_states_in_order(pdfa)
    ids = {id(node): index for index, node in enumerate(order)}
    edges = []
    for index, node in enumerate(order):
        _, outgoing = pdfa.probs[id(node)]
        for symbol, (child, probability) in sorted(outgoing.items()):
            edges.append({"src": index, "dst": ids[id(child)], "symbol": symbol,
                          "prob": round(float(probability), 4)})
    return {"states": [{"id": index, "visits": int(node.visits)} for index, node in enumerate(order)],
            "edges": edges}


def plot_pdfa(pdfa, path=None, min_label_prob=0.25, label=None):
    """State graph: node size is visits, edge width is probability.

    Sized for a presentation slide (1.6:1, dpi 200) rather than a figure in a
    document, so the text stays readable when the slide is projected. Only edges
    at or above `min_label_prob` get a symbol label; the rest still draw, so nothing
    structural disappears. `label` names the capture point in the title, for a
    one-machine-per-point set.

    Edge labels are placed off the exact arc midpoint: a transition and its reverse
    bend the same way in matplotlib's arc3, so a shared midpoint would stack both
    labels on one spot, and a self-loop's midpoint is the state itself.
    """
    import matplotlib.pyplot as plt

    order = pdfa_states_in_order(pdfa)
    ids = {id(node): i for i, node in enumerate(order)}
    angles = np.linspace(0, 2 * np.pi, len(order), endpoint=False) + np.pi / 2
    pos = {i: (np.cos(a), np.sin(a)) for i, a in enumerate(angles)}
    visits = np.array([node.visits for node in order], dtype=float)

    fig, ax = plt.subplots(figsize=(8.4, 5.25))
    # States sit on the unit circle, so the lowest is at y = -1: pad the frame below
    # that and put the key in the empty bottom-left corner instead of over a state.
    ax.set_xlim(-1.52, 1.28)
    ax.set_ylim(-1.5, 1.45)
    loop_rad, pair_rad = 0.4, 0.15
    loop_label_radius = 1.34  # clear of the biggest state circle and its loop
    for i, node in enumerate(order):
        _, outgoing = pdfa.probs[id(node)]
        for symbol, (child, probability) in sorted(outgoing.items()):
            j = ids[id(child)]
            # Same rad for both directions on purpose: reversing the endpoints flips
            # the offset arc3 applies, so the two curves come out on opposite sides.
            rad = loop_rad if i == j else pair_rad
            ax.annotate("", xy=pos[j], xytext=pos[i],
                        arrowprops={"arrowstyle": "->", "color": "#1f77b4",
                                    "linewidth": 0.8 + 3.5 * probability,
                                    "alpha": 0.25 + 0.75 * probability,
                                    "connectionstyle": f"arc3,rad={rad}",
                                    "shrinkA": 18, "shrinkB": 18})
            if probability >= min_label_prob:
                dx, dy = pos[j][0] - pos[i][0], pos[j][1] - pos[i][1]
                if i == j:
                    x, y = pos[i][0] * loop_label_radius, pos[i][1] * loop_label_radius
                else:
                    # Ride the arc outward, past the midpoint where its reverse sits.
                    x = (pos[i][0] + pos[j][0]) / 2 + 1.2 * rad * dy
                    y = (pos[i][1] + pos[j][1]) / 2 - 1.2 * rad * dx
                ax.text(x, y, f"{symbol} {probability:.2f}", fontsize=9,
                        ha="center", va="center",
                        bbox={"facecolor": "white", "edgecolor": "none",
                              "alpha": 0.8, "pad": 1})
    sizes = 500 + 2800 * (visits / visits.max() if visits.max() else 1)
    for i, node in enumerate(order):
        ax.scatter([pos[i][0]], [pos[i][1]], s=sizes[i], color="#deebf7",
                   edgecolors="#1f77b4", linewidths=2, zorder=3)
        ax.text(pos[i][0], pos[i][1], f"{i}\n{node.visits}", fontsize=12,
                fontweight="bold", ha="center", va="center", zorder=4)
    ax.scatter([], [], s=200, color="#deebf7", edgecolors="#1f77b4",
               label="state (id over visits)")
    ax.plot([], [], color="#1f77b4", linewidth=2.5, label="transition (width = probability)")
    title = (f"{label}\n" if label else "") + \
            f"Learned PDFA: {len(order)} states, " \
            f"{sum(len(pdfa.probs[id(n)][1]) for n in order)} transitions" \
            f" | edge labels >= {min_label_prob:.0%}"
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.legend(fontsize=10, loc="lower left")
    ax.set_axis_off()
    fig.tight_layout()
    out = resolve_output(path or "statemachine_graph.png")
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"Wrote {out}")
    return out


def score_flows(model, flows):
    """(end-flow start time, trace score) for each sliding trace."""
    symbols = list(encode(flows, model["enc"]))
    return [(flows["start_ts"].iloc[i + model["trace_len"] - 1],
             trace_score(model["pdfa"], tuple(symbols[i:i + model["trace_len"]])))
            for i in range(len(symbols) - model["trace_len"] + 1)]


def trace_states(pdfa, trace):
    """The states a trace walks, in order, stopping where the model has no transition."""
    states, node = [], pdfa.root
    for symbol in trace:
        child, _ = pdfa.transition(node, symbol)
        if child is None:
            break
        states.append(child)
        node = child
    return states


def state_train_counts(pdfa, source=TRAIN_COUNTS):
    """{state key: training count}, from `node.visits` or from entries into the state.

    The two differ only where training traces started: every state but the start state is
    entered exactly as often as it is visited, and the start state's visits add one per
    training trace.
    """
    if source == "visits":
        return {id(node): node.visits for node, _ in pdfa.probs.values()}
    if source != "entries":
        raise ValueError(f"Unknown training count source: {source!r}")
    counts = {id(node): 0 for node, _ in pdfa.probs.values()}
    for node, outgoing in pdfa.probs.values():
        for symbol, (child, _) in outgoing.items():
            counts[id(child)] += node.edge[symbol]
    return counts


class FrequencyScorer:
    """SEQUENT's rolling score: test-time state frequency against a fixed training count.

    One state contributes `log(freq_test + 1) - log(freq_train + 1) + log(total_train + 1)
    + log(states_seen + 1)`, and a trace's score is the sum over the states it visits. The
    test counter accumulates across every trace scored, so a scorer built per chunk is not
    the same detector as one scorer held for the whole stream, and a burst never stops
    counting. `WindowedFrequencyScorer` is the bounded version.
    """

    def __init__(self, pdfa, train_counts=TRAIN_COUNTS):
        self.pdfa = pdfa
        self.train = state_train_counts(pdfa, train_counts)
        self.total_train = sum(self.train.values())
        self.test = Counter()
        self.states_seen = 0

    def score(self, trace):
        total = 0.0
        for state in trace_states(self.pdfa, trace):
            key = id(state)
            total += (np.log(self.test[key] + 1) - np.log(self.train.get(key, 0) + 1)
                      + np.log(self.total_train + 1) + np.log(self.states_seen + 1))
            self.test[key] += 1
            self.states_seen = len(self.test)
        return float(total)


class WindowedFrequencyScorer:
    """SEQUENT's score with the test counter bounded to the last `forget_seconds`.

    The cumulative `FrequencyScorer` counts every visit for the life of the stream, so one
    burst keeps the score elevated for good and recovery is unobservable. Here a visit stops
    counting once it is older than the window, so the score depends only on the traces seen
    in the trailing `forget_seconds` and falls back to baseline after a burst leaves it.

    The per-state arithmetic and update order are exactly `FrequencyScorer`'s (score a state,
    then count it, so a later state in the same trace sees the earlier one), and
    `len(self.counts)` plays the part of `states_seen` inside the window. With an infinite
    window the two scorers return bit-identical scores; the tests hold that.
    """

    def __init__(self, pdfa, forget_seconds=FORGET_SECONDS, train_counts=TRAIN_COUNTS):
        if not forget_seconds > 0:
            raise ValueError("forget_seconds must be positive.")
        self.pdfa = pdfa
        self.forget_seconds = float(forget_seconds)
        self.train = state_train_counts(pdfa, train_counts)
        self.total_train = sum(self.train.values())
        self.visits = deque()          # (when, state key), oldest first
        self.counts = Counter()
        self.last_when = float("-inf")

    def _expire(self, when):
        """Drop visits older than the trailing window ending at `when`; return them."""
        oldest_allowed = when - self.forget_seconds
        expired = []
        while self.visits and self.visits[0][0] < oldest_allowed:
            expired.append(self.visits.popleft())
            key = expired[-1][1]
            self.counts[key] -= 1
            if not self.counts[key]:
                del self.counts[key]
        return expired

    def score_terms(self, trace, when):
        """Per visited state, the four terms of its score; and the visits expired first.

        Terms are (log(test+1), -log(train+1), log(total_train+1), log(states_seen+1)), so
        a state's contribution is their sum and the trace's score is the sum over states.
        """
        when = float(when)
        if when < self.last_when:
            raise ValueError("Traces must arrive in time order.")
        self.last_when = when
        expired = self._expire(when)
        terms = []
        for state in trace_states(self.pdfa, trace):
            key = id(state)
            terms.append((np.log(self.counts[key] + 1), -np.log(self.train.get(key, 0) + 1),
                          np.log(self.total_train + 1), np.log(len(self.counts) + 1)))
            self.visits.append((when, key))
            self.counts[key] += 1
        return terms, expired

    def score(self, trace, when):
        """Anomaly score of one trace observed at `when` seconds; higher is more anomalous."""
        terms, _ = self.score_terms(trace, when)
        return float(sum(map(sum, terms)))


def frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds=None,
                               train_counts=TRAIN_COUNTS):
    """Most anomalous state-frequency score per window; NaN where no trace ended.

    `forget_seconds=None` is cumulative SEQUENT; a number is the windowed scorer. Each trace
    is timed by the start of its last flow, the same convention `flags_for_windows` uses.
    """
    if forget_seconds is None:
        scorer = FrequencyScorer(model["pdfa"], train_counts)
        score = lambda trace, when: scorer.score(trace)
    else:
        score = WindowedFrequencyScorer(model["pdfa"], forget_seconds, train_counts).score
    symbols = list(encode(flows, model["enc"]))
    trace_len = model["trace_len"]
    scores = np.full(n_windows, np.nan)
    for index in range(len(symbols) - trace_len + 1):
        when = float(flows["start_ts"].iloc[index + trace_len - 1]) - t0
        value = score(tuple(symbols[index:index + trace_len]), when)
        window = int(when // WINDOW_SIZE)
        if 0 <= window < n_windows:
            scores[window] = value if np.isnan(scores[window]) else max(scores[window], value)
    return scores


def warm_from(forget_seconds=FORGET_SECONDS):
    """First window of a cold-started capture whose clock has run a full `forget_seconds`.

    A windowed scorer starts with an empty clock, so its first seconds understate the
    traffic; anything compared to a warm reference has to skip them.
    """
    return int(np.ceil(forget_seconds / WINDOW_SIZE))


def held_out_scores(model, flows, holdout, t0, n_windows, forget_seconds=FORGET_SECONDS,
                    train_counts=TRAIN_COUNTS):
    """Held-out benign window scores on a warm clock, as viz.build_page calibrates.

    Every benign flow is scored in order, training flows first, and only the windows after
    the one the train/holdout split falls in are kept; NaN where no trace ended.
    """
    first_held = int((float(holdout["start_ts"].iloc[0]) - t0) // WINDOW_SIZE)
    warm = frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds, train_counts)
    return warm[first_held + 1:]


def frequency_cutoff(holdout_scores, quantile=BENIGN_QUANTILE):
    """Frequency-score cutoff flagging the top `quantile` of held-out benign; NaN ignored.

    Frequency scores rise with anomaly, so the cut is the upper tail, unlike `score_cutoff`.
    """
    scores = np.asarray(holdout_scores, dtype=float)
    if not np.isfinite(scores).any():
        raise ValueError("No held-out benign frequency scores to calibrate the cutoff.")
    return float(np.nanquantile(scores, 1 - quantile))


def score_cutoff(holdout_scores, quantile=BENIGN_QUANTILE):
    """Trace-score cutoff that flags the worst `quantile` of held-out benign."""
    if not holdout_scores:
        raise ValueError("No held-out benign traces to calibrate the cutoff.")
    return float(np.quantile([s for _, s in holdout_scores], quantile))


def flags_for_windows(scored, t0, n_windows, cutoff, window_size=WINDOW_SIZE):
    """Windows flagged by any below-cutoff trace ending inside them."""
    flags = pd.Series(False, index=range(n_windows))
    for start_ts, score in scored:
        window = int((start_ts - t0) // window_size)
        if 0 <= window < n_windows and score < cutoff:
            flags.iloc[window] = True
    return flags


def n_windows_for(packets, window_size=WINDOW_SIZE):
    return int(packets["ts"].max() - packets["ts"].min()) // int(window_size) + 1


def score_pair(benign_path, attack_path, encoding="percentile"):
    """Fit on the first 70% of benign flows; flag held-out benign and attack.

    Flows crossing a window boundary are dropped before symbolization, so a partial
    segment never becomes a symbol and never reaches a trace.
    """
    benign = load_flow_packets(benign_path)
    benign_t0 = benign["ts"].min()
    benign_flows, _ = segment_flows(make_flows(benign), benign_t0)
    train, holdout = split_flows(benign_flows)
    model = fit_model(train, encoding=encoding)
    cutoff = score_cutoff(score_flows(model, holdout))
    benign_flags = flags_for_windows(score_flows(model, holdout), benign_t0,
                                     n_windows_for(benign), cutoff)
    attack = load_flow_packets(attack_path)
    attack_t0 = attack["ts"].min()
    attack_flows, _ = segment_flows(make_flows(attack), attack_t0)
    return benign_flags, flags_for_windows(score_flows(model, attack_flows), attack_t0,
                                           n_windows_for(attack), cutoff)


def statemachine_rows(described, method="tcp", encoding="percentile", flag_bits=False):
    """One flag_stats row per stratum, same shape as compare.compare_detectors.

    `flag_bits` adds TCP SYN/RST presence to the symbol; the per-window boolean Series in
    this function is also called `flags`, so the switch keeps a distinct name.
    """

    packets = {}
    for _, capture in described.iterrows():
        key = (capture["scenario"], capture["label"], capture["method"])
        if capture["method"] != method:
            continue
        base = load_capture(capture["path"])
        issues = timebase_issues(base)
        if not issues["usable"]:
            packets[key] = None
            continue
        packets[key] = load_flow_packets(capture["path"], flags=flag_bits)
    attacks = [s for s in sorted(described["scenario"].unique()) if s != "benign"]
    labels = sorted(described[described["method"].eq(method)]["label"].unique())
    rows, excluded = [], []
    for label in labels:
        reference = packets.get(("benign", label, method))
        if reference is None:
            excluded.append(label)
            continue
        try:
            reference_t0 = reference["ts"].min()
            reference_flows, reference_dropped = segment_flows(make_flows(reference),
                                                               reference_t0)
            train, holdout = split_flows(reference_flows)
            model = fit_model(train, encoding=encoding, flags=flag_bits)
            cutoff = score_cutoff(score_flows(model, holdout))
        except ValueError as error:
            excluded.append(f"{label} ({error})")
            continue
        targets = [("benign", holdout, reference, reference_dropped)] + [
            (s, None, packets.get((s, label, method)), None) for s in attacks]
        for scenario, holdout_flows, target, dropped in targets:
            if target is None:
                excluded.append(f"{scenario}/{label} (no capture)")
                continue
            target_t0 = target["ts"].min()
            if scenario == "benign":
                scored = score_flows(model, holdout_flows)
            else:
                target_flows, dropped = segment_flows(make_flows(target), target_t0)
                scored = score_flows(model, target_flows)
                if not scored:
                    excluded.append(f"{scenario}/{label} (too few flows)")
                    continue
            flags = flags_for_windows(scored, target_t0, n_windows_for(target), cutoff)
            rows.append({"detector": "state_machine", "scenario": scenario,
                         "label": label, "method": method,
                         "states": model["pdfa"].n_states,
                         "dropped_segments": dropped,
                         "flags": bool(flag_bits), **flag_stats(flags)})
    if excluded:
        print(f"excluded captures: {len(excluded)} ({', '.join(sorted(set(excluded)))})")
    return (pd.DataFrame(rows)
            .sort_values(["label", "scenario"])
            .reset_index(drop=True))


def write_pair(benign_flags, attack_flags, path=None):
    """The two per-window flag series as one CSV: one row per window, benign and attack."""
    pair = pd.DataFrame([
        {"scenario": "benign", "window": w, "flagged": bool(f)}
        for w, f in benign_flags.items()] + [
        {"scenario": "attack", "window": w, "flagged": bool(f)}
        for w, f in attack_flags.items()])
    out_file = resolve_output(path or PAIR_CSV)
    pair.to_csv(out_file, index=False)
    return out_file
