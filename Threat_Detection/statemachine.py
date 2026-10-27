"""State-machine anomaly detection after Cao, Blaise, Verwer and Rebecchi (ARES 2022).

Packet captures become flows (5-tuple, like their NetFlow input). Each flow
becomes one symbol, ``PROTO_BYTES_DURATION``, with the two sizes percentile
binned on benign traffic. A fixed sliding window cuts the symbol stream into
traces. A probabilistic DFA is learned from benign traces with the classic
ALERGIA state-merging test, and new traces score by mean log transition
probability. Traces below the 5th percentile of held-out benign scores flag
their window, the same budget convention compare.py uses for the forest/SVM.

Run it with:  .venv/bin/python demo.py 3      (the pair demo)
              .venv/bin/python statemachine.py  (every stratum, one row each)
"""
from collections import Counter, deque

import numpy as np
import pandas as pd

from data_io import MANIFEST_NAME, load_capture, load_manifest, resolve_output, timebase_issues
from detectors import BENIGN_QUANTILE, flag_stats
from features import BENIGN_TRAIN_FRACTION, WINDOW_SIZE

FLOW_COLUMNS = ["ts", "frame_len", "src_ip", "dst_ip", "src_port",
                "dst_port", "proto"]
FLAG_COLUMNS = ["tcp_syn", "tcp_rst"]
TRACE_LEN = 5
NBINS = 4
ALERGIA_ALPHA = 0.05
MISSING_PROB = 1e-6
PAIR_CSV = "statemachine_pair.csv"
SWEEP_CSV = "statemachine_sweep.csv"

# The anomaly clock: a state visit counts only while it is inside this trailing window of
# observed seconds, so an attack's excess visits expire instead of accumulating forever.
# Sized against the dataset: captures run 51-69 s, so a 25 s window would hold an attack
# past the end of most recordings and release could never be observed inside one. 8 s holds
# a 5 s LiDAR replay loop and leaves room for a few clean windows of runway after it.
FORGET_SECONDS = 8.0


def load_flow_packets(path, flags=False):
    """Read only the packet columns flows are built from; flag columns when asked."""
    columns = FLOW_COLUMNS + (FLAG_COLUMNS if flags else [])
    return pd.read_csv(path, usecols=columns, low_memory=False)


def make_flows(packets):
    """One row per 5-tuple flow: start time, protocol, endpoints, bytes, duration, flags."""
    required = set(FLOW_COLUMNS) - {"proto"}
    missing = required - set(packets.columns)
    if missing:
        raise ValueError(f"Missing packet columns: {', '.join(sorted(missing))}")
    if packets.empty:
        raise ValueError("No packets available to build flows.")
    frames = packets.copy()
    frames["ts"] = pd.to_numeric(frames["ts"], errors="raise")
    frames["frame_len"] = pd.to_numeric(frames["frame_len"], errors="raise")
    if not np.isfinite(frames[["ts", "frame_len"]].to_numpy()).all():
        raise ValueError("Packet columns ts/frame_len contain missing or nonfinite values.")
    has_flags = all(column in frames.columns for column in FLAG_COLUMNS)
    if has_flags:
        for column in FLAG_COLUMNS:
            frames[column] = pd.to_numeric(frames[column], errors="raise")
    grouped = frames.groupby(["src_ip", "dst_ip", "src_port", "dst_port",
                              "proto"], dropna=False)
    aggregations = {
        "start_ts": ("ts", "min"),
        "bytes": ("frame_len", "sum"),
        "duration": ("ts", lambda s: float(s.max() - s.min())),
        "proto": ("proto", "first"),
        "src_ip": ("src_ip", "first"),
        "dst_ip": ("dst_ip", "first"),
    }
    if has_flags:
        aggregations["syn_seen"] = ("tcp_syn", "max")
        aggregations["rst_seen"] = ("tcp_rst", "max")
    flows = grouped.agg(**aggregations).reset_index(drop=True)
    if has_flags:
        flows["syn_seen"] = flows["syn_seen"].astype(bool)
        flows["rst_seen"] = flows["rst_seen"].astype(bool)
    return flows.sort_values("start_ts").reset_index(drop=True)


def segment_flows(flows, t0, window_size=WINDOW_SIZE):
    """Flows lying inside a single window, plus the number dropped.

    A flow cut by a window boundary would carry a partial byte count and a partial
    duration, which is an artifact of where the slice fell rather than of behaviour, so it
    is dropped instead of symbolized. The count comes back with the kept flows so a caller
    can report it rather than lose it.
    """
    start = np.floor((flows["start_ts"] - t0) / window_size)
    end = np.floor((flows["start_ts"] + flows["duration"] - 1e-9 - t0) / window_size)
    crossing = start != end
    return flows[~crossing].reset_index(drop=True), int(crossing.sum())


def fit_percentile(flows, nbins=NBINS, flags=False):
    """Quantile bin edges for bytes and duration, fitted on benign flows."""
    enc = {"kind": "percentile", "flags": bool(flags)}
    for column in ("bytes", "duration"):
        cuts = np.quantile(flows[column].to_numpy(dtype=float),
                           np.linspace(0, 1, nbins + 1))
        enc[column] = np.unique(cuts)
    return enc


def fit_frequency(flows, nbins=NBINS, min_count=3, flags=False):
    """Frequent exact values keep their own label; the rest is binned.

    The paper's frequency encoding with a count threshold, adapted to
    near-continuous flow sizes: only exactly repeated values earn a label.
    """
    enc = {"kind": "frequency", "flags": bool(flags)}
    for column in ("bytes", "duration"):
        counts = flows[column].value_counts()
        frequent = sorted(counts[counts.ge(min_count)].index.tolist())
        rest = flows[~flows[column].isin(frequent)][column].to_numpy(dtype=float)
        cuts = np.quantile(rest, np.linspace(0, 1, nbins + 1)) if len(rest) else np.array([])
        enc[column] = {"freq": {v: i for i, v in enumerate(frequent)},
                       "edges": np.unique(cuts)}
    return enc


def _bin(values, edges):
    if len(edges) < 2:
        return np.zeros(len(values), dtype=int)
    return np.clip(np.searchsorted(edges[1:-1], values, side="right"),
                   0, len(edges) - 2)


def _flag_bits(flows, enabled):
    """`s1r0` per TCP flow when flags are enabled; empty strings otherwise."""
    if not enabled:
        return [""] * len(flows)
    missing = {"syn_seen", "rst_seen"} - set(flows.columns)
    if missing:
        raise ValueError("Flags requested but flows lack syn_seen/rst_seen; "
                         "load them with load_flow_packets(path, flags=True).")
    return [f"s{int(syn)}r{int(rst)}" if str(proto).lower() == "tcp" else ""
            for proto, syn, rst in zip(flows["proto"], flows["syn_seen"],
                                       flows["rst_seen"])]


def encode(flows, enc):
    """Flows to PROTO_[FLAGS_]SIZE_DURATION symbols using the fitted encoding."""
    symbols = []
    for proto, flags, size, duration in zip(flows["proto"],
                                            _flag_bits(flows, enc.get("flags", False)),
                                            flows["bytes"], flows["duration"]):
        parts = [str(proto)]
        if flags:
            parts.append(flags)
        parts += [_encode_value(size, enc["bytes"]),
                  _encode_value(duration, enc["duration"])]
        symbols.append("_".join(parts))
    return pd.Series(symbols, index=flows.index)


def _encode_value(value, spec):
    if isinstance(spec, dict):  # frequency encoding
        if value in spec["freq"]:
            return f"f{spec['freq'][value]}"
        return f"p{_bin(np.array([float(value)]), spec['edges'])[0]}"
    return f"p{_bin(np.array([float(value)]), spec)[0]}"


def make_traces(symbols, length=TRACE_LEN):
    """Fixed sliding window over the symbol stream, one tuple per trace."""
    symbols = list(symbols)
    if length < 1:
        raise ValueError("Trace length must be positive.")
    return [tuple(symbols[i:i + length]) for i in range(len(symbols) - length + 1)]


class _Node:
    __slots__ = ("children", "edge", "visits", "final")

    def __init__(self):
        self.children = {}
        self.edge = {}
        self.visits = 0
        self.final = 0


def _hoeffding(n1, n2, alpha=ALERGIA_ALPHA):
    return np.sqrt(0.5 * np.log(2.0 / alpha)) * (1 / np.sqrt(n1) + 1 / np.sqrt(n2))


def _frequency_tests(node1, node2):
    """(symbol, p1, p2) for every next symbol of either state, "#" for termination."""
    tests = []
    for symbol in sorted(set(node1.children) | set(node2.children)) + ["#"]:
        if symbol == "#":
            first, second = node1.final, node2.final
        else:
            first = node1.edge.get(symbol, 0)
            second = node2.edge.get(symbol, 0)
        tests.append((symbol, first / node1.visits, second / node2.visits))
    return tests


def _compatible(node1, node2, alpha=ALERGIA_ALPHA):
    """ALERGIA test: same next-symbol and termination probabilities."""
    if node1.visits == 0 or node2.visits == 0:
        return False
    bound = _hoeffding(node1.visits, node2.visits, alpha)
    return all(abs(p1 - p2) < bound for _, p1, p2 in _frequency_tests(node1, node2))


def _fold_into(target, other):
    """Merge other into target, determinizing shared continuations."""
    if target is other:
        return  # already the same state; folding would double-count
    target.visits += other.visits
    target.final += other.final
    for symbol, count in other.edge.items():
        target.edge[symbol] = target.edge.get(symbol, 0) + count
    for symbol, child in other.children.items():
        if symbol in target.children:
            _fold_into(target.children[symbol], child)
        else:
            target.children[symbol] = child


class PDFA:
    """Deterministic probabilistic automaton with transition probabilities."""

    def __init__(self, root):
        self.root = root
        self.probs = {}
        stack = [root]
        seen = {id(root)}
        while stack:
            node = stack.pop()
            outgoing = {s: (c, node.edge[s] / node.visits)
                        for s, c in node.children.items()}
            self.probs[id(node)] = (node, outgoing)
            for child in node.children.values():
                if id(child) not in seen:
                    seen.add(id(child))
                    stack.append(child)
        self.n_states = len(seen)

    def transition(self, node, symbol):
        _, outgoing = self.probs[id(node)]
        return outgoing.get(symbol, (None, 0.0))


def _copy_tree(root):
    """An independent copy of a prefix tree; merging rewires the original in place."""
    copy = _Node()
    stack = [(root, copy)]
    while stack:
        source, target = stack.pop()
        target.visits, target.final, target.edge = source.visits, source.final, dict(source.edge)
        for symbol, child in source.children.items():
            target.children[symbol] = _Node()
            stack.append((child, target.children[symbol]))
    return copy


def _step(kind, red, blue, path, red_path, alpha):
    """One red-blue step as plain data, read before the fold changes either state."""
    tests = _frequency_tests(red, blue) if red.visits and blue.visits else []
    bound = (_hoeffding(red.visits, blue.visits, alpha) if red.visits and blue.visits
             else float("inf"))
    return {"kind": kind, "path": path, "red_path": red_path, "red_visits": red.visits,
            "blue_visits": blue.visits, "tests": tests, "bound": bound}


def learn_pdfa(traces, alpha=ALERGIA_ALPHA, trace=None):
    """PTA from traces, then red-blue ALERGIA state merging.

    `trace`, when a list, receives ("pta", copy of the unmerged tree) and then one dict per
    red-blue step, so a visualization can replay the learning. It never changes the result.
    A state is named by its symbol path from the root in the unmerged tree.
    """
    root = _Node()
    paths = {id(root): ()}      # each node's prefix in the unmerged tree; folds keep identity
    for sequence in traces:
        node = root
        node.visits += 1
        for symbol in sequence:
            node.edge[symbol] = node.edge.get(symbol, 0) + 1
            if symbol not in node.children:
                node.children[symbol] = _Node()
                paths[id(node.children[symbol])] = paths[id(node)] + (symbol,)
            node = node.children[symbol]
            node.visits += 1
        node.final += 1
    if trace is not None:
        trace.append(("pta", _copy_tree(root)))
    red = [root]
    while True:
        fringe = [(parent, s, c) for parent in red
                  for s, c in sorted(parent.children.items()) if c not in red]
        if not fringe:
            break
        parent, symbol, blue = fringe[0]
        path = paths[id(blue)]
        for candidate in red:
            if _compatible(candidate, blue, alpha):
                if trace is not None:
                    trace.append(_step("merge", candidate, blue, path,
                                       paths[id(candidate)], alpha))
                parent.children[symbol] = candidate
                _fold_into(candidate, blue)
                break
        else:
            if trace is not None:
                trace.append(_step("promote", red[-1], blue, path, paths[id(red[-1])], alpha))
            red.append(blue)
    return PDFA(root)


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


def plot_pdfa(pdfa, path=None, min_label_prob=0.25):
    """State graph: node size is visits, edge width is probability.

    Sized for a presentation slide (1.6:1, dpi 200) rather than a figure in a
    document, so the text stays readable when the slide is projected. Only edges
    at or above `min_label_prob` get a symbol label; the rest still draw, so nothing
    structural disappears.

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
    ax.set_title(f"Learned PDFA: {len(order)} states, "
                 f"{sum(len(pdfa.probs[id(n)][1]) for n in order)} transitions"
                 f" | labels on edges >= {min_label_prob:.0%}",
                 fontsize=14, fontweight="bold")
    ax.legend(fontsize=10, loc="lower left")
    ax.set_axis_off()
    fig.tight_layout()
    out = resolve_output(path or "statemachine_graph.png")
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"Wrote {out}")
    return out


def split_flows(flows, train_fraction=BENIGN_TRAIN_FRACTION):
    """First `train_fraction` of flows (time order) fit the model."""
    split = int(len(flows) * train_fraction)
    if split < 1 or split >= len(flows):
        raise ValueError("Insufficient benign flows for fitting and holdout.")
    return flows.iloc[:split].reset_index(drop=True), flows.iloc[split:].reset_index(drop=True)


def fit_model(train_flows, nbins=NBINS, trace_len=TRACE_LEN, alpha=ALERGIA_ALPHA,
              encoding="percentile", flags=False, trace=None):
    """Bin edges plus PDFA learned from benign training flows; `trace` as in learn_pdfa."""
    fitter = fit_frequency if encoding == "frequency" else fit_percentile
    enc = fitter(train_flows, nbins, flags=flags)
    traces = make_traces(encode(train_flows, enc), trace_len)
    if not traces:
        raise ValueError("Too few training flows for one trace.")
    return {"enc": enc, "pdfa": learn_pdfa(traces, alpha, trace=trace), "trace_len": trace_len}


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


class FrequencyScorer:
    """SEQUENT's rolling score: test-time state frequency against a fixed training count.

    One state contributes `log(freq_test + 1) - log(freq_train + 1) + log(total_train + 1)
    + log(states_seen + 1)`, and a trace's score is the sum over the states it visits. The
    test counter accumulates across every trace scored, so a scorer built per chunk is not
    the same detector as one scorer held for the whole stream, and a burst never stops
    counting. `WindowedFrequencyScorer` is the bounded version.
    """

    def __init__(self, pdfa):
        self.pdfa = pdfa
        self.train = {id(node): node.visits for node, _ in pdfa.probs.values()}
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

    def __init__(self, pdfa, forget_seconds=FORGET_SECONDS):
        if not forget_seconds > 0:
            raise ValueError("forget_seconds must be positive.")
        self.pdfa = pdfa
        self.forget_seconds = float(forget_seconds)
        self.train = {id(node): node.visits for node, _ in pdfa.probs.values()}
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


def frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds=None):
    """Most anomalous state-frequency score per window; NaN where no trace ended.

    `forget_seconds=None` is cumulative SEQUENT; a number is the windowed scorer. Each trace
    is timed by the start of its last flow, the same convention `flags_for_windows` uses.
    """
    if forget_seconds is None:
        scorer = FrequencyScorer(model["pdfa"])
        score = lambda trace, when: scorer.score(trace)
    else:
        score = WindowedFrequencyScorer(model["pdfa"], forget_seconds).score
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


def main():
    """Write one flag_stats row per stratum: the sweep behind the pair demo.

    Same shape as sweep.py's output, so the two detectors can be compared row by row.
    """
    import argparse

    import local_paths

    parser = argparse.ArgumentParser(
        description="Score every capture against its matched benign reference with the "
                    "state machine. One row per stratum.")
    parser.add_argument("--method", default="tcp", choices=("tcp", "ptcp"),
                        help="capture method; tcp and ptcp are separate measurements")
    parser.add_argument("--encoding", default="percentile",
                        choices=("percentile", "frequency"))
    parser.add_argument("--flags", action="store_true",
                        help="add TCP SYN/RST presence to the symbol alphabet")
    parser.add_argument("--out", default=SWEEP_CSV)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    rows = statemachine_rows(manifest, method=args.method, encoding=args.encoding,
                             flag_bits=args.flags)
    out_file = resolve_output(args.out)
    rows.to_csv(out_file, index=False)

    print(f"Wrote {out_file} | rows={len(rows)} | method={args.method} "
          f"| encoding={args.encoding} | flags={args.flags}")
    for scenario, group in rows.groupby("scenario"):
        print(f"  {scenario:<16} flagged fraction {group['flagged_fraction'].mean():.3f} "
              f"(mean over {len(group)} strata) | {int(group['windows'].sum())} windows")
    print(f"Windows are {WINDOW_SIZE:g}s. Flags are deviations, not confirmed attacks.")


if __name__ == "__main__":
    main()
