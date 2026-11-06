"""Learning: packet captures to a probabilistic automaton (the ALERGIA half).

After Cao, Blaise, Verwer and Rebecchi (ARES 2022). Packets become 5-tuple flows (like
their NetFlow input); each flow becomes one symbol, ``PROTO_[FLAGS_]BYTES_DURATION``, with
the two sizes percentile-binned on benign traffic. A fixed sliding window cuts the symbol
stream into traces. A probabilistic DFA is learned from benign traces with the classic
ALERGIA red-blue state-merging test.

This module only *learns*. Scoring a trace, and the SEQUENT frequency scores built on it,
live in ``scores``.
"""
from collections import Counter

import numpy as np
import pandas as pd

from data_io import load_capture, timebase_issues
from features import BENIGN_TRAIN_FRACTION, WINDOW_SIZE

FLOW_COLUMNS = ["ts", "frame_len", "src_ip", "dst_ip", "src_port",
                "dst_port", "proto"]
FLAG_COLUMNS = ["tcp_syn", "tcp_rst"]
TRACE_LEN = 5
NBINS = 4
ALERGIA_ALPHA = 0.05
MISSING_PROB = 1e-6


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


def _attempt(red, blue, red_path, alpha):
    """One compatibility test as plain data, read before any fold changes either state."""
    tests = _frequency_tests(red, blue) if red.visits and blue.visits else []
    bound = (_hoeffding(red.visits, blue.visits, alpha) if red.visits and blue.visits
             else float("inf"))
    return {"red_path": red_path, "red_visits": red.visits, "tests": tests, "bound": bound}


def _step(kind, blue, path, attempts):
    """One red-blue step: every red state tried, in order; the last decided it."""
    return {"kind": kind, "path": path, "blue_visits": blue.visits,
            "attempts": attempts, **attempts[-1]}


def learn_pdfa(traces, alpha=ALERGIA_ALPHA, trace=None):
    """PTA from traces, then red-blue ALERGIA state merging.

    `trace`, when a list, receives ("pta", copy of the unmerged tree) and then one dict per
    red-blue step, with every red state the candidate was tested against in "attempts", so a
    visualization can replay the learning. It never changes the result.
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
        attempts = []
        for candidate in red:
            if trace is not None:
                attempts.append(_attempt(candidate, blue, paths[id(candidate)], alpha))
            if _compatible(candidate, blue, alpha):
                if trace is not None:
                    trace.append(_step("merge", blue, path, attempts))
                parent.children[symbol] = candidate
                _fold_into(candidate, blue)
                break
        else:
            if trace is not None:
                trace.append(_step("promote", blue, path, attempts))
            red.append(blue)
    return PDFA(root)


def split_flows(flows, train_fraction=BENIGN_TRAIN_FRACTION):
    """First `train_fraction` of flows (time order) fit the model."""
    split = int(len(flows) * train_fraction)
    if split < 1 or split >= len(flows):
        raise ValueError("Insufficient benign flows for fitting and holdout.")
    return flows.iloc[:split].reset_index(drop=True), flows.iloc[split:].reset_index(drop=True)


def fit_model(train_flows, nbins=NBINS, trace_len=TRACE_LEN, alpha=ALERGIA_ALPHA,
              encoding="percentile", flags=False, trace=None):
    """Bin edges plus PDFA learned from benign training flows; `trace` as in learn_pdfa."""
    return fit_segments([train_flows], nbins, trace_len, alpha, encoding, flags, trace)


def fit_segments(segments, nbins=NBINS, trace_len=TRACE_LEN, alpha=ALERGIA_ALPHA,
                 encoding="percentile", flags=False, trace=None):
    """fit_model over several stretches of one recording, with no trace across a gap.

    The bins are fitted on every segment's flows together; traces slide within each segment
    only, so holding a block out of the middle of a recording never splices its two sides
    into a trace benign traffic did not produce.
    """
    fitter = fit_frequency if encoding == "frequency" else fit_percentile
    enc = fitter(pd.concat(segments, ignore_index=True), nbins, flags=flags)
    traces = [t for segment in segments for t in make_traces(encode(segment, enc), trace_len)]
    if not traces:
        raise ValueError("Too few training flows for one trace.")
    return {"enc": enc, "pdfa": learn_pdfa(traces, alpha, trace=trace), "trace_len": trace_len}
