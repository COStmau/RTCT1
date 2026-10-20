"""State-machine anomaly detection after Cao, Blaise, Verwer and Rebecchi (ARES 2022).

Packet captures become flows (5-tuple, like their NetFlow input). Each flow
becomes one symbol, ``PROTO_BYTES_DURATION``, with the two sizes percentile
binned on benign traffic. A fixed sliding window cuts the symbol stream into
traces. A probabilistic DFA is learned from benign traces with the classic
ALERGIA state-merging test, and new traces score by mean log transition
probability. Traces below the 5th percentile of held-out benign scores flag
their window, the same budget convention compare.py uses for the forest/SVM.

Run it with:  .venv/bin/python demo.py 3      (the narrated pair demo)
              .venv/bin/python statemachine.py  (every stratum, one row each)
"""
import numpy as np
import pandas as pd

from data_io import load_capture, resolve_output, timebase_issues
from detectors import BENIGN_QUANTILE, flag_stats
from features import BENIGN_TRAIN_FRACTION, WINDOW_SIZE

FLOW_COLUMNS = ["ts", "frame_len", "src_ip", "dst_ip", "src_port",
                "dst_port", "proto"]
TRACE_LEN = 5
NBINS = 4
ALERGIA_ALPHA = 0.05
MISSING_PROB = 1e-6
PAIR_CSV = "statemachine_pair.csv"
SWEEP_CSV = "statemachine_sweep.csv"
MANIFEST_FILE = "capture_manifest.csv"   # inside outputs/


def load_flow_packets(path):
    """Read only the packet columns flows are built from."""
    return pd.read_csv(path, usecols=FLOW_COLUMNS, low_memory=False)


def make_flows(packets):
    """One row per 5-tuple flow: start time, protocol, bytes, duration."""
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
    grouped = frames.groupby(["src_ip", "dst_ip", "src_port", "dst_port",
                              "proto"], dropna=False)
    flows = grouped.agg(start_ts=("ts", "min"), bytes=("frame_len", "sum"),
                        duration=("ts", lambda s: float(s.max() - s.min())),
                        proto=("proto", "first")).reset_index(drop=True)
    return flows.sort_values("start_ts").reset_index(drop=True)


def fit_percentile(flows, nbins=NBINS):
    """Quantile bin edges for bytes and duration, fitted on benign flows."""
    enc = {"kind": "percentile"}
    for column in ("bytes", "duration"):
        cuts = np.quantile(flows[column].to_numpy(dtype=float),
                           np.linspace(0, 1, nbins + 1))
        enc[column] = np.unique(cuts)
    return enc


def fit_frequency(flows, nbins=NBINS, min_count=3):
    """Frequent exact values keep their own label; the rest is binned.

    The paper's frequency encoding with a count threshold, adapted to
    near-continuous flow sizes: only exactly repeated values earn a label.
    """
    enc = {"kind": "frequency"}
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


def encode(flows, enc):
    """Flows to PROTO_BYTES_DURATION symbols using the fitted encoding."""
    return pd.Series([f"{p}_{_encode_value(b, enc['bytes'])}_{_encode_value(d, enc['duration'])}"
                      for p, b, d in zip(flows["proto"], flows["bytes"], flows["duration"])],
                     index=flows.index)


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


def _compatible(node1, node2, alpha=ALERGIA_ALPHA):
    """ALERGIA test: same next-symbol and termination probabilities."""
    if node1.visits == 0 or node2.visits == 0:
        return False
    bound = _hoeffding(node1.visits, node2.visits, alpha)
    symbols = set(node1.children) | set(node2.children) | {"#"}
    for symbol in symbols:
        if symbol == "#":
            first, second = node1.final, node2.final
        else:
            first = node1.edge.get(symbol, 0)
            second = node2.edge.get(symbol, 0)
        if abs(first / node1.visits - second / node2.visits) >= bound:
            return False
    return True


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


def learn_pdfa(traces, alpha=ALERGIA_ALPHA):
    """PTA from traces, then red-blue ALERGIA state merging."""
    root = _Node()
    for trace in traces:
        node = root
        node.visits += 1
        for symbol in trace:
            node.edge[symbol] = node.edge.get(symbol, 0) + 1
            node = node.children.setdefault(symbol, _Node())
            node.visits += 1
        node.final += 1
    red = [root]
    while True:
        fringe = [(parent, s, c) for parent in red
                  for s, c in sorted(parent.children.items()) if c not in red]
        if not fringe:
            break
        parent, symbol, blue = fringe[0]
        for candidate in red:
            if _compatible(candidate, blue, alpha):
                parent.children[symbol] = candidate
                _fold_into(candidate, blue)
                break
        else:
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

    Only edges at or above `min_label_prob` get a symbol label; the rest
    still draw, so nothing structural disappears.
    """
    import matplotlib.pyplot as plt

    order = pdfa_states_in_order(pdfa)
    ids = {id(node): i for i, node in enumerate(order)}
    angles = np.linspace(0, 2 * np.pi, len(order), endpoint=False) + np.pi / 2
    pos = {i: (np.cos(a), np.sin(a)) for i, a in enumerate(angles)}
    visits = np.array([node.visits for node in order], dtype=float)

    fig, ax = plt.subplots(figsize=(13, 8))
    for i, node in enumerate(order):
        _, outgoing = pdfa.probs[id(node)]
        for symbol, (child, probability) in sorted(outgoing.items()):
            j = ids[id(child)]
            style = "arc3,rad=0.3" if i == j else "arc3,rad=0.15" if i < j else "arc3,rad=-0.15"
            ax.annotate("", xy=pos[j], xytext=pos[i],
                        arrowprops={"arrowstyle": "->", "color": "#1f77b4",
                                    "linewidth": 0.5 + 3 * probability,
                                    "alpha": 0.25 + 0.75 * probability,
                                    "connectionstyle": style,
                                    "shrinkA": 18, "shrinkB": 18})
            if probability >= min_label_prob:
                x, y = pos[i] if i == j else ((pos[i][0] + pos[j][0]) / 2,
                                              (pos[i][1] + pos[j][1]) / 2)
                ax.text(x, y, f"{symbol} {probability:.2f}", fontsize=6,
                        ha="center", va="center",
                        bbox={"facecolor": "white", "edgecolor": "none",
                              "alpha": 0.8, "pad": 1})
    sizes = 300 + 1700 * (visits / visits.max() if visits.max() else 1)
    for i, node in enumerate(order):
        ax.scatter([pos[i][0]], [pos[i][1]], s=sizes[i], color="#deebf7",
                   edgecolors="#1f77b4", linewidths=2, zorder=3)
        ax.text(pos[i][0], pos[i][1], f"{i}\n{node.visits}", fontsize=8,
                fontweight="bold", ha="center", va="center", zorder=4)
    ax.scatter([], [], s=200, color="#deebf7", edgecolors="#1f77b4",
               label="state (id over visits)")
    ax.plot([], [], color="#1f77b4", linewidth=2.5, label="transition (width = probability)")
    ax.set_title(f"Learned PDFA: {len(order)} states, "
                 f"{sum(len(pdfa.probs[id(n)][1]) for n in order)} transitions"
                 f" | labels on edges >= {min_label_prob:.0%}",
                 fontsize=11, fontweight="bold")
    ax.legend(fontsize=9, loc="lower center")
    ax.set_axis_off()
    fig.tight_layout()
    out = resolve_output(path or "statemachine_graph.png")
    fig.savefig(out, dpi=150)
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
              encoding="percentile"):
    """Bin edges plus PDFA learned from benign training flows."""
    fitter = fit_frequency if encoding == "frequency" else fit_percentile
    enc = fitter(train_flows, nbins)
    traces = make_traces(encode(train_flows, enc), trace_len)
    if not traces:
        raise ValueError("Too few training flows for one trace.")
    return {"enc": enc, "pdfa": learn_pdfa(traces, alpha), "trace_len": trace_len}


def score_flows(model, flows):
    """(end-flow start time, trace score) for each sliding trace."""
    symbols = list(encode(flows, model["enc"]))
    return [(flows["start_ts"].iloc[i + model["trace_len"] - 1],
             trace_score(model["pdfa"], tuple(symbols[i:i + model["trace_len"]])))
            for i in range(len(symbols) - model["trace_len"] + 1)]


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


def score_capture(model, packets, cutoff):
    """Per-window flags for one capture under a fitted model and cutoff."""
    flows = make_flows(packets)
    if len(flows) < model["trace_len"]:
        return None  # too few flows to form a trace; caller records the note
    scored = score_flows(model, flows)
    return flags_for_windows(scored, packets["ts"].min(),
                             n_windows_for(packets), cutoff)


def score_pair(benign_path, attack_path, encoding="percentile"):
    """Fit on the first 70% of benign flows; flag held-out benign and attack."""
    benign = load_flow_packets(benign_path)
    benign_flows = make_flows(benign)
    train, holdout = split_flows(benign_flows)
    model = fit_model(train, encoding=encoding)
    cutoff = score_cutoff(score_flows(model, holdout))
    benign_flags = flags_for_windows(score_flows(model, holdout), benign["ts"].min(),
                                     n_windows_for(benign), cutoff)
    attack = load_flow_packets(attack_path)
    attack_flags = score_capture(model, attack, cutoff)
    if attack_flags is None:
        attack_flags = pd.Series(False, index=range(n_windows_for(attack)))
    return benign_flags, attack_flags


def statemachine_rows(described, method="tcp", encoding="percentile"):
    """One flag_stats row per stratum, same shape as compare.compare_detectors."""

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
        packets[key] = load_flow_packets(capture["path"])
    attacks = [s for s in sorted(described["scenario"].unique()) if s != "benign"]
    labels = sorted(described[described["method"].eq(method)]["label"].unique())
    rows, excluded = [], []
    for label in labels:
        reference = packets.get(("benign", label, method))
        if reference is None:
            excluded.append(label)
            continue
        try:
            train, holdout = split_flows(make_flows(reference))
            model = fit_model(train, encoding=encoding)
            cutoff = score_cutoff(score_flows(model, holdout))
        except ValueError as error:
            excluded.append(f"{label} ({error})")
            continue
        targets = [("benign", holdout, reference)] + [
            (s, None, packets.get((s, label, method))) for s in attacks]
        for scenario, holdout_flows, target in targets:
            if target is None:
                excluded.append(f"{scenario}/{label} (no capture)")
                continue
            if scenario == "benign":
                scored = score_flows(model, holdout_flows)
                flags = flags_for_windows(scored, target["ts"].min(),
                                          n_windows_for(target), cutoff)
            else:
                flags = score_capture(model, target, cutoff)
                if flags is None:
                    excluded.append(f"{scenario}/{label} (too few flows)")
                    continue
            rows.append({"detector": "state_machine", "scenario": scenario,
                         "label": label, "method": method, "states": model["pdfa"].n_states,
                         **flag_stats(flags)})
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
    from data_io import load_manifest

    parser = argparse.ArgumentParser(
        description="Score every capture against its matched benign reference with the "
                    "state machine. One row per stratum.")
    parser.add_argument("--method", default="tcp", choices=("tcp", "ptcp"),
                        help="capture method; tcp and ptcp are separate measurements")
    parser.add_argument("--encoding", default="percentile",
                        choices=("percentile", "frequency"))
    parser.add_argument("--out", default=SWEEP_CSV)
    parser.add_argument("--manifest", default=MANIFEST_FILE)
    args = parser.parse_args()

    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    rows = statemachine_rows(manifest, method=args.method, encoding=args.encoding)
    out_file = resolve_output(args.out)
    rows.to_csv(out_file, index=False)

    print(f"Wrote {out_file} | rows={len(rows)} | method={args.method} "
          f"| encoding={args.encoding}")
    for scenario, group in rows.groupby("scenario"):
        print(f"  {scenario:<16} flagged fraction {group['flagged_fraction'].mean():.3f} "
              f"(mean over {len(group)} strata) | {int(group['windows'].sum())} windows")
    print(f"Windows are {WINDOW_SIZE:g}s. Flags are deviations, not confirmed attacks.")


if __name__ == "__main__":
    main()
