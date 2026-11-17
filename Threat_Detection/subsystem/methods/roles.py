"""Role contracts: one machine per kind of workload, learned from every instance of it.

A tap's own machine, learned from a minute of that tap, mostly learns that minute
(dev/PROGRESS.md, 2026-11-15). A web server or a sensor publisher behaves in a characteristic
way wherever it runs, so the contract is learned per role, pooled over instances and
recordings, and each instance is judged against it.

    exchanges(packets, own, t0)     what the workload said to each peer, second by second
    ROLES                           the roles, as data: who they are and what their symbols read
    fit_role / role_scores          the pooled machine and an instance scored against it
    role_leaving                    how many of an instance's conversations left the contract

The unit is an exchange slice: one peer, one service, one second, both directions together,
with how the connection stood (opened, carried on, closed, reset). It is Zeek's connection
record cut at the seconds it crosses, so a long stream is seen while it runs and the rule is
causal. A role's symbols are decided by how its protocol works and by nothing else: a server
answers requests, so its symbols read bytes in and bytes out; a publisher emits on a cadence,
so its symbols read messages out and bytes out. No attack informs either.
"""
from collections import deque
from dataclasses import dataclass

import numpy as np
import pandas as pd

from core.features import WINDOW_SIZE
from methods.pdfa import ALERGIA_ALPHA, FLOW_COLUMNS, NBINS, TRACE_LEN, learn_pdfa
from methods.scores import FORGET_SECONDS, NoveltyScorer, WindowedFrequencyScorer

ROLE_COLUMNS = FLOW_COLUMNS + ["tcp_syn", "tcp_fin", "tcp_rst"]
START = "^"                # pads a peer's first traces, so the machine learns how a conversation begins
PORT_CLASSES = ((53, "dns"), (80, "web"), (443, "web"), (8080, "web"), (8443, "web"), (6443, "kube"))


@dataclass(frozen=True)
class Role:
    name: str
    workloads: tuple       # workload names that play this role, as a pod tap's label carries them
    fields: tuple          # the two exchange quantities its symbols bin, in order


ROLES = (Role("web server", ("nginx", "frontend", "api"), ("bytes_in", "bytes_out")),
         Role("sensor publisher", ("lidar", "camera"), ("packets_out", "bytes_out")))


def role_of(label):
    """The role of a pod tap, from the workload its label names; None for any other tap."""
    workload = label[len("pod-"):] if label.startswith("pod-") else None
    return next((role for role in ROLES if workload in role.workloads), None)


def load_packets(path):
    """A capture's packets with the TCP flags a connection's state is read from."""
    from convert.read import CaptureReader, detect_format
    from convert.rows import dissect, ts_seconds
    try:
        kind = detect_format(path)
    except (ValueError, OSError):
        kind = "csv"
    if kind == "csv":
        return pd.read_csv(path, usecols=ROLE_COLUMNS, low_memory=False)
    rows = []
    for frame in CaptureReader(str(path)).frames():
        row, _ = dissect(frame)
        rows.append([ts_seconds(frame.ts_sec, frame.ts_frac, frame.ts_digits)] + [row[c] for c in ROLE_COLUMNS[1:]])
    return pd.DataFrame(rows, columns=ROLE_COLUMNS)


def own_address(packets):
    """The tapped workload's address: the one on an end of the most packets.

    A tap with a single peer has two such addresses and no way to tell them apart from the
    packets; that is an error, and the caller must say which it is.
    """
    counts = pd.concat([packets["src_ip"], packets["dst_ip"]]).dropna().value_counts()
    if counts.empty:
        raise ValueError("No addressed packets to find the workload's own address in.")
    if len(counts) > 1 and counts.iloc[0] == counts.iloc[1]:
        raise ValueError(f"The workload's own address is ambiguous: {counts.index[0]} or {counts.index[1]}.")
    return counts.index[0]


def port_class(port):
    """A service port as a small general class; the number itself would not transfer."""
    known = dict(PORT_CLASSES).get(int(port))
    return known or ("low" if port < 1024 else "reg" if port < 32768 else "high")


def exchanges(packets, own, t0, window_size=WINDOW_SIZE):
    """One row per peer, service and window: both directions of what `own` exchanged.

    The service is the lower port of a packet, which is the listening side for every
    client/server protocol on a cluster; `side` is "s" when that port is `own`'s (it serves)
    and "c" when it is the peer's (it calls). `phase` is how the connection stood in that
    second: "o" opened (a SYN), "c" carried on from the second before, "n" neither (UDP, or a
    connection first seen midway), then "f" or "r" when a FIN or a RST was seen.
    """
    frames = packets[packets["src_ip"].eq(own) | packets["dst_ip"].eq(own)].dropna(subset=["src_ip", "dst_ip"])
    if frames.empty:
        raise ValueError("No packets to or from the workload.")
    out = frames["src_ip"].eq(own).to_numpy()
    ports = frames[["src_port", "dst_port"]].apply(pd.to_numeric, errors="coerce").fillna(0)
    serves = np.where(out, ports["src_port"] <= ports["dst_port"], ports["dst_port"] < ports["src_port"])
    size = pd.to_numeric(frames["frame_len"]).to_numpy()
    flags = frames[["tcp_syn", "tcp_fin", "tcp_rst"]].apply(pd.to_numeric, errors="coerce").fillna(0)
    table = pd.DataFrame({
        "window": np.floor((frames["ts"].astype(float) - t0) / window_size).astype(int).to_numpy(),
        "peer": np.where(out, frames["dst_ip"], frames["src_ip"]),
        "service": ports.min(axis=1).astype(int).to_numpy(), "side": np.where(serves, "s", "c"),
        "proto": frames["proto"].astype(str).to_numpy(), "ts": frames["ts"].astype(float).to_numpy(),
        "packets_in": ~out, "packets_out": out, "bytes_in": size * ~out, "bytes_out": size * out,
        "syn": flags["tcp_syn"].to_numpy(), "fin": flags["tcp_fin"].to_numpy(), "rst": flags["tcp_rst"].to_numpy()})
    key = ["peer", "service", "side", "proto"]
    rows = table.groupby(["window"] + key).agg(
        start_ts=("ts", "min"), packets_in=("packets_in", "sum"), packets_out=("packets_out", "sum"),
        bytes_in=("bytes_in", "sum"), bytes_out=("bytes_out", "sum"),
        syn=("syn", "max"), fin=("fin", "max"), rst=("rst", "max")).reset_index()
    before = rows[key].assign(window=rows["window"] + 1, continuing=True)
    rows = rows.merge(before, on=["window"] + key, how="left")
    opened = np.where(rows["syn"] > 0, "o", np.where(rows["continuing"].notna(), "c", "n"))
    closed = np.where(rows["rst"] > 0, "r", np.where(rows["fin"] > 0, "f", ""))
    rows["phase"] = pd.Series(opened, index=rows.index) + closed
    columns = ["start_ts", "window", "peer", "service", "side", "proto", "phase",
               "packets_in", "packets_out", "bytes_in", "bytes_out"]
    return rows.sort_values("start_ts", kind="stable").reset_index(drop=True)[columns]


def fit_bins(records, role, nbins=NBINS):
    """Quantile edges for the role's two quantities, over the exchanges where each is non-zero."""
    edges = {}
    for field in role.fields:
        values = records[field].to_numpy(dtype=float)
        values = values[values > 0]
        edges[field] = np.unique(np.quantile(values, np.linspace(0, 1, nbins + 1))) if len(values) else np.array([])
    return edges


def _bin(value, edges):
    if value <= 0:
        return "z"                  # nothing that way this second is its own symbol, not a small amount
    if len(edges) and value > edges[-1]:
        return "x"                  # more than was ever learned is not the top bin; it is outside the contract
    if len(edges) < 2:
        return "0"
    return str(int(np.clip(np.searchsorted(edges[1:-1], value, side="right"), 0, len(edges) - 2)))


def symbols(records, role, edges):
    """One symbol per exchange: side and service class, protocol, phase, and the role's two bins."""
    return [f"{side}{port_class(service)}_{proto}_{phase}_" + "_".join(_bin(row[f], edges[f]) for f in role.fields)
            for side, service, proto, phase, row in zip(
                records["side"], records["service"], records["proto"], records["phase"],
                records[list(role.fields)].to_dict("records"))]


def peer_traces(records, role, edges, trace_len=TRACE_LEN):
    """(when, peer, trace) per exchange, the trace being that peer's last `trace_len` symbols.

    A tap's traffic is many conversations interleaved; a trace over all of it is mostly the
    interleaving. Each peer keeps its own, padded with START until it is long enough.
    """
    recent = {}
    for when, peer, symbol in zip(records["start_ts"], records["peer"], symbols(records, role, edges)):
        own = recent.setdefault(peer, deque([START] * trace_len, maxlen=trace_len))
        own.append(symbol)
        yield float(when), peer, tuple(own)


def fit_role(benign, role, nbins=NBINS, trace_len=TRACE_LEN, alpha=ALERGIA_ALPHA):
    """The role's machine from the benign exchanges of its instances, one frame each.

    Bins are fitted on all of them together; traces never run from one instance into another.
    """
    edges = fit_bins(pd.concat(benign, ignore_index=True), role, nbins)
    traces = [trace for records in benign for _, _, trace in peer_traces(records, role, edges, trace_len)]
    if not traces:
        raise ValueError(f"No benign exchanges to learn the {role.name} from.")
    return {"role": role, "edges": edges, "trace_len": trace_len, "pdfa": learn_pdfa(traces, alpha)}


def role_scores(model, records, t0, n_windows, forget_seconds=FORGET_SECONDS, window_size=WINDOW_SIZE):
    """Per window: the largest frequency score of any peer's trace, and that peer.

    The instance has its own clock (one scorer), the role's machine and the role's symbols.
    NaN and None where the instance exchanged nothing.
    """
    scorer = WindowedFrequencyScorer(model["pdfa"], forget_seconds)
    scores, peers = np.full(n_windows, np.nan), [None] * n_windows
    for when, peer, trace in peer_traces(records, model["role"], model["edges"], model["trace_len"]):
        value = scorer.score(trace, max(when - t0, scorer.last_when))
        window = int((when - t0) // window_size)
        if 0 <= window < n_windows and not value <= scores[window]:
            scores[window], peers[window] = value, peer
    return scores, peers


def role_leaving(model, records, t0, n_windows, forget_seconds=FORGET_SECONDS, window_size=WINDOW_SIZE):
    """Per window: how many conversations in the clock left the contract, and the last peer to.

    The frequency score counts visits to learned states, so a trace the machine lacks scores
    lower, not higher. This counts those traces: a quantity beyond the learned range, a
    service or a connection state never seen, a peer that does not begin as peers begin.
    NaN and None where the instance exchanged nothing.
    """
    scorer = NoveltyScorer(model["pdfa"], forget_seconds)
    scores, peers = np.full(n_windows, np.nan), [None] * n_windows
    for when, peer, trace in peer_traces(records, model["role"], model["edges"], model["trace_len"]):
        value = scorer.score(trace, when - t0)
        window = int((when - t0) // window_size)
        if 0 <= window < n_windows:
            scores[window] = value
            if scorer.leaves(trace):
                peers[window] = peer
    return scores, peers
