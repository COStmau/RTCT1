"""The state machine's story as one interactive page: the cluster, the learning, the replay.

build_story() runs the same pipeline the detector runs, through the instrumentation hooks in
statemachine.py, and returns a plain dict (the "bundle"). write_html() inlines that bundle and
the renderer in story_template/ into one self-contained page in outputs/. The page draws only
what the bundle says: the cluster is inferred from traffic (cluster.py), positions are
computed (layout.py), and every score is the scorer's own number.

Run it with:  .venv/bin/python story.py                       (pod-lidar, every attack)
              .venv/bin/python story.py --vantage pod-nginx
"""
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

import cluster as topology
import layout
from data_io import MANIFEST_NAME, level_from_label, load_manifest, resolve_output
from detectors import PERSISTENCE_WINDOW, persistent_mask
from features import WINDOW_SIZE
from statemachine import (FORGET_SECONDS, FrequencyScorer, WindowedFrequencyScorer, encode,
                          fit_model, frequency_cutoff, frequency_scores_by_window, make_flows,
                          n_windows_for, pdfa_states_in_order, score_cutoff, score_flows,
                          load_flow_packets, segment_flows, split_flows, trace_score,
                          trace_states)

DEFAULT_VANTAGE = "pod-lidar"   # its 5 s replay loop is what FORGET_SECONDS was sized for
HELD_OUT = "benign (held out)"
WINDOW_STATUSES = ("alert", "flagged", "unseen", "released", "normal")   # strongest first
RELEASE_SHOWN = 2           # windows after a release that still say "released"
MAX_STEP_DETAIL = 400       # merge steps drawn one by one; the rest are counted
MAX_STREAM = 2000           # training flows shown in the symbol stream
STORY_HTML = "statemachine_story.html"
TEMPLATE_DIR = Path(__file__).resolve().parent / "story_template"
D3_FILE = "vendor/d3.v7.9.0.min.js"


def build_story(benign, targets, cluster_captures, vantage, forget_seconds=FORGET_SECONDS):
    """The story bundle for one vantage.

    `benign` and each `targets[scenario]` are packet frames for `vantage` (flow columns, as
    statemachine.load_flow_packets reads them). `cluster_captures` maps every capture label
    to a benign packet frame and drives the cluster drawing; it may be empty.
    """
    t0 = float(benign["ts"].min())
    flows, dropped = segment_flows(make_flows(benign), t0)
    train, holdout = split_flows(flows)
    events = []
    model = fit_model(train, trace=events)
    found = topology.infer_cluster(cluster_captures)
    element_of = topology.element_index(found)

    n_windows = n_windows_for(benign)
    cutoffs = {
        "likelihood": score_cutoff(score_flows(model, holdout)),
        "windowed": frequency_cutoff(frequency_scores_by_window(
            model, holdout, t0, n_windows, forget_seconds)),
        "cumulative": frequency_cutoff(frequency_scores_by_window(
            model, holdout, t0, n_windows, None)),
    }
    captures = [_capture(HELD_OUT, holdout, t0, n_windows, float(benign["ts"].max()) - t0,
                         model, element_of, forget_seconds, cutoffs)]
    for scenario, packets in targets.items():
        target_t0 = float(packets["ts"].min())
        target_flows, _ = segment_flows(make_flows(packets), target_t0)
        captures.append(_capture(scenario, target_flows, target_t0, n_windows_for(packets),
                                 float(packets["ts"].max()) - target_t0, model, element_of,
                                 forget_seconds, cutoffs))

    return {
        "meta": {"vantage": vantage, "level": level_from_label(vantage),
                 "forget_seconds": float(forget_seconds), "trace_len": model["trace_len"],
                 "window_size": float(WINDOW_SIZE), "persistence": PERSISTENCE_WINDOW,
                 "train_flows": len(train), "holdout_flows": len(holdout),
                 "train_span_s": float(train["start_ts"].max() - train["start_ts"].min()),
                 "dropped_flows": dropped,
                 "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        "cluster": found,
        "learning": _learning(model, events, train, t0),
        "playback": {"captures": captures},
    }


def _symbol_parts(symbol):
    parts = symbol.split("_")
    return {"symbol": symbol, "proto": parts[0], "bytes_bin": parts[-2],
            "duration_bin": parts[-1]}


def _learning(model, events, train, t0):
    """Symbols, the unmerged prefix tree, the red-blue steps, and the final machine."""
    pdfa = model["pdfa"]
    nodes = layout.icicle(events[0][1])
    by_path = {node["path"]: node["id"] for node in nodes}
    graph = layout.layered(pdfa)
    absorbed = layout.pta_to_pdfa_map(pdfa, nodes)
    for state in graph["states"]:
        state["pta_ids"] = absorbed.get(state["id"], [])

    steps = [{"kind": step["kind"], "red": by_path[step["red_path"]],
              "blue": by_path[step["path"]], "red_visits": step["red_visits"],
              "blue_visits": step["blue_visits"], "bound": step["bound"],
              "tests": [{"symbol": s, "p_red": a, "p_blue": b} for s, a, b in step["tests"]]}
             for step in events[1:1 + MAX_STEP_DETAIL]]
    symbols = list(encode(train, model["enc"]))
    counts = Counter(symbols)
    enc = model["enc"]
    return {
        "bins": {column: list(np.asarray(enc[column], dtype=float))
                 for column in ("bytes", "duration") if not isinstance(enc[column], dict)},
        "symbols": [dict(_symbol_parts(symbol), count=count)
                    for symbol, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))],
        "stream": [{"t": float(start) - t0, "symbol": symbol}
                   for start, symbol in zip(train["start_ts"], symbols)][:MAX_STREAM],
        "traces": max(len(symbols) - model["trace_len"] + 1, 0),
        "pta": [{key: value for key, value in node.items() if key != "path"} for node in nodes],
        "steps": steps,
        "steps_total": len(events) - 1,
        "pdfa": graph,
    }


def _capture(scenario, flows, t0, n_windows, duration, model, element_of, forget, cutoffs):
    """Every trace of one capture replayed through one windowed and one cumulative scorer."""
    pdfa, length = model["pdfa"], model["trace_len"]
    ids = {id(node): index for index, node in enumerate(pdfa_states_in_order(pdfa))}
    symbols = list(encode(flows, model["enc"]))
    windowed = WindowedFrequencyScorer(pdfa, forget)
    cumulative = FrequencyScorer(pdfa)
    traces = []
    for index in range(len(symbols) - length + 1):
        trace = tuple(symbols[index:index + length])
        when = float(flows["start_ts"].iloc[index + length - 1]) - t0
        terms, expired = windowed.score_terms(trace, when)
        states = [ids[id(state)] for state in trace_states(pdfa, trace)]
        traces.append({
            "i": index, "t": when, "symbols": list(trace), "states": states,
            "fell_off_at": len(states) if len(states) < length else None,
            "likelihood": trace_score(pdfa, trace),
            "windowed": float(sum(map(sum, terms))),
            "cumulative": cumulative.score(trace),
            "terms": [[float(term) for term in state_terms] for state_terms in terms],
            "expired": [[float(seen), ids[key]] for seen, key in expired],
        })
    return {
        "scenario": scenario, "duration_s": duration,
        "start_s": traces[0]["t"] if traces else 0.0,
        "cutoffs": cutoffs,
        "flow_edges": [[element_of(src), element_of(dst)]
                       for src, dst in zip(flows["src_ip"], flows["dst_ip"])],
        "traces": traces,
        "windows": _windows(traces, n_windows, cutoffs),
    }


def _windows(traces, n_windows, cutoffs):
    """Per window: both detectors' flags, sustained alerts, releases, and one status.

    `status` is the strongest verdict, in WINDOW_STATUSES order. "unseen" is the likelihood
    detector alone: a trace that falls off the machine visits fewer states, which lowers the
    frequency score, so novel behaviour shows there and not in the windowed score.
    `forgetting_shown` marks windows where forgetting visibly matters: an alert came earlier,
    the windowed score has let go, and the cumulative score is still above its own cutoff.
    """
    peak = np.full(n_windows, np.nan)
    cumulative = np.full(n_windows, np.nan)
    unlikely = np.zeros(n_windows, dtype=bool)
    for trace in traces:
        window = int(trace["t"] // WINDOW_SIZE)
        if 0 <= window < n_windows:
            peak[window] = np.nanmax([peak[window], trace["windowed"]])
            cumulative[window] = np.nanmax([cumulative[window], trace["cumulative"]])
            unlikely[window] |= trace["likelihood"] < cutoffs["likelihood"]
    flagged = np.nan_to_num(peak, nan=-np.inf) > cutoffs["windowed"]
    held = np.nan_to_num(cumulative, nan=-np.inf) > cutoffs["cumulative"]
    alert = persistent_mask(flagged).to_numpy()
    released = np.array([w > 0 and alert[w - 1] and not flagged[w] for w in range(n_windows)],
                        dtype=bool)
    windows, since_release, alerted = [], None, False
    for w in range(n_windows):
        since_release = 0 if released[w] else (
            since_release + 1 if since_release is not None and not flagged[w] else None)
        status = ("alert" if alert[w] else "flagged" if flagged[w] else "unseen" if unlikely[w]
                  else "released" if since_release is not None and since_release <= RELEASE_SHOWN
                  else "normal")
        windows.append({"index": w, "peak": peak[w], "flagged": bool(flagged[w]),
                        "likelihood_flag": bool(unlikely[w]), "alert": bool(alert[w]),
                        "released": bool(released[w]), "status": status,
                        "forgetting_shown": bool(alerted and not flagged[w] and held[w])})
        alerted = alerted or bool(alert[w])
    return windows


def _clean(value):
    """JSON-safe: numpy scalars to Python, non-finite floats to null, floats to 4 places."""
    if isinstance(value, dict):
        return {str(key): _clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, np.ndarray)):
        return [_clean(item) for item in value]
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        return round(float(value), 4) if math.isfinite(value) else None
    return value


def to_json(story):
    """The bundle as compact JSON that JSON.parse accepts (no NaN, no Infinity)."""
    return json.dumps(_clean(story), allow_nan=False, separators=(",", ":"))


def write_html(story, path=None):
    """One self-contained page: template, styles, D3, renderer and bundle all inlined."""
    page = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")
    # "</" inside an inline script would close it early; "<\/" is the same string to JSON
    bundle = "window.STORY = " + to_json(story).replace("</", "<\\/") + ";\n"
    for marker, text in (("/*__CSS__*/", (TEMPLATE_DIR / "story.css").read_text(encoding="utf-8")),
                         ("/*__D3__*/", (TEMPLATE_DIR / D3_FILE).read_text(encoding="utf-8")),
                         ("/*__JS__*/", (TEMPLATE_DIR / "story.js").read_text(encoding="utf-8")),
                         ("/*__STORY__*/", bundle)):
        head, found, tail = page.partition(marker)
        if not found:
            raise ValueError(f"Template is missing {marker}")
        page = head + text + tail
    out = resolve_output(path or STORY_HTML)
    out.write_text(page, encoding="utf-8")
    return out


def story_inputs(manifest, vantage, method="tcp", scenarios=None):
    """(benign packets, {scenario: attack packets}, {label: benign packets}) for one vantage.

    Captures whose timebase the manifest marks unusable are skipped. The benign captures of
    every label feed the cluster drawing; only `vantage` is learned and replayed.
    """
    rows = manifest[manifest["method"].eq(method)]
    if "usable" in rows.columns:
        rows = rows[rows["usable"].astype(str).str.lower().eq("true")]
    benign = rows[rows["scenario"].eq("benign")]
    if vantage not in set(benign["label"]):
        raise ValueError(f"No usable benign {method} capture for {vantage}; "
                         f"choose one of {', '.join(sorted(benign['label']))}.")
    cluster_captures = {row.label: load_flow_packets(row.path) for row in benign.itertuples()}
    attacks = rows[rows["label"].eq(vantage) & ~rows["scenario"].eq("benign")]
    if scenarios is not None:
        attacks = attacks[attacks["scenario"].isin(scenarios)]
    targets = {row.scenario: load_flow_packets(row.path)
               for row in attacks.sort_values("scenario").itertuples()}
    return cluster_captures[vantage], targets, cluster_captures


def main(argv=None, manifest=None):
    """Build the story for one vantage and write the page; returns its path."""
    import argparse

    parser = argparse.ArgumentParser(
        description="The state machine learned and replayed, as one interactive page.")
    parser.add_argument("--vantage", default=DEFAULT_VANTAGE,
                        help="capture label to learn and replay (default: %(default)s)")
    parser.add_argument("--method", default="tcp", choices=("tcp", "ptcp"))
    parser.add_argument("--scenarios", nargs="*", default=None,
                        help="attack scenarios to replay (default: every one in the manifest)")
    parser.add_argument("--forget", type=float, default=FORGET_SECONDS,
                        help="anomaly clock, seconds (default: %(default)s)")
    parser.add_argument("--out", default=STORY_HTML)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args(argv)

    if manifest is None:
        import local_paths
        manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    benign, targets, cluster_captures = story_inputs(manifest, args.vantage, args.method,
                                                     args.scenarios)
    built = build_story(benign, targets, cluster_captures, args.vantage, args.forget)
    out = write_html(built, args.out)
    print(f"Wrote {out} | {out.stat().st_size / 1e6:.1f} MB | vantage={args.vantage} "
          f"| replays: held-out benign, {', '.join(targets) or 'no attacks'}")
    print("Open it in a browser; it needs no network.")
    return out


if __name__ == "__main__":
    main()
