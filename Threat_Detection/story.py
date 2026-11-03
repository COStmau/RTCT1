"""The state machine's story as one interactive page: the cluster, the learning, the replay.

build_story() runs the same pipeline the detector runs, through the instrumentation hooks in
statemachine.py, and returns a plain dict (the "bundle") for one vantage. build_stories()
composes one bundle per vantage around a single shared cluster, so the page can switch taps
without re-running Python. write_html() inlines that bundle and the renderer in
story_template/ into one self-contained page in outputs/. The page draws only what the bundle
says: the cluster is inferred from traffic (cluster.py), positions are computed (layout.py),
and every score is the scorer's own number.

Run it with:  .venv/bin/python story.py                       (every steady tap, every attack)
              .venv/bin/python story.py --vantage pod-nginx   (open on pod-nginx)
              .venv/bin/python story.py --vantages pod-lidar pod-nginx
"""
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

import cluster as topology
import layout
from data_io import (MANIFEST_NAME, level_from_label, load_manifest, resolve_output,
                     timebase_issues)
from detectors import PERSISTENCE_WINDOW, persistent_mask
from evaluation import BULK_LABELS
from reporting import CLEAR_WINDOWS
from features import WINDOW_SIZE
from statemachine import (FORGET_SECONDS, FrequencyScorer, WindowedFrequencyScorer, encode,
                          fit_model, frequency_cutoff, frequency_scores_by_window, make_flows,
                          n_windows_for, pdfa_states_in_order, score_cutoff, score_flows,
                          load_flow_packets, segment_flows, split_flows, trace_score,
                          trace_states)

DEFAULT_VANTAGE = "pod-lidar"   # its 5 s replay loop is what FORGET_SECONDS was sized for
HELD_OUT = "benign (held out)"
# strongest first; "warmup" and "nodata" are insufficient evidence, never "normal"
WINDOW_STATUSES = ("alert", "flagged", "unseen", "nodata", "warmup", "released", "normal")
RELEASE_SHOWN = 2           # windows after a release that still say "released"
MAX_STEP_DETAIL = 400       # merge steps drawn one by one; the rest are counted
MAX_STREAM = 2000           # training flows shown in the symbol stream
STORY_HTML = "statemachine_story.html"
PAGE_LIMIT = 15 * 1024 * 1024   # bytes; past it, trace detail of the other vantages is dropped
VANTAGE_PARTS = ("meta", "learning", "playback")   # what each vantage carries; the cluster is shared
TRIMMED_KEYS = ("terms", "expired")                # per-trace detail only the side panel reads
TEMPLATE_DIR = Path(__file__).resolve().parent / "story_template"
D3_FILE = "vendor/d3.v7.9.0.min.js"


def build_story(benign, targets, cluster_captures, vantage, forget_seconds=FORGET_SECONDS,
                found=None):
    """The story bundle for one vantage.

    `benign` and each `targets[scenario]` are packet frames for `vantage` (flow columns, as
    statemachine.load_flow_packets reads them). `cluster_captures` maps every capture label
    to a benign packet frame and drives the cluster drawing; it may be empty. `found` is that
    cluster already inferred, so several vantages can share one inference.

    Calibration is held to the replay's own conditions. The windowed cutoff comes from the
    held-out windows scored on a warm clock (the training flows run first, as they did in the
    recording), so a half-empty clock does not drag it down. The cumulative score grows with
    capture length alone, so it gets no single cutoff: each window is compared with the most
    the whole benign recording reached by the same age.
    """
    t0 = float(benign["ts"].min())
    flows, dropped = segment_flows(make_flows(benign), t0)
    train, holdout = split_flows(flows)
    events = []
    model = fit_model(train, trace=events)
    if found is None:
        found = topology.infer_cluster(cluster_captures)

    n_windows = n_windows_for(benign)
    first_held = int((float(holdout["start_ts"].iloc[0]) - t0) // WINDOW_SIZE)
    warm = frequency_scores_by_window(model, flows, t0, n_windows, forget_seconds)
    by_age = frequency_scores_by_window(model, flows, t0, n_windows, None)
    cutoffs = {
        "likelihood": score_cutoff(score_flows(model, holdout)),
        "windowed": frequency_cutoff(warm[first_held + 1:]),
        "cumulative_reference": list(pd.Series(by_age).cummax().to_numpy()),
    }
    # the held-out replay runs on the whole recording so its clock is warm; only the traces
    # ending in the held-out part are kept
    captures = [_capture(HELD_OUT, flows, t0, n_windows, float(benign["ts"].max()) - t0,
                         model, found, forget_seconds, cutoffs, dropped,
                         first_trace=max(len(train) - model["trace_len"] + 1, 0), warmup_s=0.0)]
    for scenario, packets in targets.items():
        target_t0 = float(packets["ts"].min())
        target_flows, target_dropped = segment_flows(make_flows(packets), target_t0)
        captures.append(_capture(scenario, target_flows, target_t0, n_windows_for(packets),
                                 float(packets["ts"].max()) - target_t0, model, found,
                                 forget_seconds, cutoffs, target_dropped,
                                 first_trace=0, warmup_s=float(forget_seconds)))

    return {
        "meta": {"vantage": vantage, "level": level_from_label(vantage),
                 "forget_seconds": float(forget_seconds), "trace_len": model["trace_len"],
                 "window_size": float(WINDOW_SIZE), "persistence": PERSISTENCE_WINDOW,
                 "clear_windows": CLEAR_WINDOWS,
                 "train_flows": len(train), "holdout_flows": len(holdout),
                 "train_span_s": float(train["start_ts"].max() - train["start_ts"].min()),
                 "holdout_span_s": float(holdout["start_ts"].max() - holdout["start_ts"].min()),
                 "dropped_flows": dropped,
                 "calibration_warning": (
                     f"{vantage} steps into bulk transfer mid-recording; evaluation.BULK_LABELS "
                     "says such a vantage never sets a cutoff, so these verdicts are for "
                     "inspection only." if vantage in BULK_LABELS else None),
                 "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        "cluster": found,
        "learning": _learning(model, events, train, t0),
        "playback": {"captures": captures},
    }


def build_stories(inputs, cluster_captures, forget_seconds=FORGET_SECONDS, selected=None):
    """One page's bundle for several vantages: the cluster once, then each vantage's story.

    `inputs` maps a vantage label to its (benign packets, {scenario: attack packets}), as
    story_inputs returns them. Each vantage block is build_story for that vantage alone;
    the cluster is inferred once from `cluster_captures` and shared. `selected` is the
    vantage the page opens on (default: the first).
    """
    found = topology.infer_cluster(cluster_captures)
    stories = {vantage: build_story(benign, targets, cluster_captures, vantage, forget_seconds,
                                    found=found)
               for vantage, (benign, targets) in inputs.items()}
    return compose(stories, found, selected)


def compose(stories, cluster, selected=None):
    """{vantage: build_story bundle} as the page bundle: a shared cluster, one block each."""
    if not stories:
        raise ValueError("No vantage to draw.")
    selected = selected if selected in stories else next(iter(stories))
    return {"selected": selected, "cluster": cluster, "trimmed": [],
            "vantages": {vantage: {part: story[part] for part in VANTAGE_PARTS}
                         for vantage, story in stories.items()}}


def trim(bundle, keep):
    """The bundle with per-trace `terms` and `expired` dropped from every vantage but `keep`.

    Those two only feed the side panel's breakdown of the trace under the playhead; scores,
    states, visit counts and every window verdict stay. Trimmed vantages are listed in
    `trimmed`, and the page says so instead of drawing the breakdown.
    """
    vantages = {}
    for vantage, block in bundle["vantages"].items():
        if vantage == keep:
            vantages[vantage] = block
            continue
        captures = [dict(capture, traces=[{k: v for k, v in trace.items() if k not in TRIMMED_KEYS}
                                          for trace in capture["traces"]])
                    for capture in block["playback"]["captures"]]
        vantages[vantage] = dict(block, playback=dict(block["playback"], captures=captures))
    return dict(bundle, vantages=vantages,
                trimmed=sorted(vantage for vantage in vantages if vantage != keep))


def vantage_sizes(bundle):
    """Bytes of compact JSON each vantage adds to the page, and the shared cluster's."""
    sizes = {vantage: len(to_json(block)) for vantage, block in bundle["vantages"].items()}
    return dict(sizes, cluster=len(to_json(bundle["cluster"])))


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

    attempt = lambda a: {"red": by_path[a["red_path"]], "red_visits": a["red_visits"],
                         "bound": a["bound"],
                         "tests": [{"symbol": s, "p_red": p, "p_blue": q} for s, p, q in a["tests"]]}
    steps = [dict(attempt(step), kind=step["kind"], blue=by_path[step["path"]],
                  blue_visits=step["blue_visits"],
                  attempts=[attempt(a) for a in step["attempts"]])
             for step in events[1:1 + MAX_STEP_DETAIL]]
    settled = layout.settled_steps(nodes, [
        {"kind": step["kind"], "red": by_path[step["red_path"]], "blue": by_path[step["path"]]}
        for step in events[1:]])
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
        "pta": [dict({key: value for key, value in node.items() if key != "path"},
                     settled_step=settled[node["id"]]) for node in nodes],
        "steps": steps,
        "steps_total": len(events) - 1,
        "pdfa": graph,
    }


def _capture(scenario, flows, t0, n_windows, duration, model, found, forget, cutoffs, dropped,
             first_trace, warmup_s):
    """One capture's traces replayed through one windowed and one cumulative scorer.

    Every trace from the start of `flows` is scored, so the clocks are as warm as they were
    in the recording, and the traces from `first_trace` on are kept. `warmup_s` is how long
    the windowed clock runs cold at the start of what is kept.
    """
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
        total = cumulative.score(trace)
        if index < first_trace:
            continue
        reached = trace_states(pdfa, trace)
        traces.append({
            "i": index, "t": when, "symbols": list(trace),
            "states": [ids[id(state)] for state in reached],
            "fell_off_at": len(reached) if len(reached) < length else None,
            "likelihood": trace_score(pdfa, trace),
            "windowed": float(sum(map(sum, terms))),
            "cumulative": total,
            "terms": [[float(term) for term in state_terms] for state_terms in terms],
            # exact integers: the page would otherwise invert rounded logarithms
            "visits": [[int(np.rint(np.expm1(state_terms[0]))), int(state.visits)]
                       for state_terms, state in zip(terms, reached)],
            "expired": [[float(seen), ids[key]] for seen, key in expired],
        })
    edges, new_elements, new_edges = _flow_elements(flows, found)
    return {
        # t0 is the capture's first packet (epoch seconds): taps recorded side by side line
        # up on it, so the page can compare one scenario across taps on one time axis
        "scenario": scenario, "t0": float(t0), "duration_s": duration,
        "start_s": traces[0]["t"] if traces else 0.0,
        "warmup_s": warmup_s, "dropped_flows": int(dropped),
        "cutoffs": cutoffs,
        "flow_edges": edges, "new_elements": new_elements, "new_edges": new_edges,
        "traces": traces,
        "windows": _windows(traces, n_windows, cutoffs, warmup_s),
    }


def _flow_elements(flows, found):
    """Each flow's element pair, plus elements and conversations benign never showed.

    The cluster is drawn from benign traffic, so an attack's new address or a new pair of
    known elements has nothing to light up; those are returned so the page can draw them.
    """
    element_of = topology.element_index(found)
    known = {e["id"] for kind in ("hosts", "pods", "services", "external") for e in found[kind]}
    benign_pairs = {tuple(sorted((e["src"], e["dst"]))) for e in found["edges"]}
    new_elements, new_pairs = {}, Counter()

    def place(address):
        element = element_of(address)
        if element is None or element not in known:
            located = topology.locate(found, address)
            if located is None:
                return None
            element = located["id"]
            if element not in known:
                new_elements.setdefault(element, located)
        return element

    edges = []
    for src, dst in zip(flows["src_ip"], flows["dst_ip"]):
        pair = [place(src), place(dst)]
        edges.append(pair)
        if pair[0] and pair[1] and pair[0] != pair[1]:
            key = tuple(sorted(pair))
            if key not in benign_pairs:
                new_pairs[key] += 1
    return (edges, list(new_elements.values()),
            [{"src": a, "dst": b, "flows": n} for (a, b), n in sorted(new_pairs.items())])


def _windows(traces, n_windows, cutoffs, warmup_s):
    """Per window: both detectors' flags, sustained alerts, releases, and one status.

    `status` is the strongest verdict, in WINDOW_STATUSES order. "unseen" is the likelihood
    detector alone: a trace that falls off the machine visits fewer states, which lowers the
    frequency score, so novel behaviour shows there and not in the windowed score. A window
    no trace ended in is "nodata", and a quiet window inside the cold clock is "warmup":
    missing evidence is reported as missing, never as normal.

    An alert is released only after CLEAR_WINDOWS scored, unflagged windows since the last
    flag, the incident rule reporting uses. A window with no trace is absence of evidence: it
    neither counts toward the run nor resets it, and a release never lands on one. `forgetting_shown`
    marks windows where forgetting visibly matters: an alert came earlier, the windowed
    score has let go, and the cumulative score is above anything benign reached by that age.
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
    scored = ~np.isnan(peak)
    flagged = np.nan_to_num(peak, nan=-np.inf) > cutoffs["windowed"]
    reference = np.full(n_windows, np.nan)
    known = np.array(cutoffs["cumulative_reference"][:n_windows], dtype=float)
    reference[:len(known)] = known
    held = np.nan_to_num(cumulative, nan=-np.inf) > np.nan_to_num(reference, nan=np.inf)
    alert = persistent_mask(flagged).to_numpy()
    windows, pending, clean, since_release, alerted = [], False, 0, None, False
    for w in range(n_windows):
        pending = pending or bool(alert[w])
        clean = 0 if flagged[w] else clean + 1 if scored[w] else clean
        released = pending and scored[w] and clean >= CLEAR_WINDOWS
        if released:
            pending, since_release = False, 0
        elif since_release is not None:
            since_release = since_release + 1 if clean else None
        status = ("alert" if alert[w] else "flagged" if flagged[w] else "unseen" if unlikely[w]
                  else "nodata" if not scored[w] else "warmup" if w * WINDOW_SIZE < warmup_s
                  else "released" if since_release is not None and since_release <= RELEASE_SHOWN
                  else "normal")
        windows.append({"index": w, "peak": peak[w], "flagged": bool(flagged[w]),
                        "likelihood_flag": bool(unlikely[w]), "alert": bool(alert[w]),
                        "released": released, "status": status,
                        "forgetting_shown": bool(alerted and scored[w] and not flagged[w]
                                                 and held[w])})
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


def page_html(bundle):
    """The page as text: template, styles, D3, renderer and bundle all inlined."""
    page = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")
    # "</" inside an inline script would close it early; "<\/" is the same string to JSON
    script = "window.STORY = " + to_json(bundle).replace("</", "<\\/") + ";\n"
    for marker, text in (("/*__CSS__*/", (TEMPLATE_DIR / "story.css").read_text(encoding="utf-8")),
                         ("/*__D3__*/", (TEMPLATE_DIR / D3_FILE).read_text(encoding="utf-8")),
                         ("/*__JS__*/", (TEMPLATE_DIR / "story.js").read_text(encoding="utf-8")),
                         ("/*__STORY__*/", script)):
        head, found, tail = page.partition(marker)
        if not found:
            raise ValueError(f"Template is missing {marker}")
        page = head + text + tail
    return page


def write_html(story, path=None, limit=PAGE_LIMIT):
    """One self-contained page, kept under `limit` bytes.

    `story` is a build_stories bundle, or one build_story bundle (drawn as a one-tap page).
    A page over the limit drops trace detail from every vantage but the selected one (see
    trim); one still over it is refused rather than written.
    """
    bundle = story if "vantages" in story else compose(
        {story["meta"]["vantage"]: story}, story["cluster"])
    page = page_html(bundle)
    if len(page.encode("utf-8")) > limit:
        bundle = trim(bundle, bundle["selected"])
        page = page_html(bundle)
        print(f"page over {limit / 1e6:.1f} MB: dropped per-trace terms and expired visits "
              f"from {', '.join(bundle['trimmed'])}")
    size = len(page.encode("utf-8"))
    if size > limit:
        raise ValueError(f"The page is {size / 1e6:.1f} MB even trimmed, over the "
                         f"{limit / 1e6:.1f} MB limit; pass fewer --vantages.")
    out = resolve_output(path or STORY_HTML)
    out.write_text(page, encoding="utf-8")
    return out


def _usable_rows(manifest, method):
    rows = manifest[manifest["method"].eq(method)]
    if "usable" in rows.columns:
        rows = rows[rows["usable"].astype(str).str.lower().eq("true")]
    return rows


def _load(path):
    packets = load_flow_packets(path)
    return packets if timebase_issues(packets)["usable"] else None


def benign_captures(manifest, method="tcp"):
    """{label: benign packets} for every capture whose timebase is usable."""
    benign = _usable_rows(manifest, method)
    benign = benign[benign["scenario"].eq("benign")]
    loaded = {row.label: _load(row.path) for row in benign.itertuples()}
    return {label: packets for label, packets in loaded.items() if packets is not None}


def steady_vantages(cluster_captures, allow_bulk=False):
    """The labels a page draws by default: every usable benign capture, bulk ones only on consent."""
    return sorted(label for label in cluster_captures if allow_bulk or label not in BULK_LABELS)


def story_inputs(manifest, vantage, method="tcp", scenarios=None, allow_bulk=False,
                 cluster_captures=None):
    """(benign packets, {scenario: attack packets}, {label: benign packets}) for one vantage.

    Every capture's timebase is checked as it loads, whether or not the manifest carries a
    `usable` column, so a zero-timestamp capture is skipped instead of being windowed across
    decades. A bulk-transfer vantage (evaluation.BULK_LABELS) never sets a cutoff in this
    repo, so it is refused unless `allow_bulk`, and the page then says its verdicts are for
    inspection only. The benign captures of every label feed the cluster drawing; pass them
    as `cluster_captures` (benign_captures) to load them once for several vantages.
    """
    if vantage in BULK_LABELS and not allow_bulk:
        raise ValueError(f"{vantage} steps into bulk transfer mid-recording, and a bulk "
                         "vantage never sets a cutoff (evaluation.BULK_LABELS); pass "
                         "--allow-bulk to build it for inspection anyway.")
    rows = _usable_rows(manifest, method)
    if cluster_captures is None:
        cluster_captures = benign_captures(manifest, method)
    if vantage not in cluster_captures:
        raise ValueError(f"No usable benign {method} capture for {vantage}; "
                         f"choose one of {', '.join(sorted(cluster_captures))}.")
    attacks = rows[rows["label"].eq(vantage) & ~rows["scenario"].eq("benign")]
    if scenarios is not None:
        attacks = attacks[attacks["scenario"].isin(scenarios)]
    targets = {row.scenario: _load(row.path) for row in attacks.sort_values("scenario").itertuples()}
    skipped = sorted(s for s, p in targets.items() if p is None)
    if skipped:
        print(f"skipped {vantage} (unusable timebase): {', '.join(skipped)}")
    return (cluster_captures[vantage], {s: p for s, p in targets.items() if p is not None},
            cluster_captures)


def main(argv=None, manifest=None):
    """Build the story for several vantages and write one page; returns its path."""
    import argparse

    parser = argparse.ArgumentParser(
        description="The state machine learned and replayed, as one interactive page.")
    parser.add_argument("--vantages", nargs="+", default=None,
                        help="capture labels the page can switch between (default: every "
                             "usable benign capture; bulk-transfer ones only with --allow-bulk)")
    parser.add_argument("--vantage", default=None,
                        help=f"the tap the page opens on (default: {DEFAULT_VANTAGE} when drawn)")
    parser.add_argument("--method", default="tcp", choices=("tcp", "ptcp"))
    parser.add_argument("--scenarios", nargs="*", default=None,
                        help="attack scenarios to replay (default: every one in the manifest)")
    parser.add_argument("--forget", type=float, default=FORGET_SECONDS,
                        help="anomaly clock, seconds (default: %(default)s)")
    parser.add_argument("--allow-bulk", action="store_true",
                        help="draw bulk-transfer vantages too; their cutoffs are not trusted")
    parser.add_argument("--out", default=STORY_HTML)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args(argv)

    if manifest is None:
        import local_paths
        manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    cluster_captures = benign_captures(manifest, args.method)
    vantages = list(args.vantages or steady_vantages(cluster_captures, args.allow_bulk))
    if args.vantage and args.vantage not in vantages:
        vantages.append(args.vantage)
    inputs = {}
    for vantage in vantages:
        benign, targets, _ = story_inputs(manifest, vantage, args.method, args.scenarios,
                                          args.allow_bulk, cluster_captures)
        inputs[vantage] = (benign, targets)
    built = build_stories(inputs, cluster_captures, args.forget,
                          selected=args.vantage or DEFAULT_VANTAGE)
    out = write_html(built, args.out)
    for vantage, size in vantage_sizes(built).items():
        replays = ("" if vantage == "cluster" else " | held-out benign, " + ", ".join(
            c["scenario"] for c in built["vantages"][vantage]["playback"]["captures"][1:]))
        print(f"  {vantage:<22} {size / 1e6:5.2f} MB{replays}")
    print(f"Wrote {out} | {out.stat().st_size / 1e6:.1f} MB | {len(vantages)} vantages, "
          f"opens on {built['selected']}")
    print("Open it in a browser; it needs no network.")
    return out


if __name__ == "__main__":
    main()
