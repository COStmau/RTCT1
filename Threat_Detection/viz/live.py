"""Live detection: packets as they arrive, scored one closed second at a time.

The page (viz/page.py) scores whole recordings. This scores a stream with the same machine,
the same cutoffs (page.calibrate) and the same window rules (page.LiveStatus), so a live tap
and a replayed recording of it can only differ where a stream has to: it cannot see the future.

  PcapStream(fileobj)      frames from a classic-pcap byte stream (tcpdump -U -w -), no seeks
  packet_row(frame)        one frame as the flow columns (ts, frame_len, src_ip, ...)
  Windower(lateness)       packet rows in, closed 1-second windows of flows out
  LiveDetector(cal)        one held scorer: each closed window's peak score and status
  replay(path, cal)        a recording through the live path, for checking it against the page

Run as a worker, one per tap, so taps score on separate cores (viz/monitor.py does this):
  <capture command writing pcap to stdout> | python viz/live.py watch --label pod-api
      --baseline <the tap's benign csv or pcap> [--record out.pcap]
It prints one JSON line per closed window (and a "ready" line with the cutoff first).

The one rule that changes: offline, methods.pdfa.segment_flows drops a 5-tuple whose packets
span more than one window anywhere in the capture. Live, a window is held `lateness` seconds
after it ends, and a 5-tuple is kept in it only if it appeared in no earlier window (within
HISTORY_SECONDS) and in none of the `lateness` windows after. A connection that idles longer
than `lateness` and then speaks again is the case the two can disagree on.
"""
import argparse
import json
import os
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path

# a script run as `python viz/live.py` gets viz/ as sys.path[0]; the project root goes first
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from convert.read import HEAD_BYTES, LINKTYPES, PCAP_MAGIC, CaptureReader, Frame
from convert.rows import dissect, ts_seconds
from core.features import WINDOW_SIZE
from methods.pdfa import encode
from methods.scores import FORGET_SECONDS, WindowedFrequencyScorer, trace_score

LATENESS = 2               # windows a closed window waits for the packets after it
HISTORY_SECONDS = 120      # how long a 5-tuple is remembered as "already seen"
PAIRS_KEPT = 40            # address pairs a window reports to the live map
FLOW_KEY = ("src_ip", "dst_ip", "src_port", "dst_port", "proto")


# ---------------------------------------------------------------- frames from a pipe

class PcapStream:
    """Frames of a classic pcap arriving on a pipe, in order, without seeking.

    `tee`, when given, receives every byte read (global header, then each record whole), so
    the stream can be written to disk as the same pcap it arrived as.
    """

    def __init__(self, fileobj, tee=None):
        self.fileobj, self.tee = fileobj, tee
        self.frames_read = 0

    def _read(self, size):
        data = self.fileobj.read(size)
        if data and self.tee:
            self.tee(data)
        return data

    def frames(self):
        magic = self._read(4)
        if not magic:
            return
        if magic not in PCAP_MAGIC:
            raise ValueError("not a classic pcap stream (tcpdump -w - writes one)")
        order, digits = PCAP_MAGIC[magic]
        header = self._read(20)
        if len(header) < 20:
            return
        linktype = struct.unpack(order + "I", header[16:])[0] & 0xFFFF
        if linktype not in LINKTYPES:
            raise ValueError(f"unsupported linktype {linktype}")
        while True:
            record = self._read(16)
            if len(record) < 16:
                return
            sec, frac, incl_len, orig_len = struct.unpack(order + "IIII", record)
            data = self._read(incl_len) if incl_len else b""
            if len(data) < incl_len:
                return
            self.frames_read += 1
            yield Frame(self.frames_read, sec, frac, digits, orig_len, data[:HEAD_BYTES], linktype)


def packet_row(frame):
    """The flow columns for one frame, as the CSV path would give them (blank -> None)."""
    row, _ = dissect(frame)
    return {"ts": ts_seconds(frame.ts_sec, frame.ts_frac, frame.ts_digits),
            "frame_len": row["frame_len"], "src_ip": row["src_ip"], "dst_ip": row["dst_ip"],
            "src_port": row["src_port"], "dst_port": row["dst_port"], "proto": row["proto"]}


# ---------------------------------------------------------------- windows of flows

class Windower:
    """Packet rows in, closed windows out, each with the flows that lie wholly inside it.

    Rows must arrive in roughly time order (a tap's own capture does). Window w closes once
    the stream's clock passes the end of window w + `lateness`, or, for a quiet tap, when
    `tick(now)` says wall time has. A packet for a window already closed is counted as
    `late` and its 5-tuple marked as spanning, never added to the past.
    """

    def __init__(self, lateness=LATENESS, history_seconds=HISTORY_SECONDS):
        self.lateness = int(lateness)
        self.history_windows = int(history_seconds / WINDOW_SIZE)
        self.t0 = None
        self.offset = None            # wall time minus capture time, from the first packet
        self.next_window = 0          # the oldest window not yet closed
        self.open = {}                # window -> {"flows": {key: [...]}, "packets", "bytes", "ends"}
        self.history = {}             # key -> last closed window it appeared in
        self.endpoints = set()
        self.late = 0
        self.clock = None             # newest packet time seen

    def _window(self, w):
        return self.open.setdefault(w, {"flows": {}, "packets": 0, "bytes": 0, "ends": set(), "pairs": {}})

    def add(self, row, wall=None):
        """Take one packet row; return the windows that closed because of it."""
        ts = float(row["ts"])
        if self.t0 is None:
            self.t0 = ts
            if wall is not None:
                self.offset = wall - ts
        w = int(np.floor((ts - self.t0) / WINDOW_SIZE))
        key = tuple(row[c] for c in FLOW_KEY)
        if w < self.next_window:
            self.late += 1
            self.history[key] = max(self.history.get(key, -1), self.next_window - 1)
            return []
        window = self._window(w)
        window["packets"] += 1
        window["bytes"] += int(row["frame_len"] or 0)
        for end in (row["src_ip"], row["dst_ip"]):
            if end is not None:
                window["ends"].add(str(end))
        if row["src_ip"] is not None and row["dst_ip"] is not None:
            pair = (str(row["src_ip"]), str(row["dst_ip"]))
            window["pairs"][pair] = window["pairs"].get(pair, 0) + 1
        flow = window["flows"].get(key)
        if flow is None:
            window["flows"][key] = [ts, ts, int(row["frame_len"] or 0)]
        else:
            flow[0], flow[1] = min(flow[0], ts), max(flow[1], ts)
            flow[2] += int(row["frame_len"] or 0)
        self.clock = ts if self.clock is None else max(self.clock, ts)
        return self._close_through(int(np.floor((self.clock - self.t0) / WINDOW_SIZE)) - self.lateness - 1)

    def tick(self, wall):
        """Close the windows wall time says are over, for a tap with nothing to say."""
        if self.t0 is None or self.offset is None:
            return []
        now = wall - self.offset
        return self._close_through(int(np.floor((now - self.t0) / WINDOW_SIZE)) - self.lateness - 1)

    def flush(self):
        """Close every window: the stream ended."""
        if not self.open:
            return []
        return self._close_through(max(self.open), final=True)

    def _close_through(self, last, final=False):
        closed = []
        while self.next_window <= last:
            closed.append(self._close(self.next_window, final))
            self.next_window += 1
        return closed

    def _close(self, w, final):
        window = self.open.pop(w, None) or {"flows": {}, "packets": 0, "bytes": 0, "ends": set(), "pairs": {}}
        after = [self.open.get(w + k) for k in range(1, self.lateness + 1)]
        kept, spanning = [], 0
        for key, (first, last, size) in window["flows"].items():
            seen_before = key in self.history and self.history[key] >= w - self.history_windows
            seen_after = any(a is not None and key in a["flows"] for a in after)
            # the offline rule's own boundary: a flow ending exactly on the next window's
            # start belongs to this one, and a lone packet on a boundary to the one before
            inside = np.floor((first - self.t0) / WINDOW_SIZE) == np.floor((last - 1e-9 - self.t0) / WINDOW_SIZE)
            if seen_before or seen_after or not inside:
                spanning += 1
                continue
            kept.append({"start_ts": first, "bytes": size, "duration": float(last - first),
                         "src_ip": key[0], "dst_ip": key[1], "proto": key[4]})
        for key in window["flows"]:
            self.history[key] = w
        if w % 30 == 0:   # forget 5-tuples older than the history window
            floor = w - self.history_windows
            self.history = {k: v for k, v in self.history.items() if v >= floor}
        new = window["ends"] - self.endpoints
        self.endpoints |= window["ends"]
        flows = pd.DataFrame(kept, columns=["start_ts", "bytes", "duration", "src_ip", "dst_ip", "proto"])
        return {"t": w, "packets": window["packets"], "bytes": window["bytes"],
                "flows": len(kept), "dropped": spanning, "new_endpoints": len(new),
                "endpoints": len(self.endpoints), "late": self.late,
                # who talked to whom this second (packets), busiest first: the live map draws it
                "pairs": [[a, b, n] for (a, b), n in sorted(window["pairs"].items(),
                                                            key=lambda kv: -kv[1])[:PAIRS_KEPT]],
                "flow_rows": flows.sort_values("start_ts", kind="stable").reset_index(drop=True)}


# ---------------------------------------------------------------- scoring

class LiveDetector:
    """One tap's detector held for a whole stream: closed windows in, verdicts out.

    `calibration` is page.calibrate(benign) for this tap. Traces slide across window edges,
    exactly as they do over a recording, and the windowed clock starts cold, so the first
    `warmup_s` seconds report warmup instead of normal.
    """

    def __init__(self, calibration, forget_seconds=FORGET_SECONDS, warmup_s=None):
        from viz.page import LiveStatus   # page imports nothing from here; keep it one-way
        self.model = calibration["model"]
        self.cutoffs = calibration["cutoffs"]
        self.length = self.model["trace_len"]
        self.scorer = WindowedFrequencyScorer(self.model["pdfa"], forget_seconds)
        self.rules = LiveStatus(forget_seconds if warmup_s is None else warmup_s)
        self.symbols = deque(maxlen=self.length)
        self.t0 = None

    def window(self, closed, t0):
        """The verdict for one closed window from Windower (t0: the stream's first packet)."""
        self.t0 = t0
        flows = closed["flow_rows"]
        peak, unlikely = np.nan, False
        if len(flows):
            for symbol, start in zip(encode(flows, self.model["enc"]), flows["start_ts"]):
                self.symbols.append(symbol)
                if len(self.symbols) < self.length:
                    continue
                trace = tuple(self.symbols)
                score = self.scorer.score(trace, float(start) - t0)
                peak = score if np.isnan(peak) else max(peak, score)
                unlikely |= trace_score(self.model["pdfa"], trace) < self.cutoffs["likelihood"]
        scored = not np.isnan(peak)
        flagged = bool(scored and peak > self.cutoffs["windowed"])
        verdict = self.rules.step(closed["t"], scored, flagged, bool(unlikely))
        return {"t": closed["t"], "peak": None if not scored else float(peak),
                "cutoff": float(self.cutoffs["windowed"]), "flagged": flagged,
                "likelihood_flag": bool(unlikely), **verdict,
                **{k: closed[k] for k in ("packets", "bytes", "flows", "dropped",
                                          "new_endpoints", "endpoints", "late", "pairs")}}


def frame_rows(path):
    """Packet rows of a capture file in order: pcap/pcapng through convert, a CSV as read."""
    from viz.sources import _kind, load_packets
    if _kind(path) in ("pcap", "pcapng"):
        for frame in CaptureReader(str(path)).frames():
            yield packet_row(frame)
        return
    frame = load_packets(path)
    for row in frame.itertuples(index=False):
        values = dict(zip(frame.columns, row))
        yield {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in values.items()}


def live_flows(rows, lateness=LATENESS):
    """Every flow the live rule keeps from a sequence of packet rows, in time order."""
    windower, parts = Windower(lateness), []
    for row in rows:
        parts.extend(c["flow_rows"] for c in windower.add(row))
    parts.extend(c["flow_rows"] for c in windower.flush())
    parts = [p for p in parts if len(p)]
    if not parts:
        return pd.DataFrame(columns=["start_ts", "bytes", "duration", "src_ip", "dst_ip", "proto"])
    return pd.concat(parts, ignore_index=True)


def calibrate_live(path_or_packets, forget_seconds=FORGET_SECONDS, lateness=LATENESS):
    """page.calibrate on a benign recording, with flows cut by the live rule.

    Offline, a DNS lookup whose source port is reused half a minute later is one long flow and
    is dropped; live it is two short ones and is kept. Training on the offline flows would
    teach a live tap that its own DNS is unusual, so the live monitor learns from the
    flows it will see.
    """
    from viz.page import calibrate
    from viz.sources import load_packets
    if isinstance(path_or_packets, pd.DataFrame):
        packets = path_or_packets
        rows = ({k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in r.items()}
                for r in packets.to_dict("records"))
    else:
        packets = load_packets(path_or_packets)
        rows = frame_rows(path_or_packets)
    return calibrate(packets, forget_seconds, flows=live_flows(rows, lateness))


def replay(path, calibration, forget_seconds=FORGET_SECONDS, lateness=LATENESS):
    """A recording run through the live path: one verdict per window, as a live tap gives."""
    windower = Windower(lateness)
    detector = LiveDetector(calibration, forget_seconds)
    verdicts = []
    for row in frame_rows(path):
        for closed in windower.add(row):
            verdicts.append(detector.window(closed, windower.t0))
    for closed in windower.flush():
        verdicts.append(detector.window(closed, windower.t0))
    return verdicts


# ---------------------------------------------------------------- the per-tap worker

def watch(stream, calibration, emit, record=None, forget_seconds=FORGET_SECONDS,
          lateness=LATENESS, clock=time.time, tick_every=0.5):
    """Score a pcap byte stream until it ends: one `emit(dict)` per closed window.

    A reader thread takes packets; this thread closes windows on wall time while the tap is
    quiet. `record`, a binary file, gets the stream's bytes as they arrive (a valid pcap).
    Each window carries `wall`, the wall-clock time its second began, and `lag`, how long
    after its end it was scored (about lateness + 1 s when keeping up).
    """
    windower = Windower(lateness)
    detector = LiveDetector(calibration, forget_seconds)
    lock, done = threading.Lock(), threading.Event()
    failure = []

    def publish(closed_windows):
        for closed in closed_windows:
            verdict = detector.window(closed, windower.t0)
            start = windower.offset + windower.t0 + closed["t"] * WINDOW_SIZE
            verdict.update(kind="window", wall=start, lag=round(clock() - start - WINDOW_SIZE, 2))
            emit(verdict)

    def read():
        try:
            for frame in PcapStream(stream, tee=record.write if record else None).frames():
                row = packet_row(frame)
                with lock:
                    publish(windower.add(row, wall=clock()))
        except Exception as error:     # a broken stream ends this tap, and says why
            failure.append(f"{type(error).__name__}: {error}")
        finally:
            done.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    while not done.wait(tick_every):
        with lock:
            publish(windower.tick(clock()))
    with lock:
        publish(windower.flush())
    emit({"kind": "end", "error": failure[0] if failure else None, "late": windower.late})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Score one tap's live pcap stream (stdin).")
    parser.add_argument("command", choices=["watch"])
    parser.add_argument("--label", required=True)
    parser.add_argument("--baseline", required=True, help="the tap's benign recording (csv or pcap)")
    parser.add_argument("--record", help="also write the stream to this pcap")
    parser.add_argument("--forget", type=float, default=FORGET_SECONDS)
    parser.add_argument("--lateness", type=int, default=LATENESS)
    args = parser.parse_args(argv)

    def emit(message):
        message["label"] = args.label
        try:
            sys.stdout.write(json.dumps(message) + "\n")
            sys.stdout.flush()
        except BrokenPipeError:     # the monitor stopped listening: stop quietly
            sys.stderr.close()
            os._exit(0)

    try:
        calibration = calibrate_live(Path(args.baseline).expanduser(), args.forget, args.lateness)
    except Exception as error:
        emit({"kind": "end", "error": f"could not learn {args.label}: {error}"})
        return 1
    cal = calibration["cutoffs"]["calibration"]
    emit({"kind": "ready", "cutoff": float(calibration["cutoffs"]["windowed"]),
          "train_flows": len(calibration["train"]), "held_windows": cal["windowed_windows"],
          "benign_rate": cal["windowed_benign_rate"], "baseline": str(args.baseline)})
    record = open(args.record, "wb") if args.record else None
    try:
        watch(sys.stdin.buffer, calibration, emit, record, args.forget, args.lateness)
    finally:
        if record:
            record.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
