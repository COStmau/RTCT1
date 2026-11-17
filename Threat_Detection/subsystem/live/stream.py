"""Live detection: packets as they arrive, scored one closed second at a time.

The demo page (viz/page.py) scores whole recordings. This scores a stream with the same
machine, the same cutoffs (methods.calibration.calibrate) and the same window rules
(methods.calibration.WindowRules), so a live tap and a replayed recording of it can only
differ where a stream has to: it cannot see the future.

  PcapStream(fileobj)      frames from a classic-pcap byte stream (tcpdump -U -w -), no seeks
  packet_row(frame)        one frame as the flow columns (ts, frame_len, src_ip, ...)
  Windower(lateness)       packet rows in, closed 1-second windows of flows out
  LiveDetector(cal)        one held scorer: each closed window's peak score and status
  calibrate_live(source)   the calibration for a tap, from a recording or from buffered rows
  replay(path, cal)        a recording through the live path, for checking it against the page

The one rule that changes: offline, methods.pdfa.segment_flows drops a 5-tuple whose packets
span more than one window anywhere in the capture. Live, a window is held `lateness` seconds
after it ends, and a 5-tuple is kept in it only if it appeared in no earlier window (within
HISTORY_SECONDS) and in none of the `lateness` windows after. A connection that idles longer
than `lateness` and then speaks again is the case the two can disagree on.
"""
import struct
import sys
from collections import deque
from pathlib import Path

# a script run as `python live/worker.py` gets live/ as sys.path[0]; the project root goes first
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from convert.read import HEAD_BYTES, LINKTYPES, PCAP_MAGIC, CaptureReader, Frame, detect_format
from convert.rows import dissect, ts_seconds
from core.data_io import normalize_columns
from core.detectors import PERSISTENCE_WINDOW
from core.features import WINDOW_SIZE
from core.reporting import CLEAR_WINDOWS
from methods.calibration import WindowRules, calibrate
from methods.pdfa import FLOW_COLUMNS, encode
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

    `calibration` is calibrate_live(...) for this tap. Traces slide across window edges,
    exactly as they do over a recording, and the windowed clock starts cold, so the first
    `warmup_s` seconds report warmup instead of normal. `swap` replaces the machine while
    the stream runs (a re-learned baseline): open alerts and the window count carry over,
    the clock starts cold again.
    """

    def __init__(self, calibration, forget_seconds=FORGET_SECONDS, warmup_s=None):
        self.forget_seconds = float(forget_seconds)
        self.rules = WindowRules(forget_seconds if warmup_s is None else warmup_s)
        self.last_window = -1
        self._load(calibration)

    def _load(self, calibration):
        self.model = calibration["model"]
        self.cutoffs = calibration["cutoffs"]
        self.length = self.model["trace_len"]
        self.scorer = WindowedFrequencyScorer(self.model["pdfa"], self.forget_seconds)
        self.symbols = deque(maxlen=self.length)
        self.pairs = deque(maxlen=self.length)      # each symbol's flow, for the peak trace

    def swap(self, calibration):
        """Score with a newly learned machine from the next window on."""
        self._load(calibration)
        self.rules.warmup_s = (self.last_window + 1) * WINDOW_SIZE + self.forget_seconds

    def window(self, closed, t0):
        """The verdict for one closed window from Windower (t0: the stream's first packet)."""
        flows = closed["flow_rows"]
        peak, unlikely, top = np.nan, False, None
        if len(flows):
            for symbol, start, src, dst in zip(encode(flows, self.model["enc"]), flows["start_ts"],
                                               flows["src_ip"], flows["dst_ip"]):
                self.symbols.append(symbol)
                self.pairs.append((src, dst))
                if len(self.symbols) < self.length:
                    continue
                trace = tuple(self.symbols)
                # the scorer wants time order; a re-learned machine may see an older flow first
                score = self.scorer.score(trace, max(float(start) - t0, self.scorer.last_when))
                if np.isnan(peak) or score > peak:
                    peak, top = score, (trace, tuple(self.pairs))
                unlikely |= trace_score(self.model["pdfa"], trace) < self.cutoffs["likelihood"]
        scored = not np.isnan(peak)
        flagged = bool(scored and peak > self.cutoffs["windowed"])
        verdict = self.rules.step(closed["t"], scored, flagged, bool(unlikely))
        self.last_window = closed["t"]
        out = {"t": closed["t"], "peak": None if not scored else float(peak),
               "cutoff": float(self.cutoffs["windowed"]), "flagged": flagged,
               "likelihood_flag": bool(unlikely), **verdict}
        if top is not None and (flagged or unlikely):
            # why: the trace behind the peak, and who its flows were between
            out["top"] = {"symbols": list(top[0]),
                          "pairs": [[str(a), str(b)] for a, b in dict.fromkeys(top[1])
                                    if a is not None and b is not None]}
        return out


def describe(calibration, forget_seconds=FORGET_SECONDS, lateness=None):
    """What a page needs to know about a calibration: the cutoff and what it rests on."""
    cal = calibration["cutoffs"]["calibration"]
    return {"cutoff": float(calibration["cutoffs"]["windowed"]),
            "train_flows": int(calibration["train_flows"]) if "train_flows" in calibration
            else len(calibration["train"]),
            "held_windows": cal["windowed_windows"], "benign_rate": cal["windowed_benign_rate"],
            "trace_len": calibration["model"]["trace_len"],
            "forget_seconds": float(forget_seconds), "lateness": lateness,
            "persistence": PERSISTENCE_WINDOW, "clear_windows": CLEAR_WINDOWS}


def no_verdict(closed):
    """A closed window from a tap with no machine yet: counted, not judged."""
    return {"t": closed["t"], "peak": None, "cutoff": None, "flagged": False,
            "likelihood_flag": False, "alert": False, "released": False, "status": "learning",
            "forgetting_shown": False}


WINDOW_FACTS = ("packets", "bytes", "flows", "dropped", "new_endpoints", "endpoints", "late", "pairs")


def _blank_to_none(values):
    return {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in values.items()}


def load_packets(path):
    """A recording's packets as a frame of FLOW_COLUMNS: a pcap/pcapng dissected, a CSV as read."""
    path = Path(path)
    try:
        kind = detect_format(path)
    except (ValueError, OSError):
        kind = "csv" if path.suffix.lower() == ".csv" else None
    if kind in ("pcap", "pcapng"):
        return pd.DataFrame([packet_row(frame) for frame in CaptureReader(str(path)).frames()],
                            columns=FLOW_COLUMNS)
    if kind != "csv":
        raise ValueError(f"{path.name}: not a CSV, pcap or pcapng file")
    frame = normalize_columns(pd.read_csv(path, low_memory=False))
    missing = [c for c in FLOW_COLUMNS if c not in frame.columns]
    if missing:
        raise ValueError(f"{path.name} is missing packet columns: {', '.join(missing)}")
    return frame[FLOW_COLUMNS]


def packet_rows(packets):
    """A packet frame as the row dicts Windower takes, blanks as None."""
    for row in packets.to_dict("records"):
        yield _blank_to_none(row)


def frame_rows(path):
    """Packet rows of a capture file, in order."""
    return packet_rows(load_packets(path))


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


def calibrate_live(source, forget_seconds=FORGET_SECONDS, lateness=LATENESS):
    """methods.calibration.calibrate on benign packets, with flows cut by the live rule.

    `source` is a recording's path or a packet frame (what a tap buffered from its stream).
    Offline, a DNS lookup whose source port is reused half a minute later is one long flow and
    is dropped; live it is two short ones and is kept. Training on the offline flows would
    teach a live tap that its own DNS is unusual, so the live monitor learns from the
    flows it will see.
    """
    packets = source if isinstance(source, pd.DataFrame) else load_packets(source)
    if packets.empty:
        raise ValueError("Too few training flows: no packets")
    return calibrate(packets, forget_seconds, flows=live_flows(packet_rows(packets), lateness))


def replay(path, calibration, forget_seconds=FORGET_SECONDS, lateness=LATENESS):
    """A recording run through the live path: one verdict per window, as a live tap gives."""
    windower = Windower(lateness)
    detector = LiveDetector(calibration, forget_seconds)
    verdicts = []
    for row in frame_rows(path):
        for closed in windower.add(row):
            verdicts.append(_verdict(detector, closed, windower.t0))
    for closed in windower.flush():
        verdicts.append(_verdict(detector, closed, windower.t0))
    return verdicts


def _verdict(detector, closed, t0):
    """One window's verdict with its traffic facts, as a tap reports it."""
    judged = detector.window(closed, t0) if detector is not None else no_verdict(closed)
    return {**judged, **{k: closed[k] for k in WINDOW_FACTS}}
