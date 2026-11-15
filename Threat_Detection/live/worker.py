"""One tap's scoring process: a pcap byte stream on stdin, one JSON line per closed second out.

live/monitor.py runs one of these per watched tap, so taps score on separate cores:

  <capture writing pcap to stdout> | python live/worker.py watch --label pod-api
        [--model m.pkl] [--baseline benign.csv] [--learn 60] [--control c.jsonl] [--record out.pcap]

Where the machine comes from, first that applies:
  --model      a machine saved by an earlier run, unless --baseline is newer than it
  --baseline   a benign recording (csv or pcap): learned now, then saved to --model
  --learn N    the tap's own stream: the first N seconds are taken as benign

Until a machine exists every window is reported with status "learning": counted, not judged.
A line {"cmd": "learn", "seconds": N} appended to --control re-learns from the next N seconds
while the old machine keeps scoring, then swaps (no restart, open alerts carry over).

Lines written (each carries "label"):
  {"kind": "ready", cutoff, train_flows, held_windows, benign_rate, source, learned_at, ...}
  {"kind": "learn", "phase": "collecting" | "fitting" | "failed", ...}
  {"kind": "window", t, wall, lag, behind, peak, cutoff, status, alert, released, packets, pairs, ...}
  {"kind": "end", "error": None | text}

  python live/worker.py pace capture.pcap [--speed 10]
writes a recording to stdout as a pcap stream paced like the original, its clock moved to now:
a tap with no cluster behind it, for running the monitor on a recording.
"""
import argparse
import json
import os
import pickle
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd

from core.features import WINDOW_SIZE
from live.stream import (LATENESS, CaptureReader, LiveDetector, PcapStream, Windower, _verdict,
                         calibrate_live, describe, packet_row)
from methods.pdfa import FLOW_COLUMNS, PDFA
from methods.scores import FORGET_SECONDS, pdfa_graph

MODEL_VERSION = 2              # bump when a saved machine can no longer be scored as it was learned
LEARN_SECONDS = 60
LEARN_LIMIT = 600              # a quiet tap keeps collecting up to this long before giving up
LEARN_PACKETS = 1_500_000      # a flood during learning stops the collection here
BEHIND_SECONDS = 5             # scored this much later than it should be: the tap is not keeping up
THIN = ("Too few training flows", "Insufficient benign flows")


# ---------------------------------------------------------------- saved machines

def save_model(path, calibration, forget_seconds, lateness, source):
    """Keep a learned machine so the next start needs no learning. Returns its description.

    The machine indexes its states by identity (methods.pdfa.PDFA.probs), which no copy
    keeps, so the file holds the state graph and load_model builds the index again.
    """
    saved = {"version": MODEL_VERSION, "forget_seconds": float(forget_seconds), "lateness": int(lateness),
             "model": calibration["model"], "cutoffs": calibration["cutoffs"],
             "train_flows": len(calibration["train"]), "source": source, "learned_at": time.time()}
    model = calibration["model"]
    stored = dict(saved, model={"enc": model["enc"], "trace_len": model["trace_len"], "root": model["pdfa"].root})
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(".partial")
    partial.write_bytes(pickle.dumps(stored))
    partial.replace(path)
    return saved


def load_model(path, forget_seconds, lateness):
    """A machine saved by save_model for these settings, or None."""
    try:
        saved = pickle.loads(Path(path).read_bytes())
    except (OSError, pickle.UnpicklingError, EOFError, AttributeError, ImportError, KeyError):
        return None
    same = (isinstance(saved, dict) and saved.get("version") == MODEL_VERSION
            and saved.get("forget_seconds") == float(forget_seconds) and saved.get("lateness") == int(lateness))
    if not same:
        return None
    model = saved["model"]
    saved["model"] = {"enc": model["enc"], "trace_len": model["trace_len"], "pdfa": PDFA(model["root"])}
    return saved


def announce(saved, forget_seconds, lateness):
    return {"kind": "ready", **describe(saved, forget_seconds, lateness),
            "source": saved["source"], "learned_at": saved["learned_at"],
            "graph": pdfa_graph(saved["model"]["pdfa"])}


# ---------------------------------------------------------------- the tap

class Tap:
    """A stream being scored: windows out, a machine that can be learned or replaced mid-stream."""

    def __init__(self, emit, detector=None, forget_seconds=FORGET_SECONDS, lateness=LATENESS,
                 clock=time.time, model_path=None):
        self.emit, self.clock = emit, clock
        self.forget_seconds, self.lateness = forget_seconds, lateness
        self.model_path = model_path
        self.windower = Windower(lateness)
        self.detector = detector
        self.lock = threading.Lock()
        self.learning = None          # {"seconds", "rows", "from", "asked"} while collecting

    # ---- learning from the stream
    def learn(self, seconds=LEARN_SECONDS):
        with self.lock:
            if self.learning is not None:
                return
            self.learning = {"seconds": float(seconds), "rows": [], "from": None, "asked": float(seconds)}
        self.emit({"kind": "learn", "phase": "collecting", "seconds": float(seconds), "started": self.clock()})

    def _collect(self, row):
        job = self.learning
        if job is None or "fitting" in job:
            return
        ts = float(row["ts"])
        if job["from"] is None:
            job["from"] = ts
        job["rows"].append(tuple(row[c] for c in FLOW_COLUMNS))
        if ts - job["from"] >= job["seconds"] or len(job["rows"]) >= LEARN_PACKETS:
            self._fit(job)

    def _fit(self, job):
        job["fitting"] = True
        self.emit({"kind": "learn", "phase": "fitting", "packets": len(job["rows"])})
        threading.Thread(target=self._fitted, args=(job,), daemon=True).start()

    def _fitted(self, job):
        try:
            calibration = calibrate_live(pd.DataFrame(job["rows"], columns=FLOW_COLUMNS),
                                         self.forget_seconds, self.lateness)
        except Exception as error:
            thin = isinstance(error, ValueError) and str(error).startswith(THIN)
            with self.lock:
                more = thin and job["seconds"] < LEARN_LIMIT and len(job["rows"]) < LEARN_PACKETS
                if more:      # a quiet tap: keep what was collected and listen for as long again
                    job["seconds"] += job["asked"]
                    del job["fitting"]
                else:
                    self.learning = None
            self.emit({"kind": "learn", "phase": "collecting" if more else "failed", "error": str(error),
                       "seconds": job["seconds"], "extended": bool(more)})
            return
        saved = {"model": calibration["model"], "cutoffs": calibration["cutoffs"],
                 "train_flows": len(calibration["train"]), "source": "stream", "learned_at": self.clock()}
        if self.model_path:
            try:
                saved = save_model(self.model_path, calibration, self.forget_seconds, self.lateness, "stream")
            except OSError:
                pass      # the machine still scores; it just has to be learned again next start
        with self.lock:
            if self.detector is None:
                self.detector = LiveDetector(calibration, self.forget_seconds)
                # the clock starts now, not at the stream's first packet
                self.detector.rules.warmup_s = self.windower.next_window * WINDOW_SIZE + self.forget_seconds
            else:
                self.detector.swap(calibration)
            self.learning = None
        self.emit(announce(saved, self.forget_seconds, self.lateness))

    # ---- windows
    def _publish(self, closed_windows):
        for closed in closed_windows:
            verdict = _verdict(self.detector, closed, self.windower.t0)
            start = self.windower.offset + self.windower.t0 + closed["t"] * WINDOW_SIZE
            lag = self.clock() - start - WINDOW_SIZE
            verdict.update(kind="window", wall=start, lag=round(lag, 2),
                           behind=bool(lag > self.lateness + 1 + BEHIND_SECONDS))
            self.emit(verdict)

    def packet(self, row):
        with self.lock:
            self._collect(row)
            self._publish(self.windower.add(row, wall=self.clock()))

    def tick(self):
        """Wall time moved: close the windows a quiet tap has finished, end a quiet collection."""
        with self.lock:
            now = self.clock()
            self._publish(self.windower.tick(now))
            job = self.learning
            if (job and "fitting" not in job and job["from"] is not None
                    and self.windower.offset is not None
                    and now - self.windower.offset - job["from"] >= job["seconds"]):
                self._fit(job)

    def finish(self):
        with self.lock:
            self._publish(self.windower.flush())


def follow(path, position=0):
    """(new complete JSON lines of a file since `position`, the next position)."""
    try:
        with open(path, "rb") as handle:
            handle.seek(position)
            data = handle.read()
    except OSError:
        return [], position
    whole = data[:data.rfind(b"\n") + 1]
    commands = []
    for line in whole.splitlines():
        try:
            commands.append(json.loads(line))
        except ValueError:
            continue
    return commands, position + len(whole)


def watch(stream, emit, detector=None, learn=None, control=None, record=None,
          forget_seconds=FORGET_SECONDS, lateness=LATENESS, clock=time.time, tick_every=0.5,
          model_path=None):
    """Score a pcap byte stream until it ends: one `emit(dict)` per closed window.

    A reader thread takes packets; this thread closes windows on wall time while the tap is
    quiet and reads `control`. `record`, a binary file, gets the stream's bytes as they arrive
    (a valid pcap). Each window carries `wall`, the wall-clock time its second began, and
    `lag`, how long after its end it was scored (about lateness + 1 s when keeping up).
    """
    tap = Tap(emit, detector, forget_seconds, lateness, clock, model_path)
    if detector is None or learn:
        tap.learn(learn or LEARN_SECONDS)
    done, failure = threading.Event(), []

    def read():
        try:
            for frame in PcapStream(stream, tee=record.write if record else None).frames():
                tap.packet(packet_row(frame))
        except Exception as error:     # a broken stream ends this tap, and says why
            failure.append(f"{type(error).__name__}: {error}")
        finally:
            done.set()

    threading.Thread(target=read, daemon=True).start()
    position = 0
    while not done.wait(tick_every):
        tap.tick()
        if control:
            commands, position = follow(control, position)
            for command in commands:
                if command.get("cmd") == "learn":
                    tap.learn(command.get("seconds") or LEARN_SECONDS)
    tap.finish()
    emit({"kind": "end", "error": failure[0] if failure else None, "late": tap.windower.late})
    return tap


# ---------------------------------------------------------------- a recording as a stream

def pace(path, out, speed=1.0, clock=time.time, sleep=time.sleep):
    """Write a capture to `out` as a classic pcap stream, paced `speed` times real time.

    Timestamps move so the first frame is now and keep their spacing, so the detector sees
    the recording's own flows and windows; only how fast they arrive changes.
    """
    began, first, shift = clock(), None, 0
    for frame in CaptureReader(str(path)).frames():
        if first is None:
            first = frame.ts_sec + frame.ts_frac / 10 ** frame.ts_digits
            shift = int(began) - frame.ts_sec
            magic = 0xA1B23C4D if frame.ts_digits == 9 else 0xA1B2C3D4
            out.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 262144, frame.linktype))
        at = frame.ts_sec + frame.ts_frac / 10 ** frame.ts_digits
        wait = began + (at - first) / speed - clock()
        if wait > 0:
            out.flush()
            sleep(wait)
        out.write(struct.pack("<IIII", frame.ts_sec + shift, frame.ts_frac, len(frame.data), frame.orig_len))
        out.write(frame.data)
    out.flush()


# ---------------------------------------------------------------- command line

def main(argv=None):
    parser = argparse.ArgumentParser(description="Score one tap's live pcap stream (stdin).")
    commands = parser.add_subparsers(dest="command", required=True)
    w = commands.add_parser("watch")
    w.add_argument("--label", required=True)
    w.add_argument("--model", help="where this tap's learned machine is kept")
    w.add_argument("--baseline", help="a benign recording (csv or pcap) to learn from")
    w.add_argument("--learn", type=float, default=None, help="learn from the stream's first N seconds")
    w.add_argument("--control", help="a file of JSON command lines to follow")
    w.add_argument("--record", help="also write the stream to this pcap")
    w.add_argument("--forget", type=float, default=FORGET_SECONDS)
    w.add_argument("--lateness", type=int, default=LATENESS)
    p = commands.add_parser("pace")
    p.add_argument("path")
    p.add_argument("--speed", type=float, default=1.0)
    args = parser.parse_args(argv)

    if args.command == "pace":
        try:
            pace(Path(args.path).expanduser(), sys.stdout.buffer, max(args.speed, 0.01))
        except BrokenPipeError:
            os._exit(0)
        return 0

    out_lock = threading.Lock()

    def emit(message):
        message["label"] = args.label
        try:
            with out_lock:
                sys.stdout.write(json.dumps(message) + "\n")
                sys.stdout.flush()
        except BrokenPipeError:     # the monitor stopped listening: stop quietly
            sys.stderr.close()
            os._exit(0)

    saved, detector = None, None
    baseline = Path(args.baseline).expanduser() if args.baseline else None
    if args.model and not args.learn:
        saved = load_model(args.model, args.forget, args.lateness)
        if saved and baseline and baseline.exists() and baseline.stat().st_mtime > saved["learned_at"]:
            saved = None        # a newer recording replaces the saved machine
    if saved is None and baseline and not args.learn:
        try:
            calibration = calibrate_live(baseline, args.forget, args.lateness)
            saved = {"model": calibration["model"], "cutoffs": calibration["cutoffs"],
                     "train_flows": len(calibration["train"]), "source": str(baseline),
                     "learned_at": time.time()}
            if args.model:
                saved = save_model(args.model, calibration, args.forget, args.lateness, str(baseline))
        except Exception as error:   # fall back to the stream rather than not watching at all
            emit({"kind": "learn", "phase": "failed", "error": f"could not learn from {baseline.name}: {error}"})
    if saved is not None:
        detector = LiveDetector(saved, args.forget)
        emit(announce(saved, args.forget, args.lateness))
    record = open(args.record, "wb") if args.record else None
    try:
        watch(sys.stdin.buffer, emit, detector, args.learn, args.control, record, args.forget,
              args.lateness, model_path=args.model)
    finally:
        if record:
            record.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
