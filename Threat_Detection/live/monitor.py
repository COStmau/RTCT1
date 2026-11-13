"""The live monitor: taps watched as they run, verdicts kept and streamed to the dashboard.

live/serve.py holds one Monitor over one provider (live/taps.py). For every watched tap it
keeps a supervised pair of processes, the provider's capture piped into a scoring worker
(`live/worker.py watch`, so taps score on separate cores), and it owns everything a page needs:

  state()        the snapshot: inventory, every tap's state and machine, attacks, limits
  subscribe()    the event stream, resumable from a sequence number

A tap moves between: starting, learning (no machine yet: its stream is being taken as
benign), scoring, stalled (no window for a while), failed (waiting to be restarted), ended.
A capture that dies is restarted with a growing delay; one tap failing leaves the rest alone.

Files, under <provider data dir>/ (outside the repo, like the recordings):
  models/<label>.pkl                      each tap's learned machine, reused by the next start
  session-<time>/events.jsonl             every verdict, alert and attack of a session
  session-<time>/attacks.json             when each attack started and stopped
  session-<time>/live attack/pcapng files/<label>-tcp.pcap    the packets, with Record on
  logs/<label>.capture.log, .worker.log   what the two processes said
"""
import json
import queue
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from live.taps import WORKER, ProviderError   # noqa: E402

EVENTS_KEPT = 300              # alerts, attacks, tap changes: kept apart from windows, never evicted by them
WINDOWS_KEPT = 900             # windows kept per tap (15 minutes)
BACKLOG_SECONDS = 300          # windows a newly opened page is sent
QUEUE_MAX = 4000               # events a slow page may fall behind before its oldest are dropped
LEARN_SECONDS = 60
LEARN_RANGE = (20, 600)
ATTACK_SECONDS = (5, 300)      # the durations the page may ask for
RELEASE_WATCH = 120            # seconds after an attack ends that an alert still counts against it
STALL_AFTER = 10               # seconds without a window before a tap is called stalled
STALL_RESTART = 30             # ... and before its processes are restarted
BACKOFF = (2, 5, 15, 30)       # seconds before each restart of a failed tap
HEALTHY_AFTER = 60             # seconds of scoring that forgive earlier restarts
LIVE_STATES = ("starting", "learning", "scoring", "stalled")


class MonitorError(ValueError):
    """A request the monitor refuses; the page shows the message."""


def _quiet_kill(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def _tail(path, lines=1):
    try:
        text = Path(path).read_text(errors="replace").strip().splitlines()
    except OSError:
        return ""
    return " | ".join(line.strip() for line in text[-lines:] if line.strip())


class TapRun:
    """One watched tap: its processes, what it last said, the windows it has scored."""

    def __init__(self, tap):
        self.tap, self.label = tap, tap["label"]
        self.state, self.error = "starting", None
        self.ready = None            # the worker's description of its machine
        self.learning = None         # {"seconds", "started", "phase"} while collecting
        self.learn_error = None      # why the last attempt to learn gave no machine
        self.windows = deque(maxlen=WINDOWS_KEPT)
        self.last_seen = time.time()
        self.scoring_since = None
        self.alert_since = None
        self.restarts = 0
        self.want = True
        self.halt = threading.Event()
        self.capture = self.worker = self.thread = self.control = None

    def view(self):
        return {"state": self.state, "error": self.error, "ready": self.ready, "learning": self.learning,
                "learn_error": self.learn_error, "restarts": self.restarts, "alert_since": self.alert_since}


class Monitor:
    def __init__(self, provider, python=sys.executable):
        self.provider, self.python = provider, python
        self.boot = f"{time.time():.0f}"
        self._ctl = threading.RLock()        # starting, stopping, attacks: one at a time
        self._pub = threading.Lock()         # events and subscribers: never held across a subprocess
        self.seq = 0
        self.events = deque(maxlen=EVENTS_KEPT)
        self.subscribers = []
        self.taps = {}                       # label -> TapRun
        self.session = self.log = None
        self.recording = False
        self.attack = None                   # the provider's handle plus "ends"
        self.attacks = []                    # every attack this session: scenario, started, ended
        self.started = None
        self._watchdog = None

    # ------------------------------------------------ events
    def publish(self, event):
        event.setdefault("at", time.time())
        with self._pub:
            self.seq += 1
            event["seq"] = self.seq
            run = self.taps.get(event.get("label")) if event["kind"] == "window" else None
            if run is not None:
                run.windows.append(event)
            elif event["kind"] != "window":
                self.events.append(event)
            if self.log is not None:
                slim = {k: v for k, v in event.items() if k != "pairs"}
                try:
                    self.log.write(json.dumps(slim) + "\n")
                except (OSError, ValueError):
                    pass
            for q in self.subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:           # a page that stopped reading: drop its oldest, keep going
                    try:
                        q.get_nowait()
                        q.put_nowait(event)
                    except (queue.Empty, queue.Full):
                        pass

    def subscribe(self, since=None):
        """(queue, events the page has not seen) for one page; drop the queue with unsubscribe.

        `since` is the last sequence number the page got (from this process: see `boot`); a
        new page gets the kept events and the last BACKLOG_SECONDS of every tap's windows.
        """
        q = queue.Queue(maxsize=QUEUE_MAX)
        with self._pub:
            if since is not None and since <= self.seq:
                past = [e for e in self.events if e["seq"] > since]
                past += [w for run in self.taps.values() for w in run.windows if w["seq"] > since]
            else:
                floor = time.time() - BACKLOG_SECONDS
                past = list(self.events)
                past += [w for run in self.taps.values() for w in run.windows if w["wall"] >= floor]
            self.subscribers.append(q)
        return q, sorted(past, key=lambda e: e["seq"])

    def unsubscribe(self, q):
        with self._pub:
            if q in self.subscribers:
                self.subscribers.remove(q)

    # ------------------------------------------------ the snapshot
    def state(self, fresh=False):
        view = self.provider.view(fresh)
        inventory = view["inventory"]
        out = {"boot": self.boot, "seq": self.seq, "now": time.time(), "provider": self.provider.name,
               "clusters": view["clusters"], "inventory": inventory,
               "profile": inventory["profile"] if inventory else None,
               "monitoring": bool(self.taps), "monitor_started": self.started if self.taps else None,
               "session": str(self.session) if self.session else None, "recording": self.recording,
               "can_attack": self.provider.can_attack, "finite": self.provider.finite,
               "attack": self._attack_view(), "attacks": list(self.attacks),
               "scenarios": self.provider.scenarios() if inventory else [],
               "attack_seconds": list(ATTACK_SECONDS), "learn_seconds": list(LEARN_RANGE),
               "learn_default": LEARN_SECONDS, "taps": []}
        if inventory is None:
            return out
        baselines = self.provider.baselines()
        models = self.provider.data_dir() / "models"
        for tap in self.provider.taps():
            label = tap["label"]
            run = self.taps.get(label)
            model, baseline = models / f"{label}.pkl", baselines.get(label)
            out["taps"].append({
                "label": label, "level": tap["level"],
                "default": tap["level"] in self.provider.default_levels,
                "machine": ("saved" if model.exists() else "recording" if baseline else "stream"),
                "baseline": str(baseline) if baseline else None,
                "watching": run is not None, **(run.view() if run else {"state": None})})
        return out

    def _attack_view(self):
        if self.attack is None:
            return None
        return {"scenario": self.attack["scenario"], "started": self.attack["started"],
                "ends": self.attack["ends"]}

    # ------------------------------------------------ watching taps
    def start(self, labels=None, record=False):
        """Watch these taps (the default ones when none are named), on top of any already watched."""
        with self._ctl:
            if self.provider.inventory(fresh=not self.taps) is None:
                hint = ("`localcluster/collect.py up` starts one." if self.provider.name == "local"
                        else "check the kubeconfig and that the cluster's API server answers.")
                raise MonitorError(f"No cluster is reachable to watch: {hint}")
            points = {t["label"]: t for t in self.provider.taps()}
            labels = list(labels or [l for l, t in points.items() if t["level"] in self.provider.default_levels])
            unknown = [l for l in labels if l not in points]
            if unknown:
                raise MonitorError(f"{', '.join(unknown)}: not a tap here")
            fresh = [l for l in labels if l not in self.taps]
            if not fresh:
                raise MonitorError("Those taps are already watched.")
            if not self.taps:
                self._open_session(bool(record))
            baselines = self.provider.baselines()
            for label in fresh:
                run = TapRun(points[label])
                self.taps[label] = run
                run.thread = threading.Thread(target=self._supervise, args=(run, baselines.get(label)),
                                              daemon=True)
                run.thread.start()
            if self._watchdog is None or not self._watchdog.is_alive():
                self._watchdog = threading.Thread(target=self._watch, daemon=True)
                self._watchdog.start()
        self.publish({"kind": "started", "taps": fresh, "session": str(self.session),
                      "recording": self.recording})
        return self.state()

    def _open_session(self, record):
        data = self.provider.data_dir()
        self.session = data / f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        (self.session / "control").mkdir(parents=True, exist_ok=True)
        (data / "models").mkdir(parents=True, exist_ok=True)
        (data / "logs").mkdir(parents=True, exist_ok=True)
        self.recording = record
        if record:
            (self.session / "live attack" / "pcapng files").mkdir(parents=True, exist_ok=True)
        self.started, self.attacks = time.time(), []
        with self._pub:
            self.log = open(self.session / "events.jsonl", "a", buffering=1)

    def _worker_argv(self, run, baseline):
        data, label = self.provider.data_dir(), run.label
        run.control = self.session / "control" / f"{label}.jsonl"
        run.control.write_text("")      # a restarted worker must not obey commands given to the last one
        argv = [self.python, str(WORKER), "watch", "--label", label,
                "--model", str(data / "models" / f"{label}.pkl"), "--control", str(run.control)]
        if baseline:
            argv += ["--baseline", str(baseline)]
        if self.recording:
            again = f".{run.restarts}" if run.restarts else ""
            argv += ["--record", str(self.session / "live attack" / "pcapng files" / f"{label}-tcp{again}.pcap")]
        return argv

    def _supervise(self, run, baseline):
        """Keep one tap's capture and worker running until it is stopped."""
        logs = self.provider.data_dir() / "logs"
        while run.want:
            error = None
            try:
                capture_argv = self.provider.stream(run.tap)
                with open(logs / f"{run.label}.capture.log", "w") as capture_log, \
                        open(logs / f"{run.label}.worker.log", "w") as worker_log:
                    run.capture = subprocess.Popen(capture_argv, stdout=subprocess.PIPE, stderr=capture_log)
                    run.worker = subprocess.Popen(self._worker_argv(run, baseline), stdin=run.capture.stdout,
                                                  stdout=subprocess.PIPE, stderr=worker_log, text=True,
                                                  cwd=str(ROOT))
                    run.capture.stdout.close()   # the worker owns the pipe now: its exit ends the capture too
                    run.last_seen = time.time()
                    self._set(run, "starting")
                    said_end, error = self._pump(run)
                    run.worker.wait()
                    run.worker.stdout.close()
                    if not said_end:     # the worker died instead of finishing: never a clean end
                        error = _tail(logs / f"{run.label}.worker.log", 1) or "the scoring process stopped"
                    _quiet_kill(run.capture)
            except (ProviderError, OSError) as failure:
                error = str(failure)
            if not run.want:
                return
            if self.provider.finite and not error:
                self._set(run, "ended")
                return
            said = _tail(logs / f"{run.label}.capture.log") or _tail(logs / f"{run.label}.worker.log")
            if run.scoring_since and time.time() - run.scoring_since > HEALTHY_AFTER:
                run.restarts = 0
            delay = BACKOFF[min(run.restarts, len(BACKOFF) - 1)]
            run.restarts += 1
            self._set(run, "failed", f"{error or said or 'the capture stream ended'} · restarting in {delay} s")
            if run.halt.wait(delay):
                return

    def _set(self, run, state, error=None):
        if (run.state, run.error) == (state, error):
            return
        run.state, run.error = state, error
        run.scoring_since = time.time() if state == "scoring" else None
        self.publish({"kind": "tap", "label": run.label, **run.view()})

    def _pump(self, run):
        """Take one worker's lines until it exits: (it said it was done, the error it gave)."""
        said_end, ended = False, None
        for line in run.worker.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            event["label"] = run.label
            kind = event.get("kind")
            if kind == "window":
                run.last_seen = time.time()
                if run.state in ("starting", "stalled", "learning", "scoring"):
                    self._set(run, "scoring" if run.ready else "learning")
                self._track(run, event)
            elif kind == "ready":
                run.ready, run.learning, run.learn_error = event, None, None
            elif kind == "learn":
                failed = event.get("phase") == "failed"
                run.learning = None if failed else {"phase": event["phase"], "seconds": event.get("seconds"),
                                                    "started": event.get("started") or (run.learning or {}).get("started")}
                run.learn_error = event.get("error") if failed else None
            elif kind == "end":
                said_end, ended = True, event.get("error")
                continue        # the supervisor reports how the tap ended
            self.publish(event)
            if kind in ("ready", "learn"):
                self.publish({"kind": "tap", "label": run.label, **run.view()})
        return said_end, ended

    def _track(self, run, window):
        """Alert raised / released events, timed against the attack that was running."""
        if window["alert"] and run.alert_since is None:
            run.alert_since = window["wall"]
            # score and cutoff ride along, so a logged alert says what raised it and against what
            self.publish({"kind": "alert", "label": run.label, "wall": window["wall"], "top": window.get("top"),
                          "score": window.get("peak"), "cutoff": window.get("cutoff"),
                          **self._latency(window["wall"])})
        elif window["released"] and run.alert_since is not None:
            began, run.alert_since = run.alert_since, None
            self.publish({"kind": "release", "label": run.label, "wall": window["wall"],
                          "lasted": round(window["wall"] - began, 1),
                          "score": window.get("peak"), "cutoff": window.get("cutoff"),
                          **self._latency(window["wall"])})

    def _latency(self, wall):
        for attack in reversed(self.attacks):
            ended = attack.get("ended") or float("inf")
            if attack["started"] - 2 <= wall <= ended + RELEASE_WATCH:
                return {"attack": attack["scenario"], "since_start": round(wall - attack["started"], 1),
                        "since_end": None if attack.get("ended") is None else round(wall - attack["ended"], 1)}
        return {"attack": None}

    def _watch(self):
        """Notice a tap that has gone quiet: a live tap closes a window every second, traffic or not."""
        while self.taps:
            time.sleep(2)
            for run in list(self.taps.values()):
                quiet = time.time() - run.last_seen
                if run.state in ("scoring", "learning") and quiet > STALL_AFTER and not self.provider.finite:
                    self._set(run, "stalled", f"no window for {quiet:.0f} s")
                elif run.state == "stalled" and quiet > STALL_RESTART:
                    _quiet_kill(run.worker)     # the supervisor takes it from here
                    _quiet_kill(run.capture)

    def stop(self, labels=None):
        """Stop watching these taps, or every tap."""
        with self._ctl:
            chosen = [self.taps[l] for l in (labels or list(self.taps)) if l in self.taps]
            for run in chosen:
                run.want = False
                run.halt.set()
            threads = [threading.Thread(target=self._halt, args=(run,)) for run in chosen]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            for run in chosen:
                self.taps.pop(run.label, None)
                self.publish({"kind": "tap", "label": run.label, "state": None})
            if chosen and not self.taps:
                self.publish({"kind": "stopped", "session": str(self.session)})
                if self.session:
                    (self.session / "attacks.json").write_text(json.dumps(self.attacks, indent=2))
                with self._pub:
                    if self.log is not None:
                        self.log.close()
                    self.log = None
        return self.state()

    def _halt(self, run):
        _quiet_kill(run.worker)
        _quiet_kill(run.capture)
        try:
            self.provider.cleanup(run.tap)
        except Exception:
            pass

    # ------------------------------------------------ learning
    def learn(self, labels=None, seconds=LEARN_SECONDS):
        """Re-learn watched taps from the next `seconds` of their own traffic, without restarting them."""
        seconds = _whole(seconds, LEARN_RANGE, "learning time")
        with self._ctl:
            if self.attack is not None:
                raise MonitorError("An attack is running: learning now would take it as normal.")
            chosen = [self.taps[l] for l in (labels or list(self.taps)) if l in self.taps]
            chosen = [run for run in chosen if run.state in LIVE_STATES and run.control]
            if not chosen:
                raise MonitorError("No watched tap to re-learn.")
            for run in chosen:
                with open(run.control, "a") as control:
                    control.write(json.dumps({"cmd": "learn", "seconds": seconds}) + "\n")
        return self.state()

    # ------------------------------------------------ attacks
    def launch(self, scenario=None, seconds=30):
        if not self.provider.can_attack:
            raise MonitorError("This monitor cannot launch attacks.")
        if not scenario:
            raise MonitorError("Choose an attack.")
        seconds = _whole(seconds, ATTACK_SECONDS, "attack length")
        with self._ctl:
            if self.attack is not None:
                raise MonitorError(f"{self.attack['scenario']} is still running: stop it first.")
            learning = [run.label for run in self.taps.values() if run.learning]
            if learning:
                raise MonitorError(f"{', '.join(learning)} still learning: an attack now would be learned as normal.")
            try:
                handle = self.provider.start_attack(scenario, seconds)
            except ProviderError as failure:
                raise MonitorError(str(failure)) from None
            handle["ends"] = handle["started"] + seconds
            self.attack = handle
            record = {"scenario": scenario, "started": handle["started"], "seconds": seconds}
            self.attacks.append(record)
        self.publish({"kind": "attack", "phase": "start", "scenario": scenario,
                      "wall": handle["started"], "seconds": seconds})
        threading.Thread(target=self._attack_timer, args=(handle, record), daemon=True).start()
        return self.state()

    def _attack_timer(self, handle, record):
        while time.time() < handle["ends"] + 1:
            if self.attack is not handle:
                return   # stopped early
            time.sleep(0.5)
        self._end_attack(handle, record, early=False)

    def _end_attack(self, handle, record, early):
        with self._ctl:
            if self.attack is not handle:
                return
            self.attack = None
        record["ended"] = min(time.time(), handle["ends"]) if not early else time.time()
        try:
            self.provider.stop_attack(handle)
        except Exception as error:   # the attack is over either way; say what cleanup missed
            self.publish({"kind": "note", "text": f"cleanup after {handle['scenario']}: {error}"})
        self.publish({"kind": "attack", "phase": "stop", "scenario": handle["scenario"],
                      "wall": record["ended"], "early": early})

    def stop_attack(self):
        handle = self.attack
        if handle is None:
            raise MonitorError("No attack is running.")
        record = next(a for a in reversed(self.attacks) if a["started"] == handle["started"])
        self._end_attack(handle, record, early=True)
        return self.state()

    def shutdown(self):
        if self.attack is not None:
            try:
                self.stop_attack()
            except Exception:
                pass
        self.stop()


def _whole(value, bounds, what):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise MonitorError(f"{what} must be a whole number of seconds") from None
    if not bounds[0] <= value <= bounds[1]:
        raise MonitorError(f"{what} must be {bounds[0]}-{bounds[1]} s")
    return value
