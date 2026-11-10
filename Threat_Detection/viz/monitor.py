"""The harness's live test mode: watch the local k3d cluster, launch attacks, see verdicts.

viz/serve.py holds one Monitor. It finds the running local profile (localcluster/collect.py
detect), starts one capture per chosen tap, each piped into its own scoring worker
(`python viz/live.py watch`, so taps score on separate cores), and fans every worker's
verdicts out to the page as server-sent events. Attacks are the profile's own named
scenarios, launched through collect.start_attack, so the page can only ever attack the local
cluster, and only with what the profile already defines.

Files, all under ~/rtct-data/<profile>/live/ (outside the repo, like the recordings):
  baseline-<time>/benign/...        a "Record new baseline" recording (KUBEDATA layout)
  session-<time>/live attack/pcapng files/<label>-tcp.pcap   with Record on
  session-<time>/attacks.json       when each attack started and stopped (with Record on)
"""
import json
import queue
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "localcluster"))

import collect   # noqa: E402  (localcluster/collect.py; stdlib only)

LIVE_WORKER = ROOT / "viz" / "live.py"
HISTORY = 6000                 # events kept for a page that connects late
DEFAULT_TAPS = ("pod", "node")   # router taps carry every packet between nodes: opt in
BASELINE_SECONDS = 60
BASELINE_RANGE = (30, 600)     # a longer baseline gives each cutoff more held-out windows
ATTACK_SECONDS = (5, 300)      # the durations the page may ask for
RELEASE_WATCH = 120            # seconds after an attack ends that an alert still counts against it


class MonitorError(ValueError):
    """A request the monitor refuses; the page shows the message."""


def _quiet_kill(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


class Monitor:
    def __init__(self, out_root=None, python=sys.executable):
        self.out_root = Path(out_root or collect.DEFAULT_OUT).expanduser()
        self.python = python
        self.lock = threading.RLock()
        self.subscribers = []
        self.history = deque(maxlen=HISTORY)
        self.profile = None
        self.taps = {}               # label -> {"capture", "worker", "thread", "baseline", ...}
        self.session = None          # recording folder, when Record is on
        self.attack = None           # collect handle plus "ends"
        self.attacks = []            # every attack this session: scenario, started, ended
        self.alerts = {}             # label -> open alert's start wall time
        self.baseline_job = None
        self.started = None

    # ------------------------------------------------ events
    def publish(self, event):
        event.setdefault("at", time.time())
        with self.lock:
            self.history.append(event)
            for subscriber in list(self.subscribers):
                subscriber.put(event)

    def subscribe(self):
        """(queue, past events) for one page; drop the queue with unsubscribe."""
        q = queue.Queue()
        with self.lock:
            self.subscribers.append(q)
            return q, list(self.history)

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    # ------------------------------------------------ what is there
    def running_profile(self):
        clusters = collect.detect()
        running = [c for c in clusters if c["running"]]
        return clusters, (collect.load_profile(running[0]["profile"]) if running else None)

    def baselines(self, profile):
        """{label: file}: the newest benign recording of each tap, recordings or live baselines."""
        roots = [self.out_root / profile["name"]]
        live = self.out_root / profile["name"] / "live"
        if live.is_dir():
            roots += sorted(live.glob("baseline-*"))
        chosen = {}
        for root in roots:
            for label, path in collect.newest_benign(profile, root).items():
                if label not in chosen or path.stat().st_mtime > chosen[label].stat().st_mtime:
                    chosen[label] = path
        return chosen

    def state(self):
        clusters, profile = self.running_profile()
        out = {"clusters": clusters, "profile": None, "taps": [], "scenarios": [],
               "monitoring": bool(self.taps), "monitor_started": self.started if self.taps else None,
               "now": time.time(), "recording": str(self.session) if self.session else None,
               "attack": self._attack_view(), "baseline_job": self.baseline_job,
               "attack_seconds": list(ATTACK_SECONDS), "baseline_seconds": list(BASELINE_RANGE)}
        if profile is None:
            return out
        baselines = self.baselines(profile)
        out["profile"] = profile["name"]
        out["harness_profile"] = profile["harness_profile"]
        out["scenarios"] = [{"name": name, "kind": spec["kind"], "mode": spec.get("mode"),
                             "target": _target(spec)} for name, spec in profile["attacks"].items()]
        for tap in collect.taps(profile):
            path = baselines.get(tap["label"])
            out["taps"].append({
                "label": tap["label"], "level": tap["level"],
                "default": tap["level"] in DEFAULT_TAPS,
                "baseline": str(path) if path else None,
                "baseline_time": (datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
                                  if path else None),
                "watching": tap["label"] in self.taps})
        return out

    def _attack_view(self):
        if self.attack is None:
            return None
        return {"scenario": self.attack["scenario"], "started": self.attack["started"],
                "ends": self.attack["ends"]}

    # ------------------------------------------------ monitoring
    def start(self, labels=None, record=False):
        with self.lock:
            if self.taps:
                raise MonitorError("Already monitoring: stop first.")
            _, profile = self.running_profile()
            if profile is None:
                raise MonitorError("No local cluster is running: `localcluster/collect.py up` starts one.")
            points = {t["label"]: t for t in collect.taps(profile)}
            labels = list(labels or [l for l, t in points.items() if t["level"] in DEFAULT_TAPS])
            unknown = [l for l in labels if l not in points]
            if unknown:
                raise MonitorError(f"{', '.join(unknown)} are not taps of the {profile['name']} profile")
            baselines = self.baselines(profile)
            missing = [l for l in labels if l not in baselines]
            if missing:
                raise MonitorError(f"No benign recording for {', '.join(missing)}: record a baseline "
                                   "first (button above, or collect.py run benign).")
            self.profile, self.started, self.attacks, self.alerts = profile, time.time(), [], {}
            self.session = None
            if record:
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                self.session = self.out_root / profile["name"] / "live" / f"session-{stamp}"
                (self.session / "live attack" / "pcapng files").mkdir(parents=True, exist_ok=True)
            try:
                pods = {l: collect.pod_for(profile, t["workload"]) for l, t in points.items()
                        if l in labels and t["level"] == "pod"}
            except SystemExit as failure:   # collect.py speaks to a shell; the page needs words
                raise MonitorError(str(failure)) from None
            bridge = collect.bridge_for(profile) if any(points[l]["level"] == "router" for l in labels) else None
            for label in labels:
                self._start_tap(profile, points[label], pods.get(label), bridge, baselines[label])
        self.publish({"kind": "started", "profile": profile["name"], "taps": labels,
                      "recording": str(self.session) if self.session else None})
        return self.state()

    def _start_tap(self, profile, tap, pod, bridge, baseline):
        label = tap["label"]
        if tap["level"] != "pod":   # a stale container from a crash would block the name
            subprocess.run(["docker", "rm", "-f", collect.live_container(tap)], capture_output=True)
        logs = self.out_root / profile["name"] / "live" / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        capture = subprocess.Popen(collect.stream_argv(profile, tap, pod, bridge),
                                   stdout=subprocess.PIPE,
                                   stderr=open(logs / f"{label}.capture.log", "w"))
        argv = [self.python, str(LIVE_WORKER), "watch", "--label", label, "--baseline", str(baseline)]
        if self.session:
            argv += ["--record", str(self.session / "live attack" / "pcapng files" / f"{label}-tcp.pcap")]
        worker = subprocess.Popen(argv, stdin=capture.stdout, stdout=subprocess.PIPE,
                                  stderr=open(logs / f"{label}.worker.log", "w"), text=True,
                                  cwd=str(ROOT))
        capture.stdout.close()   # the worker owns the pipe now: its exit ends the capture too
        entry = {"tap": tap, "capture": capture, "worker": worker, "baseline": str(baseline)}
        entry["thread"] = threading.Thread(target=self._pump, args=(label, worker), daemon=True)
        self.taps[label] = entry
        entry["thread"].start()

    def _pump(self, label, worker):
        for line in worker.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            event["label"] = label
            if event.get("kind") == "window":
                self._track(label, event)
            self.publish(event)
        worker.wait()

    def _track(self, label, window):
        """Alert raised / released events, timed against the attack that was running."""
        if window["alert"] and label not in self.alerts:
            self.alerts[label] = window["wall"]
            self.publish({"kind": "alert", "label": label, "wall": window["wall"],
                          **self._latency(window["wall"])})
        elif window["released"] and label in self.alerts:
            began = self.alerts.pop(label)
            self.publish({"kind": "release", "label": label, "wall": window["wall"],
                          "lasted": round(window["wall"] - began, 1), **self._latency(window["wall"])})

    def _latency(self, wall):
        for attack in reversed(self.attacks):
            ended = attack.get("ended") or float("inf")
            if attack["started"] - 2 <= wall <= ended + RELEASE_WATCH:
                return {"attack": attack["scenario"], "since_start": round(wall - attack["started"], 1),
                        "since_end": None if attack.get("ended") is None else round(wall - attack["ended"], 1)}
        return {"attack": None}

    def stop(self):
        with self.lock:
            taps, self.taps = self.taps, {}
        for entry in taps.values():
            _quiet_kill(entry["worker"])
            _quiet_kill(entry["capture"])
            if entry["tap"]["level"] != "pod":
                subprocess.run(["docker", "rm", "-f", collect.live_container(entry["tap"])],
                               capture_output=True)
        if self.session and self.attacks:
            (self.session / "attacks.json").write_text(json.dumps(self.attacks, indent=2))
        if taps:
            self.publish({"kind": "stopped", "recording": str(self.session) if self.session else None})
        return self.state()

    # ------------------------------------------------ attacks
    def launch(self, scenario=None, seconds=30):
        if not scenario:
            raise MonitorError("Choose an attack.")
        try:
            seconds = int(seconds)
        except (TypeError, ValueError):
            raise MonitorError("attack length must be a whole number of seconds") from None
        if not ATTACK_SECONDS[0] <= seconds <= ATTACK_SECONDS[1]:
            raise MonitorError(f"attack length must be {ATTACK_SECONDS[0]}-{ATTACK_SECONDS[1]} s")
        with self.lock:
            if self.attack is not None:
                raise MonitorError(f"{self.attack['scenario']} is still running: stop it first.")
            if self.baseline_job:
                raise MonitorError("A baseline is recording: an attack now would be learned as normal.")
            _, profile = self.running_profile()
            if profile is None:
                raise MonitorError("No local cluster is running.")
            if not collect.context(profile).startswith("k3d-rtct-"):
                raise MonitorError("Attacks only run against the local rtct clusters.")
            if scenario not in profile["attacks"]:
                raise MonitorError(f"{scenario!r} is not an attack of the {profile['name']} profile")
            try:
                handle = collect.start_attack(profile, scenario, seconds)
            except SystemExit as failure:
                raise MonitorError(str(failure)) from None
            handle["ends"] = handle["started"] + seconds
            handle["profile"] = profile
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
        with self.lock:
            if self.attack is not handle:
                return
            self.attack = None
        record["ended"] = min(time.time(), handle["ends"]) if not early else time.time()
        try:
            collect.stop_attack(handle["profile"], handle)
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

    # ------------------------------------------------ baseline
    def record_baseline(self, seconds=BASELINE_SECONDS):
        try:
            seconds = int(seconds)
        except (TypeError, ValueError):
            raise MonitorError("baseline length must be a whole number of seconds") from None
        if not BASELINE_RANGE[0] <= seconds <= BASELINE_RANGE[1]:
            raise MonitorError(f"baseline length must be {BASELINE_RANGE[0]}-{BASELINE_RANGE[1]} s")
        with self.lock:
            if self.baseline_job:
                raise MonitorError("A baseline is already recording.")
            if self.attack is not None:
                raise MonitorError("An attack is running: a baseline now would learn it as normal.")
            _, profile = self.running_profile()
            if profile is None:
                raise MonitorError("No local cluster is running.")
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            out = self.out_root / profile["name"] / "live" / f"baseline-{stamp}"
            self.baseline_job = {"started": time.time(), "seconds": seconds, "out": str(out),
                                 "phase": "starting", "phase_since": time.time()}
        self.publish({"kind": "baseline", "phase": "start", "seconds": seconds, "out": str(out)})
        threading.Thread(target=self._baseline, args=(profile, out, seconds), daemon=True).start()
        return self.state()

    def _baseline(self, profile, out, seconds):
        error = None
        logs = self.out_root / profile["name"] / "live" / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        job = self.baseline_job
        # collect.py narrates its stages; following them gives the page a phase to show
        with open(logs / "baseline.log", "w") as log:
            proc = subprocess.Popen([self.python, "-u", str(ROOT / "localcluster" / "collect.py"), "run",
                                     "benign", "--profile", profile["name"], "--seconds", str(seconds),
                                     "--out", str(out), "--csv"], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, cwd=str(ROOT))
            for line in proc.stdout:
                log.write(line)
                if line.startswith("Recording "):
                    self._phase(job, "recording", recording_since=time.time())
                elif line.startswith("Collecting"):
                    self._phase(job, "collecting")
            returncode = proc.wait()
        if returncode:
            error = f"collect.py exited {returncode}; see {logs / 'baseline.log'}"
        with self.lock:
            restart = list(self.taps) if (self.taps and error is None) else None
            record = self.session is not None
        if restart:   # the running taps re-learn from the recording just made
            self._phase(job, "relearning")
            self.stop()
            try:
                self.start(restart, record)
            except Exception as failure:
                error = f"re-learning failed: {failure}"
        with self.lock:
            self.baseline_job = None
        self.publish({"kind": "baseline", "phase": "done", "out": str(out), "error": error,
                      "relearned": bool(restart) and error is None})

    def _phase(self, job, phase, **extra):
        """Move a baseline job to its next stage and tell the page."""
        with self.lock:
            job.update(phase=phase, phase_since=time.time(), **extra)
        self.publish({"kind": "baseline", "phase": phase, "seconds": job["seconds"]})

    def shutdown(self):
        if self.attack is not None:
            try:
                self.stop_attack()
            except Exception:
                pass
        self.stop()


def _target(spec):
    args = spec.get("args", {})
    if spec["kind"] == "scan":
        return ", ".join(spec["targets"])
    if spec["kind"] == "exec":
        return f"from {spec['from']} to {args.get('targets', '')}"
    host = args.get("url_host") or args.get("host")
    return f"{host}:{args.get('port')}" if host else ""
