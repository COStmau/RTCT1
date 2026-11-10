"""Where a monitor's packets come from: the seam between live/monitor.py and any one cluster.

A provider answers five questions, and the monitor asks nothing else of its surroundings:

  inventory()         what is running: {"profile", "nodes", "pods", "services", ...} or None
  taps()              the capture points: [{"label", "level", ...}]
  stream(tap)         an argv whose stdout is that tap's packets as a pcap stream
  cleanup(tap)        whatever a stopped stream leaves behind
  baselines()         {label: a benign recording to learn from}, where there is one

and, when `can_attack`, launches the cluster's own named attack scenarios.

  LocalClusterProvider   the k3d clusters localcluster/collect.py makes
  ReplayProvider         recordings played back as if they were taps: no cluster needed

A deployed cluster is a third provider (its own kubeconfig, no attacks); nothing else changes.
"""
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "live" / "worker.py"
INVENTORY_TTL = 5.0            # seconds an inventory answer is reused


class ProviderError(ValueError):
    """Something the provider cannot do right now; the page shows the message."""


class TapProvider:
    name = "none"
    can_attack = False
    finite = False             # True when a stream ending is the end, not a failure to restart
    default_levels = ("pod", "node")

    def __init__(self):
        self._cached, self._cached_at = None, 0.0
        self._refresh = threading.Lock()

    # ---- what is there
    def discover(self):
        """{"clusters": [...], "inventory": dict or None}, asked of the cluster now (slow)."""
        raise NotImplementedError

    def view(self, fresh=False):
        """discover(), reused for INVENTORY_TTL seconds so a busy page costs one lookup."""
        with self._refresh:
            if fresh or self._cached is None or time.time() - self._cached_at > INVENTORY_TTL:
                self._cached, self._cached_at = self.discover(), time.time()
            return self._cached

    def inventory(self, fresh=False):
        return self.view(fresh)["inventory"]

    def taps(self):
        return []

    def baselines(self):
        return {}

    def data_dir(self):
        raise NotImplementedError

    # ---- streams
    def stream(self, tap):
        raise NotImplementedError

    def cleanup(self, tap):
        pass

    # ---- attacks
    def scenarios(self):
        return []

    def start_attack(self, scenario, seconds):
        raise ProviderError("This monitor cannot launch attacks.")

    def stop_attack(self, handle):
        pass


# ---------------------------------------------------------------- the local k3d clusters

class LocalClusterProvider(TapProvider):
    """The cluster localcluster/collect.py brought up: its taps, its recordings, its attacks."""

    name = "local"
    can_attack = True

    def __init__(self, out_root=None):
        super().__init__()
        sys.path.insert(0, str(ROOT / "localcluster"))
        import collect   # stdlib only
        self.collect = collect
        self.out_root = Path(out_root or collect.DEFAULT_OUT).expanduser()
        self.profile = None

    def discover(self):
        clusters = self.collect.detect()
        running = [c for c in clusters if c["running"]]
        self.profile = self.collect.load_profile(running[0]["profile"]) if running else None
        return {"clusters": clusters, "inventory": running[0] if running else None}

    def _profile(self):
        if self.profile is None:
            self.view()
        if self.profile is None:
            raise ProviderError("No local cluster is running: `localcluster/collect.py up` starts one.")
        return self.profile

    def taps(self):
        return self.collect.taps(self.profile) if self.profile else []

    def data_dir(self):
        return self.out_root / self._profile()["name"] / "live"

    def baselines(self):
        return self.collect.newest_benign(self.profile, self.out_root / self.profile["name"]) if self.profile else {}

    def stream(self, tap):
        profile, collect = self._profile(), self.collect
        try:
            if tap["level"] == "pod":      # asked each time: a restarted pod has a new name
                return collect.stream_argv(profile, tap, pod=collect.pod_for(profile, tap["workload"]))
            self.cleanup(tap)              # a stale container from a crash would block the name
            bridge = collect.bridge_for(profile) if tap["level"] == "router" else None
            return collect.stream_argv(profile, tap, bridge=bridge)
        except SystemExit as failure:      # collect.py speaks to a shell; the page needs words
            raise ProviderError(str(failure)) from None

    def cleanup(self, tap):
        if tap["level"] != "pod":
            self.collect.sh("docker", "rm", "-f", self.collect.live_container(tap), check=False,
                            capture=True, quiet=True)

    def scenarios(self):
        if not self.profile:
            return []
        return [{"name": name, "kind": spec["kind"], "mode": spec.get("mode"), "target": _target(spec)}
                for name, spec in self.profile["attacks"].items()]

    def start_attack(self, scenario, seconds):
        profile = self._profile()
        if not self.collect.context(profile).startswith("k3d-rtct-"):
            raise ProviderError("Attacks only run against the local rtct clusters.")
        if scenario not in profile["attacks"]:
            raise ProviderError(f"{scenario!r} is not an attack of the {profile['name']} profile")
        try:
            handle = self.collect.start_attack(profile, scenario, seconds)
        except SystemExit as failure:
            raise ProviderError(str(failure)) from None
        handle["profile"] = profile
        return handle

    def stop_attack(self, handle):
        self.collect.stop_attack(handle["profile"], handle)


def _target(spec):
    args = spec.get("args", {})
    if spec["kind"] == "scan":
        return ", ".join(spec["targets"])
    if spec["kind"] == "exec":
        return f"from {spec['from']} to {args.get('targets', '')}"
    host = args.get("url_host") or args.get("host")
    return f"{host}:{args.get('port')}" if host else ""


# ---------------------------------------------------------------- recordings as taps

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")
RECORDING_FOLDERS = ("csv files", "pcapng files", "pcap files")


def tap_label(path):
    """pod-nginx-tcp.pcap -> pod-nginx: the tap a recording's name says it was taken at."""
    stem = Path(path).stem
    for method in ("-ptcp", "-tcp"):
        if stem.endswith(method):
            stem = stem[:-len(method)]
    return stem


class ReplayProvider(TapProvider):
    """Capture files played back as taps (`worker.py pace`), paced like the original.

    `paths` are pcap/pcapng files or folders of them. A recording laid out the KUBEDATA way
    (<root>/<scenario>/pcapng files/<label>-tcp.pcap) finds its benign sibling as its baseline;
    any other learns from its own first minute.
    """

    name = "replay"
    finite = True
    default_levels = ("pod", "node", "router")

    def __init__(self, paths, speed=1.0, out_root=None, python=sys.executable):
        super().__init__()
        self.speed, self.python = float(speed), python
        self.out_root = Path(out_root or Path.home() / "rtct-data").expanduser()
        self.files = {}
        for raw in paths:
            path = Path(raw).expanduser()
            if not path.exists():
                raise ProviderError(f"No such file or folder: {path}")
            found = [path] if path.is_file() else sorted(
                p for p in path.rglob("*") if p.suffix.lower() in CAPTURE_SUFFIXES and p.is_file())
            for file in found:
                label = tap_label(file)
                while label in self.files:      # two scenarios of one tap
                    label += "+"
                self.files[label] = file
        if not self.files:
            raise ProviderError("No pcap or pcapng file to replay.")

    def discover(self):
        inventory = {"profile": "replay", "cluster": None, "running": True, "harness_profile": None,
                     "nodes": [], "pods": [], "services": []}
        return {"clusters": [], "inventory": inventory}

    def taps(self):
        return [{"label": label, "level": next((lv for lv in ("pod", "node", "router")
                                                if label.startswith(lv + "-")), "pod"),
                 "file": str(path)} for label, path in self.files.items()]

    def data_dir(self):
        return self.out_root / "replay" / "live"

    def baselines(self):
        found = {}
        for label, path in self.files.items():
            if path.parent.name.lower() not in RECORDING_FOLDERS:
                continue
            root = path.parent.parent.parent
            for folder in RECORDING_FOLDERS:
                for sibling in sorted((root / "benign" / folder).glob(f"{tap_label(path)}-*")):
                    if sibling.resolve() != path.resolve() and label not in found:
                        found[label] = sibling
        return found

    def stream(self, tap):
        return [self.python, str(WORKER), "pace", tap["file"], "--speed", str(self.speed)]
