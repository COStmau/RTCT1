"""A deployed Kubernetes cluster as a tap provider: its own kubeconfig, no attacks of its own.

The lab's RKE2 cluster already runs a `tcpdump-sidecar` in every workload and node DaemonSet pod, so
unlike the k3d test bed there is nothing to start or remove here: a tap is `kubectl exec` into a
container that is already capturing. That is why `cleanup()` is empty and `can_attack` is False.

Measured on the lab cluster (2026-11-12): three nodes Ready, six pods carrying a `tcpdump-sidecar`,
and one of those six (camera-5s) whose sidecar image has no `tcpdump` binary at all. A tap whose
sidecar cannot be probed is left out rather than restarted forever, so this list is the list that
works.

Two readings to keep in mind when quoting numbers from these taps:

- The node taps are `hostNetwork` DaemonSets, so they see the LAN as well as the pod network,
  including this Mac's own SSH session and the monitor's kubectl calls to the API server. The
  monitoring channel is therefore part of the baseline.
- `pod-lidar-live` and `node-child1` are the same network namespace (the pod is `hostNetwork`), so
  they are two views of one recording, not two independent vantages.

`summarize_cluster` in `localcluster/collect.py` already turns kubectl's JSON into the inventory the
dashboard map draws, so this module reuses it instead of describing the cluster a second way.
"""
import json
import subprocess
import sys
from pathlib import Path

# a script run as `python live/serve.py` gets live/ as sys.path[0]; the project root goes first
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live.taps import ProviderError, TapProvider

ROOT = Path(__file__).resolve().parents[1]
SIDECAR = "tcpdump-sidecar"
# -s 128 keeps every header convert/rows.py reads and every column the pipeline loads: all 34 are
# header or port derived, frame_len uses the record's original length and tcp_payload_len comes
# from the IP total-length field, so a short snaplen truncates nothing that is measured. -U flushes
# each packet and -w - streams it, which is what makes a live tap possible at all.
TCPDUMP = ["tcpdump", "-U", "-n", "-s", "128", "-w", "-", "-i", "any"]
# the argv above, as a pkill pattern: names this provider's stream and not the sidecar's own
# chunked capture, which runs `tcpdump -i any -w /pcap/...`
STREAM_PATTERN = "tcpdump -U -n -s 128"
PROFILE = {"name": "rke2-lab", "cluster": "rke2-lab", "namespace": "default",
           # canal gives pods 10.42/16 and services 10.43/16, exactly the k3s map preset
           "harness_profile": "k3s"}


def taps_from_pods(pods_json, usable=None):
    """The capture points of a pod list: DaemonSet sidecars are node taps, the rest pod taps.

    `usable` is the set of (namespace, pod) whose sidecar answered a `tcpdump` probe. A pod missing
    from it is left out, so a sidecar image without the binary is absent from the list instead of
    failing on every restart. Pass None to list every running pod that has a sidecar container.
    """
    found, seen = [], set()
    for item in (pods_json or {}).get("items", []):
        meta, spec = item.get("metadata", {}), item.get("spec", {})
        if SIDECAR not in [c.get("name") for c in spec.get("containers", [])]:
            continue
        if item.get("status", {}).get("phase") != "Running":
            continue
        namespace, name = meta.get("namespace"), meta["name"]
        if usable is not None and (namespace, name) not in usable:
            continue
        owners = [o.get("kind") for o in meta.get("ownerReferences", [])]
        if "DaemonSet" in owners:
            label, level = f"node-{spec.get('nodeName')}", "node"
        else:
            # the pod's own app label, never a guess from its generated name: `lidar-live` is the
            # deployment's name and does not equal the dataset's `lidar`
            app = meta.get("labels", {}).get("app") or name.rsplit("-", 2)[0]
            label, level = f"pod-{app}", "pod"
        if label in seen:            # a rollout briefly holds two pods of one DaemonSet
            continue
        seen.add(label)
        found.append({"label": label, "level": level, "namespace": namespace, "pod": name,
                      "host_network": bool(spec.get("hostNetwork"))})
    return sorted(found, key=lambda t: (t["level"] != "pod", t["label"]))


class ClusterProvider(TapProvider):
    """A deployed cluster reached through `kubectl --kubeconfig`: taps, no attacks, no cleanup."""

    name = "cluster"
    can_attack = False
    # measured: the three node DaemonSet taps carry traffic today. Pod taps are one click away;
    # `pod-nginx` is idle until its trigger file is armed, and `pod-camera-5s` has no tcpdump.
    default_levels = ("node",)

    def __init__(self, kubeconfig, out_root=None, context=None):
        super().__init__()
        self.kubeconfig = Path(kubeconfig).expanduser()
        self.context = context
        self.out_root = Path(out_root or Path.home() / "rtct-data").expanduser()
        self._probed = {}            # (namespace, pod) -> does its sidecar have tcpdump
        self._pods = {"items": []}

    # ---- kubectl
    def _kubectl(self, *args, timeout=30):
        argv = ["kubectl", "--kubeconfig", str(self.kubeconfig)]
        if self.context:
            argv += ["--context", self.context]
        argv += list(args)
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise ProviderError(f"kubectl is not usable: {error}") from None
        if done.returncode != 0:
            raise ProviderError(f"kubectl {' '.join(args)}: {(done.stderr or '').strip()[:200]}")
        return json.loads(done.stdout or "{}")

    def _has_tcpdump(self, namespace, pod):
        """Probed once per pod name and remembered; a restarted pod has a new name and re-probes."""
        key = (namespace, pod)
        if key not in self._probed:
            argv = ["kubectl", "--kubeconfig", str(self.kubeconfig)]
            if self.context:
                argv += ["--context", self.context]
            argv += ["exec", pod, "-n", namespace, "-c", SIDECAR, "--", "sh", "-c",
                     "command -v tcpdump"]
            try:
                self._probed[key] = subprocess.run(argv, capture_output=True, text=True,
                                                   timeout=20).returncode == 0
            except (OSError, subprocess.SubprocessError):
                self._probed[key] = False
        return self._probed[key]

    # ---- what is there
    def discover(self):
        try:
            nodes = self._kubectl("get", "nodes", "-o", "json")
            pods = self._kubectl("get", "pods", "-A", "-o", "json")
            services = self._kubectl("get", "services", "-A", "-o", "json")
        except (ProviderError, ValueError):
            return {"clusters": [], "inventory": None}
        self._pods = pods
        ready = [n for n in nodes.get("items", [])
                 if any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in n.get("status", {}).get("conditions", []))]
        planes = [n for n in ready if "node-role.kubernetes.io/control-plane"
                  in n["metadata"].get("labels", {})]
        listed = [{"name": PROFILE["cluster"], "serversRunning": len(planes),
                   "serversCount": len(planes), "agentsRunning": len(ready) - len(planes),
                   "agentsCount": len(ready) - len(planes)}]
        from localcluster.collect import summarize_cluster
        inventory = summarize_cluster(PROFILE, listed, nodes, pods, services)
        cluster = {"name": PROFILE["name"], "cluster": PROFILE["cluster"],
                   "profile": PROFILE["name"], "running": inventory["running"]}
        return {"clusters": [cluster], "inventory": inventory}

    def taps(self):
        usable = {(p["namespace"], p["pod"]) for p in taps_from_pods(self._pods, None)
                  if self._has_tcpdump(p["namespace"], p["pod"])}
        return taps_from_pods(self._pods, usable)

    def baselines(self):
        return {}

    def data_dir(self):
        return self.out_root / PROFILE["name"] / "live"

    def cleanup(self, tap):
        """Stop a stream's tcpdump if it outlived the kubectl that was reading it.

        Killing the local `kubectl exec` does not kill the process on the far side, so every stop
        and every restart can leave one behind. The pattern names this provider's own argv, so the
        sidecar's own chunked capture, which is a different command, is untouched.
        """
        pod = tap.get("pod")
        if not pod:
            return
        argv = ["kubectl", "--kubeconfig", str(self.kubeconfig)]
        if self.context:
            argv += ["--context", self.context]
        argv += ["exec", pod, "-n", tap.get("namespace", "default"), "-c", SIDECAR, "--",
                 "sh", "-c", f"pkill -f '{STREAM_PATTERN}' || true"]
        try:
            subprocess.run(argv, capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass

    # ---- streams
    def stream_argv(self, tap):
        """The exec that writes this tap's packets as a classic pcap on stdout."""
        argv = ["kubectl", "--kubeconfig", str(self.kubeconfig)]
        if self.context:
            argv += ["--context", self.context]
        return [*argv, "exec", tap["pod"], "-n", tap["namespace"], "-c", SIDECAR, "--", *TCPDUMP]

    def stream(self, tap):
        label = tap["label"]
        current = next((t for t in self.taps() if t["label"] == label), None)
        if current is None:          # the pod was replaced since this tap started
            raise ProviderError(f"{label}: no running {SIDECAR} pod for this tap"
                                f" (was {tap['pod']})")
        return self.stream_argv(current)
