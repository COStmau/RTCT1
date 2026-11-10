"""A local k3s cluster that records new captures, laid out like KUBEDATA.

    .venv/bin/python localcluster/collect.py up                       # lab look-alike cluster
    .venv/bin/python localcluster/collect.py run benign --csv         # one 60 s recording
    .venv/bin/python localcluster/collect.py run http-flood --csv     # an attack at second 10
    .venv/bin/python localcluster/collect.py all --csv                # benign + every attack
    .venv/bin/python localcluster/collect.py status | down
    ... --profile general                                             # the not-the-lab cluster

The cluster is k3d (k3s in Docker). A profile (profiles/<name>/) is two files:
k3d.yaml, the cluster, and profile.json, the workloads, taps and attacks as data. This script
renders the Kubernetes objects from profile.json, so a workload is one line to add.

A recording starts tcpdump at every tap at once and stops it after --seconds:
  pod-<name>      inside the pod, from its `capture` sidecar (the pod's own namespace)
  node-<name>     inside the k3d node container's namespace (a netshoot container joins it)
  router-any      the Docker bridge the nodes share: every packet between nodes
  router-flannel  the same bridge, VXLAN only (udp 8472): the pod overlay between nodes
An attack scenario starts its traffic at --attack-at seconds. Files land in
  <out>/<scenario folder>/pcapng files/<label>-tcp.pcap      (and csv files/ with --csv)
which is the KUBEDATA layout, so the harness's Data tab loads <out> as a manifest root.

Attack traffic only ever targets this local cluster's own addresses.
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

IMAGES = {"python": "python:3.12-alpine", "nginx": "nginx:1.27-alpine",
          "redis": "redis:7.4-alpine", "netshoot": "nicolaka/netshoot:v0.13"}
NAMESPACE_LABEL = "rtct/role"
CAPTURE_DIR = "/tmp"
METHOD = "tcp"                 # the lab's tcpdump method; files are named <label>-tcp
VXLAN_FILTER = "udp port 8472"
SETTLE_SECONDS = 15
DEFAULT_OUT = Path.home() / "rtct-data"


# ---------------------------------------------------------------- profiles (pure)

def profile_names():
    return sorted(p.name for p in (HERE / "profiles").iterdir() if (p / "profile.json").exists())


def load_profile(name):
    folder = HERE / "profiles" / name
    if not (folder / "profile.json").exists():
        raise SystemExit(f"no profile {name!r}; choose one of {', '.join(profile_names())}")
    profile = json.loads((folder / "profile.json").read_text(encoding="utf-8"))
    profile["name"], profile["folder"] = name, folder
    return profile


def context(profile):
    return f"k3d-{profile['cluster']}"


def node_container(profile, k3d_node):
    """The Docker container a k3d node runs in: server-0 -> k3d-<cluster>-server-0."""
    return f"k3d-{profile['cluster']}-{k3d_node}"


def taps(profile):
    """Every capture point of a recording, in label order: pods, then nodes, then routers."""
    out = [{"label": f"pod-{w['name']}", "level": "pod", "workload": w["name"]}
           for w in profile["workloads"] if w.get("tap")]
    out += [{"label": f"node-{name}", "level": "node", "container": node_container(profile, k3d)}
            for k3d, name in profile["nodes"].items()]
    out += [{"label": "router-any", "level": "router", "filter": None},
            {"label": "router-flannel", "level": "router", "filter": VXLAN_FILTER}]
    return out


def scenarios(profile):
    return ["benign"] + list(profile["attacks"])


def scenario_folder(scenario):
    """The KUBEDATA folder a scenario's files go in: 'benign', or '<name> attack'."""
    return "benign" if scenario == "benign" else f"{scenario} attack"


def pcap_path(out, scenario, label):
    return Path(out) / scenario_folder(scenario) / "pcapng files" / f"{label}-{METHOD}.pcap"


def csv_path(out, scenario, label):
    return Path(out) / scenario_folder(scenario) / "csv files" / f"{label}-{METHOD}.csv"


def _app_container(profile, workload):
    if workload.get("image"):
        image = IMAGES[workload["image"]]
        return {"name": "app", "image": image, "imagePullPolicy": "IfNotPresent"}
    args = [f"{k}={v}" for k, v in workload.get("args", {}).items()]
    return {"name": "app", "image": IMAGES["python"], "imagePullPolicy": "IfNotPresent",
            "command": ["python", "-u", "/app/traffic.py", workload["mode"], *args],
            "volumeMounts": [{"name": "traffic", "mountPath": "/app"}]}


def capture_sidecar():
    """An idle netshoot container sharing the pod's network namespace, for tcpdump."""
    return {"name": "capture", "image": IMAGES["netshoot"], "imagePullPolicy": "IfNotPresent",
            "command": ["sleep", "infinity"],
            "securityContext": {"capabilities": {"add": ["NET_ADMIN", "NET_RAW"]}}}


def render_workloads(profile):
    """The namespace, one Deployment per workload, and a Service for each that has ports."""
    ns = profile["namespace"]
    objects = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}]
    for w in profile["workloads"]:
        labels = {"app": w["name"], NAMESPACE_LABEL: "workload"}
        containers = [_app_container(profile, w)]
        if w.get("tap"):
            containers.append(capture_sidecar())
        pod = {"nodeSelector": {"rtct/name": w["node"]}, "containers": containers,
               "terminationGracePeriodSeconds": 2,
               "volumes": [{"name": "traffic", "configMap": {"name": "traffic"}}]}
        if w.get("host_network"):
            # a host-network pod still resolves cluster names, as the lab's controller did
            pod.update(hostNetwork=True, dnsPolicy="ClusterFirstWithHostNet")
        objects.append({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": w["name"], "namespace": ns, "labels": labels},
            "spec": {"replicas": w.get("replicas", 1), "selector": {"matchLabels": {"app": w["name"]}},
                     "template": {"metadata": {"labels": labels}, "spec": pod}}})
        if w.get("ports"):
            objects.append({
                "apiVersion": "v1", "kind": "Service",
                "metadata": {"name": w["name"], "namespace": ns},
                "spec": {"selector": {"app": w["name"]},
                         "ports": [{"name": f"p{p['port']}-{p.get('protocol', 'TCP').lower()}",
                                    "port": p["port"], "targetPort": p.get("target", p["port"]),
                                    "protocol": p.get("protocol", "TCP")}
                                   for p in w["ports"]]}})
    return objects


def attack_seconds(seconds, attack_at):
    """How long an attack runs: from its start to the end of the recording."""
    if not 0 <= attack_at < seconds:
        raise ValueError(f"--attack-at {attack_at} must fall inside the {seconds} s recording")
    return seconds - attack_at


def render_attack_job(profile, scenario, seconds):
    """The Job that runs an attack from its own pod (kind job or scan), on attack_node."""
    spec = profile["attacks"][scenario]
    if spec["kind"] == "scan":
        container = {"name": "attack", "image": IMAGES["netshoot"], "imagePullPolicy": "IfNotPresent",
                     # fast enough to finish inside a recording: most of these addresses
                     # are empty, so wide host groups and a packet-rate floor matter more
                     # than port count
                     "command": ["timeout", str(int(seconds)), "nmap", "-sT", "-Pn", "-n", "-T4",
                                 "--max-retries", "0", "--host-timeout", "5s",
                                 "--min-hostgroup", "256", "--min-rate", "2000",
                                 "--top-ports", "20", *spec["targets"]]}
        volumes = []
    elif spec["kind"] == "job":
        args = [f"{k}={v}" for k, v in spec.get("args", {}).items()] + [f"seconds={int(seconds)}"]
        container = {"name": "attack", "image": IMAGES["python"], "imagePullPolicy": "IfNotPresent",
                     "command": ["python", "-u", "/app/traffic.py", spec["mode"], *args],
                     "volumeMounts": [{"name": "traffic", "mountPath": "/app"}]}
        volumes = [{"name": "traffic", "configMap": {"name": "traffic"}}]
    else:
        raise ValueError(f"{scenario} runs inside a workload, not as a Job")
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": f"attack-{scenario}", "namespace": profile["namespace"],
                         "labels": {NAMESPACE_LABEL: "attack"}},
            "spec": {"backoffLimit": 0, "ttlSecondsAfterFinished": 300,   # its logs are read after the run
                     "template": {"metadata": {"labels": {NAMESPACE_LABEL: "attack"}},
                                  "spec": {"restartPolicy": "Never",
                                           "nodeSelector": {"rtct/name": profile["attack_node"]},
                                           "containers": [container], "volumes": volumes}}}}


def attack_exec_args(profile, scenario, seconds):
    """The traffic.py command an exec attack runs inside the workload it compromises."""
    spec = profile["attacks"][scenario]
    args = [f"{k}={v}" for k, v in spec.get("args", {}).items()] + [f"seconds={int(seconds)}"]
    return spec["from"], ["python", "-u", "/app/traffic.py", spec["mode"], *args]


def capture_argv(profile, tap, seconds, staging, pod=None, bridge=None):
    """The command that records one tap for `seconds`, writing <label>-tcp.pcap.

    Pods record inside their sidecar (copied out afterwards); nodes and routers record from a
    netshoot container whose output folder is `staging` on this Mac.
    """
    name = f"{tap['label']}-{METHOD}.pcap"
    tcpdump = ["timeout", "-s", "INT", str(int(seconds)), "tcpdump", "-U", "-n"]
    if tap["level"] == "pod":
        return ["kubectl", "--context", context(profile), "-n", profile["namespace"], "exec", pod,
                "-c", "capture", "--", *tcpdump, "-i", "any", "-w", f"{CAPTURE_DIR}/{name}"]
    docker = ["docker", "run", "--rm", "--name", f"rtct-cap-{tap['label']}",
              "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "-v", f"{staging}:/out"]
    if tap["level"] == "node":
        return [*docker, "--net", f"container:{tap['container']}", IMAGES["netshoot"],
                *tcpdump, "-i", "any", "-w", f"/out/{name}"]
    return [*docker, "--net", "host", "--privileged", IMAGES["netshoot"],
            *tcpdump, "-i", bridge, "-w", f"/out/{name}", *([tap["filter"]] if tap["filter"] else [])]


def live_container(tap):
    """The netshoot container a live node or router tap runs in, named so it can be removed."""
    return f"rtct-live-{tap['label']}"


def stream_argv(profile, tap, pod=None, bridge=None):
    """capture_argv for the live monitor: pcap to stdout, headers only, until stopped.

    -s 128 keeps every header the dissector reads (convert/read.HEAD_BYTES is 256, but no
    header it parses runs past 128) and keeps a flood's pipe small; -U flushes each packet.
    """
    tcpdump = ["tcpdump", "-U", "-n", "-s", "128", "-w", "-"]
    if tap["level"] == "pod":
        return ["kubectl", "--context", context(profile), "-n", profile["namespace"], "exec", pod,
                "-c", "capture", "--", *tcpdump, "-i", "any"]
    docker = ["docker", "run", "--rm", "--name", live_container(tap),
              "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
    if tap["level"] == "node":
        return [*docker, "--net", f"container:{tap['container']}", IMAGES["netshoot"],
                *tcpdump, "-i", "any"]
    return [*docker, "--net", "host", "--privileged", IMAGES["netshoot"],
            *tcpdump, "-i", bridge, *([tap["filter"]] if tap["filter"] else [])]


def newest_benign(profile, out=None):
    """{tap label: file} of the profile's benign recording (CSV when written, else pcap)."""
    out = Path(out or DEFAULT_OUT / profile["name"]).expanduser()
    found = {}
    for tap in taps(profile):
        for path in (csv_path(out, "benign", tap["label"]), pcap_path(out, "benign", tap["label"])):
            if path.exists() and path.stat().st_size > 24:
                found[tap["label"]] = path
                break
    return found


def summarize_cluster(profile, listed, nodes_json, pods_json, services_json=None):
    """What detect() reports, from `k3d cluster list -o json` and kubectl's JSON (pure).

    Pods and services come from every namespace (kube-system's DNS talks to everything), so
    the live map can name each address it sees; `role` is the rtct label, None elsewhere.
    """
    entry = next((c for c in listed if c.get("name") == profile["cluster"]), None)
    if entry is None:
        return {"profile": profile["name"], "cluster": profile["cluster"], "running": False}
    nodes = []
    for item in (nodes_json or {}).get("items", []):
        ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in item.get("status", {}).get("conditions", []))
        labels = item["metadata"].get("labels", {})
        addresses = {a.get("type"): a.get("address") for a in item.get("status", {}).get("addresses", [])}
        nodes.append({"name": labels.get("rtct/name", item["metadata"]["name"]),
                      "k3d": item["metadata"]["name"], "ready": ready,
                      "ip": addresses.get("InternalIP"), "pod_cidr": item.get("spec", {}).get("podCIDR"),
                      "control_plane": "node-role.kubernetes.io/control-plane" in labels})
    pods = []
    for item in (pods_json or {}).get("items", []):
        statuses = item.get("status", {}).get("containerStatuses", [])
        labels = item["metadata"].get("labels", {})
        pods.append({"name": item["metadata"]["name"],
                     "namespace": item["metadata"].get("namespace"),
                     "app": labels.get("app") or labels.get("k8s-app") or item["metadata"]["name"].rsplit("-", 2)[0],
                     "host_network": bool(item.get("spec", {}).get("hostNetwork")),
                     "role": labels.get(NAMESPACE_LABEL),
                     "phase": item.get("status", {}).get("phase"),
                     "ready": bool(statuses) and all(c.get("ready") for c in statuses),
                     "ip": item.get("status", {}).get("podIP"),
                     "node": item.get("spec", {}).get("nodeName")})
    services = []
    for item in (services_json or {}).get("items", []):
        ip = item.get("spec", {}).get("clusterIP")
        if not ip or ip == "None":
            continue
        services.append({"name": item["metadata"]["name"], "namespace": item["metadata"].get("namespace"),
                         "ip": ip, "ports": [{"name": p.get("name"), "port": p.get("port"),
                                              "protocol": p.get("protocol", "TCP")}
                                             for p in item.get("spec", {}).get("ports", [])]})
    running = bool(nodes) and all(n["ready"] for n in nodes)
    return {"profile": profile["name"], "cluster": profile["cluster"], "running": running,
            "harness_profile": profile["harness_profile"],
            "servers": [entry.get("serversRunning"), entry.get("serversCount")],
            "agents": [entry.get("agentsRunning"), entry.get("agentsCount")],
            "nodes": sorted(nodes, key=lambda n: n["name"]), "pods": sorted(pods, key=lambda p: p["name"]),
            "services": sorted(services, key=lambda x: (x["namespace"] or "", x["name"]))}


# ---------------------------------------------------------------- the cluster (side effects)

def sh(*argv, check=True, capture=False, quiet=False, input_text=None):
    if not quiet:
        print("  $", " ".join(str(a) for a in argv), flush=True)
    result = subprocess.run([str(a) for a in argv], check=check, text=True, input=input_text,
                            capture_output=capture)
    return result.stdout.strip() if capture else result


def kubectl(profile, *args, **kw):
    return sh("kubectl", "--context", context(profile), *args, **kw)


def require_tools():
    for tool in ("docker", "k3d", "kubectl"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} is not on PATH (brew install {tool}; Docker Desktop for docker)")
    if subprocess.run(["docker", "info"], capture_output=True).returncode:
        raise SystemExit("Docker is not running: start Docker Desktop first.")


def cluster_exists(profile):
    listed = json.loads(sh("k3d", "cluster", "list", "-o", "json", capture=True, quiet=True) or "[]")
    return any(c["name"] == profile["cluster"] for c in listed)


def apply(profile, objects):
    kubectl(profile, "apply", "-f", "-",
            input_text=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}))


def detect():
    """Every local profile whose k3d cluster exists, with node and pod health."""
    if not shutil.which("k3d") or not shutil.which("kubectl"):
        return []
    try:
        listed = json.loads(sh("k3d", "cluster", "list", "-o", "json", capture=True, quiet=True) or "[]")
    except subprocess.CalledProcessError:
        return []
    found = []
    for name in profile_names():
        profile = load_profile(name)
        if not any(c.get("name") == profile["cluster"] for c in listed):
            continue
        get = lambda *what: json.loads(kubectl(profile, "get", *what, "-o", "json", check=False,
                                               capture=True, quiet=True) or "{}")
        found.append(summarize_cluster(profile, listed, get("nodes"), get("pods", "-A"),
                                       get("services", "-A")))
    return found


def start_attack(profile, scenario, seconds, log=None):
    """Launch one attack now for `seconds`; returns the handle stop_attack and run() take."""
    spec = profile["attacks"].get(scenario)
    if spec is None:
        raise ValueError(f"{scenario!r} is not an attack of the {profile['name']} profile")
    ns = profile["namespace"]
    kubectl(profile, "-n", ns, "delete", "job", "-l", f"{NAMESPACE_LABEL}=attack",
            "--ignore-not-found", "--wait=true", capture=True, quiet=True)
    handle = {"scenario": scenario, "kind": spec["kind"], "seconds": int(seconds),
              "started": time.time(), "proc": None, "pod": None}
    if spec["kind"] == "exec":
        workload, argv = attack_exec_args(profile, scenario, seconds)
        handle["pod"] = pod_for(profile, workload)
        handle["proc"] = subprocess.Popen(
            ["kubectl", "--context", context(profile), "-n", ns, "exec", handle["pod"], "-c", "app",
             "--", *argv], stdout=log or subprocess.DEVNULL, stderr=subprocess.STDOUT)
    else:
        apply(profile, [render_attack_job(profile, scenario, seconds)])
    return handle


def attack_logs(profile, handle):
    if handle["kind"] == "exec":
        return ""
    return kubectl(profile, "-n", profile["namespace"], "logs", f"job/attack-{handle['scenario']}",
                   check=False, capture=True, quiet=True) or ""


def stop_attack(profile, handle):
    """End an attack early (or clean up after one): delete its Job, or end the exec."""
    ns = profile["namespace"]
    if handle["kind"] == "exec":
        if handle["proc"] is not None and handle["proc"].poll() is None:
            handle["proc"].terminate()
        # killing kubectl exec does not end the process it started inside the pod
        kubectl(profile, "-n", ns, "exec", handle["pod"], "-c", "app", "--", "pkill", "-f",
                f"traffic.py {profile['attacks'][handle['scenario']]['mode']}",
                check=False, capture=True, quiet=True)
    else:
        kubectl(profile, "-n", ns, "delete", "job", f"attack-{handle['scenario']}", "--wait=false",
                "--ignore-not-found", capture=True, quiet=True)


def up(profile):
    require_tools()
    existed = cluster_exists(profile)
    if existed:
        print(f"{profile['cluster']} exists; re-applying its workloads.")
    else:
        sh("k3d", "cluster", "create", "--config", profile["folder"] / "k3d.yaml")
    for image in IMAGES.values():
        # pull only what Docker lacks: a cached image needs no network
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode:
            sh("docker", "pull", "-q", image)
    # one pull into Docker, then into every node: otherwise each node pulls on its own
    sh("k3d", "image", "import", "-c", profile["cluster"], *IMAGES.values())
    apply(profile, render_workloads(profile)[:1])   # the namespace, before its ConfigMap
    configmap = kubectl(profile, "-n", profile["namespace"], "create", "configmap", "traffic",
                        f"--from-file=traffic.py={HERE / 'traffic.py'}", "--dry-run=client",
                        "-o", "json", capture=True, quiet=True)
    kubectl(profile, "apply", "-f", "-", input_text=configmap)
    apply(profile, render_workloads(profile))
    if existed:   # a ConfigMap edit does not restart pods by itself
        kubectl(profile, "-n", profile["namespace"], "rollout", "restart", "deployment")
    for w in profile["workloads"]:
        kubectl(profile, "-n", profile["namespace"], "rollout", "status", f"deployment/{w['name']}",
                "--timeout=180s")
    print(f"Settling {SETTLE_SECONDS} s so the first recording starts on steady traffic ...")
    time.sleep(SETTLE_SECONDS)
    status(profile)


def pod_for(profile, workload):
    names = kubectl(profile, "-n", profile["namespace"], "get", "pods", "-l", f"app={workload}",
                    "--field-selector=status.phase=Running", "-o",
                    "jsonpath={.items[*].metadata.name}", capture=True, quiet=True).split()
    if not names:
        raise SystemExit(f"no running pod for {workload}: run `collect.py up` first")
    return sorted(names)[0]


def bridge_for(profile):
    network = sh("docker", "network", "inspect", f"k3d-{profile['cluster']}", "-f", "{{.Id}}",
                 capture=True, quiet=True)
    return f"br-{network[:12]}"


def capture_summary(path):
    """(frames, span seconds) of a capture, read with the project's own reader."""
    from convert.read import CaptureReader
    first = last = None
    frames = 0
    for frame in CaptureReader(path).frames():
        ts = frame.ts_sec + frame.ts_frac / 10 ** frame.ts_digits
        first = ts if first is None else first
        last = ts
        frames += 1
    return frames, (last - first) if frames else 0.0


def run(profile, scenario, seconds=60, attack_at=10, out=None, csv=False):
    if scenario not in scenarios(profile):
        raise SystemExit(f"scenario must be one of {', '.join(scenarios(profile))}")
    require_tools()
    if not cluster_exists(profile):
        raise SystemExit(f"{profile['cluster']} is not up: run `collect.py up --profile {profile['name']}`")
    out = Path(out or DEFAULT_OUT / profile["name"]).expanduser()
    staging = out / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    ns = profile["namespace"]
    kubectl(profile, "-n", ns, "delete", "job", "-l", f"{NAMESPACE_LABEL}=attack",
            "--ignore-not-found", "--wait=true", capture=True)

    points = taps(profile)
    pods = {t["label"]: pod_for(profile, t["workload"]) for t in points if t["level"] == "pod"}
    bridge = bridge_for(profile)
    print(f"Recording {scenario} for {seconds} s at {len(points)} taps ...")
    procs = {}
    for tap in points:
        argv = capture_argv(profile, tap, seconds, staging, pods.get(tap["label"]), bridge)
        log = open(staging / f"{tap['label']}.log", "w")
        procs[tap["label"]] = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    started = time.time()

    attack = None
    if scenario != "benign":
        time.sleep(max(0.0, attack_at - (time.time() - started)))
        length = attack_seconds(seconds, attack_at) - 1
        print(f"  attack {scenario} at {time.time() - started:.1f} s for {length} s")
        attack = start_attack(profile, scenario, length, log=open(staging / "attack.log", "w"))

    for label, proc in procs.items():
        proc.wait(timeout=seconds + 60)
    if attack is not None:
        if attack["proc"] is not None:
            attack["proc"].wait(timeout=30)
        else:
            (staging / "attack.log").write_text(attack_logs(profile, attack))
            stop_attack(profile, attack)

    print("Collecting ...")
    rows = []
    for tap in points:
        label, target = tap["label"], pcap_path(out, scenario, tap["label"])
        target.parent.mkdir(parents=True, exist_ok=True)
        name = f"{label}-{METHOD}.pcap"
        if tap["level"] == "pod":
            kubectl(profile, "-n", ns, "cp", "-c", "capture", f"{pods[label]}:{CAPTURE_DIR}/{name}",
                    str(target), quiet=True, capture=True)
        else:
            shutil.move(str(staging / name), target)
        frames, span = capture_summary(target)
        rows.append((label, frames, span))
        if csv:
            from convert.rows import write_capture_rows
            csv_target = csv_path(out, scenario, label)
            csv_target.parent.mkdir(parents=True, exist_ok=True)
            write_capture_rows(target, csv_target)
    logs = out / scenario_folder(scenario) / "logs"
    shutil.rmtree(logs, ignore_errors=True)
    shutil.move(str(staging), logs)
    (out / "profile.json").write_text(json.dumps(
        {"profile": profile["name"], "harness_profile": profile["harness_profile"],
         "cidrs": profile["cidrs"], "taps": [t["label"] for t in points]}, indent=2))

    for label, frames, span in rows:
        warn = "   <- EMPTY" if frames == 0 else ""
        print(f"  {label:<24} {frames:>8} packets  {span:6.1f} s{warn}")
    print(f"Wrote {out / scenario_folder(scenario)}")


def run_all(profile, seconds, attack_at, out, csv):
    for i, scenario in enumerate(scenarios(profile)):
        if i:
            print(f"Pausing {SETTLE_SECONDS} s between recordings ...")
            time.sleep(SETTLE_SECONDS)
        run(profile, scenario, seconds, attack_at, out, csv)


def status(profile):
    require_tools()
    if not cluster_exists(profile):
        print(f"{profile['cluster']} is not running.")
        return
    kubectl(profile, "get", "nodes", "-L", "rtct/name")
    kubectl(profile, "-n", profile["namespace"], "get", "pods", "-o", "wide")


def down(profile):
    require_tools()
    if cluster_exists(profile):
        sh("k3d", "cluster", "delete", profile["cluster"])
    else:
        print(f"{profile['cluster']} is not running.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Record KUBEDATA-style captures from a local k3s cluster.")
    parser.add_argument("command", choices=["up", "run", "all", "status", "down", "render"])
    parser.add_argument("scenario", nargs="?", help="for run: benign or an attack name")
    parser.add_argument("--profile", default="lab", choices=profile_names())
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--attack-at", type=int, default=10)
    parser.add_argument("--out", default=None, help="default: ~/rtct-data/<profile>")
    parser.add_argument("--csv", action="store_true", help="also write the sponsor's packet CSVs")
    args = parser.parse_args(argv)
    profile = load_profile(args.profile)
    if args.command == "up":
        up(profile)
    elif args.command == "run":
        if not args.scenario:
            raise SystemExit(f"run what? one of {', '.join(scenarios(profile))}")
        run(profile, args.scenario, args.seconds, args.attack_at, args.out, args.csv)
    elif args.command == "all":
        run_all(profile, args.seconds, args.attack_at, args.out, args.csv)
    elif args.command == "status":
        status(profile)
    elif args.command == "down":
        down(profile)
    elif args.command == "render":
        print(json.dumps({"apiVersion": "v1", "kind": "List", "items": render_workloads(profile)}, indent=2))


if __name__ == "__main__":
    main()
