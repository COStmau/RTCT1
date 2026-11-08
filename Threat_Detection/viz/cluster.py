"""The cluster's shape, inferred from the traffic the captures recorded.

Nothing about the testbed is written down here: hosts, pods, services and who talks to whom
come from the packets. The only fixed knowledge is the cluster's address plan and the names
of well-known ports, held in a ClusterProfile. The default, K3S, is the testbed's: pods in
10.42/16, one /24 per node; services in 10.43/16; flannel VXLAN. Another cluster passes its
own profile (PROFILES has a kubeadm preset), so nothing below assumes k3s by itself.

  infer_cluster(captures, profile)  {label: packet frame} -> hosts, pods, services, edges,
                                    vantages, and the profile it was inferred under
  element_index(cluster)   ip -> the element id that address belongs to, or None
  locate(cluster, ip)      an element for an address only an attack capture shows

The rules, each pinned by a test in tests.ClusterChecks:
  - Each node capture claims one distinct host: the private address in the largest share of
    its packets, assigned greedily so the control plane, which every node talks to, goes to
    the capture it dominates most. Only an address serving a cluster port, claimed by a
    capture, or carrying a host-network pod is a node; API clients are LAN devices.
  - A node's pod /24 is the one whose pods it sees talking to anything but the node itself
    (its own bridge traffic); claims are one-to-one.
  - A pod capture names a pod when one pod address is in at least half of its non-local
    packets and in more than any host address. Otherwise the pod runs on the host network
    and sits on the node address that dominates it.
  - A host serving the apiserver, etcd or k3s supervisor port is the control plane, one
    serving NFS is the storage server, and every other host is a worker.
  - Edges count packets per pair of elements at the vantage that saw the most of them: one
    packet crosses pod, node and router taps, so a sum would count it three times.
"""
import ipaddress
from dataclasses import asdict, dataclass, field

import pandas as pd

from core.data_io import level_from_label

POD_FRACTION = 0.5          # a pod capture is "about" a pod address this dominant

WELL_KNOWN_PORTS = {53: "dns", 80: "http", 443: "https", 2049: "nfs", 2379: "etcd",
                    6443: "kube-apiserver", 8080: "http-alt", 8472: "vxlan",
                    9345: "k3s-supervisor", 10250: "kubelet"}


@dataclass(frozen=True)
class ClusterProfile:
    """What the inference may assume about one cluster's address plan and ports.

    `pod_cidrs` and `service_cidrs` are the ranges pod and ClusterIP addresses come from;
    each node owns one /`pod_subnet_prefix` of the pod range. `skip_bridge_hosts` drops the
    .0 and .1 of every pod subnet (flannel's VTEP and cni bridge), which are not pods. A host
    serving a `control_plane_ports` port is the control plane; `cluster_ports` (control plane
    plus kubelet) mark an address as a node; `nfs_port` marks the storage server.
    """
    name: str = "k3s"
    pod_cidrs: tuple = ("10.42.0.0/16",)
    service_cidrs: tuple = ("10.43.0.0/16",)
    pod_subnet_prefix: int = 24
    control_plane_ports: tuple = (6443, 2379, 9345)
    kubelet_ports: tuple = (10250,)
    nfs_port: int = 2049
    overlay_name: str = "flannel overlay"
    skip_bridge_hosts: bool = True
    port_names: dict = field(default_factory=lambda: dict(WELL_KNOWN_PORTS), compare=False,
                             hash=False)

    def __post_init__(self):
        # validate early: a typo in a CIDR should fail at the form, not deep in inference
        for cidr in self.pod_cidrs + self.service_cidrs:
            ipaddress.ip_network(cidr)
        if not 8 <= int(self.pod_subnet_prefix) <= 32:
            raise ValueError(f"pod subnet prefix /{self.pod_subnet_prefix} is out of range")

    @property
    def pod_networks(self):
        return [ipaddress.ip_network(c) for c in self.pod_cidrs]

    @property
    def service_networks(self):
        return [ipaddress.ip_network(c) for c in self.service_cidrs]

    @property
    def cluster_ports(self):
        return set(self.control_plane_ports) | set(self.kubelet_ports)

    def port_name(self, port):
        return self.port_names.get(int(port), str(int(port)))

    def networks(self):
        return [{"id": "overlay", "kind": "overlay", "name": self.overlay_name},
                {"id": "uplink", "kind": "uplink", "name": "LAN uplink"}]

    def to_dict(self):
        out = asdict(self)
        out["port_names"] = {str(k): v for k, v in self.port_names.items()}
        for key in ("pod_cidrs", "service_cidrs", "control_plane_ports", "kubelet_ports"):
            out[key] = list(out[key])
        return out


def profile_from_dict(data):
    """A ClusterProfile from a form or JSON dict; missing keys take the k3s defaults."""
    data = dict(data or {})
    known = {f for f in ClusterProfile.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown profile fields: {', '.join(sorted(unknown))}")
    for key in ("pod_cidrs", "service_cidrs"):
        if key in data:
            value = data[key]
            items = value.replace(",", " ").split() if isinstance(value, str) else value
            data[key] = tuple(str(v).strip() for v in items if str(v).strip())
    for key in ("control_plane_ports", "kubelet_ports"):
        if key in data:
            value = data[key]
            items = value.replace(",", " ").split() if isinstance(value, str) else value
            data[key] = tuple(int(v) for v in items)
    if "port_names" in data:
        data["port_names"] = {int(k): str(v) for k, v in data["port_names"].items()}
    for key in ("pod_subnet_prefix", "nfs_port"):
        if key in data:
            data[key] = int(data[key])
    if "skip_bridge_hosts" in data:
        data["skip_bridge_hosts"] = bool(data["skip_bridge_hosts"])
    return ClusterProfile(**data)


K3S = ClusterProfile()
# kubeadm with flannel's or Calico's usual defaults: pods 10.244/16, services 10.96/12, and
# no k3s supervisor port
KUBEADM = ClusterProfile(name="kubeadm", pod_cidrs=("10.244.0.0/16",),
                         service_cidrs=("10.96.0.0/12",), control_plane_ports=(6443, 2379),
                         overlay_name="pod overlay")
PROFILES = {p.name: p for p in (K3S, KUBEADM)}

# The k3s plan as module constants, for callers written before profiles existed.
POD_CIDR = K3S.pod_networks[0]
SERVICE_CIDR = K3S.service_networks[0]
POD_SUBNET_PREFIX = K3S.pod_subnet_prefix
CONTROL_PLANE_PORTS = set(K3S.control_plane_ports)
CLUSTER_PORTS = K3S.cluster_ports
NFS_PORT = K3S.nfs_port
NETWORKS = K3S.networks()


def classify(address, profile=K3S):
    """'pod', 'service', 'private', 'internet', or None for addresses we do not draw."""
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return None
    if ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_unspecified:
        return None
    # limited broadcast, and the .255 directed broadcast of the /24 LANs the testbed uses
    if ip.version == 4 and (ip.is_reserved or int(ip) % 256 == 255):
        return None
    if any(ip.version == net.version and ip in net for net in profile.pod_networks):
        # .0 is the node's flannel VTEP and .1 its cni bridge, not pods
        return "pod" if not profile.skip_bridge_hosts or int(ip) % 256 >= 2 else None
    if any(ip.version == net.version and ip in net for net in profile.service_networks):
        return "service"
    return "private" if ip.is_private else "internet"


def pod_subnet(address, profile=K3S):
    return str(ipaddress.ip_network(f"{address}/{profile.pod_subnet_prefix}", strict=False))


def _conversations(frame):
    """Packets per (src, dst, src_port, dst_port), ports numeric (NaN for portless)."""
    frame = frame[["src_ip", "dst_ip", "src_port", "dst_port"]].copy()
    for column in ("src_port", "dst_port"):
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
    return (frame.groupby(["src_ip", "dst_ip", "src_port", "dst_port"], dropna=False)
            .size().rename("packets").reset_index())


def _address_counts(conversations, kinds, wanted):
    """Packets in which each address of a wanted kind appears, most frequent first."""
    counts = {}
    for row in conversations.itertuples(index=False):
        for address in {row.src_ip, row.dst_ip}:
            if kinds.get(address) in wanted:
                counts[address] = counts.get(address, 0) + row.packets
    return sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))


def _local_packets(conversations, kinds):
    """Packets with at least one endpoint we draw; loopback chatter does not count."""
    drawn = conversations["src_ip"].map(kinds).notna() | conversations["dst_ip"].map(kinds).notna()
    return int(conversations.loc[drawn, "packets"].sum())


def _top_subnet(conversations, kinds, profile):
    """The pod /24 seen in the most packets, or None."""
    subnets = {}
    for address, count in _address_counts(conversations, kinds, {"pod"}):
        subnet = pod_subnet(address, profile)
        subnets[subnet] = subnets.get(subnet, 0) + count
    return max(sorted(subnets), key=subnets.get) if subnets else None


def _local_subnets(conversations, kinds, own, profile):
    """Packets per pod /24 in which a pod of it talks to something other than `own`."""
    subnets = {}
    for row in conversations.itertuples(index=False):
        for address, other in ((row.src_ip, row.dst_ip), (row.dst_ip, row.src_ip)):
            if kinds.get(address) == "pod" and other != own:
                subnet = pod_subnet(address, profile)
                subnets[subnet] = subnets.get(subnet, 0) + row.packets
                break
    return subnets


def _served(conversations, ports):
    """Addresses seen as the destination of any of `ports`."""
    hit = conversations["dst_port"].isin(ports)
    return set(conversations.loc[hit, "dst_ip"])


def infer_cluster(captures, profile=K3S):
    """Hosts, pods, services, external endpoints, edges and vantages from benign captures.

    `captures` maps a capture label (pod-nginx, node-child1, router-any, ...) to its packet
    frame with src_ip, dst_ip, src_port and dst_port. `profile` is the cluster's address plan
    and ports (default: the k3s testbed); the result carries it, so element_index and locate
    classify later addresses under the same plan.
    """
    conversations = {label: _conversations(frame) for label, frame in sorted(captures.items())}
    addresses = set()
    for table in conversations.values():
        addresses |= set(table["src_ip"]) | set(table["dst_ip"])
    kinds = {address: classify(address, profile) for address in addresses}
    cluster_ports = profile.cluster_ports
    control_ports = set(profile.control_plane_ports)

    # Hosts: an address that serves a cluster port is a node; so is one a node capture claims
    # or a host-network pod sits on. A client of the API server is not: a kubectl laptop or a
    # probe talks to 6443 too, so clients are drawn as LAN devices that say what they reach.
    private = {a for a in addresses if kinds[a] == "private"}
    cluster_servers, nfs_servers, control_servers, clients = set(), set(), set(), {}
    for table in conversations.values():
        cluster_servers |= _served(table, cluster_ports) & private
        control_servers |= _served(table, control_ports) & private
        nfs_servers |= _served(table, {profile.nfs_port}) & private
        talks = table[table["dst_port"].isin(cluster_ports)]
        for src, port in zip(talks["src_ip"], talks["dst_port"]):
            if src in private:
                clients.setdefault(src, set()).add(profile.port_name(port))
    host_ips = set(cluster_servers)

    # Node captures: each claims a distinct host, greedily by the share of its packets that
    # address is in. Every node talks to the control plane, so a raw "most frequent" would
    # hand the control plane to every capture; one-to-one gives it to the capture it owns.
    shares = []
    for label, table in conversations.items():
        if level_from_label(label) != "node":
            continue
        local = _local_packets(table, kinds) or 1
        shares += [(count / local, label, address)
                   for address, count in _address_counts(table, kinds, {"private"})]
    host_names, owner_of, claimed = {}, {}, set()
    for _, label, address in sorted(shares, key=lambda item: (-item[0], item[1], str(item[2]))):
        if label in claimed or address in host_names:
            continue
        claimed.add(label)
        host_ips.add(address)
        host_names[address] = label.removeprefix("node-")
        owner_of[label] = address

    # Pod subnets: a node's own pods talk to services, the internet and each other on its
    # bridge, so its capture holds pod traffic that does not involve the node's address. A
    # remote node only sees pods talking to itself. Claims are one-to-one, strongest first.
    evidence = []
    for label, address in owner_of.items():
        for subnet, count in _local_subnets(conversations[label], kinds, address, profile).items():
            evidence.append((count, label, subnet, address))
    host_subnets, taken = {}, set()
    for _, label, subnet, address in sorted(evidence, key=lambda e: (-e[0], e[1], e[2])):
        if address in host_subnets or subnet in taken:
            continue
        host_subnets[address] = subnet
        taken.add(subnet)
    subnet_owner = {subnet: host for host, subnet in host_subnets.items()}

    # Pod captures: a pod address in at least half the packets, and in more of them than any
    # host address, names that pod. A host-network pod carries its node's address in nearly
    # every packet, so it is placed on the node address in the largest share of them; the
    # pod subnet it sees most only decides when no node address reaches half.
    pod_names, host_network_pods = {}, {}
    for label, table in conversations.items():
        if level_from_label(label) != "pod":
            continue
        ranked = _address_counts(table, kinds, {"pod"})
        hosts_seen = _address_counts(table, kinds, {"private"})
        local = _local_packets(table, kinds)
        top_host = hosts_seen[0][1] if hosts_seen else 0
        if ranked and local and ranked[0][1] >= POD_FRACTION * local and ranked[0][1] > top_host:
            pod_names[ranked[0][0]] = label
            continue
        nodes = [a for a, count in hosts_seen
                 if a in host_names and local and count >= POD_FRACTION * local]
        owner = (nodes[0] if nodes else subnet_owner.get(_top_subnet(table, kinds, profile))
                 or (hosts_seen[0][0] if hosts_seen else None))
        host_network_pods[label] = owner
        if owner:
            host_ips.add(owner)

    hosts = []
    for ip in sorted(host_ips, key=ipaddress.ip_address):
        roles = (["control-plane"] if ip in control_servers else []) + (
            ["nfs"] if ip in nfs_servers else [])
        hosts.append({"id": f"host:{ip}", "ip": ip, "name": host_names.get(ip),
                      "pod_cidr": host_subnets.get(ip), "roles": roles or ["worker"]})

    pods = []
    for ip in sorted((a for a in addresses if kinds[a] == "pod"), key=ipaddress.ip_address):
        owner = subnet_owner.get(pod_subnet(ip, profile))
        pods.append({"id": f"pod:{ip}", "ip": ip, "host": owner and f"host:{owner}",
                     "name": pod_names.get(ip), "host_network": False})
    for label, owner in sorted(host_network_pods.items()):
        pods.append({"id": f"pod:{label}", "ip": owner, "host": owner and f"host:{owner}",
                     "name": label, "host_network": True})

    found = {"hosts": hosts, "pods": pods, "networks": profile.networks(),
             "profile": profile.to_dict()}
    found["services"] = _services(conversations, kinds, profile)
    found["external"] = (
        [{"id": f"lan:{a}", "ip": a, "kind": "lan",
          "note": f"reaches {', '.join(sorted(clients[a]))}" if a in clients else ""}
         for a in sorted((a for a in addresses if kinds[a] == "private" and a not in host_ips),
                         key=ipaddress.ip_address)]
        + ([{"id": "internet", "ip": None, "kind": "internet"}]
           if any(kind == "internet" for kind in kinds.values()) else []))
    found["edges"] = _edges(conversations, element_index(found), profile)
    found["vantages"] = _vantages(conversations, found)
    return found


def _services(conversations, kinds, profile=K3S):
    ports = {}
    for table in conversations.values():
        for row in table.itertuples(index=False):
            if kinds.get(row.dst_ip) == "service":
                names = ports.setdefault(row.dst_ip, set())
                if row.dst_port in profile.port_names:
                    names.add(profile.port_names[int(row.dst_port)])
            if kinds.get(row.src_ip) == "service":
                ports.setdefault(row.src_ip, set())
    return [{"id": f"svc:{ip}", "ip": ip, "port_names": sorted(names)}
            for ip, names in sorted(ports.items(), key=lambda item: ipaddress.ip_address(item[0]))]


def _edges(conversations, element_of, profile=K3S):
    best = {}
    for table in conversations.values():
        seen = {}
        for row in table.itertuples(index=False):
            src, dst = element_of(row.src_ip), element_of(row.dst_ip)
            if src is None or dst is None or src == dst:
                continue
            pair = tuple(sorted((src, dst)))
            packets, ports = seen.get(pair, (0, set()))
            low = min(row.src_port, row.dst_port)
            if low in profile.port_names:
                ports = ports | {profile.port_names[int(low)]}
            seen[pair] = (packets + row.packets, ports)
        for pair, (packets, ports) in seen.items():
            old_packets, old_ports = best.get(pair, (0, set()))
            best[pair] = (max(packets, old_packets), ports | old_ports)
    return [{"src": src, "dst": dst, "packets": int(packets), "ports": sorted(ports)}
            for (src, dst), (packets, ports) in sorted(best.items())]


def _vantages(conversations, found):
    pods_by_name = {pod["name"]: pod["id"] for pod in found["pods"] if pod["name"]}
    hosts_by_name = {host["name"]: host["id"] for host in found["hosts"] if host["name"]}
    vantages = []
    for label in conversations:
        level = level_from_label(label)
        if level == "pod":
            element = pods_by_name.get(label)
        elif level == "node":
            element = hosts_by_name.get(label.removeprefix("node-"))
        else:
            element = "overlay" if label.endswith("flannel") else "uplink"
        vantages.append({"label": label, "level": level, "element": element})
    return vantages


def _profile_of(found):
    """The profile a cluster was inferred under; k3s for one built before profiles."""
    return profile_from_dict(found["profile"]) if found.get("profile") else K3S


def element_index(found):
    """A function from an IP address to the id of the element it belongs to, or None."""
    profile = _profile_of(found)
    by_ip = {}
    for host in found["hosts"]:
        by_ip[host["ip"]] = host["id"]
    for pod in found["pods"]:
        if not pod["host_network"]:
            by_ip[pod["ip"]] = pod["id"]
    for service in found["services"]:
        by_ip[service["ip"]] = service["id"]
    for external in found["external"]:
        if external["ip"] is not None:
            by_ip[external["ip"]] = external["id"]

    def element_of(address):
        if address in by_ip:
            return by_ip[address]
        return "internet" if classify(address, profile) == "internet" else None
    return element_of


def locate(found, address):
    """An element for an address the benign captures never showed, marked new; or None.

    A pod address lands on the node that owns its /24, the same rule benign pods follow.
    """
    profile = _profile_of(found)
    kind = classify(address, profile)
    if kind is None:
        return None
    if kind == "internet":
        return {"id": "internet", "ip": None, "kind": "internet", "new": True}
    if kind == "service":
        return {"id": f"svc:{address}", "ip": address, "kind": "service", "port_names": [],
                "new": True}
    if kind == "pod":
        owner = next((h["id"] for h in found["hosts"] if h["pod_cidr"] == pod_subnet(address, profile)),
                     None)
        return {"id": f"pod:{address}", "ip": address, "kind": "pod", "host": owner,
                "name": None, "host_network": False, "new": True}
    return {"id": f"lan:{address}", "ip": address, "kind": "lan", "note": "", "new": True}
