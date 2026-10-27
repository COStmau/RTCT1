"""The cluster's shape, inferred from the traffic the captures recorded.

Nothing about the testbed is written down here: hosts, pods, services and who talks to whom
come from the packets. The only fixed knowledge is the k3s address plan (pods in 10.42/16,
one /24 per node; services in 10.43/16) and the names of well-known ports.

  infer_cluster(captures)  {label: packet frame} -> hosts, pods, services, edges, vantages
  element_index(cluster)   ip -> the element id that address belongs to, or None

The rules, each pinned by a test in tests.ClusterChecks:
  - Each node capture claims one distinct host: the private address in the largest share of
    its packets, assigned greedily so the control plane, which every node talks to, goes to
    the capture it dominates most. The pod /24 it sees most is that host's pod subnet.
  - A pod capture names a pod when one pod address is in at least half of its non-local
    packets. Otherwise the pod runs on the host network and sits on the host whose pod
    subnet it sees most.
  - A host serving the apiserver, etcd or k3s supervisor port is the control plane, one
    serving NFS is the storage server, and every other host is a worker.
  - Edges count packets per pair of elements at the vantage that saw the most of them: one
    packet crosses pod, node and router taps, so a sum would count it three times.
"""
import ipaddress

import pandas as pd

from data_io import level_from_label

POD_CIDR = ipaddress.ip_network("10.42.0.0/16")
SERVICE_CIDR = ipaddress.ip_network("10.43.0.0/16")
POD_SUBNET_PREFIX = 24
POD_FRACTION = 0.5          # a pod capture is "about" a pod address this dominant

WELL_KNOWN_PORTS = {53: "dns", 80: "http", 443: "https", 2049: "nfs", 2379: "etcd",
                    6443: "kube-apiserver", 8080: "http-alt", 8472: "vxlan",
                    9345: "k3s-supervisor", 10250: "kubelet"}
CONTROL_PLANE_PORTS = {6443, 2379, 9345}
CLUSTER_PORTS = CONTROL_PLANE_PORTS | {10250}
NFS_PORT = 2049

NETWORKS = [{"id": "overlay", "kind": "overlay", "name": "flannel overlay"},
            {"id": "uplink", "kind": "uplink", "name": "LAN uplink"}]


def classify(address):
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
    if ip.version == 4 and ip in POD_CIDR:
        # .0 is the node's flannel VTEP and .1 its cni bridge, not pods
        return "pod" if int(ip) % 256 >= 2 else None
    if ip.version == 4 and ip in SERVICE_CIDR:
        return "service"
    return "private" if ip.is_private else "internet"


def pod_subnet(address):
    return str(ipaddress.ip_network(f"{address}/{POD_SUBNET_PREFIX}", strict=False))


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


def _top_subnet(conversations, kinds):
    """The pod /24 seen in the most packets, or None."""
    subnets = {}
    for address, count in _address_counts(conversations, kinds, {"pod"}):
        subnets[pod_subnet(address)] = subnets.get(pod_subnet(address), 0) + count
    return max(sorted(subnets), key=subnets.get) if subnets else None


def _served(conversations, ports):
    """Addresses seen as the destination of any of `ports`."""
    hit = conversations["dst_port"].isin(ports)
    return set(conversations.loc[hit, "dst_ip"])


def infer_cluster(captures):
    """Hosts, pods, services, external endpoints, edges and vantages from benign captures.

    `captures` maps a capture label (pod-nginx, node-child1, router-any, ...) to its packet
    frame with src_ip, dst_ip, src_port and dst_port.
    """
    conversations = {label: _conversations(frame) for label, frame in sorted(captures.items())}
    addresses = set()
    for table in conversations.values():
        addresses |= set(table["src_ip"]) | set(table["dst_ip"])
    kinds = {address: classify(address) for address in addresses}

    # Hosts: cluster-port servers and their clients, node-capture owners, host-net pods' hosts
    host_ips = set()
    cluster_servers, nfs_servers, control_servers = set(), set(), set()
    for label, table in conversations.items():
        private = {a for a in addresses if kinds[a] == "private"}
        cluster_servers |= _served(table, CLUSTER_PORTS) & private
        control_servers |= _served(table, CONTROL_PLANE_PORTS) & private
        nfs_servers |= _served(table, {NFS_PORT}) & private
    host_ips |= cluster_servers
    for table in conversations.values():
        talks = table["dst_port"].isin(CLUSTER_PORTS) & table["dst_ip"].isin(cluster_servers)
        host_ips |= {a for a in table.loc[talks, "src_ip"] if kinds.get(a) == "private"}

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
    host_names, host_subnets, claimed = {}, {}, set()
    for _, label, address in sorted(shares, key=lambda item: (-item[0], item[1], str(item[2]))):
        if label in claimed or address in host_names:
            continue
        claimed.add(label)
        host_ips.add(address)
        host_names[address] = label.removeprefix("node-")
        subnet = _top_subnet(conversations[label], kinds)
        if subnet:
            host_subnets[address] = subnet
    subnet_owner = {subnet: host for host, subnet in host_subnets.items()}

    # Pod captures: a dominant pod address names that pod. Otherwise the pod shares its
    # node's network namespace, and the node is the one whose pod subnet it sees most.
    pod_names, host_network_pods = {}, {}
    for label, table in conversations.items():
        if level_from_label(label) != "pod":
            continue
        ranked = _address_counts(table, kinds, {"pod"})
        local = _local_packets(table, kinds)
        if ranked and local and ranked[0][1] >= POD_FRACTION * local:
            pod_names[ranked[0][0]] = label
            continue
        owner = subnet_owner.get(_top_subnet(table, kinds))
        if owner is None:
            hosts_seen = _address_counts(table, kinds, {"private"})
            owner = hosts_seen[0][0] if hosts_seen else None
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
        owner = subnet_owner.get(pod_subnet(ip))
        pods.append({"id": f"pod:{ip}", "ip": ip, "host": owner and f"host:{owner}",
                     "name": pod_names.get(ip), "host_network": False})
    for label, owner in sorted(host_network_pods.items()):
        pods.append({"id": f"pod:{label}", "ip": owner, "host": owner and f"host:{owner}",
                     "name": label, "host_network": True})

    found = {"hosts": hosts, "pods": pods, "networks": NETWORKS}
    found["services"] = _services(conversations, kinds)
    found["external"] = (
        [{"id": f"lan:{a}", "ip": a, "kind": "lan"}
         for a in sorted((a for a in addresses if kinds[a] == "private" and a not in host_ips),
                         key=ipaddress.ip_address)]
        + ([{"id": "internet", "ip": None, "kind": "internet"}]
           if any(kind == "internet" for kind in kinds.values()) else []))
    found["edges"] = _edges(conversations, element_index(found))
    found["vantages"] = _vantages(conversations, found)
    return found


def _services(conversations, kinds):
    ports = {}
    for table in conversations.values():
        for row in table.itertuples(index=False):
            if kinds.get(row.dst_ip) == "service":
                names = ports.setdefault(row.dst_ip, set())
                if row.dst_port in WELL_KNOWN_PORTS:
                    names.add(WELL_KNOWN_PORTS[int(row.dst_port)])
            if kinds.get(row.src_ip) == "service":
                ports.setdefault(row.src_ip, set())
    return [{"id": f"svc:{ip}", "ip": ip, "port_names": sorted(names)}
            for ip, names in sorted(ports.items(), key=lambda item: ipaddress.ip_address(item[0]))]


def _edges(conversations, element_of):
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
            if low in WELL_KNOWN_PORTS:
                ports = ports | {WELL_KNOWN_PORTS[int(low)]}
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


def element_index(found):
    """A function from an IP address to the id of the element it belongs to, or None."""
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
        return "internet" if classify(address) == "internet" else None
    return element_of
