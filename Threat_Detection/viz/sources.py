"""Where the harness gets its packets: files on disk, uploads, and a stream.

The page builder (viz/page.py) takes packet frames already in memory. This module is the
step before it, so the harness can point at any capture rather than only the KUBEDATA tree:

  scan(paths)                 files found under paths: kind (csv/pcap/pcapng), a guessed
                              role, tap and scenario, and whether they can be read
  load_packets(path)          one file -> the flow-packet frame the pipeline reads; a pcap or
                              pcapng is converted to the sponsor's packet rows first (cached)
  manifest_assignments(...)   the assignment rows today's page is built from, read from the
                              KUBEDATA manifest by the same rules viz/page.py applies
  build(assignments, ...)     assignment rows -> the page bundle, with its provenance
  ReplaySource                a capture replayed as a stream of 1-second windows: the first
                              step towards live input. TapSource is the stub for the real one.

An assignment row is {path, role, vantage, level, scenario}. `role` is benign, attack or
ignore. A tap's label is `<level>-<name>` (pod-nginx, node-child1, router-any), because the
cluster inference reads the level from the label; `assignment_label` builds it.
"""
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from convert.read import detect_format
from convert.rows import write_capture_rows
from core.data_io import (LEVELS, METHODS, level_from_label, normalize_columns, parse_capture,
                          resolve_output, timebase_issues)
from core.evaluation import BULK_LABELS
from methods.pdfa import FLOW_COLUMNS
from methods.scores import FORGET_SECONDS
from viz import cluster as topology

ROLES = ("benign", "attack", "ignore")
CAPTURE_SUFFIXES = {".csv", ".pcap", ".pcapng", ".cap"}
CONVERTED_DIR = "converted"
UPLOAD_DIR = "uploads"
MAX_SCAN_FILES = 2000


# ---------------------------------------------------------------- finding files

def _kind(path):
    """'csv', 'pcap', 'pcapng' or 'unknown'. Captures are told by magic number, not name."""
    try:
        return detect_format(path)
    except (ValueError, OSError):
        pass
    if path.suffix.lower() == ".csv":
        return "csv"
    return "unknown"


def csv_columns(path):
    """The CSV's header, normalized the way data_io reads it (lowercase, underscores)."""
    written = list(pd.read_csv(path, nrows=0, low_memory=False).columns)
    return written, list(normalize_columns(pd.DataFrame(columns=written)).columns)


def missing_flow_columns(path):
    """The flow columns a CSV lacks; empty when the pipeline can read it."""
    _, columns = csv_columns(path)
    return [c for c in FLOW_COLUMNS if c not in columns]


def _guess(path):
    """(role, vantage, level, scenario, method) read from a file's name and folders.

    Sponsor names end in the capture method (pod-nginx-tcp.csv) and sit under a scenario
    folder (benign/, nginx attack/); anything else falls back to the file stem.
    """
    method = None
    try:
        label, method = parse_capture(path)
    except ValueError:
        label = path.stem
    level = next((lv for lv in LEVELS if label.startswith(lv + "-")), "pod")
    name = label[len(level) + 1:] if label.startswith(level + "-") else label
    parts = [p.lower() for p in path.parts]
    scenario = None
    for marker in ("csv files", "pcapng files", "pcap files"):
        if marker in parts:
            index = parts.index(marker)
            if index > 0:
                scenario = path.parts[index - 1]
    if scenario is None:
        scenario = path.parent.name
    folders = " ".join(parts[:-1])
    role = ("benign" if "benign" in folders or "benign" in path.stem.lower()
            else "attack" if "attack" in folders or "attack" in path.stem.lower()
            else "ignore")
    if role == "benign":
        scenario = "benign"
    return role, name, level, scenario, method


def describe_file(path):
    """One scan row for a file: what it is, what it is guessed to be, and any problem."""
    path = Path(path)
    kind = _kind(path)
    role, name, level, scenario, method = _guess(path)
    problem = None
    if kind == "csv":
        try:
            missing = missing_flow_columns(path)
            if missing:
                problem = f"missing columns: {', '.join(missing)}"
        except Exception as error:   # an unreadable CSV is reported, not raised
            problem = f"unreadable CSV: {error}"
    elif kind == "unknown":
        problem = "not a CSV, pcap or pcapng file"
    if problem:
        role = "ignore"
    return {"path": str(path), "name": path.name, "size": path.stat().st_size, "kind": kind,
            "method": method, "role": role, "vantage": name, "level": level,
            "scenario": scenario, "problem": problem}


def scan(paths, recursive=True, limit=MAX_SCAN_FILES):
    """Scan rows for every capture-like file at or under `paths`, sorted by path.

    A directory is walked (recursively unless told not to) for .csv, .pcap, .pcapng and .cap
    files; a file is described as given. A path that does not exist is an error, so a typo
    is not silently an empty dataset.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]
    found = []
    for raw in paths:
        path = Path(str(raw)).expanduser()
        if not path.exists():
            raise ValueError(f"No such file or folder: {path}")
        if path.is_file():
            found.append(path)
            continue
        walk = path.rglob("*") if recursive else path.glob("*")
        found += [p for p in walk if p.is_file() and p.suffix.lower() in CAPTURE_SUFFIXES
                  and not p.name.startswith(".")]
    found = sorted(set(found))
    if len(found) > limit:
        raise ValueError(f"{len(found)} capture files under that path; the limit is {limit}. "
                         "Point at a narrower folder.")
    return [describe_file(p) for p in found]


# ---------------------------------------------------------------- reading packets

def converted_path(path):
    """Where a capture's packet rows are cached: keyed by name, size and modification time."""
    stat = Path(path).stat()
    key = f"{Path(path).stem}-{stat.st_size}-{int(stat.st_mtime)}.csv"
    folder = resolve_output(CONVERTED_DIR)
    folder.mkdir(parents=True, exist_ok=True)
    return folder / key


def packet_csv(path):
    """A CSV of packet rows for `path`: the file itself, or its converted capture."""
    path = Path(path)
    kind = _kind(path)
    if kind == "csv":
        return path
    if kind in ("pcap", "pcapng"):
        out = converted_path(path)
        if not out.exists():
            partial = out.with_suffix(".partial")
            write_capture_rows(path, partial)
            partial.replace(out)
        return out
    raise ValueError(f"{path.name}: not a CSV, pcap or pcapng file")


def load_packets(path):
    """The flow-packet frame for one file (FLOW_COLUMNS), header spelling normalized.

    A CSV with 'Src IP' style headers reads the same as the sponsor's src_ip. A missing
    column is named in the error, since that is the contract a new dataset has to meet.
    """
    source = packet_csv(path)
    written, normalized = csv_columns(source)
    original = dict(zip(normalized, written))
    missing = [c for c in FLOW_COLUMNS if c not in original]
    if missing:
        raise ValueError(f"{Path(path).name} is missing packet columns: {', '.join(missing)} "
                         f"(the pipeline needs {', '.join(FLOW_COLUMNS)})")
    frame = pd.read_csv(source, usecols=[original[c] for c in FLOW_COLUMNS], low_memory=False)
    return frame.rename(columns={original[c]: c for c in FLOW_COLUMNS})[FLOW_COLUMNS]


# ---------------------------------------------------------------- assignments

def assignment_label(row):
    """A tap's label, `<level>-<name>`; a name that already carries its level keeps it."""
    name = str(row.get("vantage") or "").strip()
    level = str(row.get("level") or "pod").strip()
    if level not in LEVELS:
        raise ValueError(f"tap level must be one of {', '.join(LEVELS)}, not {level!r}")
    if not name:
        raise ValueError(f"{row.get('path')}: give the capture a tap name")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", name):
        raise ValueError(f"tap name {name!r}: use letters, digits, '.', '_', ':' or '-'")
    return name if name.startswith(level + "-") else f"{level}-{name}"


def usable_rows(rows):
    """Manifest rows whose `usable` column (when there is one) says the timebase is sound."""
    if "usable" in rows.columns:
        rows = rows[rows["usable"].astype(str).str.lower().eq("true")]
    return rows


def manifest_assignments(manifest, method="tcp"):
    """The assignment rows for one capture method of a KUBEDATA manifest.

    Every usable benign capture is a benign row (the cluster map reads all of them, bulk taps
    included) and every usable attack capture is an attack row. Which taps the page draws is
    decided at build time by `drawn_vantages`, the same rule viz/page.py applies.
    """
    if method not in METHODS:
        raise ValueError(f"method must be one of {', '.join(METHODS)}")
    rows = usable_rows(manifest[manifest["method"].eq(method)])
    out = []
    for row in rows.sort_values(["scenario", "label"]).itertuples():
        level = level_from_label(row.label)
        out.append({"path": str(row.path), "role": "benign" if row.scenario == "benign" else "attack",
                    "vantage": row.label, "level": level, "scenario": row.scenario,
                    "method": method, "kind": "csv"})
    return out


def drawn_vantages(benign_labels, allow_bulk=False, chosen=None):
    """The taps a page draws: `chosen` if given, else every benign tap but bulk-transfer ones."""
    if chosen:
        return list(chosen)
    return sorted(label for label in benign_labels if allow_bulk or label not in BULK_LABELS)


def load_assigned(assignments, loader=load_packets):
    """({label: benign frame}, {label: {scenario: attack frame}}, notes) from assignment rows.

    A capture whose timebase would corrupt 1-second binning is skipped with a note, as the
    static page skips it. Two benign captures for one tap is ambiguous and refused.
    """
    benign, attacks, notes, seen = {}, {}, [], set()
    for row in assignments:
        role = row.get("role", "ignore")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}, not {role!r}")
        if role == "ignore":
            continue
        label = assignment_label(row)
        scenario = "benign" if role == "benign" else str(row.get("scenario") or "attack").strip()
        key = (label, scenario)
        if key in seen:
            raise ValueError(f"two captures assigned to {label} / {scenario}; ignore one of them")
        seen.add(key)
        packets = loader(row["path"])
        if not timebase_issues(packets)["usable"]:
            notes.append(f"skipped {Path(row['path']).name}: unusable timebase")
            continue
        if role == "benign":
            benign[label] = packets
        else:
            attacks.setdefault(label, {})[scenario] = packets
    orphans = sorted(set(attacks) - set(benign))
    if orphans:
        notes.append(f"no benign capture for {', '.join(orphans)}, so their attacks are not "
                     "drawn: a tap needs benign traffic to learn from")
    if not benign:
        raise ValueError("No benign capture assigned. Every tap learns from benign traffic, "
                         "so mark at least one capture benign.")
    return benign, attacks, notes


def build(assignments, profile=None, forget=FORGET_SECONDS, selected=None, allow_bulk=False,
          vantages=None, loader=load_packets, origin="files"):
    """The page bundle for assignment rows, with `source` saying what it was built from."""
    from viz import page   # page imports this module, so the reverse import waits until here

    profile = profile or topology.K3S
    benign, attacks, notes = load_assigned(assignments, loader)
    drawn = [v for v in drawn_vantages(benign, allow_bulk, vantages) if v in benign]
    if not drawn:
        raise ValueError("Every benign tap is a bulk-transfer one; tick allow-bulk to draw it.")
    inputs = {v: (benign[v], {s: attacks.get(v, {})[s] for s in sorted(attacks.get(v, {}))})
              for v in drawn}
    bundle = page.build_pages(inputs, benign, forget, selected=selected or page.DEFAULT_VANTAGE,
                              profile=profile)
    better = better_preset(benign, profile)
    if better:
        name, count = better
        notes.append(f"the {profile.name} address plan found no pod addresses, but {count} addresses "
                     f"fall in the {name} plan's pod range: rebuild with the {name} preset")
    thin = sorted(v for v, why in bundle["absent"].items() if why == "too few flows")
    if thin:
        notes.append(f"left off {', '.join(thin)}: too few benign flows to learn from "
                     "(it still feeds the map)")
    drawn = [v for v in drawn if v in bundle["vantages"]]
    bundle["source"] = provenance(assignments, profile, forget, allow_bulk, drawn, notes, origin)
    return bundle


def better_preset(captures, profile):
    """(preset, addresses) when `profile` puts no address in its pod range but a preset would.

    Choosing kubeadm for k3s traffic (or the reverse) does not fail: every pod lands outside
    the cluster as a LAN device, and the map fills with unlabelled-looking addresses. This
    names the preset that fits, so the Data tab can say so.
    """
    import ipaddress
    addresses = set()
    for packets in captures.values():
        for column in ("src_ip", "dst_ip"):
            addresses.update(str(a) for a in packets[column].dropna().unique())
    parsed = []
    for address in addresses:
        try:
            parsed.append(ipaddress.ip_address(address))
        except ValueError:
            continue

    def in_pods(plan):
        nets = [ipaddress.ip_network(c) for c in plan.pod_cidrs]
        return sum(any(a in n for n in nets if a.version == n.version) for a in parsed)

    if in_pods(profile):
        return None
    counts = {name: in_pods(plan) for name, plan in topology.PROFILES.items() if name != profile.name}
    name = max(counts, key=counts.get, default=None)
    return (name, counts[name]) if name and counts[name] else None


def provenance(assignments, profile, forget, allow_bulk, drawn, notes, origin):
    """What a bundle was built from, so a shared page says where its numbers came from."""
    return {"origin": origin,
            "built": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": [{"name": Path(r["path"]).name, "path": str(r["path"]),
                       "role": r.get("role"), "tap": assignment_label(r) if r.get("role") != "ignore" else None,
                       "scenario": "benign" if r.get("role") == "benign" else r.get("scenario")}
                      for r in assignments if r.get("role") != "ignore"],
            "profile": profile.to_dict(), "forget_seconds": float(forget),
            "allow_bulk": bool(allow_bulk), "drawn": list(drawn), "notes": list(notes)}


# ---------------------------------------------------------------- uploads

def safe_upload_name(name):
    """An uploaded file's name, or ValueError for one that tries to leave its folder."""
    name = str(name or "").strip()
    if not name or "/" in name or "\\" in name or name in (".", "..") or name.startswith("."):
        raise ValueError(f"refused upload name {name!r}")
    if not re.fullmatch(r"[A-Za-z0-9 _.()+-]+", name):
        raise ValueError(f"upload name {name!r}: use letters, digits, spaces and . _ - ( ) +")
    return name


def upload_folder(session):
    folder = resolve_output(UPLOAD_DIR) / session
    folder.mkdir(parents=True, exist_ok=True)
    return folder


# ---------------------------------------------------------------- streams

class LiveSource:
    """A source of packets that arrive over time, seen as 1-second windows.

    `windows()` yields one dict per second of capture time, in order:
    {t, packets, bytes, flows, new_endpoints, endpoints}. The detection side is not wired to
    it yet; this is the contract a real collector will meet, so the page and the scorer can
    be written against it now.
    """

    def windows(self):
        raise NotImplementedError


class ReplaySource(LiveSource):
    """A capture file replayed as if it were arriving now, `speed` times faster than real.

    The stand-in for a live feed: it exercises the same per-second contract with traffic
    whose ground truth is known. `sleep` is injectable so tests run it instantly.
    """

    def __init__(self, path, speed=1.0, loader=load_packets, sleep=time.sleep):
        if not speed or speed <= 0:
            raise ValueError("replay speed must be positive")
        self.path, self.speed, self.loader, self.sleep = Path(path), float(speed), loader, sleep

    def windows(self):
        packets = self.loader(self.path)
        ts = pd.to_numeric(packets["ts"], errors="coerce")
        packets = packets[ts.notna()].assign(ts=ts[ts.notna()])
        if packets.empty:
            return
        t0 = float(packets["ts"].min())
        second = ((packets["ts"] - t0) // 1).astype(int)
        known = set()
        last = int(second.max())
        groups = dict(tuple(packets.groupby(second)))
        for t in range(last + 1):
            frame = groups.get(t)
            if frame is None:
                window = {"t": t, "packets": 0, "bytes": 0, "flows": 0, "new_endpoints": 0,
                          "endpoints": len(known)}
            else:
                flows = frame[["src_ip", "dst_ip", "src_port", "dst_port", "proto"]]
                ends = set(frame["src_ip"].astype(str)) | set(frame["dst_ip"].astype(str))
                new = ends - known
                known |= ends
                window = {"t": t, "packets": int(len(frame)),
                          "bytes": int(pd.to_numeric(frame["frame_len"], errors="coerce").fillna(0).sum()),
                          "flows": int(len(flows.drop_duplicates())),
                          "new_endpoints": len(new), "endpoints": len(known)}
            yield window
            if t < last:
                self.sleep(1.0 / self.speed)


class TapSource(LiveSource):
    """Not built yet: packets from a running collector instead of a file.

    The intended shape: a collector at a tap (ptcpdump or tcpdump writing pcapng to stdout,
    or an eBPF exporter) feeds frames through convert.read and convert.rows, one packet row
    at a time, into the same 1-second windowing ReplaySource does. Windows close on a
    watermark (capture time plus a lateness allowance), so late frames are counted rather than
    reordering the past. Until then the harness replays files.
    """

    def __init__(self, command=None):
        self.command = command

    def windows(self):
        raise NotImplementedError(
            "Live taps are not wired yet; replay a capture instead (ReplaySource).")
