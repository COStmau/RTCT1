"""Frames in, the sponsor's 34-column packet rows out. Knows protocols, not containers.

The target is the CSV that data_io.load_capture reads, reproduced cell for cell so a capture
taken today scores exactly like the dataset. Where the sponsor's own conversion did something
surprising, this module copies it on purpose rather than correcting it.

SPONSOR_QUIRKS (each one copied deliberately, each pinned by a test):
  - SLL2 frames (the tcp captures) leave eth_src, eth_dst and eth_type blank.
  - A raw IP packet stored under an Ethernet interface is read as Ethernet: its eth_type is
    two bytes of the source address (0xc0a8 for 192.168.x.x) and its IP columns stay blank.
  - icmp_type and icmp_code are blank when their value is 0 (echo reply prints no type).
  - An ICMP error message takes its ports, TCP flags and udp_length from the packet it
    quotes, so a port-unreachable for :8080 counts as HTTP. tcp_payload_len stays blank.
  - is_dns, is_http and is_https match either port (53, 8080, 443), whatever the transport.
  - The first row's iat is the integer 0; later ones are float differences and can be
    negative when the capture wrote frames out of timestamp order.
"""
import csv
import ipaddress
import struct

from pcap_read import CaptureReader

COLUMNS = ["frame_number", "ts", "iat", "frame_len", "eth_src", "eth_dst", "eth_type",
           "ip_version", "src_ip", "dst_ip", "proto", "ttl_or_hlim", "src_port", "dst_port",
           "arp_opcode", "arp_sender_ip", "arp_target_ip", "arp_sender_mac", "arp_target_mac",
           "is_dns", "is_http", "is_https", "icmp_type", "icmp_code", "tcp_fin", "tcp_syn",
           "tcp_rst", "tcp_psh", "tcp_ack", "tcp_urg", "tcp_ece", "tcp_cwr", "tcp_payload_len",
           "udp_length"]

# How a frame's integer timestamp becomes the float the CSV prints. The two candidates differ
# only in the last bit, which changes the printed ts and every iat after it.
TS_RULE = "div"

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
TCP_FLAGS = ["tcp_fin", "tcp_syn", "tcp_rst", "tcp_psh", "tcp_ack", "tcp_urg", "tcp_ece",
             "tcp_cwr"]
APP_PORTS = {"is_dns": 53, "is_http": 8080, "is_https": 443}
ICMP_ERRORS = {1: {3, 4, 5, 11, 12}, 58: {1, 2, 3, 4}}   # message types that quote a packet
LINK_HEADER = {1: 14, 276: 20}
IPV4, IPV6, ARP = 0x0800, 0x86DD, 0x0806


class _Short(Exception):
    """The captured bytes end before a header does."""


def _take(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise _Short
    return struct.unpack_from(fmt, data, offset)


def _mac(raw):
    return ":".join(f"{byte:02x}" for byte in raw)


def ts_seconds(sec, frac, digits, rule=TS_RULE):
    """The frame's timestamp as float seconds."""
    if rule == "add":
        return sec + frac / 10 ** digits
    if rule == "div":
        return (sec * 10 ** digits + frac) / 10 ** digits
    raise ValueError(f"unknown ts rule {rule!r}")


def _empty_row(frame):
    row = dict.fromkeys(COLUMNS[3:])
    row["frame_len"] = frame.orig_len
    row.update(dict.fromkeys(list(APP_PORTS) + TCP_FLAGS, 0))
    return row


def dissect(frame):
    """(row, complete): the row for one frame, and False if its bytes ran out mid-header.

    Fields the bytes never reached stay blank, so a short frame still yields its row.
    """
    row, data = _empty_row(frame), frame.data
    try:
        if frame.linktype == 1:
            dst, src, ethertype = _take(data, 0, ">6s6sH")
            row.update(eth_src=_mac(src), eth_dst=_mac(dst), eth_type=f"0x{ethertype:04x}")
        else:
            ethertype = _take(data, 0, ">H")[0]
        offset = LINK_HEADER[frame.linktype]
        if ethertype == ARP:
            _arp(data, offset, row)
        elif ethertype in (IPV4, IPV6):
            proto, l4, ip_payload = _ip(data, offset, row, outer=True)
            _transport(data, proto, l4, ip_payload, row)
    except _Short:
        return row, False
    return row, True


def _arp(data, offset, row):
    opcode, sender_mac, sender_ip, target_mac, target_ip = _take(data, offset + 6, ">H6s4s6s4s")
    row.update(arp_opcode=opcode, arp_sender_mac=_mac(sender_mac), arp_target_mac=_mac(target_mac),
               arp_sender_ip=str(ipaddress.IPv4Address(sender_ip)),
               arp_target_ip=str(ipaddress.IPv4Address(target_ip)))


def _ip(data, offset, row, outer):
    """(protocol, transport offset, IP payload length). Fills the IP columns for the outer header."""
    version = _take(data, offset, ">B")[0] >> 4
    if version == 4:
        first, _, total, _, _, ttl, proto, _, src, dst = _take(data, offset, ">BBHHHBBH4s4s")
        header = (first & 0x0F) * 4
        payload, hops = total - header, ttl
        src, dst = ipaddress.IPv4Address(src), ipaddress.IPv4Address(dst)
    elif version == 6:
        _, payload, proto, hops, src, dst = _take(data, offset, ">IHBB16s16s")
        header = 40
        src, dst = ipaddress.IPv6Address(src), ipaddress.IPv6Address(dst)
    else:
        raise _Short
    if outer:
        row.update(ip_version=version, src_ip=str(src), dst_ip=str(dst),
                   proto=PROTO_NAMES.get(proto, str(proto)), ttl_or_hlim=hops)
    return proto, offset + header, payload


def _transport(data, proto, offset, ip_payload, row, quoted=False):
    if proto == 6:
        sport, dport, _, _, offset_byte, flags = _take(data, offset, ">HHIIBB")
        row.update(src_port=sport, dst_port=dport)
        row.update({name: (flags >> bit) & 1 for bit, name in enumerate(TCP_FLAGS)})
        if not quoted:
            row["tcp_payload_len"] = ip_payload - (offset_byte >> 4) * 4
    elif proto == 17:
        sport, dport, length = _take(data, offset, ">HHH")
        row.update(src_port=sport, dst_port=dport, udp_length=length)
    elif proto in ICMP_ERRORS and not quoted:
        icmp_type, code = _take(data, offset, ">BB")
        row.update(icmp_type=icmp_type or None, icmp_code=code or None)
        if icmp_type in ICMP_ERRORS[proto]:
            inner_proto, inner_l4, _ = _ip(data, offset + 8, row, outer=False)
            _transport(data, inner_proto, inner_l4, None, row, quoted=True)
    if row["src_port"] is not None:
        for column, port in APP_PORTS.items():
            row[column] = int(port in (row["src_port"], row["dst_port"]))


def frame_row(frame):
    """Every column but frame_number, ts and iat, for one frame. None is a blank cell."""
    return dissect(frame)[0]


def capture_rows(path, warnings=None):
    """One list per frame in COLUMNS order. Reader and dissection warnings go to `warnings`."""
    reader, previous, short = CaptureReader(path), None, 0
    for frame in reader.frames():
        row, complete = dissect(frame)
        short += not complete
        ts = ts_seconds(frame.ts_sec, frame.ts_frac, frame.ts_digits)
        iat = 0 if previous is None else ts - previous
        previous = ts
        yield [frame.number, ts, iat] + [row[column] for column in COLUMNS[3:]]
    if warnings is not None:
        warnings.extend(reader.warnings)
        if short:
            warnings.append(f"{short} frames too short to dissect")


def format_cell(value):
    """A cell as the sponsor's CSV prints it: blank for None, Python's str() otherwise."""
    return "" if value is None else str(value)


def write_capture_rows(pcap_path, csv_path):
    """Write the capture as a sponsor-format CSV. Returns {'rows': n, 'warnings': [...]}."""
    warnings, rows = [], 0
    with open(csv_path, "w", newline="") as handle:
        writer = csv.writer(handle)                # csv's default line ending is \r\n, as theirs
        writer.writerow(COLUMNS)
        for row in capture_rows(pcap_path, warnings):
            writer.writerow([format_cell(value) for value in row])
            rows += 1
    return {"rows": rows, "warnings": warnings}
