"""Capture files in, raw frames out. Knows the pcap and pcapng containers, nothing about protocols.

The corpus mixes both containers under one extension: the tcp captures are classic pcap
(LINUX_SLL2, microseconds) and the ptcp captures are pcapng from ptcpdump (Ethernet,
nanoseconds), all named .pcapng. So the format comes from the magic number, never the name.

Only the first HEAD_BYTES of each frame are read; the rest is skipped with a seek. Every
header the row layer dissects fits in that, and it keeps a 20 GB capture from being read
into memory.
"""
import os
import struct
from collections import namedtuple

# One captured frame. ts is kept as integers (seconds, fraction, digits of the fraction) so
# the row layer decides the float arithmetic; data is the captured bytes, cut to HEAD_BYTES.
Frame = namedtuple("Frame", "number ts_sec ts_frac ts_digits orig_len data linktype")

HEAD_BYTES = 256

# Link layers the row layer can dissect. Anything else is refused rather than emitted as blanks.
LINKTYPES = {1: "ethernet", 276: "sll2"}

# pcap magic as written on disk -> (struct byte order, digits of the timestamp fraction)
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
              b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_ORDER = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}

SHB, IDB, EPB = 0x0A0D0D0A, 1, 6
REFUSED_BLOCKS = (2, 3)            # obsolete packet block, simple packet block: no timestamp
TSRESOL, TSOFFSET = 9, 14          # IDB option codes


def detect_format(path):
    """'pcap' or 'pcapng', from the first four bytes."""
    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic in PCAP_MAGIC:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise ValueError(f"{path}: unknown capture magic {magic.hex() or 'empty'}")


class CaptureReader:
    """Frames of one capture file, in file order.

    A file cut off mid-record yields every complete frame and records a warning instead of
    raising: the frames that exist are real, but the capture must not be called complete.
    """

    def __init__(self, path):
        self.path = path
        self.format = detect_format(path)
        self.warnings = []

    def frames(self):
        size = os.path.getsize(self.path)
        with open(self.path, "rb") as handle:
            walk = self._pcap if self.format == "pcap" else self._pcapng
            try:
                yield from walk(handle, size)
            except struct.error as error:     # a field that runs past what its block holds
                raise ValueError(f"{self.path}: malformed capture ({error})") from None

    def _linktype(self, linktype):
        if linktype not in LINKTYPES:
            raise ValueError(f"{self.path}: unsupported linktype {linktype}")
        return linktype

    def _malformed(self, what):
        return ValueError(f"{self.path}: malformed {what}")

    def _truncated(self, number):
        self.warnings.append(f"truncated after frame {number}")

    def _pcap(self, handle, size):
        order, digits = PCAP_MAGIC[handle.read(4)]
        header = handle.read(20)
        if len(header) < 20:
            raise ValueError(f"{self.path}: truncated pcap global header")
        # The top bits of the linktype field can carry FCS information; the type is the low 16.
        snaplen = struct.unpack(order + "I", header[12:16])[0]
        linktype = self._linktype(struct.unpack(order + "I", header[16:])[0] & 0xFFFF)
        number = 0
        while True:
            record = handle.read(16)
            if not record:
                return
            sec, frac, incl_len, orig_len = (struct.unpack(order + "IIII", record)
                                              if len(record) == 16 else (0, 0, 0, 0))
            # pcap has no end marker, so a zero-filled tail reads as records of zeros. A record
            # that is empty, longer than the wire frame, or past the snaplen is not a record.
            if (len(record) < 16 or handle.tell() + incl_len > size
                    or (incl_len == 0 and orig_len == 0) or incl_len > orig_len
                    or (snaplen and incl_len > snaplen)):
                self._truncated(number)
                return
            data = handle.read(min(incl_len, HEAD_BYTES))
            handle.seek(incl_len - len(data), os.SEEK_CUR)
            number += 1
            yield Frame(number, sec, frac, digits, orig_len, data, linktype)

    def _pcapng(self, handle, size):
        order, interfaces, number = "<", [], 0
        while True:
            start = handle.tell()
            head = handle.read(8)
            if not head:
                return
            if len(head) < 8:
                self._truncated(number)
                return
            block_type = struct.unpack(order + "I", head[:4])[0]
            if block_type == SHB:                 # palindromic, so readable in either order
                order = PCAPNG_ORDER.get(handle.read(4))
                if order is None:
                    raise ValueError(f"{self.path}: bad pcapng byte-order magic at {start}")
                interfaces = []                   # each section starts its own interface list
            length = struct.unpack(order + "I", head[4:])[0]
            if length < 12 or start + length > size:
                self._truncated(number)
                return
            # A block ends by repeating its length. A file whose tail was zero-filled can hold a
            # block whose header survived but whose end did not: that block is not complete.
            handle.seek(start + length - 4)
            if struct.unpack(order + "I", handle.read(4))[0] != length:
                self._truncated(number)
                return
            handle.seek(start + 8)
            if block_type == IDB:
                if length < 20:
                    raise self._malformed(f"interface block at {start}")
                interfaces.append(self._interface(handle.read(length - 12), order))
            elif block_type == EPB:
                if length < 32:
                    raise self._malformed(f"packet block at {start}")
                interface, high, low, incl_len, orig_len = struct.unpack(order + "IIIII",
                                                                         handle.read(20))
                if incl_len > length - 32:
                    raise self._malformed(f"packet block at {start}: captured length past its block")
                if interface >= len(interfaces):
                    raise ValueError(f"{self.path}: packet on undeclared interface {interface}")
                linktype, digits = interfaces[interface]
                data = handle.read(min(incl_len, HEAD_BYTES))
                sec, frac = divmod((high << 32) | low, 10 ** digits)
                number += 1
                yield Frame(number, sec, frac, digits, orig_len, data, linktype)
            elif block_type in REFUSED_BLOCKS:
                raise ValueError(f"{self.path}: unsupported pcapng block type {block_type}")
            handle.seek(start + length)

    def _interface(self, body, order):
        """(linktype, timestamp digits) from an interface description block."""
        linktype = self._linktype(struct.unpack(order + "H", body[:2])[0])
        digits, offset = 6, 8                     # if_tsresol defaults to microseconds
        while offset + 4 <= len(body):
            code, length = struct.unpack(order + "HH", body[offset:offset + 4])
            value = body[offset + 4:offset + 4 + length]
            if code == 0:
                break
            if code == TSRESOL:
                if not value:
                    raise self._malformed("if_tsresol option")
                if value[0] & 0x80:
                    raise ValueError(f"{self.path}: base-2 if_tsresol is not supported")
                digits = value[0]
            elif code == TSOFFSET:
                raise ValueError(f"{self.path}: if_tsoffset is not supported")
            offset += 4 + length + (-length % 4)
        return linktype, digits
