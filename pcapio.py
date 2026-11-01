"""Capture file readers yielding (timestamp, linktype, frame) per packet.

Classic PCAP goes through dpkt.  PCAPNG is read here because dpkt's pcapng
Reader applies the *first* interface's link type and timestamp resolution
to every packet, which mis-decodes multi-interface captures (e.g. Wireshark
capturing Ethernet and a tunnel at once) and concatenated sections.
"""

from __future__ import annotations

import logging
import struct
from collections import Counter

import dpkt

log = logging.getLogger("parse_pcap")

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_PB = 0x00000002   # obsolete Packet Block
PCAPNG_SPB = 0x00000003  # Simple Packet Block
PCAPNG_EPB = 0x00000006
OPT_IF_TSRESOL = 9
OPT_IF_TSOFFSET = 14
BYTE_ORDER_MAGIC = 0x1A2B3C4D


class _Interface:
    __slots__ = ("linktype", "divisor", "tsoffset")

    def __init__(self, linktype: int, divisor: int, tsoffset: int):
        self.linktype, self.divisor, self.tsoffset = linktype, divisor, tsoffset


def _parse_idb(body: bytes, e: str) -> _Interface:
    linktype = struct.unpack_from(e + "H", body, 0)[0]
    divisor, tsoffset = 10 ** 6, 0
    p = 8  # linktype(2) reserved(2) snaplen(4)
    while p + 4 <= len(body):
        code, ln = struct.unpack_from(e + "HH", body, p)
        val = body[p + 4:p + 4 + ln]
        p += 4 + ln + (-ln % 4)
        if code == 0:
            break
        if code == OPT_IF_TSRESOL and ln >= 1:
            r = val[0]
            divisor = 2 ** (r & 0x7F) if r & 0x80 else 10 ** (r & 0x7F)
        elif code == OPT_IF_TSOFFSET and ln >= 8:
            tsoffset = struct.unpack_from(e + "q", val)[0]
    return _Interface(linktype, divisor, tsoffset)


def iter_pcapng(fh, stats: Counter | None = None, path: str = ""):
    e = "<"
    ifaces: list[_Interface] = []
    while True:
        head = fh.read(8)
        if len(head) < 8:
            if head and stats is not None:
                stats["file_truncated"] += 1
            return
        btype = struct.unpack_from("<I", head)[0]
        if btype == PCAPNG_SHB:  # new section: byte order may change, interfaces reset
            bom = fh.read(4)
            if len(bom) < 4:
                return
            e = "<" if struct.unpack("<I", bom)[0] == BYTE_ORDER_MAGIC else ">"
            blen = struct.unpack_from(e + "I", head, 4)[0]
            body = bom + fh.read(blen - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack_from(e + "II", head)
        if blen < 12 or blen % 4:
            log.warning("%s: corrupt pcapng block length %d, stopping", path, blen)
            if stats is not None:
                stats["file_truncated"] += 1
            return
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            if stats is not None:
                stats["file_truncated"] += 1
            return
        body = body[:-4]  # trailing block length

        if btype == PCAPNG_IDB:
            ifaces.append(_parse_idb(body, e))
        elif btype == PCAPNG_EPB:
            iid, th, tl, caplen = struct.unpack_from(e + "IIII", body)
            if iid >= len(ifaces):
                continue
            itf = ifaces[iid]
            yield (itf.tsoffset + ((th << 32) | tl) / itf.divisor, itf.linktype,
                   body[20:20 + caplen])
        elif btype == PCAPNG_SPB:
            if ifaces:
                yield 0.0, ifaces[0].linktype, body[4:]  # SPB carries no timestamp
        elif btype == PCAPNG_PB:
            iid, _, th, tl, caplen = struct.unpack_from(e + "HHIII", body)
            if iid < len(ifaces):
                itf = ifaces[iid]
                yield (itf.tsoffset + ((th << 32) | tl) / itf.divisor, itf.linktype,
                       body[20:20 + caplen])
        # other blocks (NRB, ISB, DSB, custom) are ignored


def iter_pcap(fh, stats: Counter | None = None, path: str = ""):
    reader = dpkt.pcap.Reader(fh)
    linktype = reader.datalink()
    it = iter(reader)
    while True:
        try:
            ts, buf = next(it)
        except StopIteration:
            return
        except (dpkt.NeedData, dpkt.UnpackError, ValueError, struct.error) as exc:
            log.warning("%s: stopped reading at a damaged record (%s)", path, exc)
            if stats is not None:
                stats["file_truncated"] += 1
            return
        yield float(ts), linktype, buf


def iter_frames(path: str, stats: Counter | None = None):
    """Yield (timestamp, linktype, frame bytes) from a PCAP or PCAPNG file."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if len(magic) == 4 and struct.unpack("<I", magic)[0] == PCAPNG_SHB:
            yield from iter_pcapng(fh, stats, path)
        else:
            yield from iter_pcap(fh, stats, path)
