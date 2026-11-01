"""Link-layer stripping and L3/L4 header decoding.

Headers are parsed by hand with ``struct`` instead of with dpkt's protocol
classes: dpkt raises on a truncated header and hides raw values we need
(raw flag bytes, IHL, option bytes), while the requirements say a truncated
packet must still yield every field that is present.  dpkt is used for the
PCAP/PCAPNG readers (see main.py).

Every decoded field is stored under its final CSV column name
(``ipv4_ttl``, ``tcp_window`` ...) so writer.py can pick columns directly.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------- link types
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_12 = 12  # some BSDs
DLT_RAW_14 = 14  # OpenBSD
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TPIDS = {0x8100, 0x88A8, 0x9100, 0x9200}

AF_INET = 2
AF_INET6_ALL = {10, 24, 28, 30}  # Linux, NetBSD/OpenBSD, FreeBSD, Darwin

PROTO_TCP = 6
PROTO_UDP = 17

# IPv6 extension headers we walk through to find the real L4 protocol.
IPV6_EXT_HOPOPTS = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_AH = 51
IPV6_EXT_DSTOPTS = 60
IPV6_EXT_GENERIC = {IPV6_EXT_HOPOPTS, IPV6_EXT_ROUTING, IPV6_EXT_DSTOPTS, 135, 139, 140}

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
_TCP_FLAG_COLS = (
    ("tcp_flag_fin", TCP_FIN), ("tcp_flag_syn", TCP_SYN), ("tcp_flag_rst", TCP_RST),
    ("tcp_flag_psh", TCP_PSH), ("tcp_flag_ack", TCP_ACK), ("tcp_flag_urg", TCP_URG),
    ("tcp_flag_ece", TCP_ECE), ("tcp_flag_cwr", TCP_CWR),
)


class Skip(Exception):
    """The packet cannot be assigned to a TCP/UDP flow; ``reason`` is counted."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Decoded:
    """One packet after decoding.  ``fields`` holds CSV-column -> value."""

    __slots__ = ("l3", "l4", "proto", "src", "dst", "sport", "dport",
                 "tcp_flags", "tcp_seq", "payload", "frag", "fields", "warnings")

    def __init__(self):
        self.l3 = ""            # "ipv4" | "ipv6"
        self.l4 = ""            # "tcp" | "udp"
        self.proto = 0          # 6 | 17
        self.src = b""          # raw address bytes
        self.dst = b""
        self.sport = None       # None for a non-first fragment
        self.dport = None
        self.tcp_flags = 0
        self.tcp_seq = None
        self.payload = b""      # L4 payload (trimmed to the IP length)
        # None, ("first", key) or ("nonfirst", key); key identifies the datagram
        self.frag = None
        self.fields: dict = {}
        self.warnings: list[str] = []


# ------------------------------------------------------------------- link
def strip_link(linktype: int, buf: bytes) -> tuple[int, int]:
    """Return (ip_version, offset of the IP header)."""
    if linktype == DLT_EN10MB:
        if len(buf) < 14:
            raise Skip("truncated_link")
        etype = (buf[12] << 8) | buf[13]
        off = 14
        while etype in VLAN_TPIDS:
            if len(buf) < off + 4:
                raise Skip("truncated_link")
            etype = (buf[off + 2] << 8) | buf[off + 3]
            off += 4
        return _ethertype_to_version(etype), off

    if linktype in (DLT_NULL, DLT_LOOP):
        if len(buf) < 4:
            raise Skip("truncated_link")
        if linktype == DLT_LOOP:
            fams = (struct.unpack_from(">I", buf)[0],)
        else:  # DLT_NULL is in the capturing host's byte order
            fams = (struct.unpack_from("<I", buf)[0], struct.unpack_from(">I", buf)[0])
        for fam in fams:
            if fam == AF_INET:
                return 4, 4
            if fam in AF_INET6_ALL:
                return 6, 4
        raise Skip("non_ip")

    if linktype in (DLT_RAW, DLT_RAW_12, DLT_RAW_14, DLT_IPV4, DLT_IPV6):
        if not buf:
            raise Skip("truncated_link")
        ver = buf[0] >> 4
        if ver not in (4, 6):
            raise Skip("non_ip")
        return ver, 0

    if linktype == DLT_LINUX_SLL:
        if len(buf) < 16:
            raise Skip("truncated_link")
        return _ethertype_to_version((buf[14] << 8) | buf[15]), 16

    if linktype == DLT_LINUX_SLL2:
        if len(buf) < 20:
            raise Skip("truncated_link")
        return _ethertype_to_version((buf[0] << 8) | buf[1]), 20

    raise Skip(f"unsupported_linktype_{linktype}")


def _ethertype_to_version(etype: int) -> int:
    if etype == ETH_IPV4:
        return 4
    if etype == ETH_IPV6:
        return 6
    raise Skip("non_ip")


# --------------------------------------------------------------------- L3
def _decode_ipv4(buf: bytes, off: int, d: Decoded) -> tuple[bytes, int, bool]:
    """Fill IPv4 fields; return (l4 bytes, protocol, is_non_first_fragment)."""
    if len(buf) - off < 20:
        raise Skip("truncated_l3")
    b0 = buf[off]
    ver, ihl = b0 >> 4, b0 & 0x0F
    if ver != 4:
        raise Skip("bad_ip_version")
    tos = buf[off + 1]
    tot_len, ident, ff, ttl, proto, csum = struct.unpack_from("!HHHBBH", buf, off + 2)
    flags, frag_off = ff >> 13, ff & 0x1FFF
    d.src, d.dst = bytes(buf[off + 12:off + 16]), bytes(buf[off + 16:off + 20])
    d.l3 = "ipv4"
    d.fields.update({
        "ipv4_version": ver, "ipv4_ihl": ihl, "ipv4_tos": tos,
        "ipv4_dscp": tos >> 2, "ipv4_ecn": tos & 0x03,
        "ipv4_total_length": tot_len, "ipv4_id": ident,
        "ipv4_flags": flags, "ipv4_flag_df": (flags >> 1) & 1, "ipv4_flag_mf": flags & 1,
        "ipv4_fragment_offset": frag_off, "ipv4_ttl": ttl,
        "ipv4_protocol": proto, "ipv4_checksum": csum,
    })
    hlen = ihl * 4
    if hlen < 20:
        d.warnings.append("bad_ipv4_ihl")
        hlen = 20
    # Bound the L4 data by the IP total length; this drops Ethernet padding.
    end = off + tot_len if tot_len >= hlen else len(buf)
    if end > len(buf):
        d.warnings.append("truncated_packet")
        end = len(buf)
    if flags & 1 or frag_off:
        key = (4, d.src, d.dst, ident, proto)
        d.frag = ("nonfirst" if frag_off else "first", key)
    return buf[off + hlen:end], proto, frag_off > 0


def _decode_ipv6(buf: bytes, off: int, d: Decoded) -> tuple[bytes, int, bool]:
    if len(buf) - off < 40:
        raise Skip("truncated_l3")
    vtcfl = struct.unpack_from("!I", buf, off)[0]
    ver = vtcfl >> 28
    if ver != 6:
        raise Skip("bad_ip_version")
    plen, nh, hlim = struct.unpack_from("!HBB", buf, off + 4)
    d.src, d.dst = bytes(buf[off + 8:off + 24]), bytes(buf[off + 24:off + 40])
    d.l3 = "ipv6"
    d.fields.update({
        "ipv6_version": ver, "ipv6_traffic_class": (vtcfl >> 20) & 0xFF,
        "ipv6_flow_label": vtcfl & 0xFFFFF, "ipv6_payload_length": plen,
        "ipv6_next_header": nh, "ipv6_hop_limit": hlim,
    })
    end = off + 40 + plen if plen else len(buf)  # plen 0: jumbogram / unknown
    if end > len(buf):
        d.warnings.append("truncated_packet")
        end = len(buf)

    # Walk the extension header chain to the real upper-layer protocol.
    p, proto, non_first = off + 40, nh, False
    while True:
        if proto == IPV6_EXT_FRAGMENT:
            if p + 8 > end:
                raise Skip("truncated_l3")
            nxt = buf[p]
            fo_m = struct.unpack_from("!H", buf, p + 2)[0]
            ident = struct.unpack_from("!I", buf, p + 4)[0]
            frag_off, more = fo_m >> 3, fo_m & 1
            proto, p = nxt, p + 8
            if frag_off or more:
                d.frag = ("nonfirst" if frag_off else "first", (6, d.src, d.dst, ident, proto))
            if frag_off:
                non_first = True
                break
        elif proto in IPV6_EXT_GENERIC or proto == IPV6_EXT_AH:
            if p + 2 > end:
                raise Skip("truncated_l3")
            nxt = buf[p]
            ln = (buf[p + 1] + 2) * 4 if proto == IPV6_EXT_AH else (buf[p + 1] + 1) * 8
            proto, p = nxt, p + ln
        else:
            break
    if p > end:
        raise Skip("truncated_l3")
    return buf[p:end], proto, non_first


# --------------------------------------------------------------------- L4
def parse_tcp_options(b: bytes) -> dict:
    """Parse TCP option bytes into the summary string and per-option columns."""
    parts: list[str] = []
    out = {"tcp_opt_mss": None, "tcp_opt_wscale": None, "tcp_opt_sack_permitted": None,
           "tcp_opt_sack_blocks": None, "tcp_opt_ts_val": None, "tcp_opt_ts_ecr": None}
    i, n = 0, len(b)
    while i < n:
        kind = b[i]
        if kind == 0:
            parts.append("EOL")
            break
        if kind == 1:
            parts.append("NOP")
            i += 1
            continue
        if i + 1 >= n:
            parts.append(f"OPT{kind}(truncated)")
            break
        ln = b[i + 1]
        if ln < 2 or i + ln > n:
            parts.append(f"OPT{kind}(malformed)")
            break
        data = b[i + 2:i + ln]
        if kind == 2 and ln == 4:
            out["tcp_opt_mss"] = struct.unpack("!H", data)[0]
            parts.append(f"MSS={out['tcp_opt_mss']}")
        elif kind == 3 and ln == 3:
            out["tcp_opt_wscale"] = data[0]
            parts.append(f"WS={data[0]}")
        elif kind == 4 and ln == 2:
            out["tcp_opt_sack_permitted"] = 1
            parts.append("SACK_OK")
        elif kind == 5 and (ln - 2) % 8 == 0:
            blocks = [struct.unpack_from("!II", data, j) for j in range(0, ln - 2, 8)]
            txt = ",".join(f"{l}-{r}" for l, r in blocks)
            out["tcp_opt_sack_blocks"] = txt
            parts.append(f"SACK={txt}")
        elif kind == 8 and ln == 10:
            tsv, tse = struct.unpack("!II", data)
            out["tcp_opt_ts_val"], out["tcp_opt_ts_ecr"] = tsv, tse
            parts.append(f"TS={tsv}:{tse}")
        else:
            parts.append(f"OPT{kind}={data.hex()}" if data else f"OPT{kind}")
        i += ln
    out["tcp_options"] = ";".join(parts)
    return out


def _decode_tcp(seg: bytes, d: Decoded) -> None:
    n = len(seg)
    if n < 4:
        raise Skip("truncated_l4")
    f = d.fields
    d.sport, d.dport = struct.unpack_from("!HH", seg)
    f["tcp_src_port"], f["tcp_dst_port"] = d.sport, d.dport
    # Fill whatever fixed-header fields the captured bytes still cover.
    if n >= 8:
        d.tcp_seq = f["tcp_seq"] = struct.unpack_from("!I", seg, 4)[0]
    if n >= 12:
        f["tcp_ack"] = struct.unpack_from("!I", seg, 8)[0]
    hlen = 20
    if n >= 14:
        off = seg[12] >> 4
        hlen = off * 4
        flags = seg[13]
        d.tcp_flags = flags
        f["tcp_data_offset"], f["tcp_header_length"], f["tcp_flags"] = off, hlen, flags
        for col, bit in _TCP_FLAG_COLS:
            f[col] = 1 if flags & bit else 0
    if n >= 16:
        f["tcp_window"] = struct.unpack_from("!H", seg, 14)[0]
    if n >= 18:
        f["tcp_checksum"] = struct.unpack_from("!H", seg, 16)[0]
    if n >= 20:
        f["tcp_urgent_pointer"] = struct.unpack_from("!H", seg, 18)[0]
    else:
        d.warnings.append("truncated_l4")
        return
    if hlen < 20:
        d.warnings.append("bad_tcp_data_offset")
        hlen = 20
    if hlen > 20:
        if hlen > n:
            d.warnings.append("truncated_tcp_options")
        f.update(parse_tcp_options(seg[20:min(hlen, n)]))
    else:
        f["tcp_options"] = ""
    d.payload = bytes(seg[hlen:]) if hlen <= n else b""


def _decode_udp(dg: bytes, d: Decoded) -> None:
    n = len(dg)
    if n < 4:
        raise Skip("truncated_l4")
    f = d.fields
    d.sport, d.dport = struct.unpack_from("!HH", dg)
    f["udp_src_port"], f["udp_dst_port"] = d.sport, d.dport
    if n < 8:
        d.warnings.append("truncated_l4")
        return
    length, csum = struct.unpack_from("!HH", dg, 4)
    f["udp_length"], f["udp_checksum"] = length, csum
    d.payload = bytes(dg[8:length] if length >= 8 else dg[8:])


# ----------------------------------------------------------------- entry
def decode(linktype: int, buf: bytes) -> Decoded:
    """Decode one captured frame.  Raises Skip for non TCP/UDP packets."""
    ver, off = strip_link(linktype, buf)
    d = Decoded()
    if ver == 4:
        l4buf, proto, non_first = _decode_ipv4(buf, off, d)
    else:
        l4buf, proto, non_first = _decode_ipv6(buf, off, d)
    if proto == PROTO_TCP:
        d.l4, d.proto = "tcp", PROTO_TCP
    elif proto == PROTO_UDP:
        d.l4, d.proto = "udp", PROTO_UDP
    else:
        raise Skip("non_tcp_udp")
    if non_first:
        return d  # no L4 header in this fragment; the flow tracker links it
    if d.l4 == "tcp":
        _decode_tcp(l4buf, d)
    else:
        _decode_udp(l4buf, d)
    return d
