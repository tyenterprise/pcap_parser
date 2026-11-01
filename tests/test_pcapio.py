import struct

from main import run
from pcapio import iter_frames
from pktgen import SYN, eth, ipv4, tcp, write_pcap


def _block(btype, body, e="<"):
    body += b"\x00" * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack(e + "II", btype, n) + body + struct.pack(e + "I", n)


def _shb(e="<"):
    return _block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)


def _idb(linktype, tsresol=None, e="<"):
    opts = b""
    if tsresol is not None:
        opts = struct.pack(e + "HH", 9, 1) + bytes([tsresol]) + b"\0\0\0" + struct.pack(e + "HH", 0, 0)
    return _block(1, struct.pack(e + "HHI", linktype, 0, 65535) + opts, e)


def _epb(iid, ticks, data, e="<"):
    return _block(6, struct.pack(e + "IIIII", iid, ticks >> 32, ticks & 0xFFFFFFFF,
                                 len(data), len(data)) + data, e)


PKT_V4 = ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1000, 443, 1, 0, SYN))


def test_multi_interface_and_sections(tmp_path):
    raw = (_shb() + _idb(1) + _idb(101, tsresol=9)
           + _epb(0, 1_700_000_000_000_000, eth(PKT_V4, 0x0800))   # µs, Ethernet
           + _epb(1, 1_700_000_001_000_000_000, PKT_V4)            # ns, raw IP
           + _shb(">") + _idb(101, e=">")                          # big-endian section
           + _epb(0, 1_700_000_002_000_000, PKT_V4, e=">"))
    p = tmp_path / "multi.pcapng"
    p.write_bytes(raw)
    frames = list(iter_frames(str(p)))
    assert [(round(ts, 6), lt) for ts, lt, _ in frames] == [
        (1_700_000_000.0, 1), (1_700_000_001.0, 101), (1_700_000_002.0, 101)]
    stats = run([str(p)], str(tmp_path / "out"), quiet=True)
    assert stats["packets"][("tcp", "ipv4")] == 3 and not stats["skipped"]


def test_truncated_files_do_not_crash(tmp_path):
    p = tmp_path / "t.pcapng"
    full = _shb() + _idb(1) + _epb(0, 1, eth(PKT_V4, 0x0800)) * 2
    p.write_bytes(full[:-10])
    assert len(list(iter_frames(str(p)))) == 1

    q = tmp_path / "t.pcap"
    write_pcap(q, [(1.0, eth(PKT_V4, 0x0800))] * 2)
    q.write_bytes(q.read_bytes()[:-10])
    stats = run([str(q)], str(tmp_path / "out"), quiet=True)
    # dpkt hands back the cut-off last record; it is kept as a partial row
    assert stats["packets"][("tcp", "ipv4")] == 2
    assert stats["warnings"]["truncated_packet"] == 1
