import csv
import os
import struct

import pytest

from main import run
from pktgen import (ACK, FIN, PSH, RFC9001_CLIENT_INITIAL, SYN, SYN_OPTS, client_hello,
                    crypto_frame, eth, ipv4, ipv6, quic_initial, tcp, tls_records, udp,
                    write_pcap)
from writer import COMBOS, columns_for

T0 = 1_700_000_000.0
C4, S4 = "10.0.0.1", "93.184.216.34"
C6, S6 = "2001:db8::1", "2001:db8::2"
E4, E6 = 0x0800, 0x86DD


def build_frames():
    """Return [(ts, frame)] mixing every case the tool must handle, interleaved in time."""
    f = []
    t = lambda k: T0 + k * 0.01  # noqa: E731

    # Flow A: TCP/IPv4 TLS, ClientHello split in two segments.
    ch = tls_records(client_hello("WWW.Example.com", pad=1800))
    a = lambda src, dst, sp, dp, seq, ack, fl, pl=b"", opt=b"": eth(  # noqa: E731
        ipv4(src, dst, 6, tcp(sp, dp, seq, ack, fl, pl, options=opt)), E4)
    f += [(t(0), a(C4, S4, 50000, 443, 100, 0, SYN, opt=SYN_OPTS)),
          (t(1), a(S4, C4, 443, 50000, 900, 101, SYN | ACK, opt=SYN_OPTS)),
          (t(2), a(C4, S4, 50000, 443, 101, 901, ACK))]

    # Flow B: TCP/IPv6 over two VLAN tags, interleaved with flow A.
    ch6 = tls_records(client_hello("v6.example"))
    b = lambda src, dst, sp, dp, seq, fl, pl=b"": eth(  # noqa: E731
        ipv6(src, dst, 6, tcp(sp, dp, seq, 1, fl, pl), flow_label=0xABCDE, tc=0x28), E6,
        vlans=(10, 20))
    f += [(t(3), b(C6, S6, 40000, 443, 5, SYN)),
          (t(4), b(C6, S6, 40000, 443, 6, PSH | ACK, ch6)),
          (t(5), b(S6, C6, 443, 40000, 77, ACK, b"\x16\x03\x03\x00\x02\x02\x00"))]

    f += [(t(6), a(C4, S4, 50000, 443, 101, 901, PSH | ACK, ch[:1000])),
          (t(7), a(C4, S4, 50000, 443, 1101, 901, PSH | ACK, ch[1000:])),
          (t(8), a(S4, C4, 443, 50000, 901, 101 + len(ch), ACK, b"\x17" * 50)),
          (t(9), a(C4, S4, 50000, 443, 101 + len(ch), 951, FIN | ACK)),
          (t(10), a(S4, C4, 443, 50000, 951, 102 + len(ch), FIN | ACK))]
    # Flow A2: same 5-tuple reused after FIN -> new flow, new SNI.
    ch2 = tls_records(client_hello("second.example"))
    f += [(t(11), a(C4, S4, 50000, 443, 5000, 0, SYN)),
          (t(12), a(C4, S4, 50000, 443, 5001, 0, PSH | ACK, ch2))]

    # Flow C: plain DNS over UDP/IPv4 -> Unknown; reused after idle timeout.
    dns = lambda src, dst, sp, dp, k: (t(k), eth(ipv4(src, dst, 17, udp(sp, dp, b"\x12\x34" + b"\0" * 10)), E4))  # noqa: E731,E501
    f += [dns(C4, "8.8.8.8", 5353, 53, 13), dns("8.8.8.8", C4, 53, 5353, 14)]

    # Flow D: QUIC over UDP/IPv6; a 2nd connection (new DCID) on the same 5-tuple.
    q = lambda src, dst, sp, dp, pl: eth(ipv6(src, dst, 17, udp(sp, dp, pl)), E6)  # noqa: E731
    server_initial = b"\xc0\x00\x00\x00\x01\x00\x08" + b"\xbb" * 8 + b"\x00\x40\x20" + b"\x55" * 32
    f += [(t(15), q(C6, S6, 51000, 443, RFC9001_CLIENT_INITIAL)),
          (t(16), q(S6, C6, 443, 51000, server_initial)),
          (t(17), q(C6, S6, 51000, 443, b"\x40" + b"\x01" * 40)),  # 1-RTT short header
          (t(18), q(C6, S6, 51000, 443, quic_initial(b"\x07" * 8, crypto_frame(0, client_hello("other.example"))))),
          (t(19), q(S6, C6, 443, 51000, b"\x40" + b"\x02" * 40))]

    # Flow E: TCP without TLS -> Unknown.
    f += [(t(20), a(C4, "10.0.0.80", 41000, 80, 1, 0, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n"))]

    # Fragmented UDP/IPv4 datagram, plus an orphan fragment.
    f += [(t(21), eth(ipv4(C4, "10.0.0.9", 17, udp(7000, 9000, b"x" * 16), ident=77, flags=0b001), E4)),
          (t(22), eth(ipv4(C4, "10.0.0.9", 17, b"y" * 16, ident=77, flags=0, frag_off=3), E4)),
          (t(23), eth(ipv4(C4, "10.0.0.9", 17, b"z" * 16, ident=99, flags=0, frag_off=3), E4))]

    # Skipped: ICMP, ARP.  Kept but partial: TCP header cut after 6 bytes.
    f += [(t(24), eth(ipv4(C4, S4, 1, b"\x08\x00" + b"\0" * 6), E4)),
          (t(25), eth(b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\0" * 20, 0x0806))]
    trunc = eth(ipv4(C4, "10.0.0.7", 6, tcp(42000, 22, 1, 0, SYN)), E4)
    f += [(t(26), trunc[:14 + 20 + 6])]

    # Flow C again after > idle timeout -> new flow.
    f += [dns(C4, "8.8.8.8", 5353, 53, 30000)]
    return f


def read_csv(path):
    with open(path, newline="") as fh:
        rows = list(csv.reader(fh))
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]


@pytest.fixture(params=[False, True], ids=["pcap", "pcapng"])
def outputs(tmp_path, request):
    pcap = tmp_path / ("in.pcapng" if request.param else "in.pcap")
    write_pcap(pcap, build_frames(), ng=request.param)
    out = tmp_path / "out"
    stats = run([str(pcap)], str(out), idle_timeout=120, buffer_rows=3, quiet=True)
    return out, stats


def labels_by_flow(rows):
    res = {}
    for r in rows:
        res.setdefault(int(r["flow_id"]), []).append(r["label"])
    return res


def test_four_files_with_expected_columns(outputs):
    out, _ = outputs
    for (l4, l3), name in COMBOS.items():
        header, rows = read_csv(out / name)
        assert header == columns_for(l4, l3, with_source_file=False)
        assert header[-1] == "label"
        keys = [(int(r["flow_id"]), int(r["packet_index_in_flow"])) for r in rows]
        assert keys == sorted(keys) and rows, name


def test_tcp_ipv4(outputs):
    out, _ = outputs
    _, rows = read_csv(out / "tcp_ipv4.csv")
    by_flow = labels_by_flow(rows)
    flows = sorted(by_flow)
    assert by_flow[flows[0]] == ["www.example.com"] * 8   # incl. handshake & FIN
    assert by_flow[flows[1]] == ["second.example"] * 2    # reused 5-tuple
    assert by_flow[flows[2]] == ["Unknown"]               # plain HTTP
    assert by_flow[flows[3]] == ["Unknown"]               # truncated header row kept

    syn = rows[0]
    assert syn["direction"] == "0" and syn["tcp_flags"] == "2" and syn["tcp_flag_syn"] == "1"
    assert syn["tcp_options"] == "MSS=1460;SACK_OK;TS=123:0;NOP;WS=7"
    assert (syn["tcp_opt_mss"], syn["tcp_opt_wscale"], syn["tcp_opt_ts_val"],
            syn["tcp_opt_ts_ecr"], syn["tcp_opt_sack_permitted"]) == ("1460", "7", "123", "0", "1")
    assert syn["tcp_data_offset"] == "10" and syn["tcp_header_length"] == "40"
    assert syn["ipv4_flag_df"] == "1" and syn["ipv4_ttl"] == "64" and syn["ipv4_protocol"] == "6"
    assert syn["pcap_timestamp"] == f"{T0:.6f}"
    assert rows[1]["direction"] == "1"
    assert rows[3]["tcp_opt_mss"] == "" and rows[3]["tcp_options"] == ""

    cut = [r for r in rows if r["tcp_dst_port"] == "22"][0]
    assert cut["tcp_src_port"] == "42000" and cut["tcp_seq"] == ""   # partial parse


def test_tcp_ipv6_over_vlan(outputs):
    out, _ = outputs
    _, rows = read_csv(out / "tcp_ipv6.csv")
    assert [r["label"] for r in rows] == ["v6.example"] * 3
    assert rows[0]["ipv6_flow_label"] == str(0xABCDE)
    assert rows[0]["ipv6_traffic_class"] == str(0x28)
    assert rows[0]["ipv6_next_header"] == "6" and rows[0]["src_ip"] == "2001:db8::1"


def test_udp_ipv4_dns_fragments_and_timeout(outputs):
    out, stats = outputs
    _, rows = read_csv(out / "udp_ipv4.csv")
    by_flow = labels_by_flow(rows)
    assert all(set(v) == {"Unknown"} for v in by_flow.values())
    dns_flows = {r["flow_id"] for r in rows if "53" in (r["udp_src_port"], r["udp_dst_port"])}
    assert len(dns_flows) == 2                         # split by idle timeout
    frag = [r for r in rows if r["ipv4_id"] == "77"]
    assert len(frag) == 2 and frag[0]["flow_id"] == frag[1]["flow_id"]
    assert frag[0]["ipv4_flag_mf"] == "1" and frag[0]["udp_dst_port"] == "9000"
    assert frag[1]["ipv4_fragment_offset"] == "3" and frag[1]["udp_dst_port"] == ""
    assert stats["skipped"] == {"fragment_unlinked": 1, "non_tcp_udp": 1, "non_ip": 1}
    assert stats["warnings"]["truncated_l4"] == 1


def test_udp_ipv6_quic_label_switches(outputs):
    out, _ = outputs
    _, rows = read_csv(out / "udp_ipv6.csv")
    assert [r["label"] for r in rows] == ["example.com"] * 3 + ["other.example"] * 2
    assert len({r["flow_id"] for r in rows}) == 1


def test_summary_counts(outputs):
    _, stats = outputs
    assert stats["total_packets"] == len(build_frames())
    assert stats["flows"][("tcp", "ipv4")] == 4
    assert stats["label_flows"]["example.com"] == 1 and stats["label_flows"]["other.example"] == 1


def test_empty_combos_and_multiple_files(tmp_path):
    only_tcp = [(T0, eth(ipv4(C4, S4, 6, tcp(1, 443, 1, 0, SYN)), E4))]
    write_pcap(tmp_path / "a.pcap", only_tcp)
    write_pcap(tmp_path / "b.pcap", only_tcp)
    out = tmp_path / "out"
    run([str(tmp_path)], str(out), quiet=True)
    header, rows = read_csv(out / "tcp_ipv4.csv")
    assert header[0] == "source_file" and header[-1] == "label"
    assert [(r["source_file"], r["flow_id"]) for r in rows] == [("a.pcap", "0"), ("b.pcap", "1")]
    for name in ("tcp_ipv6.csv", "udp_ipv4.csv", "udp_ipv6.csv"):
        h, r = read_csv(out / name)
        assert h[-1] == "label" and r == []


def test_raw_and_sll_linktypes(tmp_path):
    raw = [(T0, ipv4(C4, S4, 6, tcp(1, 443, 1, 0, SYN)))]
    write_pcap(tmp_path / "raw.pcap", raw, linktype=101)
    sll2 = [(T0, struct.pack("!HHIHBB8s", 0x86DD, 0, 2, 1, 0, 6, b"\0" * 8)
             + ipv6(C6, S6, 17, udp(1, 2, b"hi")))]
    write_pcap(tmp_path / "sll2.pcap", sll2, linktype=276)
    out = tmp_path / "out"
    stats = run([str(tmp_path / "raw.pcap"), str(tmp_path / "sll2.pcap")], str(out), quiet=True)
    assert stats["packets"][("tcp", "ipv4")] == 1 and stats["packets"][("udp", "ipv6")] == 1
    assert not os.listdir(out) == []
