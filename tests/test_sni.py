import random

import pytest

from headers import TCP_SYN
from pktgen import (RFC9001_CLIENT_INITIAL, client_hello, crypto_frame, quic_initial,
                    tls_records)
from sni import (NOT_TLS, OK, QuicSniExtractor, TcpSniExtractor,
                 client_hello_from_tls_stream, decrypt_initial, iter_long_headers,
                 normalize_sni, quic_v1_client_initial_keys, sni_from_client_hello)


# ----------------------------------------------------------------- TLS
def test_normalize():
    assert normalize_sni("  WWW.Example.COM. ") == "www.example.com"
    assert normalize_sni(" . ") is None


def test_client_hello_single_record():
    status, body = client_hello_from_tls_stream(tls_records(client_hello("Example.com.")))
    assert status == OK
    assert sni_from_client_hello(body) == "example.com"


def test_client_hello_without_sni():
    status, body = client_hello_from_tls_stream(tls_records(client_hello(None)))
    assert status == OK and sni_from_client_hello(body) is None


def test_client_hello_over_several_records():
    stream = tls_records(client_hello("multi.example", pad=3000), record_size=700)
    status, body = client_hello_from_tls_stream(stream)
    assert status == OK and sni_from_client_hello(body) == "multi.example"


def test_not_tls():
    assert client_hello_from_tls_stream(b"GET / HTTP/1.1\r\n")[0] == NOT_TLS
    server_hello = b"\x16\x03\x03\x00\x04\x02\x00\x00\x00"
    assert client_hello_from_tls_stream(server_hello)[0] == NOT_TLS


def _feed_segments(stream, seg_size, order, isn=1000, syn=True):
    ex = TcpSniExtractor()
    if syn:
        assert ex.feed(isn, TCP_SYN, b"", 0) is None
    segs = [(isn + 1 + i, stream[i:i + seg_size]) for i in range(0, len(stream), seg_size)]
    results = []
    for pkt_idx, k in enumerate(order(len(segs)), start=1):
        seq, data = segs[k]
        results.append(ex.feed(seq, 0x18, data, pkt_idx))
    return [r for r in results if r]


def test_tcp_split_in_order():
    stream = tls_records(client_hello("split.example", pad=2500))
    hits = _feed_segments(stream, 500, lambda n: range(n))
    assert hits == [(1, "split.example")]


def test_tcp_split_out_of_order_with_retransmission():
    stream = tls_records(client_hello("ooo.example", pad=2500))

    def order(n):
        idx = list(range(n))
        random.Random(7).shuffle(idx)
        return idx + idx[:2]  # duplicates at the end are ignored after success
    hits = _feed_segments(stream, 400, order)
    assert len(hits) == 1 and hits[0][1] == "ooo.example"


def test_tcp_without_syn_and_seq_wraparound():
    stream = tls_records(client_hello("wrap.example", pad=1500))
    hits = _feed_segments(stream, 300, lambda n: range(n), isn=0xFFFFFF00, syn=False)
    assert hits == [(1, "wrap.example")]


# ---------------------------------------------------------------- QUIC
def test_rfc9001_a1_keys():
    key, iv, hp = quic_v1_client_initial_keys(bytes.fromhex("8394c8f03e515708"))
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_rfc9001_a2_client_initial():
    pkt = RFC9001_CLIENT_INITIAL
    assert len(pkt) == 1200
    (start, version, ptype, dcid, pn_off, end), = iter_long_headers(pkt)
    assert (version, ptype, dcid.hex()) == (1, 0, "8394c8f03e515708")
    plain = decrypt_initial(pkt, start, pn_off, end, quic_v1_client_initial_keys(dcid))
    assert plain is not None and plain.startswith(bytes.fromhex("060040f1010000ed0303"))
    assert QuicSniExtractor().feed(pkt, 5) == [(5, "example.com")]


def test_quic_client_hello_split_over_packets_shuffled():
    dcid = bytes(range(8))
    hs = client_hello("chrome.example", pad=2600)  # > 1 datagram, like PQ key shares
    chunks = [(o, hs[o:o + 400]) for o in range(0, len(hs), 400)]
    random.Random(3).shuffle(chunks)              # Chrome-style CRYPTO frame shuffling
    groups = [chunks[i:i + 2] for i in range(0, len(chunks), 2)]  # 2 frames per packet
    pkts = [quic_initial(dcid, b"\x01" + b"".join(crypto_frame(o, c) for o, c in g), pn=i)
            for i, g in enumerate(groups)]
    zero_pkt = next(i for i, g in enumerate(groups) if any(o == 0 for o, _ in g))
    assert len(pkts) >= 3
    ex = QuicSniExtractor()
    events = [e for i, p in enumerate(pkts) for e in ex.feed(p, i)]
    assert events == [(zero_pkt, "chrome.example")]


def test_quic_non_initial_and_garbage_are_ignored():
    ex = QuicSniExtractor()
    assert ex.feed(b"\x40" + b"\x00" * 30, 0) == []         # short header
    assert ex.feed(b"\xc0\x00\x00\x00\x01\x08", 1) == []    # truncated long header
    bad = bytearray(RFC9001_CLIENT_INITIAL)
    bad[-1] ^= 0xFF                                         # broken AEAD tag
    assert ex.feed(bytes(bad), 2) == []


@pytest.mark.parametrize("garbage", [b"", b"\x16", b"\x16\x03\x01\xff\xff" + b"\x01" * 10])
def test_tls_garbage_never_raises(garbage):
    ex = TcpSniExtractor()
    assert ex.feed(1, 0x18, garbage, 0) is None
