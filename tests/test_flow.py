import pytest

from flow import FlowTracker, flow_key
from headers import Skip, decode
from pktgen import ACK, FIN, SYN, eth, ip4, ipv4, tcp, udp


def _dec(frame):
    return decode(1, frame)


def _tcp(src, sp, dst, dp, flags=ACK, payload=b""):
    return _dec(eth(ipv4(src, dst, 6, tcp(sp, dp, 1, 1, flags, payload)), 0x0800))


def test_flow_key_is_direction_independent():
    a, b = ip4("10.0.0.1"), ip4("10.0.0.2")
    assert flow_key(6, a, 1234, b, 443) == flow_key(6, b, 443, a, 1234)
    assert flow_key(6, a, 1234, b, 443) != flow_key(17, a, 1234, b, 443)
    assert flow_key(6, a, 1234, b, 443) != flow_key(6, a, 1235, b, 443)


def test_both_directions_share_flow_and_direction_is_set():
    t = FlowTracker()
    f1, d1, i1 = t.assign(_tcp("10.0.0.1", 1234, "10.0.0.2", 443, SYN), 0.0)
    f2, d2, i2 = t.assign(_tcp("10.0.0.2", 443, "10.0.0.1", 1234, SYN | ACK), 0.1)
    f3, d3, i3 = t.assign(_tcp("10.0.0.1", 1234, "10.0.0.2", 443), 0.2)
    assert f1 is f2 is f3
    assert (d1, d2, d3) == (0, 1, 0)
    assert (i1, i2, i3) == (0, 1, 2)


def test_idle_timeout_starts_new_flow():
    t = FlowTracker(idle_timeout=10)
    pkt = lambda: _dec(eth(ipv4("10.0.0.1", "8.8.8.8", 17, udp(5000, 53, b"q")), 0x0800))  # noqa: E731
    a, _, _ = t.assign(pkt(), 0.0)
    b, _, _ = t.assign(pkt(), 5.0)
    c, _, idx = t.assign(pkt(), 16.0)
    assert a is b and c is not a and idx == 0
    assert (a.flow_id, c.flow_id) == (0, 1)


def test_syn_after_fin_starts_new_flow():
    t = FlowTracker()
    a, _, _ = t.assign(_tcp("10.0.0.1", 1234, "10.0.0.2", 80, SYN), 0)
    t.assign(_tcp("10.0.0.1", 1234, "10.0.0.2", 80, FIN | ACK), 1)
    same, _, _ = t.assign(_tcp("10.0.0.2", 80, "10.0.0.1", 1234, FIN | ACK), 1.1)
    new, _, _ = t.assign(_tcp("10.0.0.1", 1234, "10.0.0.2", 80, SYN), 2)
    assert same is a and new is not a


def test_fragments_are_linked_to_first_fragment():
    t = FlowTracker()
    first = _dec(eth(ipv4("10.0.0.1", "10.0.0.9", 17, udp(7000, 9000, b"x" * 16),
                          ident=77, flags=0b001), 0x0800))
    rest = _dec(eth(ipv4("10.0.0.1", "10.0.0.9", 17, b"y" * 16, ident=77, flags=0,
                         frag_off=3), 0x0800))
    orphan = _dec(eth(ipv4("10.0.0.1", "10.0.0.9", 17, b"z" * 16, ident=78, flags=0,
                           frag_off=3), 0x0800))
    f1, _, _ = t.assign(first, 0)
    f2, d2, i2 = t.assign(rest, 0.001)
    assert f2 is f1 and (d2, i2) == (0, 1)
    with pytest.raises(Skip) as e:
        t.assign(orphan, 0.002)
    assert e.value.reason == "fragment_unlinked"
