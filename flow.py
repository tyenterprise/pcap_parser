"""Bidirectional 5-tuple flow tracking.

The tracker is deterministic: running it twice over the same packets gives
the same flow ids, which is what lets main.py do two passes over a file.
"""

from __future__ import annotations

from headers import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Decoded, Skip

PURGE_EVERY = 50_000  # packets between sweeps of idle flows


def flow_key(proto: int, src: bytes, sport: int, dst: bytes, dport: int) -> tuple:
    """Direction-independent key: the two (ip, port) endpoints are sorted."""
    a, b = (src, sport), (dst, dport)
    return (proto, a, b) if a <= b else (proto, b, a)


class FlowState:
    __slots__ = ("flow_id", "key", "client", "l3", "l4", "first_ts", "last_ts",
                 "n_packets", "closed", "ext")

    def __init__(self, flow_id: int, key: tuple, client: tuple, l3: str, l4: str, ts: float):
        self.flow_id = flow_id
        self.key = key
        self.client = client          # (ip, port) of the first sender
        self.l3, self.l4 = l3, l4
        self.first_ts = self.last_ts = ts
        self.n_packets = 0
        self.closed = False           # TCP FIN or RST seen
        self.ext = None               # per-pass scratch (e.g. SNI extractors)


class FlowTracker:
    def __init__(self, idle_timeout: float = 120.0, start_id: int = 0):
        self.idle_timeout = idle_timeout
        self.next_id = start_id
        self.table: dict[tuple, FlowState] = {}
        # fragment datagram key -> (FlowState, direction, ts of first fragment)
        self.frags: dict[tuple, tuple[FlowState, int, float]] = {}
        self._since_purge = 0

    def _new_flow(self, key: tuple, d: Decoded, ts: float) -> FlowState:
        fs = FlowState(self.next_id, key, (d.src, d.sport), d.l3, d.l4, ts)
        self.next_id += 1
        self.table[key] = fs
        return fs

    def assign(self, d: Decoded, ts: float) -> tuple[FlowState, int, int]:
        """Return (flow, direction, packet_index_in_flow) for a decoded packet."""
        self._since_purge += 1
        if self._since_purge >= PURGE_EVERY:
            self._purge(ts)

        if d.frag is not None and d.frag[0] == "nonfirst":
            hit = self.frags.get(d.frag[1])
            if hit is None or ts - hit[2] > self.idle_timeout:
                raise Skip("fragment_unlinked")
            fs, direction, _ = hit
            return fs, direction, self._touch(fs, ts)

        if d.sport is None:
            raise Skip("truncated_l4")
        key = flow_key(d.proto, d.src, d.sport, d.dst, d.dport)
        fs = self.table.get(key)
        if fs is None or ts - fs.last_ts > self.idle_timeout:
            fs = self._new_flow(key, d, ts)
        elif (d.l4 == "tcp" and fs.closed
              and d.tcp_flags & TCP_SYN and not d.tcp_flags & TCP_ACK):
            fs = self._new_flow(key, d, ts)  # 5-tuple reused after FIN/RST

        if d.l4 == "tcp" and d.tcp_flags & (TCP_FIN | TCP_RST):
            fs.closed = True
        direction = 0 if (d.src, d.sport) == fs.client else 1
        if d.frag is not None:  # first fragment: remember for the rest
            self.frags[d.frag[1]] = (fs, direction, ts)
        return fs, direction, self._touch(fs, ts)

    @staticmethod
    def _touch(fs: FlowState, ts: float) -> int:
        idx = fs.n_packets
        fs.n_packets += 1
        if ts > fs.last_ts:
            fs.last_ts = ts
        return idx

    def _purge(self, now: float) -> None:
        """Drop flows/fragments idle past the timeout.

        A purged flow would be replaced by a new one on its next packet
        anyway, so this frees memory without changing any assignment.
        """
        self._since_purge = 0
        limit = self.idle_timeout
        self.table = {k: v for k, v in self.table.items() if now - v.last_ts <= limit}
        self.frags = {k: v for k, v in self.frags.items() if now - v[2] <= limit}
