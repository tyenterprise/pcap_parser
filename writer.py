"""CSV schemas and a bounded-memory writer that sorts rows by (flow_id, packet index).

Packets arrive in capture order, so flows are interleaved.  Rows are
buffered, sorted, and spilled to temporary run files when the buffer is
full; close() merges the runs (external merge sort), so memory stays
bounded for multi-GB captures.
"""

from __future__ import annotations

import csv
import heapq
import os
import tempfile

META_COLUMNS = ["flow_id", "packet_index_in_flow", "direction", "pcap_timestamp",
                "src_ip", "dst_ip", "captured_length"]

IPV4_COLUMNS = ["ipv4_version", "ipv4_ihl", "ipv4_tos", "ipv4_dscp", "ipv4_ecn",
                "ipv4_total_length", "ipv4_id", "ipv4_flags", "ipv4_flag_df",
                "ipv4_flag_mf", "ipv4_fragment_offset", "ipv4_ttl", "ipv4_protocol",
                "ipv4_checksum"]

IPV6_COLUMNS = ["ipv6_version", "ipv6_traffic_class", "ipv6_flow_label",
                "ipv6_payload_length", "ipv6_next_header", "ipv6_hop_limit"]

TCP_COLUMNS = ["tcp_src_port", "tcp_dst_port", "tcp_seq", "tcp_ack", "tcp_data_offset",
               "tcp_header_length", "tcp_flags", "tcp_flag_fin", "tcp_flag_syn",
               "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_ack", "tcp_flag_urg",
               "tcp_flag_ece", "tcp_flag_cwr", "tcp_window", "tcp_checksum",
               "tcp_urgent_pointer", "tcp_options", "tcp_opt_mss", "tcp_opt_wscale",
               "tcp_opt_sack_permitted", "tcp_opt_sack_blocks", "tcp_opt_ts_val",
               "tcp_opt_ts_ecr"]

UDP_COLUMNS = ["udp_src_port", "udp_dst_port", "udp_length", "udp_checksum"]

LABEL_COLUMN = "label"

COMBOS = {  # (l4, l3) -> file name
    ("tcp", "ipv4"): "tcp_ipv4.csv",
    ("tcp", "ipv6"): "tcp_ipv6.csv",
    ("udp", "ipv4"): "udp_ipv4.csv",
    ("udp", "ipv6"): "udp_ipv6.csv",
}


def columns_for(l4: str, l3: str, with_source_file: bool) -> list[str]:
    cols = (["source_file"] if with_source_file else []) + META_COLUMNS
    cols += IPV4_COLUMNS if l3 == "ipv4" else IPV6_COLUMNS
    cols += TCP_COLUMNS if l4 == "tcp" else UDP_COLUMNS
    return cols + [LABEL_COLUMN]


def _cell(v) -> str:
    return "" if v is None else str(v)


class SortedCsvWriter:
    def __init__(self, path: str, columns: list[str], tmp_dir: str, buffer_rows: int):
        self.path = path
        self.columns = columns
        self.tmp_dir = tmp_dir
        self.buffer_rows = buffer_rows
        self.buf: list[tuple[int, int, list[str]]] = []
        self.runs: list[str] = []
        self.rows = 0

    def add(self, flow_id: int, pkt_idx: int, values: dict) -> None:
        self.buf.append((flow_id, pkt_idx, [_cell(values.get(c)) for c in self.columns]))
        self.rows += 1
        if len(self.buf) >= self.buffer_rows:
            self._spill()

    def _spill(self) -> None:
        self.buf.sort(key=lambda r: (r[0], r[1]))
        fd, name = tempfile.mkstemp(prefix="run_", suffix=".csv", dir=self.tmp_dir)
        with os.fdopen(fd, "w", newline="") as fh:
            w = csv.writer(fh)
            for fid, idx, row in self.buf:
                w.writerow([fid, idx, *row])
        self.runs.append(name)
        self.buf = []

    def close(self) -> None:
        with open(self.path, "w", newline="") as out:
            w = csv.writer(out)
            w.writerow(self.columns)
            if not self.runs:  # everything fit in memory
                self.buf.sort(key=lambda r: (r[0], r[1]))
                for _, _, row in self.buf:
                    w.writerow(row)
                self.buf = []
                return
            if self.buf:
                self._spill()
            handles = [open(r, newline="") for r in self.runs]
            try:
                streams = [((int(r[0]), int(r[1]), r[2:]) for r in csv.reader(h))
                           for h in handles]
                for _, _, row in heapq.merge(*streams, key=lambda r: (r[0], r[1])):
                    w.writerow(row)
            finally:
                for h in handles:
                    h.close()
                for r in self.runs:
                    os.remove(r)
                self.runs = []
