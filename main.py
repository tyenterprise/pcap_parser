"""PCAP/PCAPNG -> per-(L4, L3) CSV datasets labelled by TLS/QUIC SNI.

Pass 1 splits each file into flows and finds the SNI events of every flow.
Pass 2 replays the same flow assignment, parses all headers and streams the
rows into the four CSV files.
"""

from __future__ import annotations

import argparse
import bisect
import logging
import os
import socket
import sys
import tempfile
from collections import Counter

from flow import FlowTracker
from headers import Skip, decode
from pcapio import iter_frames
from sni import QuicSniExtractor, TcpSniExtractor
from writer import COMBOS, SortedCsvWriter, columns_for

log = logging.getLogger("parse_pcap")

UNKNOWN = "Unknown"
PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap", ".dmp")


# ---------------------------------------------------------------- inputs
def collect_inputs(paths: list[str]) -> list[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in names
                          if n.lower().endswith(PCAP_EXTENSIONS)]
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise SystemExit(f"input not found: {p}")
    files = sorted(dict.fromkeys(os.path.abspath(f) for f in files))
    if not files:
        raise SystemExit("no pcap files found")
    return files


def ip_to_str(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)


# ------------------------------------------------------------------ pass 1
class FlowLabels:
    """SNI events of one flow -> label of each packet.

    A packet takes the SNI of the latest event at or before it; packets
    before the first event take the first SNI.
    """

    __slots__ = ("idxs", "snis")

    def __init__(self, events: list[tuple[int, str]]):
        events.sort()
        self.idxs: list[int] = []
        self.snis: list[str] = []
        for idx, sni in events:
            if self.snis and self.snis[-1] == sni:
                continue  # same SNI again (e.g. HelloRetryRequest, QUIC Retry)
            self.idxs.append(idx)
            self.snis.append(sni)

    def label(self, pkt_idx: int) -> str:
        pos = bisect.bisect_right(self.idxs, pkt_idx) - 1
        return self.snis[max(pos, 0)]


def find_sni_events(path: str, idle_timeout: float, start_id: int):
    """Pass 1. Returns ({flow_id: FlowLabels}, next flow id)."""
    tracker = FlowTracker(idle_timeout, start_id)
    events: dict[int, list[tuple[int, str]]] = {}
    for ts, linktype, buf in iter_frames(path):
        try:
            d = decode(linktype, buf)
            fs, direction, idx = tracker.assign(d, ts)
        except Skip:
            continue
        except Exception:  # never let one odd packet stop the run
            continue
        if d.sport is None:
            continue  # non-first fragment: no L4 header, no SNI
        if d.l4 == "tcp":
            if fs.ext is None:
                # One extractor per direction: if the capture started with a
                # server packet, the real client is direction 1.
                fs.ext = (TcpSniExtractor(), TcpSniExtractor())
            hit = fs.ext[direction].feed(d.tcp_seq, d.tcp_flags, d.payload, idx)
            if hit:
                events.setdefault(fs.flow_id, []).append(hit)
        elif d.payload:
            if fs.ext is None:
                fs.ext = QuicSniExtractor()
            try:
                found = fs.ext.feed(d.payload, idx)
            except Exception:
                found = []
            if found:
                events.setdefault(fs.flow_id, []).extend(found)
    return {fid: FlowLabels(ev) for fid, ev in events.items()}, tracker.next_id


# ------------------------------------------------------------------ pass 2
def write_rows(path: str, idle_timeout: float, start_id: int, labels: dict,
               writers: dict, source_file: str | None, stats: dict) -> int:
    tracker = FlowTracker(idle_timeout, start_id)
    skipped, warnings = stats["skipped"], stats["warnings"]
    for ts, linktype, buf in iter_frames(path, skipped):
        stats["total_packets"] += 1
        try:
            d = decode(linktype, buf)
            fs, direction, idx = tracker.assign(d, ts)
        except Skip as e:
            skipped[e.reason] += 1
            continue
        except Exception as e:
            skipped[f"decode_error_{type(e).__name__}"] += 1
            continue

        combo = (fs.l4, fs.l3)
        fl = labels.get(fs.flow_id)
        label = fl.label(idx) if fl else UNKNOWN
        row = d.fields
        row.update({
            "source_file": source_file, "flow_id": fs.flow_id,
            "packet_index_in_flow": idx, "direction": direction,
            "pcap_timestamp": f"{ts:.6f}", "src_ip": ip_to_str(d.src),
            "dst_ip": ip_to_str(d.dst), "captured_length": len(buf), "label": label,
        })
        writers[combo].add(fs.flow_id, idx, row)

        stats["packets"][combo] += 1
        stats["label_packets"][label] += 1
        if idx == 0:
            stats["flows"][combo] += 1
        if fs.ext is None:
            fs.ext = set()  # labels this flow has been counted under
        if label not in fs.ext:
            fs.ext.add(label)
            stats["label_flows"][label] += 1
        for w in d.warnings:
            warnings[w] += 1
    return tracker.next_id


# ------------------------------------------------------------------ summary
def print_summary(stats: dict, out_dir: str, file=sys.stdout) -> None:
    p = lambda *a: print(*a, file=file)  # noqa: E731
    p(f"\n=== Summary ({out_dir}) ===")
    p(f"total packets read: {stats['total_packets']}")
    written = sum(stats["packets"].values())
    p(f"packets written   : {written}")
    p("\nper file:")
    for combo, name in COMBOS.items():
        p(f"  {name:<14} packets={stats['packets'][combo]:<10} flows={stats['flows'][combo]}")

    total_flows = sum(stats["flows"].values())
    p("\nlabel distribution (top 20, by flows; a flow whose SNI changes counts under each label):")
    for label, n in stats["label_flows"].most_common(20):
        p(f"  {n:>8} flows  {stats['label_packets'][label]:>10} packets  {label}")
    unk_f = stats["label_flows"][UNKNOWN]
    unk_p = stats["label_packets"][UNKNOWN]
    if total_flows:
        p(f"Unknown: {unk_f}/{total_flows} flows ({100 * unk_f / total_flows:.1f}%), "
          f"{unk_p}/{written} packets ({100 * unk_p / max(written, 1):.1f}%)")

    p("\nskipped packets by reason:")
    for reason, n in stats["skipped"].most_common() or [("(none)", 0)]:
        p(f"  {n:>10}  {reason}")
    if stats["warnings"]:
        p("\npartially parsed packets (kept, missing fields left empty):")
        for reason, n in stats["warnings"].most_common():
            p(f"  {n:>10}  {reason}")


# ---------------------------------------------------------------------- main
def run(inputs: list[str], out_dir: str, idle_timeout: float = 120.0,
        tmp_dir: str | None = None, buffer_rows: int = 500_000,
        quiet: bool = False) -> dict:
    files = collect_inputs(inputs)
    os.makedirs(out_dir, exist_ok=True)
    multi = len(files) > 1
    stats = {"total_packets": 0, "packets": Counter(), "flows": Counter(),
             "label_packets": Counter(), "label_flows": Counter(),
             "skipped": Counter(), "warnings": Counter()}

    with tempfile.TemporaryDirectory(prefix="parse_pcap_", dir=tmp_dir or out_dir) as tmp:
        writers = {combo: SortedCsvWriter(os.path.join(out_dir, name),
                                          columns_for(*combo, with_source_file=multi),
                                          tmp, buffer_rows)
                   for combo, name in COMBOS.items()}
        next_id = 0
        for path in files:
            if not quiet:
                log.info("pass 1/2 (flows + SNI): %s", path)
            labels, end_id = find_sni_events(path, idle_timeout, next_id)
            if not quiet:
                log.info("pass 2/2 (headers -> CSV): %s", path)
            end2 = write_rows(path, idle_timeout, next_id, labels, writers,
                              os.path.basename(path) if multi else None, stats)
            if end2 != end_id:
                raise RuntimeError(f"flow assignment differed between passes in {path}")
            next_id = end_id
        for w in writers.values():
            w.close()
    if not quiet:
        print_summary(stats, out_dir)
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="pcap/pcapng files or directories")
    ap.add_argument("-o", "--out-dir", default="out", help="output directory (default: out)")
    ap.add_argument("--idle-timeout", type=float, default=120.0,
                    help="seconds of inactivity that end a flow (default: 120)")
    ap.add_argument("--tmp-dir", help="where sort runs are spilled (default: inside out-dir)")
    ap.add_argument("--buffer-rows", type=int, default=500_000,
                    help="rows held in memory per CSV before spilling (default: 500000)")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO,
                        format="%(levelname)s %(message)s")
    run(args.inputs, args.out_dir, args.idle_timeout, args.tmp_dir, args.buffer_rows, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
