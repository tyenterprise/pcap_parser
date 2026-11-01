"""SNI extraction from TLS-over-TCP and QUIC v1 Initial packets."""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from headers import TCP_SYN

MAX_HANDSHAKE_BYTES = 64 * 1024   # stop buffering a flow after this much data
MAX_SEGMENTS = 64
MAX_QUIC_FAILED_DECRYPTS = 32


def normalize_sni(name: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    return name or None


# ------------------------------------------------------------- ClientHello
def sni_from_client_hello(body: bytes) -> str | None:
    """Return the host_name in a ClientHello body (after the 4-byte handshake header).

    Raises ValueError/IndexError/struct.error on malformed input.
    """
    p = 34  # legacy_version(2) + random(32)
    if len(body) < p + 1:
        raise ValueError("short ClientHello")
    p += 1 + body[p]                                        # session_id
    p += 2 + struct.unpack_from("!H", body, p)[0]           # cipher_suites
    p += 1 + body[p]                                        # compression
    if p + 2 > len(body):
        return None                                         # no extensions
    end = min(p + 2 + struct.unpack_from("!H", body, p)[0], len(body))
    p += 2
    while p + 4 <= end:
        etype, elen = struct.unpack_from("!HH", body, p)
        data = body[p + 4:p + 4 + elen]
        p += 4 + elen
        if etype != 0:
            continue
        q = 2  # server_name_list length
        while q + 3 <= len(data):
            ntype = data[q]
            nlen = struct.unpack_from("!H", data, q + 1)[0]
            name = data[q + 3:q + 3 + nlen]
            q += 3 + nlen
            if ntype == 0:
                return normalize_sni(name.decode("ascii", errors="replace"))
    return None


NEED_MORE, NOT_TLS, OK = "need_more", "not_tls", "ok"


def client_hello_from_tls_stream(stream: bytes) -> tuple[str, bytes | None]:
    """Collect a ClientHello handshake message from TLS records.

    The handshake message may span several records and the records may span
    several TCP segments.  Returns (status, ClientHello body).
    """
    if stream and stream[0] != 0x16:
        return NOT_TLS, None
    if len(stream) >= 3 and (stream[1] != 0x03 or stream[2] > 0x04):
        return NOT_TLS, None
    hs = bytearray()
    i = 0
    while len(stream) - i >= 5:
        ctype, vmaj, vmin = stream[i], stream[i + 1], stream[i + 2]
        rlen = struct.unpack_from("!H", stream, i + 3)[0]
        if ctype != 0x16 or vmaj != 0x03 or vmin > 0x04 or rlen == 0 or rlen > 18432:
            return NOT_TLS, None
        hs += stream[i + 5:i + 5 + rlen]
        i += 5 + rlen
        if len(hs) >= 4:
            if hs[0] != 1:  # not a ClientHello (e.g. ServerHello)
                return NOT_TLS, None
            mlen = int.from_bytes(hs[1:4], "big")
            if mlen > 1 << 18:
                return NOT_TLS, None
            if len(hs) >= 4 + mlen:
                return OK, bytes(hs[4:4 + mlen])
    return NEED_MORE, None


class TcpSniExtractor:
    """Reassembles one direction of a TCP flow until a ClientHello is complete."""

    __slots__ = ("base", "segs", "total", "done")

    def __init__(self):
        self.base = None    # absolute seq of stream byte 0
        self.segs: dict[int, tuple[bytes, int]] = {}  # rel offset -> (data, pkt_idx)
        self.total = 0
        self.done = False

    def feed(self, seq: int | None, flags: int, payload: bytes, pkt_idx: int):
        """Return (pkt_idx where the ClientHello starts, sni) once found, else None."""
        if self.done or seq is None:
            return None
        if flags & TCP_SYN:
            self.base = (seq + 1) & 0xFFFFFFFF  # data (incl. TCP Fast Open) starts at ISN+1
            if not payload:
                return None
            seq = self.base
        if not payload:
            return None
        if self.base is None:
            self.base = seq   # capture started mid-handshake: first data is byte 0
        rel = (seq - self.base) & 0xFFFFFFFF
        if rel >= 1 << 31:    # before the stream start (e.g. old retransmission)
            return None
        if rel > MAX_HANDSHAKE_BYTES:
            self.done = True
            return None
        self.segs.setdefault(rel, (payload, pkt_idx))
        self.total += len(payload)

        stream, first_idx = self._assemble()
        status, body = client_hello_from_tls_stream(stream) if stream else (NEED_MORE, None)
        if status == NEED_MORE:
            if self.total > MAX_HANDSHAKE_BYTES or len(self.segs) > MAX_SEGMENTS:
                self._finish()
            return None
        self._finish()
        if status == OK:
            try:
                sni = sni_from_client_hello(body)
            except (ValueError, IndexError, struct.error):
                return None
            if sni:
                return first_idx, sni
        return None

    def _finish(self):
        self.done = True
        self.segs = {}

    def _assemble(self) -> tuple[bytes, int]:
        if 0 not in self.segs:
            return b"", -1
        out = bytearray()
        for off in sorted(self.segs):
            if off > len(out):
                break  # gap: wait for the missing segment
            data = self.segs[off][0]
            if off + len(data) > len(out):
                out += data[len(out) - off:]
        return bytes(out), self.segs[0][1]


# --------------------------------------------------------------------- QUIC
QUIC_V1 = 0x00000001
QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def quic_v1_client_initial_keys(dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """(key, iv, hp) protecting client Initial packets (RFC 9001 section 5.2)."""
    initial = _hkdf_extract(QUIC_V1_SALT, dcid)
    client = _hkdf_expand_label(initial, "client in", 32)
    return (_hkdf_expand_label(client, "quic key", 16),
            _hkdf_expand_label(client, "quic iv", 12),
            _hkdf_expand_label(client, "quic hp", 16))


def _varint(b: bytes, i: int) -> tuple[int, int]:
    first = b[i]
    n = 1 << (first >> 6)
    if i + n > len(b):
        raise IndexError("varint past end")
    v = first & 0x3F
    for j in range(1, n):
        v = (v << 8) | b[i + j]
    return v, i + n


def iter_long_headers(dg: bytes):
    """Yield (start, version, type, dcid, pn_offset, end) per coalesced long-header packet."""
    p = 0
    while p < len(dg) and dg[p] & 0x80:
        if p + 7 > len(dg):
            return
        b0 = dg[p]
        version = struct.unpack_from("!I", dg, p + 1)[0]
        if version == 0:  # version negotiation
            return
        q = p + 5
        dcil = dg[q]
        dcid = bytes(dg[q + 1:q + 1 + dcil])
        q += 1 + dcil
        if q >= len(dg):
            return
        q += 1 + dg[q]  # scid
        ptype = (b0 >> 4) & 0x03
        if version == QUIC_V1 and ptype == 3:  # Retry has no Length field
            return
        if version == QUIC_V1 and ptype == 0:
            toklen, q = _varint(dg, q)
            q += toklen
        if q >= len(dg):
            return
        length, q = _varint(dg, q)
        yield p, version, ptype, dcid, q, q + length
        p = q + length


def decrypt_initial(dg: bytes, start: int, pn_off: int, end: int,
                    keys: tuple[bytes, bytes, bytes]) -> bytes | None:
    """Remove header protection and decrypt one Initial packet (None if keys don't fit)."""
    key, iv, hp = keys
    if pn_off + 20 > len(dg) or end > len(dg):
        return None
    sample = bytes(dg[pn_off + 4:pn_off + 20])
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    b0 = dg[start] ^ (mask[0] & 0x0F)
    pn_len = (b0 & 0x03) + 1
    pn_bytes = bytes(dg[pn_off + k] ^ mask[1 + k] for k in range(pn_len))
    header = bytes([b0]) + bytes(dg[start + 1:pn_off]) + pn_bytes
    nonce = (int.from_bytes(iv, "big") ^ int.from_bytes(pn_bytes, "big")).to_bytes(12, "big")
    try:
        return AESGCM(key).decrypt(nonce, bytes(dg[pn_off + pn_len:end]), header)
    except InvalidTag:
        return None


def iter_crypto_frames(pt: bytes):
    """Yield (offset, data) for every CRYPTO frame in a decrypted Initial payload."""
    i = 0
    while i < len(pt):
        t = pt[i]
        if t in (0x00, 0x01):           # PADDING, PING
            i += 1
        elif t in (0x02, 0x03):         # ACK
            i += 1
            _, i = _varint(pt, i)       # largest acknowledged
            _, i = _varint(pt, i)       # ack delay
            count, i = _varint(pt, i)
            _, i = _varint(pt, i)       # first range
            for _ in range(count):
                _, i = _varint(pt, i)
                _, i = _varint(pt, i)
            if t == 0x03:
                for _ in range(3):
                    _, i = _varint(pt, i)
        elif t == 0x06:                 # CRYPTO
            off, i = _varint(pt, i + 1)
            ln, i = _varint(pt, i)
            yield off, pt[i:i + ln]
            i += ln
        elif t in (0x1C, 0x1D):         # CONNECTION_CLOSE
            _, i = _varint(pt, i + 1)
            if t == 0x1C:
                _, i = _varint(pt, i)
            rl, i = _varint(pt, i)
            i += rl
        else:
            return  # no other frame types are allowed in Initial packets


class _QuicConn:
    __slots__ = ("crypto", "first_idx", "done")

    def __init__(self):
        self.crypto: dict[int, bytes] = {}
        self.first_idx = None  # packet carrying CRYPTO offset 0
        self.done = False


class QuicSniExtractor:
    """Finds ClientHellos in the client Initial packets of one UDP flow.

    One UDP 5-tuple can carry several QUIC connections, so CRYPTO streams
    are tracked per original destination connection ID.
    """

    __slots__ = ("conns", "keys", "failed", "done")

    def __init__(self):
        self.conns: dict[bytes, _QuicConn] = {}
        self.keys: dict[bytes, tuple] = {}
        self.failed = 0
        self.done = False

    def feed(self, payload: bytes, pkt_idx: int) -> list[tuple[int, str]]:
        if self.done or not payload or not payload[0] & 0x80:
            return []
        events = []
        try:
            headers = list(iter_long_headers(payload))
        except IndexError:
            return []
        for start, version, ptype, dcid, pn_off, end in headers:
            if version != QUIC_V1 or ptype != 0 or not dcid:
                continue
            conn = self.conns.get(dcid)
            if conn is not None and conn.done:
                continue
            keys = self.keys.get(dcid)
            if keys is None:
                keys = self.keys[dcid] = quic_v1_client_initial_keys(dcid)
            plain = decrypt_initial(payload, start, pn_off, end, keys)
            if plain is None:  # e.g. a server Initial: not our keys
                self.failed += 1
                if self.failed >= MAX_QUIC_FAILED_DECRYPTS:
                    self.done = True
                continue
            if conn is None:
                conn = self.conns[dcid] = _QuicConn()
            try:
                for off, data in iter_crypto_frames(plain):
                    if off == 0 and conn.first_idx is None:
                        conn.first_idx = pkt_idx
                    if off <= MAX_HANDSHAKE_BYTES:
                        conn.crypto.setdefault(off, data)
            except IndexError:
                pass
            sni = self._try_client_hello(conn)
            if sni:
                events.append((conn.first_idx, sni))
        return events

    @staticmethod
    def _try_client_hello(conn: _QuicConn) -> str | None:
        if 0 not in conn.crypto:
            return None
        out = bytearray()
        for off in sorted(conn.crypto):
            if off > len(out):
                break
            data = conn.crypto[off]
            if off + len(data) > len(out):
                out += data[len(out) - off:]
        if len(out) < 4:
            return None
        if out[0] != 1:
            conn.done = True
            return None
        mlen = int.from_bytes(out[1:4], "big")
        if len(out) < 4 + mlen:
            if len(out) > MAX_HANDSHAKE_BYTES:
                conn.done = True
            return None
        conn.done = True
        conn.crypto = {}
        try:
            return sni_from_client_hello(bytes(out[4:4 + mlen]))
        except (ValueError, IndexError, struct.error):
            return None
