"""Hand-built packets for the tests (no external capture files needed)."""

from __future__ import annotations

import socket
import struct

import dpkt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sni import quic_v1_client_initial_keys

MAC_A, MAC_B = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


def ip4(s): return socket.inet_pton(socket.AF_INET, s)
def ip6(s): return socket.inet_pton(socket.AF_INET6, s)


def eth(payload: bytes, etype: int, vlans=()) -> bytes:
    tags = b"".join(struct.pack("!HH", 0x8100, v) for v in vlans)
    if vlans:
        return MAC_B + MAC_A + tags[:2] + tags[2:] + struct.pack("!H", etype) + payload
    return MAC_B + MAC_A + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, ident=1, ttl=64, tos=0, flags=0b010, frag_off=0,
         options=b"") -> bytes:
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, tos, total, ident,
                      (flags << 13) | frag_off, ttl, proto, 0xBEEF, ip4(src), ip4(dst))
    return hdr + options + payload


def ipv6(src, dst, nh, payload, tc=0, flow_label=0, hlim=64) -> bytes:
    first = (6 << 28) | (tc << 20) | flow_label
    return struct.pack("!IHBB16s16s", first, len(payload), nh, hlim, ip6(src), ip6(dst)) + payload


def tcp(sport, dport, seq, ack, flags, payload=b"", window=64240, options=b"") -> bytes:
    options += b"\x00" * (-len(options) % 4)
    off = 5 + len(options) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, window,
                       0x1234, 0) + options + payload


def udp(sport, dport, payload) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0xABCD) + payload


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04
SYN_OPTS = (b"\x02\x04\x05\xb4"            # MSS 1460
            b"\x04\x02"                    # SACK permitted
            b"\x08\x0a\x00\x00\x00\x7b\x00\x00\x00\x00"  # TS 123:0
            b"\x01"                        # NOP
            b"\x03\x03\x07")               # WS 7


# ------------------------------------------------------------------- TLS
def client_hello(sni: str | None, pad: int = 0) -> bytes:
    """A TLS handshake message (type 1) carrying ``sni``; ``pad`` adds a padding ext."""
    exts = b""
    if sni is not None:
        name = sni.encode()
        entry = struct.pack("!BH", 0, len(name)) + name
        lst = struct.pack("!H", len(entry)) + entry
        exts += struct.pack("!HH", 0, len(lst)) + lst
    if pad:
        exts += struct.pack("!HH", 21, pad) + b"\x00" * pad
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def tls_records(handshake: bytes, record_size: int = 16384) -> bytes:
    out = b""
    for i in range(0, len(handshake), record_size):
        chunk = handshake[i:i + record_size]
        out += b"\x16\x03\x01" + struct.pack("!H", len(chunk)) + chunk
    return out


# ------------------------------------------------------------------ QUIC
RFC9001_CLIENT_INITIAL = bytes.fromhex("""
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934""".replace(" ", "").replace("\n", ""))


def _vi(v: int) -> bytes:
    """2-byte QUIC varint (enough for test sizes)."""
    return struct.pack("!H", 0x4000 | v) if v >= 64 else bytes([v])


def crypto_frame(offset: int, data: bytes) -> bytes:
    return b"\x06" + _vi(offset) + _vi(len(data)) + data


def quic_initial(dcid: bytes, frames: bytes, pn: int = 0, scid: bytes = b"\xaa" * 8,
                 pad_to: int = 1200) -> bytes:
    """Build a protected client Initial packet (the inverse of sni.decrypt_initial)."""
    key, iv, hp = quic_v1_client_initial_keys(dcid)
    pn_len = 4
    head_len = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2  # token len 0, 2-byte length
    frames += b"\x00" * max(0, pad_to - head_len - pn_len - 16 - len(frames))
    length = pn_len + len(frames) + 16
    pn_bytes = pn.to_bytes(pn_len, "big")
    header = (bytes([0xC0 | (pn_len - 1)]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid
              + bytes([len(scid)]) + scid + b"\x00" + struct.pack("!H", 0x4000 | length)
              + pn_bytes)
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    ct = AESGCM(key).encrypt(nonce, frames, header)
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(ct[4 - pn_len:20 - pn_len])
    prot = bytearray(header + ct)
    prot[0] ^= mask[0] & 0x0F
    pn_off = len(header) - pn_len
    for k in range(pn_len):
        prot[pn_off + k] ^= mask[1 + k]
    return bytes(prot)


# ------------------------------------------------------------------ files
def write_pcap(path, frames, linktype=dpkt.pcap.DLT_EN10MB, ng=False):
    """frames: iterable of (ts, bytes)."""
    with open(path, "wb") as fh:
        w = (dpkt.pcapng.Writer(fh, linktype=linktype) if ng
             else dpkt.pcap.Writer(fh, linktype=linktype))
        for ts, buf in frames:
            w.writepkt(buf, ts=ts)
