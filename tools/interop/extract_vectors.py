#!/usr/bin/env python3
"""Turn a lab capture into DATA_V2 AES-256-GCM golden vectors.

Output line format (tests/regression/golden/data_v2_gcm.golden):
    key_hex(32B) | nonce_tail_hex(8B) | wire_packet_hex | plaintext_hex

The keys are ONE-OFF TEST keys from a throwaway lab run (tools/interop/lab.sh);
they protect nothing. The lab log/pcap themselves are not committed.

Method (no OpenVPN source used): the nonce tail of each (direction, key_id) is
recovered from keepalive packets (known plaintext) exactly as verify_aead.py
does; every packet is then decrypted with AAD = header4 || packet_id4 and only
packets whose GCM tag verifies are emitted.

usage: extract_vectors.py <lab_dir> > data_v2_gcm.golden
"""
import re, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

PING = bytes.fromhex("2a187bf3641eb4cb07ed2d0a981fc748")
lab = sys.argv[1]
out_keys, in_keys = [], []
for line in open(f"{lab}/client.log", errors="replace"):
    m = re.search(r"(Outgoing|Incoming) Data Channel: CIPHER KEY: ((?:[0-9a-f]{8} ?){8})", line)
    if m:
        k = bytes.fromhex(m.group(2).replace(" ", ""))
        (out_keys if m.group(1) == "Outgoing" else in_keys).append(k)

d = open(f"{lab}/capture.pcap", "rb").read()
off, pkts = 24, []
while off + 16 <= len(d):
    _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
    p = d[off:off + cl]; off += cl
    ihl = (p[14] & 0xF) * 4
    src = ".".join(map(str, p[26:30]))
    udp = p[14 + ihl:]; n = struct.unpack(">H", udp[4:6])[0] - 8
    pkts.append((src, udp[8:8 + n]))

def key_for(src, kid):
    ks = out_keys if src == "10.99.0.2" else in_keys
    return ks[kid] if kid < len(ks) else None

tails = {}
for src, pl in pkts:
    if pl[0] >> 3 != 9 or len(pl) != 40: continue          # keepalive: 16-byte ciphertext
    kid = pl[0] & 7; key = key_for(src, kid)
    if key is None or (src, kid) in tails: continue
    ks = bytes(a ^ b for a, b in zip(pl[24:], PING))
    cb = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(ks)
    if cb[12:] == b"\x00\x00\x00\x02" and cb[:4] == pl[4:8]:
        tails[(src, kid)] = cb[4:12]

print("# DATA_V2 AES-256-GCM golden vectors from unmodified OpenVPN 2.6.19 (tools/interop/extract_vectors.py)")
print("# TEST-ONLY one-off keys from a throwaway lab run. Format:")
print("# key_hex | nonce_tail_hex | wire_packet_hex | plaintext_hex")
n = 0
for src, pl in pkts:
    if pl[0] >> 3 != 9 or len(pl) < 24: continue
    kid = pl[0] & 7; key = key_for(src, kid); tail = tails.get((src, kid))
    if key is None or tail is None: continue
    nonce = pl[4:8] + tail
    try:
        pt = AESGCM(key).decrypt(nonce, pl[24:] + pl[8:24], pl[:8])
    except InvalidTag:
        continue
    print(f"{key.hex()} | {tail.hex()} | {pl.hex()} | {pt.hex()}"); n += 1
print(f"{n} vectors", file=sys.stderr)
