#!/usr/bin/env python3
"""Turn a lab capture into tls-crypt golden vectors (tests/regression/golden/tls_crypt.golden).

Line format:   direction | static_key_hex(256B) | wire_hex | plaintext_hex
direction = c2s (client->server) or s2c. Only packets whose HMAC tag VERIFIES are emitted.
The static key is a ONE-OFF TEST key from a throwaway lab run (tools/interop/lab.sh).

usage: extract_tls_crypt_vectors.py <lab_dir> > tls_crypt.golden
"""
import re, struct, sys, hmac, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

lab = sys.argv[1]
text = open(f"{lab}/tc.key").read()
key = bytes.fromhex("".join(re.search(r"BEGIN OpenVPN Static key V1-----(.*?)-----END", text, re.S).group(1).split()))
K = [key[i * 64:(i + 1) * 64] for i in range(4)]
KEYS = {"c2s": (K[2][:32], K[3][:32]), "s2c": (K[0][:32], K[1][:32])}   # (Ke, Ka)

d = open(f"{lab}/capture.pcap", "rb").read()
off, n = 24, 0
print("# tls-crypt golden vectors from unmodified OpenVPN 2.6.19 (tools/interop/extract_tls_crypt_vectors.py)")
print("# TEST-ONLY one-off static key from a throwaway lab run. Format:")
print("# direction | static_key_hex | wire_hex | plaintext_hex")
while off + 16 <= len(d):
    _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
    p = d[off:off + cl]; off += cl
    ihl = (p[14] & 0xF) * 4
    src = ".".join(map(str, p[26:30]))
    udp = p[14 + ihl:]; ln = struct.unpack(">H", udp[4:6])[0] - 8
    pl = udp[8:8 + ln]
    if pl[0] >> 3 == 9 or len(pl) < 49: continue
    dirn = "c2s" if src == "10.99.0.2" else "s2c"
    ke, ka = KEYS[dirn]
    tag, ct = pl[17:49], pl[49:]
    pt = Cipher(algorithms.AES(ke), modes.CTR(tag[:16])).decryptor().update(ct)
    if not hmac.compare_digest(hmac.new(ka, pl[:17] + pt, hashlib.sha256).digest(), tag): continue
    print(f"{dirn} | {key.hex()} | {pl.hex()} | {pt.hex()}"); n += 1
print(f"{n} vectors", file=sys.stderr)
