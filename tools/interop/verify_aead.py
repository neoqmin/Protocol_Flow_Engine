#!/usr/bin/env python3
"""Independent check of the OpenVPN 2.6 DATA_V2 AES-256-GCM layout using a lab capture.

Reads capture.pcap + client.log from tools/interop/lab.sh (verb 7 log prints the
TEST session cipher keys). Does NOT use any OpenVPN source code; it only
observes the unmodified binaries' wire output.

For every keepalive packet (plaintext = the fixed 16-byte ping pattern) it
recovers the GCM counter block (nonce || 00000002) by inverting AES on the
keystream, then reports how the 12-byte nonce relates to the on-wire packet-id,
and finally checks AEAD decryption with candidate AAD choices.

usage: verify_aead.py <lab_dir>
Requires: pip install cryptography
"""
import re, struct, sys, collections
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

PING = bytes.fromhex("2a187bf3641eb4cb07ed2d0a981f c748".replace(" ", ""))

lab = sys.argv[1]
# --- keys from client log: pairs (outgoing, incoming) per key generation -------
out_keys, in_keys = [], []
for line in open(f"{lab}/client.log", errors="replace"):
    m = re.search(r"(Outgoing|Incoming) Data Channel: CIPHER KEY: ((?:[0-9a-f]{8} ?){8})", line)
    if m:
        k = bytes.fromhex(m.group(2).replace(" ", ""))
        (out_keys if m.group(1) == "Outgoing" else in_keys).append(k)
print(f"key generations in log: {len(out_keys)} out / {len(in_keys)} in")

# --- pcap ------------------------------------------------------------------------
d = open(f"{lab}/capture.pcap", "rb").read()
off, pkts = 24, []
while off + 16 <= len(d):
    _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
    p = d[off:off + cl]; off += cl
    ihl = (p[14] & 0xF) * 4
    src = ".".join(map(str, p[26:30]))
    udp = p[14 + ihl:]; n = struct.unpack(">H", udp[4:6])[0] - 8
    pkts.append((src, udp[8:8 + n]))

client_ip = "10.99.0.2"
stats = collections.Counter()
rows = []
for src, pl in pkts:
    if pl[0] >> 3 != 9 or len(pl) < 24 + 1:
        continue
    kid = pl[0] & 7
    if kid >= len(out_keys):
        stats["no_key_for_kid"] += 1; continue
    key = out_keys[kid] if src == client_ip else in_keys[kid]
    hdr, pid, tag, ct = pl[:4], pl[4:8], pl[8:24], pl[24:]
    stats["data_v2"] += 1
    if len(ct) == 16:  # keepalive: known plaintext
        ks = bytes(a ^ b for a, b in zip(ct, PING))
        cb = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(ks)
        nonce, ctr = cb[:12], cb[12:]
        stats["keepalive"] += 1
        stats["counter_is_2"] += (ctr == b"\x00\x00\x00\x02")
        rows.append((src, kid, pid, nonce))
        # AEAD decrypt with candidate AADs (tag precedes ciphertext on the wire)
        for name, aad in (("hdr4+pid4", hdr + pid), ("pid4_only", pid), ("hdr4_only", hdr), ("none", b"")):
            try:
                pt = AESGCM(key).decrypt(nonce, ct + tag, aad)
                stats[f"aad_ok:{name}"] += (pt == PING)
            except InvalidTag:
                stats[f"aad_fail:{name}"] += 1

print(dict(stats))
# Nonce structure: concatenation => nonce[:4]==packet_id and nonce[4:] constant per (direction,key).
tails = collections.defaultdict(set); concat = xor_like = 0
for src, kid, pid, nonce in rows:
    tails[(src, kid)].add(nonce[4:])
    concat += (nonce[:4] == pid)
print(f"keepalives analysed: {len(rows)}; nonce[:4]==packet_id in {concat}")
for k, v in sorted(tails.items()):
    print(f"  dir={k[0]} key_id={k[1]}: distinct nonce[4:12] values = {len(v)}")
