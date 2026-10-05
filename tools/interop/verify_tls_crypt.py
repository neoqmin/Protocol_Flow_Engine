#!/usr/bin/env python3
"""Independent check of the OpenVPN 2.6 tls-crypt wire format and key layout.

Hypothesis (from the public tls-crypt design: SIV construction):
    wire  = opcode(1) | session_id(8) | packet_id(4) | net_time(4) | tag(32) | ciphertext
    tag   = HMAC-SHA256(Ka, wire[0:17] || plaintext)
    iv    = tag[0:16];  ciphertext = AES-256-CTR(Ke, iv, plaintext)
The static key file holds 4 x 64 bytes. This tool tries every (Ke block, Ka block)
pair per direction and reports which pairs make the tag VERIFY on real packets.
(Verifying an HMAC under a candidate key is unambiguous evidence.)

usage: verify_tls_crypt.py <lab_dir>      (needs tc.key and capture.pcap from lab.sh)
Requires: pip install cryptography
"""
import re, struct, sys, collections, hmac, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

lab = sys.argv[1]
text = open(f"{lab}/tc.key").read()
hexs = re.search(r"BEGIN OpenVPN Static key V1-----(.*?)-----END", text, re.S).group(1)
key = bytes.fromhex("".join(hexs.split()))
assert len(key) == 256, len(key)
blocks = [key[i * 64:(i + 1) * 64] for i in range(4)]

d = open(f"{lab}/capture.pcap", "rb").read()
off, pkts = 24, []
while off + 16 <= len(d):
    _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
    p = d[off:off + cl]; off += cl
    ihl = (p[14] & 0xF) * 4
    src = ".".join(map(str, p[26:30]))
    udp = p[14 + ihl:]; n = struct.unpack(">H", udp[4:6])[0] - 8
    pkts.append((src, udp[8:8 + n]))

def try_pair(pl, ke, ka):
    if len(pl) < 17 + 32: return None
    hdr, tag, ct = pl[:17], pl[17:49], pl[49:]
    pt = Cipher(algorithms.AES(ke), modes.CTR(tag[:16])).decryptor().update(ct)
    return pt if hmac.compare_digest(hmac.new(ka, hdr + pt, hashlib.sha256).digest(), tag) else None

ok = collections.defaultdict(list)       # (direction) -> list of (idx, ke_blk, ka_blk, opcode)
total = collections.Counter(); verified = collections.Counter()
for idx, (src, pl) in enumerate(pkts):
    op = pl[0] >> 3
    if op == 9: continue                  # data channel: not tls-crypt
    dirn = "c2s" if src == "10.99.0.2" else "s2c"
    total[dirn] += 1
    hit = False
    for i in range(4):
        for j in range(4):
            if try_pair(pl, blocks[i][:32], blocks[j][:32]) is not None:
                ok[dirn].append((idx, i, j, op)); hit = True
    verified[dirn] += hit
print("control packets:", dict(total), " verified with static key:", dict(verified))
for dirn in ("c2s", "s2c"):
    pairs = collections.Counter((i, j) for _, i, j, _ in ok[dirn])
    print(f"{dirn}: (Ke block, Ka block) -> #packets verified: {dict(pairs)}")
unv = [(i, pkts[i][0], pkts[i][1][0] >> 3) for i in range(len(pkts))
       if pkts[i][1][0] >> 3 != 9 and not any(i == x[0] for k in ok for x in ok[k])]
print("control packets NOT verified with the static key (idx, src, opcode):", unv[:8], "... total", len(unv))
if ok["c2s"]:
    idx = ok["c2s"][0][0]; src, pl = pkts[idx]
    pt = try_pair(pl, blocks[ok["c2s"][0][1]][:32], blocks[ok["c2s"][0][2]][:32])
    print(f"first verified packet #{idx}: opcode={pl[0]>>3} key_id={pl[0]&7} session_id={pl[1:9].hex()} "
          f"packet_id={int.from_bytes(pl[9:13],'big')} net_time={int.from_bytes(pl[13:17],'big')} plaintext={pt.hex()}")
