#!/usr/bin/env bash
# Protocol test: pf_connect (our ControlClient + data plane) against an UNMODIFIED OpenVPN 2.6 server.
# Needs root (network namespace, TUN), openvpn, tcpdump, iproute2, openssl. Skips (exit 77) when unavailable.
#   PF_CONNECT=<path to pf_connect> tests/protocol/run_interop.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
for t in openvpn tcpdump ip openssl; do command -v "$t" >/dev/null || { echo "SKIP: $t not installed"; exit 77; }; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PFC="${PF_CONNECT:?set PF_CONNECT to the pf_connect binary}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

LAB_RENEG=3600 LAB_CLIENT_CMD='$PFC --server $HOST_IP:$PORT --tls-crypt $OUT/tc.key --ca $OUT/ca.crt --cert $OUT/client.crt --key $OUT/client.key --timeout 20 --keepalive-seconds 8' \
  bash "$ROOT/tools/interop/lab.sh" "$OUT" 12 > "$OUT/lab.out" 2>&1
cat "$OUT/lab.out"

fail() { echo "FAIL: $*"; echo "--- server log (tail) ---"; tail -25 "$OUT/server.log" 2>/dev/null; exit 1; }

[ "$(cat "$OUT/pf_client.exit" 2>/dev/null)" = "0" ] || fail "pf_connect exit code is not 0"
grep -q "control channel ESTABLISHED" "$OUT/pf_client.log" || fail "control channel was not established"
grep -Eq "keepalive: sent=[1-9][0-9]* tx_failed=0 received_ok=[1-9][0-9]* received_other=[0-9]+ received_bad=0" "$OUT/pf_client.log" || fail "data channel keepalive exchange did not succeed in both directions"
grep -q "ignored_control_messages=0" "$OUT/pf_client.log" || fail "server key-method reply was not consumed exactly (stream misaligned)"
grep -q "key-derivation tls-ekm" "$OUT/server.log" || fail "server did not negotiate tls-ekm"
grep -q "pf-client/.*RECEIVED PING PACKET" "$OUT/server.log" || fail "server never accepted a data packet from us"
if grep -E "pf-client/.*(AEAD Decrypt error|TLS Error|Authenticate/Decrypt packet error|bad packet ID)" "$OUT/server.log"; then fail "server reported errors for our packets"; fi
grep -q "state=Established" "$OUT/pf_client.log" || fail "no Established state transition"
echo "PASS: control + data channel interoperate with unmodified OpenVPN"
