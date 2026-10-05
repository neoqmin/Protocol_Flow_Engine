#!/usr/bin/env bash
# Protocol test: pf_connect (our ControlClient + data plane + keepalive + renegotiation) against an UNMODIFIED
# OpenVPN 2.6 server. Needs root (network namespace, TUN), openvpn, tcpdump, iproute2, openssl.
# Skips (exit 77) when unavailable.     PF_CONNECT=<path to pf_connect> tests/protocol/run_interop.sh
#
# Scenarios (each with a fresh server and PKI):
#   baseline      no renegotiation; keepalive pings both ways
#   server-reneg  server renegotiates every 2 s: 8+ rekeys, key_id wraps 7 -> 1, data keeps flowing
#   client-reneg  server never rekeys; WE start renegotiations every 4 s
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
for t in openvpn tcpdump ip openssl; do command -v "$t" >/dev/null || { echo "SKIP: $t not installed"; exit 77; }; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PFC="${PF_CONNECT:?set PF_CONNECT to the pf_connect binary}"
BASE="$(mktemp -d)"
trap 'rm -rf "$BASE"' EXIT
FAILED=0

# scenario <name> <server --reneg-sec> <pf_connect extra args>
scenario() {
  local name="$1" reneg="$2" extra="$3" OUT="$BASE/$1"
  mkdir -p "$OUT"
  echo "=== scenario: $name (server reneg-sec=$reneg, pf_connect args: $extra) ==="
  LAB_RENEG="$reneg" \
  LAB_CLIENT_CMD='$PFC --server $HOST_IP:$PORT --tls-crypt $OUT/tc.key --ca $OUT/ca.crt --cert $OUT/client.crt --key $OUT/client.key --timeout 20 '"$extra" \
    bash "$ROOT/tools/interop/lab.sh" "$OUT" 12 > "$OUT/lab.out" 2>&1
  cat "$OUT/lab.out"
  fail() { echo "FAIL [$name]: $*"; echo "--- server log (tail) ---"; tail -25 "$OUT/server.log" 2>/dev/null; FAILED=1; }
  local log="$OUT/pf_client.log"

  [ "$(cat "$OUT/pf_client.exit" 2>/dev/null)" = "0" ] || { fail "pf_connect exit code is not 0"; return; }
  grep -q "control channel ESTABLISHED" "$log" || { fail "control channel was not established"; return; }
  grep -q "ignored_control_messages=0" "$log" || { fail "server key-method reply was not consumed exactly (stream misaligned)"; return; }
  grep -Eq "keepalive: sent=[1-9][0-9]* tx_failed=0 received_ok=[1-9][0-9]* received_other=[0-9]+ received_bad=0" "$log" || { fail "data channel keepalive exchange did not succeed in both directions"; return; }
  grep -q "key-derivation tls-ekm" "$OUT/server.log" || { fail "server did not negotiate tls-ekm"; return; }
  grep -q "pf-client/.*RECEIVED PING PACKET" "$OUT/server.log" || { fail "server never accepted a data packet from us"; return; }
  if grep -E "pf-client/.*(AEAD Decrypt error|TLS Error|Authenticate/Decrypt packet error|bad packet ID)" "$OUT/server.log"; then fail "server reported errors for our packets"; return; fi
  grep -Eq "reneg_failures=0 unknown_key_id=0" "$log" || { fail "renegotiation failures or unknown key ids"; return; }

  case "$name" in
    baseline)     grep -Eq "renegotiations=0 " "$log" || fail "unexpected renegotiation" ;;
    server-reneg) grep -Eq "renegotiations=([89]|[1-9][0-9]+) " "$log" || fail "fewer than 8 renegotiations"
                  grep -Eq "key_ids=.*,7,1,2" "$log" || fail "key_id did not wrap from 7 back to 1" ;;
    client-reneg) grep -Eq "renegotiations=([2-9]|[1-9][0-9]+) " "$log" || fail "fewer than 2 client-initiated renegotiations" ;;
  esac
  [ "$FAILED" = 0 ] && echo "PASS [$name]"
}

scenario baseline     3600 "--keepalive-seconds 8"
scenario server-reneg 2    "--keepalive-seconds 24"
scenario client-reneg 3600 "--keepalive-seconds 14 --reneg-seconds 4"

if [ "$FAILED" = 0 ]; then echo "PASS: control + data channel, keepalive and renegotiation interoperate with unmodified OpenVPN"; exit 0; fi
exit 1
