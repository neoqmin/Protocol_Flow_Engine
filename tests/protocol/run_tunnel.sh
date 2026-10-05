#!/usr/bin/env bash
# Protocol test (A4): pf_client (UDP socket + real TUN device + control/data plane) against an UNMODIFIED OpenVPN 2.6
# server. The client runs in a network namespace; we ping the server's tunnel address THROUGH the tunnel.
# Needs root (netns, TUN), openvpn, tcpdump, iproute2, ping, openssl. Skips (exit 77) when unavailable.
#   PF_CLIENT=<path to pf_client> tests/protocol/run_tunnel.sh
#
# Scenarios (fresh server and PKI each):
#   ping          tunnel comes up, address/route installed, 20 pings + 1300-byte pings, 0% loss
#   reneg-load    server renegotiates every 2 s while pinging continuously: >= 8 rekeys, key_id wraps 7 -> 1, 0% loss
#   soak          OPT-IN: PF_SOAK_SECONDS=3700 (A4 exit criterion: 1 hour + a renegotiation with the server's DEFAULT
#                 reneg-sec 3600). Pings once a second for the whole time; fails on any loss burst > 5 packets.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
for t in openvpn tcpdump ip openssl ping; do command -v "$t" >/dev/null || { echo "SKIP: $t not installed"; exit 77; }; done
[ -c /dev/net/tun ] || { echo "SKIP: no /dev/net/tun"; exit 77; }
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PFC="${PF_CLIENT:?set PF_CLIENT to the pf_client binary}"
BASE="$(mktemp -d)"
trap 'rm -rf "$BASE"' EXIT
FAILED=0

# scenario <name> <server --reneg-sec> <client seconds> <ping args> <extra server args...>
scenario() {
  local name="$1" reneg="$2" secs="$3" pingargs="$4" OUT="$BASE/$1"; shift 4
  mkdir -p "$OUT"
  echo "=== scenario: $name (server reneg-sec=$reneg, client runs ${secs}s) ==="
  export PF_SECS="$secs" PF_PING_ARGS="$pingargs"
  LAB_RENEG="$reneg" \
  LAB_CLIENT_CMD='$PFC --server $HOST_IP:$PORT --tls-crypt $OUT/tc.key --ca $OUT/ca.crt --cert $OUT/client.crt --key $OUT/client.key --duration $PF_SECS --stats-interval 600 &
    cpid=$!; sleep 3
    echo "--- tunnel state ---"; ip -br addr show | grep -v "^lo"; ip route
    echo "--- ping ---"; ping $PF_PING_ARGS 10.77.0.1; echo "ping exit: $?"
    ping -c 2 -s 1300 -W 1 10.77.0.1 >/dev/null; echo "large ping exit: $?"
    wait $cpid; echo "pf_client exit: $?"' \
    bash "$ROOT/tools/interop/lab.sh" "$OUT" 12 "$@" > "$OUT/lab.out" 2>&1
  local log="$OUT/pf_client.log"
  fail() { echo "FAIL [$name]: $*"; echo "--- client log (tail) ---"; tail -30 "$log" 2>/dev/null; echo "--- server log (tail) ---"; tail -15 "$OUT/server.log" 2>/dev/null; FAILED=1; }

  grep -q "tunnel UP dev=" "$log" || { fail "tunnel never came up"; return; }
  grep -q "pf_client exit: 0" "$log" || { fail "pf_client did not exit cleanly"; return; }
  grep -Eq "10\.77\.0\.2/24" "$log" || { fail "tunnel address not installed on the TUN device"; return; }
  grep -Eq "^10\.88\.0\.0/24 via 10\.77\.0\.1 dev tun[0-9]+" "$log" || { fail "pushed route not installed"; return; }
  grep -Eq "[1-9][0-9]* received" "$log" || { fail "no ping replies through the tunnel"; return; }
  grep -Eq "final: .*tx_failed=0 .*rx_dropped=0 rx_not_ip=0 renegotiations=[0-9]+ reneg_failures=0 unknown_key_id=0" "$log" || { fail "client reported failed tx / rejected rx / failed renegotiations"; return; }
  grep -q "key-derivation tls-ekm" "$OUT/server.log" || { fail "server did not negotiate tls-ekm"; return; }
  if grep -E "pf-client/.*(AEAD Decrypt error|TLS Error|Authenticate/Decrypt packet error|bad packet ID)" "$OUT/server.log"; then fail "server reported errors for our packets"; return; fi

  local loss; loss="$(grep -Eo '[0-9]+% packet loss' "$log" | head -1 | cut -d% -f1)"
  case "$name" in
    ping)        [ "$loss" = 0 ] || fail "ping loss ${loss}%"
                 grep -q "large ping exit: 0" "$log" || fail "large (1300-byte) ping got no reply" ;;
    reneg-load)  [ "$loss" = 0 ] || fail "ping loss ${loss}% during renegotiations"
                 grep -Eq "final: .*renegotiations=([89]|[1-9][0-9]+) " "$log" || fail "fewer than 8 renegotiations"
                 grep -Eq "key_ids=.*,7,1,2" "$log" || fail "key_id did not wrap from 7 back to 1" ;;
    soak)        grep -Eq "final: .*renegotiations=[1-9]" "$log" || fail "no renegotiation during the soak"
                 local sent got; sent="$(grep -Eo '[0-9]+ packets transmitted' "$log" | cut -d' ' -f1)"; got="$(grep -Eo '[0-9]+ received' "$log" | cut -d' ' -f1)"
                 [ -n "$sent" ] && [ $((sent - got)) -le 5 ] || fail "ping loss too high: sent=$sent received=$got" ;;
  esac
  [ "$FAILED" = 0 ] && echo "PASS [$name]"
}

PUSH_ROUTE=(--push "route 10.88.0.0 255.255.255.0")
if [ "${PF_ONLY:-}" != soak ]; then      # PF_ONLY=soak (with PF_SOAK_SECONDS) runs just the long scenario
  scenario ping       3600 10 "-c 20 -i 0.2 -W 1" "${PUSH_ROUTE[@]}"
  scenario reneg-load 2    28 "-c 40 -i 0.5 -W 1" "${PUSH_ROUTE[@]}"
fi
if [ -n "${PF_SOAK_SECONDS:-}" ]; then
  scenario soak 3600 "$PF_SOAK_SECONDS" "-c $((PF_SOAK_SECONDS - 6)) -i 1 -W 1" "${PUSH_ROUTE[@]}"
fi

if [ "$FAILED" = 0 ]; then echo "PASS: tunnel carries real IP traffic through a TUN device to unmodified OpenVPN, across renegotiations"; exit 0; fi
exit 1
