#!/usr/bin/env bash
# A4 protocol test: pf_vpn (UDP + TUN + control + data plane) against an UNMODIFIED OpenVPN 2.6 server.
# Real tunnel traffic: ping through the TUN device in the client namespace to the server's tunnel address.
# Needs root (netns, TUN), openvpn, tcpdump, iproute2, ping, openssl. Skips (77) when unavailable.
#   PF_VPN=<path to pf_vpn> tests/protocol/run_tunnel.sh
# Soak / single scenario (A4 exit criterion is 1 hour, default reneg-sec 3600):
#   TUNNEL_SECONDS=3700 TUNNEL_RENEG=3600 TUNNEL_EXPECT_RENEG=1 PF_VPN=... tests/protocol/run_tunnel.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
for t in openvpn tcpdump ip ping openssl; do command -v "$t" >/dev/null || { echo "SKIP: $t not installed"; exit 77; }; done
[ -c /dev/net/tun ] || { echo "SKIP: no /dev/net/tun"; exit 77; }
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PFV="${PF_VPN:?set PF_VPN to the pf_vpn binary}"
BASE="$(mktemp -d)"
trap 'rm -rf "$BASE"' EXIT
FAILED=0

# scenario <name> <server reneg-sec> <seconds> <min renegotiations> [pf_vpn extra args]
scenario() {
  local name="$1" reneg="$2" secs="$3" min_reneg="$4" extra="${5:-}" OUT="$BASE/$1"
  mkdir -p "$OUT"
  echo "=== scenario: $name (server reneg-sec=$reneg, ${secs}s, >= $min_reneg renegotiations) ==="
  TUNNEL_SECONDS="$secs" PF_VPN_EXTRA="$extra" LAB_RENEG="$reneg" \
  LAB_CLIENT_CMD="bash $ROOT/tests/protocol/tunnel_client.sh" \
    bash "$ROOT/tools/interop/lab.sh" "$OUT" 12 > "$OUT/lab.out" 2>&1
  fail() { echo "FAIL [$name]: $*"; tail -15 "$OUT/pf_vpn.log" 2>/dev/null; echo "--- server log (tail) ---"; tail -15 "$OUT/server.log" 2>/dev/null; FAILED=1; }
  local log="$OUT/pf_vpn.log"

  [ "$(cat "$OUT/pf_vpn.exit" 2>/dev/null)" = "0" ] || { fail "pf_vpn exit code is not 0 ($(cat "$OUT/pf_vpn.exit" 2>/dev/null))"; return; }
  grep -q "tunnel UP" "$log" || { fail "tunnel did not come up"; return; }
  grep -q "10.77.0.2" "$OUT/tun_addr.txt" || { fail "TUN device did not get the pushed address"; return; }
  for p in ping_small ping_large; do
    grep -Eq " 0% packet loss" "$OUT/$p.log" || { fail "$p: packet loss through the tunnel"; cat "$OUT/$p.log"; return; }
  done
  if [ -f "$OUT/ping_long.log" ]; then
    grep -Eq " 0% packet loss" "$OUT/ping_long.log" || { fail "ping_long: packet loss (renegotiation must be seamless)"; tail -5 "$OUT/ping_long.log"; return; }
  fi
  local final; final="$(grep '^final:' "$log")"
  echo "$final"
  echo "$final" | grep -Eq "rx_dropped=0 " || { fail "authenticated-data drops"; return; }
  echo "$final" | grep -Eq "tx_failed=0 " || { fail "TX failures"; return; }
  echo "$final" | grep -Eq "reneg_failures=0 " || { fail "renegotiation failures"; return; }
  local n; n="$(echo "$final" | sed -E 's/.* renegotiations=([0-9]+) .*/\1/')"
  [ "$n" -ge "$min_reneg" ] || { fail "renegotiations=$n < $min_reneg"; return; }
  grep -q "key-derivation tls-ekm" "$OUT/server.log" || { fail "server did not negotiate tls-ekm"; return; }
  if grep -E "pf-client/.*(AEAD Decrypt error|TLS Error|Authenticate/Decrypt packet error|bad packet ID)" "$OUT/server.log"; then fail "server reported errors for our packets"; return; fi
  [ "$FAILED" = 0 ] && echo "PASS [$name]"
}

if [ -n "${TUNNEL_SECONDS:-}" ]; then
  scenario custom "${TUNNEL_RENEG:-3600}" "$TUNNEL_SECONDS" "${TUNNEL_EXPECT_RENEG:-0}"
else
  scenario tunnel       3600 10 0
  scenario tunnel-reneg 3    22 4
fi
if [ "$FAILED" = 0 ]; then echo "PASS: tunnel traffic crosses pf_vpn <-> unmodified OpenVPN (including renegotiations)"; exit 0; fi
exit 1
