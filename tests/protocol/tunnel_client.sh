#!/usr/bin/env bash
# Runs INSIDE the lab's client network namespace (started by run_vpn_tunnel.sh through lab.sh's LAB_CLIENT_CMD).
# Starts pf_vpn, waits for the tunnel, pings the server through it, then lets pf_vpn finish.
# env: PFV OUT HOST_IP PORT TUNNEL_SECONDS (pf_vpn --duration) PF_VPN_EXTRA   exits with pf_vpn's code
set -u
SECS="${TUNNEL_SECONDS:-10}"
"$PFV" --server "$HOST_IP:$PORT" --tls-crypt "$OUT/tc.key" --ca "$OUT/ca.crt" --cert "$OUT/client.crt" --key "$OUT/client.key" \
  --proto "${PF_PROTO:-${PROTO:-udp}}" --dev pfvpn0 --duration "$SECS" --stats-interval 10 ${PF_VPN_EXTRA:-} > "$OUT/pf_vpn.log" 2>&1 &
VPID=$!
for _ in $(seq 1 100); do grep -q "tunnel UP" "$OUT/pf_vpn.log" && break; kill -0 $VPID 2>/dev/null || break; sleep 0.2; done
if grep -q "tunnel UP" "$OUT/pf_vpn.log"; then
  ip -br addr show pfvpn0 > "$OUT/tun_addr.txt" 2>&1
  ping -c 5 -i 0.2 -W 2 10.77.0.1 > "$OUT/ping_small.log" 2>&1                 # first traffic (also checks ARP-less TUN path)
  ping -c 5 -i 0.2 -W 2 -s 1300 10.77.0.1 > "$OUT/ping_large.log" 2>&1          # near-MTU payloads
  REMAIN=$(( SECS - 6 )); [ "$REMAIN" -gt 2 ] && ping -i 0.5 -w "$REMAIN" -s 200 10.77.0.1 > "$OUT/ping_long.log" 2>&1
fi
wait $VPID
echo $? > "$OUT/pf_vpn.exit"
exit "$(cat "$OUT/pf_vpn.exit")"
