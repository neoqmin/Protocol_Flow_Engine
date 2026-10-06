#!/usr/bin/env bash
# Throughput baseline through the tunnel: OUR client (pf_client) vs the STOCK OpenVPN 2.6 client, same unmodified
# OpenVPN server, same host (lab.sh netns + veth). iperf3 TCP (client->server and reverse) and UDP.
# Needs root, openvpn, iperf3, iproute2. Informational numbers only (shared VM, loopback-like link):
# compare the two clients with each other, not with real networks.
#   PF_CLIENT=build-rel/pf_client tools/interop/bench_tunnel.sh [seconds_per_test=8]
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "needs root"; exit 77; }
for t in openvpn iperf3 ip; do command -v "$t" >/dev/null || { echo "missing $t"; exit 77; }; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PFV="${PF_CLIENT:?set PF_CLIENT}"
T="${1:-8}"
BASE="$(mktemp -d)"; trap 'rm -rf "$BASE"; pkill iperf3 2>/dev/null' EXIT

run() {  # run <name> <client script>
  local name="$1" OUT="$BASE/$1"; mkdir -p "$OUT"
  ( until ip addr show pfs0 2>/dev/null | grep -q 10.77.0.1; do sleep 0.2; done; iperf3 -s -B 10.77.0.1 -D >/dev/null 2>&1 ) &
  BENCH_T="$T" LAB_RENEG=3600 LAB_CLIENT_CMD="bash $2" bash "$ROOT/tools/interop/lab.sh" "$OUT" 5 --verb 3 > "$OUT/lab.out" 2>&1
  pkill iperf3 2>/dev/null; wait 2>/dev/null
  echo "--- $name ---"; grep -E "^(TCP_UP|TCP_DOWN|UDP)" "$OUT/results.txt" 2>/dev/null || { echo "no results"; tail -5 "$OUT/lab.out"; }
}

cat > "$BASE/measure.sh" <<'M'
# sourced inside the client namespace once the tunnel is up
r="$OUT/results.txt"
mbps() { python3 -c "import json,sys; d=json.load(sys.stdin)['end']; s=d.get('sum_received') or d.get('sum'); print(round(s['bits_per_second']/1e6,1))"; }
echo "TCP_UP   Mbit/s: $(iperf3 -c 10.77.0.1 -t "$BENCH_T" -J | mbps)" >> "$r"
echo "TCP_DOWN Mbit/s: $(iperf3 -c 10.77.0.1 -t "$BENCH_T" -R -J | mbps)" >> "$r"
echo "UDP      Mbit/s (1G offered, 1200B): $(iperf3 -c 10.77.0.1 -u -b 1G -l 1200 -t "$BENCH_T" -J | mbps)" >> "$r"
M
cat > "$BASE/pf.sh" <<'M'
"$PFV" --server "$HOST_IP:$PORT" --tls-crypt "$OUT/tc.key" --ca "$OUT/ca.crt" --cert "$OUT/client.crt" --key "$OUT/client.key" --tun-name pfvpn0 > "$OUT/pf_client.log" 2>&1 &
V=$!
for _ in $(seq 1 100); do grep -q "tunnel UP" "$OUT/pf_client.log" && break; sleep 0.2; done
sleep 1
M
echo 'source '"$BASE"'/measure.sh; kill $V; wait $V 2>/dev/null' >> "$BASE/pf.sh"
cat > "$BASE/ovpn.sh" <<M
openvpn --client --dev pfc0 --dev-type tun --proto udp --remote \$HOST_IP \$PORT --nobind --cipher AES-256-GCM --data-ciphers AES-256-GCM \\
  --tls-crypt \$OUT/tc.key --ca \$OUT/ca.crt --cert \$OUT/client.crt --key \$OUT/client.key --tls-version-min 1.3 \\
  --remote-cert-tls server --verb 3 --keepalive 2 8 --disable-dco --reneg-sec 3600 > \$OUT/ovpn_client.log 2>&1 &
V=\$!
for _ in \$(seq 1 100); do ip -br addr show pfc0 2>/dev/null | grep -q 10.77.0 && break; sleep 0.2; done
sleep 1
source $BASE/measure.sh; kill \$V; wait \$V 2>/dev/null
M
run pf_client "$BASE/pf.sh"
run openvpn_stock "$BASE/ovpn.sh"
