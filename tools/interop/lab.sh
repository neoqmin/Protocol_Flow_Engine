#!/usr/bin/env bash
# Interop lab: runs UNMODIFIED OpenVPN 2.6 server (host) + client (network
# namespace) over a veth pair, so tunnel traffic really crosses the UDP link,
# and captures it. Used to collect golden pcaps and to verify the profile
# ([검증] items in docs/OpenVPN_Interop_Profile.md).
#
# Requires: root, openvpn 2.6, openssl, tcpdump, iproute2.
# Generated keys/certs live in the output dir and are NEVER committed.
#
# usage: tools/interop/lab.sh [out_dir] [seconds] [extra server options...]
#   e.g. tools/interop/lab.sh tools/interop/out 14 --reneg-sec 4
set -euo pipefail
OUT="${1:-tools/interop/out}"; SECS="${2:-14}"
shift $(( $# > 2 ? 2 : $# )) || true
PORT=11940; NS=pfct; HOST_IP=10.99.0.1; NS_IP=10.99.0.2
PROTO="${LAB_PROTO:-udp}"     # udp | tcp (server side: tcp-server)
RENEG="${LAB_RENEG:-6}"        # seconds; large value keeps the session free of renegotiations
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"; cd "$OUT"

# --- test-only PKI (EC P-256), 2-day validity ---------------------------------
if [ ! -f ca.crt ]; then
  openssl ecparam -genkey -name prime256v1 -noout -out ca.key 2>/dev/null
  openssl req -x509 -new -key ca.key -sha256 -days 2 -subj "/CN=pf-test-ca" -out ca.crt
  for n in server client; do
    openssl ecparam -genkey -name prime256v1 -noout -out $n.key 2>/dev/null
    openssl req -new -key $n.key -subj "/CN=pf-$n" -out $n.csr
    printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\n" \
      "$([ $n = server ] && echo serverAuth || echo clientAuth)" > $n.ext
    openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
      -sha256 -extfile $n.ext -out $n.crt 2>/dev/null
  done
  openvpn --genkey tls-crypt tc.key
fi

cleanup() {
  kill ${SPID:-} ${CPID:-} ${TPID:-} 2>/dev/null || true
  wait 2>/dev/null || true
  ip netns del $NS 2>/dev/null || true
  ip link del pfv0 2>/dev/null || true
}
trap cleanup EXIT
cleanup_pre() { ip netns del $NS 2>/dev/null || true; ip link del pfv0 2>/dev/null || true; }
cleanup_pre
export OUT HOST_IP PORT PROTO

ip netns add $NS
ip link add pfv0 type veth peer name pfv1
ip link set pfv1 netns $NS
ip addr add $HOST_IP/24 dev pfv0; ip link set pfv0 up
ip netns exec $NS ip addr add $NS_IP/24 dev pfv1
ip netns exec $NS ip link set pfv1 up; ip netns exec $NS ip link set lo up

# Server: tls-crypt, AES-256-GCM only, TLS>=1.3, user mode (no DCO).
openvpn --dev pfs0 --dev-type tun --proto $([ "$PROTO" = tcp ] && echo tcp-server || echo udp) --local $HOST_IP --lport $PORT \
  --server 10.77.0.0 255.255.255.0 --topology subnet \
  --cipher AES-256-GCM --data-ciphers AES-256-GCM --tls-crypt tc.key \
  --ca ca.crt --cert server.crt --key server.key --dh none \
  --tls-version-min 1.3 --remote-cert-tls client --verb 7 --reneg-sec "$RENEG" \
  --keepalive 2 8 --disable-dco --log server.log "$@" & SPID=$!
sleep 1
tcpdump -i pfv0 -n -U -w capture.pcap "$PROTO port $PORT" >/dev/null 2>&1 & TPID=$!
sleep 0.5
if [ -n "${LAB_CLIENT_CMD:-}" ]; then
  # Run an alternative client (e.g. pf_connect) inside the namespace instead of the stock OpenVPN client.
  # Placeholders available to the command: $OUT (this dir), $HOST_IP, $PORT.
  ip netns exec $NS bash -c "$LAB_CLIENT_CMD" > pf_client.log 2>&1 &
  CPID=$!
  rc=0; wait $CPID || rc=$?
  CPID=
  echo "$rc" > pf_client.exit
  echo "--- alternative client output (exit code $rc) ---"; cat pf_client.log
  echo "pcap packets: $(tcpdump -nr capture.pcap 2>/dev/null | wc -l) ($OUT/capture.pcap)"
  exit 0
fi
ip netns exec $NS openvpn --client --dev pfc0 --dev-type tun --proto $([ "$PROTO" = tcp ] && echo tcp-client || echo udp) \
  --remote $HOST_IP $PORT --nobind --cipher AES-256-GCM --data-ciphers AES-256-GCM \
  --tls-crypt tc.key --ca ca.crt --cert client.crt --key client.key \
  --tls-version-min 1.3 --remote-cert-tls server --verb 7 --reneg-sec 6 \
  --keepalive 2 8 --disable-dco --log client.log & CPID=$!
sleep 4
if ip netns exec $NS ip -br addr show pfc0 2>/dev/null | grep -q 10.77.0; then
  echo "tunnel up: $(ip netns exec $NS ip -br addr show pfc0)"
  if ip netns exec $NS ping -c 5 -i 0.5 -W 1 10.77.0.1 >ping.log 2>&1; then
    echo "ping through tunnel: OK"
  else
    echo "ping through tunnel: FAILED (see $OUT/ping.log)"
  fi
else
  echo "tunnel NOT up (see $OUT/client.log)"
fi
sleep $(( SECS > 4 ? SECS - 4 : 0 ))   # let at least one renegotiation happen
echo "renegotiations seen (client): $(grep -c 'TLS: soft reset' client.log || true)"
echo "pcap packets: $(tcpdump -nr capture.pcap 2>/dev/null | wc -l) ($OUT/capture.pcap)"
