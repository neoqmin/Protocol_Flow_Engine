#!/usr/bin/env bash
# Protocol test (PM-2b N3): pf_stun (our STUN client) against an UNMODIFIED coturn STUN server with RFC 5780 enabled,
# through a REAL kernel NAT (nftables masquerade in a router namespace). Needs root, coturn (turnserver), nft, ip.
# Skips (exit 77) when unavailable.     PF_STUN=<path to pf_stun> tests/protocol/run_stun_interop.sh
#
#   pfsrv  198.51.100.1 + 198.51.100.2 (coturn: -L both, port 3478, alt port 3479, --stun-only, no auth)
#   pfnat  198.51.100.10 (public side) / 10.77.1.1 (private side), forwards, nft masquerade out of the public side
#   pfcli  10.77.1.2, default route via 10.77.1.1
#
# Scenarios:
#   binding        Binding from behind the NAT: mapped address is the NAT's public address
#   no-nat         discovery from the router itself (public address, --bind): behind_nat no, EIM + EIF
#   masquerade     discovery through plain masquerade: EIM (Linux keeps the source port), APDF (conntrack only lets the
#                  exact remote back in)
#   fully-random   masquerade fully-random (a new random port per flow): APDM + APDF
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
for t in turnserver nft ip; do command -v "$t" >/dev/null || { echo "SKIP: $t not installed"; exit 77; }; done
PFS="${PF_STUN:?set PF_STUN to the pf_stun binary}"
OUT="$(mktemp -d)"
FAILED=0
cleanup() {
  [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null
  wait 2>/dev/null
  for n in pfsrv pfnat pfcli; do ip netns del $n 2>/dev/null; done
  rm -rf "$OUT"
}
trap cleanup EXIT
for n in pfsrv pfnat pfcli; do ip netns del $n 2>/dev/null; done

ip netns add pfsrv; ip netns add pfnat; ip netns add pfcli
ip link add pfs0 netns pfsrv type veth peer name pfn0 netns pfnat
ip link add pfn1 netns pfnat type veth peer name pfc0 netns pfcli
ip -n pfsrv addr add 198.51.100.1/24 dev pfs0; ip -n pfsrv addr add 198.51.100.2/24 dev pfs0
ip -n pfnat addr add 198.51.100.10/24 dev pfn0; ip -n pfnat addr add 10.77.1.1/24 dev pfn1
ip -n pfcli addr add 10.77.1.2/24 dev pfc0
for n in pfsrv pfnat pfcli; do ip -n $n link set lo up; done
ip -n pfsrv link set pfs0 up; ip -n pfnat link set pfn0 up; ip -n pfnat link set pfn1 up; ip -n pfcli link set pfc0 up
ip -n pfcli route add default via 10.77.1.1
ip netns exec pfnat sysctl -qw net.ipv4.ip_forward=1

ip netns exec pfsrv turnserver -n --no-auth --stun-only --no-tls --no-dtls --no-cli --log-binding --simple-log \
  -L 198.51.100.1 -L 198.51.100.2 --listening-port 3478 --alt-listening-port 3479 -l "$OUT/coturn.log" >/dev/null 2>&1 &
CPID=$!
for _ in $(seq 50); do ip netns exec pfsrv ss -uln | grep -q '198.51.100.2:3479' && break; sleep 0.1; done
ip netns exec pfsrv ss -uln | grep -q '198.51.100.2:3479' || { echo "FAIL: coturn did not start"; tail -20 "$OUT"/coturn*.log; exit 1; }

nat() {   # nat <masquerade options>
  ip netns exec pfnat nft delete table ip pfnat 2>/dev/null
  ip netns exec pfnat nft add table ip pfnat
  ip netns exec pfnat nft "add chain ip pfnat post { type nat hook postrouting priority 100; }"
  ip netns exec pfnat nft add rule ip pfnat post oifname pfn0 masquerade "$@"
  ip netns exec pfnat conntrack -F 2>/dev/null || true
}
check() {  # check <name> <log> <expected key: value>...
  local name="$1" log="$2"; shift 2
  local ok=1
  for want in "$@"; do grep -qx "$want" "$log" || { echo "FAIL [$name]: expected '$want'"; ok=0; }; done
  if [ $ok = 1 ]; then echo "PASS [$name]"; else FAILED=1; echo "--- pf_stun output ---"; cat "$log"; fi
}
PROBE="--probe-rto 100 --probe-rm 4"

echo "=== scenario: binding ==="
nat
ip netns exec pfcli "$PFS" --server 198.51.100.1:3478 > "$OUT/binding.txt"; echo "exit: $?" >> "$OUT/binding.txt"
check binding "$OUT/binding.txt" "status: Succeeded" "exit: 0"
grep -Eq '^mapped: 198\.51\.100\.10:[0-9]+$' "$OUT/binding.txt" || { echo "FAIL [binding]: mapped address is not the NAT's"; FAILED=1; }
grep -q '^other: 198.51.100.2:3479$' "$OUT/binding.txt" || { echo "FAIL [binding]: no RFC 5780 OTHER-ADDRESS from coturn"; FAILED=1; }

echo "=== scenario: no-nat ==="
ip netns exec pfnat "$PFS" --server 198.51.100.1:3478 --discover --bind 198.51.100.10:40000 $PROBE > "$OUT/nonat.txt"
check no-nat "$OUT/nonat.txt" "status: Done" "mapped: 198.51.100.10:40000" "behind_nat: no" "mapping: EIM" "filtering: EIF"

echo "=== scenario: masquerade ==="
nat
ip netns exec pfcli "$PFS" --server 198.51.100.1:3478 --discover --bind 10.77.1.2:41000 $PROBE > "$OUT/masq.txt"
check masquerade "$OUT/masq.txt" "status: Done" "mapped: 198.51.100.10:41000" "behind_nat: yes" "mapping: EIM" "filtering: APDF"

echo "=== scenario: fully-random ==="
nat fully-random
ip netns exec pfcli "$PFS" --server 198.51.100.1:3478 --discover --bind 10.77.1.2:42000 $PROBE > "$OUT/random.txt"
check fully-random "$OUT/random.txt" "status: Done" "behind_nat: yes" "mapping: APDM" "filtering: APDF"

grep -q "198.51.100" "$OUT"/coturn*.log 2>/dev/null || echo "note: coturn logged no bindings (log-binding)"
[ "$FAILED" = 0 ] && echo "PASS: pf_stun interoperates with unmodified coturn (RFC 5780) through a real kernel NAT"
exit $FAILED
