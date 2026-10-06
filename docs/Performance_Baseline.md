# 성능 기준선 (MVP-A, 2026-10-06)

목표 수치가 **아니라** 이후 최적화(PM-3)와 회귀 비교를 위한 출발점이다. 측정 환경: 클라우드 VM, Intel Xeon 2.8GHz, 4 vCPU, Release 빌드(`-DCMAKE_BUILD_TYPE=Release`), 단일 스레드 클라이언트, 링크는 veth(실제 망 아님). 공유 VM이라 **±15% 정도 흔들린다** — 두 클라이언트를 서로 비교하는 용도로만 쓴다.

## 1. 데이터 경로 마이크로벤치 (`tests/performance/bench_data_path.cpp`)

`DataPath::seal` + `open` 왕복(암호화+복호화, AES-256-GCM/OpenSSL 3.x), 1 스레드. `build-rel/tests/pf_bench_data_path`.

| 페이로드 | 왕복 packets/s | MB/s(페이로드) | ns/패킷 |
|---|---|---|---|
| 64 B | 417k | 26.7 | 2397 |
| 256 B | 418k | 106.9 | 2394 |
| 512 B | 376k | 192.3 | 2662 |
| 1024 B | 323k | 331.0 | 3094 |
| 1400 B | 333k | 466.7 | 3000 |

관찰: 작은 패킷에서도 ~2.4µs로 거의 일정 → **암호 연산이 아니라 호출당 고정 비용**(EVP 컨텍스트 생성·키 설정, 패킷마다 `PacketBuffer` 할당)이 지배한다. 최적화 후보(PM-3): 키별 EVP 컨텍스트 재사용, 버퍼 풀. 최적화 없이도 1.4KB에서 한쪽 방향 환산 > 900Mbit/s.

## 2. 터널 처리량: 우리 `pf_client` vs stock OpenVPN 2.6.19 클라이언트 (`tools/interop/bench_tunnel.sh`)

동일한 수정 없는 OpenVPN 2.6.19 서버(유저 모드, AES-256-GCM, verb 3), 같은 호스트의 netns+veth, `iperf3` 6초.

| 테스트 | pf_client | stock openvpn |
|---|---|---|
| TCP 업로드 (client→server) | 517 Mbit/s | 552 Mbit/s |
| TCP 다운로드 (server→client) | 752 Mbit/s | 550 Mbit/s |
| UDP 1200B, 1G offered | 376 Mbit/s | 377 Mbit/s |

해석: 같은 서버·같은 호스트에서 **우리 클라이언트가 stock 클라이언트와 같은 수준**이다(업로드 약 -6%는 측정 오차 범위, 다운로드는 우리가 더 높게 측정됨 — 서버와 같은 호스트의 CPU 경합 영향 가능). 병목은 상대 서버(단일 스레드 유저 모드)일 가능성이 크다. 목표 수치(성능 요구사항)는 이 기준선을 근거로 이후 확정한다.

**통합 후 재측정**(D-037, `TunnelSession`+`platform/linux`로 단일화한 `pf_client`, 같은 방법): TCP 업 479 / 다운 565 / UDP 299 Mbit/s vs stock 447 / 485 / 282 — 여전히 같은 수준(공유 VM, ±15%).

## 3. Flow 실행기 오버헤드와 trace (F-3, D-042, 2026-10-06)

`tests/performance/bench_flow_trace.cpp`: 빈 블록 8개(Decision 1개 포함)짜리 Flow를 반복 실행해 실행기 자체 비용을 잰다. Release, 같은 VM.

| 경우 | ns/실행 |
|---|---|
| trace 도입 전 | 16.9 ~ 18.9 |
| trace 도입 후, **끔**(`trace == nullptr`) | 18.0 ~ 20.8 (노이즈 범위, 끈 경로는 trace 검사가 없는 별도 인스턴스) |
| trace 도입 후, **켬**(`TraceRing`) | 179 ~ 210 (기록 9개, 기록당 약 22ns) |

§1 DataPath 왕복 벤치마크도 trace 도입 전후가 같다(노이즈 범위). trace는 진단용으로 켜는 기능이므로 켬 비용(패킷당 약 0.1~0.2µs, 왕복 2µs 대비 5~10%)은 허용 범위다.

## 재현

```sh
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release -DPF_WITH_OPENSSL=ON && cmake --build build-rel
./build-rel/tests/pf_bench_data_path
./build-rel/tests/pf_bench_flow_trace
apt-get install -y iperf3
sudo PF_CLIENT=$PWD/build-rel/pf_client tools/interop/bench_tunnel.sh 6   # run_interop/run_tunnel과 동시 실행 금지(같은 netns)
```
