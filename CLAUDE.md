# Protocol Flow Engine

OpenVPN 기반의 Block 조립형 VPN/보안 프로토콜 처리 엔진. 작은 Block을 Flow로 연결하고 Compiler/Runtime으로 실행한다.
클라우드 세션과 로컬 환경 모두에서 이 파일을 읽으므로, **결정이 바뀌면 이 파일과 `docs/DECISIONS.md`를 같이 갱신하고 커밋한다. 작업 상태가 바뀌면 `progress.md`의 체크박스를 갱신한다.**

## 문서 위치

- **작업 진행 현황(체크박스): `progress.md`** — 작업 추적의 정본. 작업을 시작/완료할 때 같은 커밋에서 갱신한다
- 개발 계획: `plans/Protocol_Flow_Engine_OpenVPN_Development_Plan.md`
- MCP/AI 확장: `plans/Protocol_Flow_Engine_MCP_AI_Extension_Plan.md`
- 멀티 플랫폼·Transport: `plans/Protocol_Flow_Engine_MultiPlatform_Transport_Plan.md`
- NAT Traversal 비전(원 계획, 참고용): `plans/Protocol_Flow_Engine_NAT_Traversal_Lab_Development_Plan.md` → **저장소 적용안: `docs/PM2_NAT_Traversal_Scope.md`** (D-039)
- Flow 모델 확장(State Machine 층·Context 일반화·Trace): `plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md` (D-040)
- 오픈소스 정책: `docs/Upstream_Extension_Policy.md`
- 참고 자료: `docs/References_OpenSource_Papers.md`
- **마일스톤(MVP / Post-MVP)**: `docs/Milestones.md`
- Block API(결과 계약, 버퍼 모델): `docs/Block_API.md`
- MVP 프로토콜 범위: `docs/OpenVPN_Interop_Profile.md`
- Linux 클라이언트(A4/B: Transport·폴백·TUN, `pf_client`): `docs/Linux_Client_Notes.md`
- Flow JSON 형식·버전 규칙: `docs/Flow_JSON_Schema_v1.md`
- State Machine 형식·실행 의미·검증 규칙(`protocol-machine` v1): `docs/Machine_JSON_Schema_v1.md` (D-041)
- 위협 모델·키 관리·라이선스(clean-room): `docs/Threat_Model_and_Key_Management.md`
- **전체 결정 기록: `docs/DECISIONS.md`** (@docs/DECISIONS.md)

## 핵심 결정 (요약)

- Windows/Linux/Android/macOS/iOS 멀티 플랫폼. 코어는 플랫폼 독립, 차이는 PAL로 격리
- TDD: 테스트 먼저. 버그는 재현 테스트/golden vector부터 추가
- Device(TUN/TAP)와 Transport(UDP/TCP/프록시/Relay)는 독립 축. TAP은 Linux/Windows만
- 오픈소스 원본 수정 금지, Adapter 경유, 패치는 최후 수단 (`third_party/`는 편집 금지)
- **MVP에서는 오픈소스 수정이 필요한 작업 제외** (DCO Adapter, Kernel Runtime은 Post-MVP)
- 언어 **C++17 확정**(D-013), TLS/암호는 **OpenSSL 3.x**(D-014, MVP-A)
- 제품 방향은 VPN 엔진 유지. NAT Traversal은 PM-2b(참고 범위, 진입 시 재논의), "Protocol Lab" 제품 라인은 PM-6·PM-7 이후 재검토(D-039)
- MVP = Linux 클라이언트 + 수정 없는 OpenVPN 2.6 상호운용(UDP+TUN, TLS1.3+tls-crypt+AES-256-GCM) → TCP/폴백 → Flow JSON/Validator. 나머지는 Post-MVP(`docs/Milestones.md`)
- Control Plane은 MVP에서 일반 코드(Flow 아님). Post-MVP에서 **순환·타이머·상태는 State Machine 층에만**, 패킷 Flow는 계속 DAG(D-040). v1 구현: 평평한 상태, 카운터 guard, Dropped=비전이·Errored=실패, Validator가 무한 재시도·livelock 거부(D-041). `TunnelSession`은 아직 `KeepaliveTimer` 사용(동등성만 증명). Trace(`pf/trace.h`, D-042)는 이름·결과·길이만 기록하고 바이트·키는 담을 필드가 없다. 끄면 비용 0. Clean-room 구현: 공개 문서/pcap만 근거, OpenVPN 소스 복사 금지, iOS는 GPL 미포함
- 키는 Key Reference로만 다루고 로그/Flow/테스트 벡터에 평문 금지, 개인 키 커밋 금지

## 빌드 / 테스트

```sh
cmake -S . -B build -G Ninja        # Ninja가 없으면 -G 생략
cmake --build build
ctest --test-dir build --output-on-failure
ctest --test-dir build -L unit      # unit | flow | regression | protocol | performance
./build/tests/pf_unit_tests <이름필터>

# 엄격 모드 (CI와 동일): 경고를 오류로 + ASan/UBSan
cmake -S . -B build-san -DPF_WARNINGS_AS_ERRORS=ON -DPF_SANITIZE=address,undefined
# 퍼저 (Clang + libFuzzer 런타임 필요): -DPF_BUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
```

## 상호운용 랩 (root 필요)

```sh
apt-get install -y openvpn tcpdump iproute2 iputils-ping nftables     # OpenVPN 2.6.x
tools/interop/lab.sh tools/interop/out 16   # 수정 없는 서버/클라이언트 실행 + pcap/로그
```
`tools/interop/verify_aead.py`/`verify_tls_crypt.py <out_dir>`로 데이터 채널 AEAD·tls-crypt 레이아웃을, `extract_vectors.py`/`extract_tls_crypt_vectors.py`로 골든 벡터를 만든다(`pip install cryptography`).
우리 클라이언트를 수정 없는 OpenVPN 서버에 붙이는 자동 상호운용 테스트(root 필요, 3 시나리오: baseline / server-reneg / client-reneg):
```sh
cmake -S . -B build -DPF_WITH_OPENSSL=ON -DPF_PROTOCOL_TESTS=ON && cmake --build build
ctest --test-dir build -L protocol --output-on-failure     # run_interop.sh(약 50초) + run_tunnel.sh(약 45초) + run_transport_tunnel.sh(약 90초)
```
`build/pf_connect`는 `ControlClient`를 UDP로 구동하는 진단 도구(`--keepalive-seconds`, `--reneg-seconds`, `--probe-keys`).
`build/pf_client`는 Linux 클라이언트(UDP→TCP 폴백 + 실제 TUN, root 필요): `pf_client --server ip:port --tls-crypt tc.key --ca ca.crt --cert c.crt --key c.key [--proto udp|tcp|auto] [--tcp-port P] [--connect-timeout S] [--tun-name N] [--mtu 1400] [--duration S] [--stats-interval S] [--trace FILE]`(`--trace`: 데이터 경로 trace를 종료 시 JSON Lines로, D-042). 세션이 죽으면 종료 코드 2(재연결은 상위 감독자, D-029). 터널 테스트(ctest 라벨 `protocol`, 같은 랩 네임스페이스라 `RESOURCE_LOCK`으로 직렬화되며 **동시에 직접 실행 금지**): `run_tunnel.sh`(ping·재협상 부하, `PF_ONLY=soak PF_SOAK_SECONDS=3700` 옵트인 1시간 soak) 와 `run_transport_tunnel.sh`(UDP·TCP·UDP 무음 차단→TCP 폴백 5개 시나리오, `TUNNEL_SECONDS=3720 TUNNEL_RENEG=3600 TUNNEL_EXPECT_RENEG=1 [TUNNEL_PROTO=tcp]`로 1시간 soak). 둘 다 `PF_CLIENT=build/pf_client`.
성능 기준선: `docs/Performance_Baseline.md` (`tests/performance/bench_data_path.cpp`, `tools/interop/bench_tunnel.sh`, Release 빌드 필수).
키/인증서는 실행마다 생성되며 커밋하지 않는다. verb 7 로그에는 테스트 세션 키가 있으므로 로그/pcap을 그대로 커밋하지 않는다.

## 코드 규칙

- 구조: `core/`(헤더 `core/include/pf/`, 구현 `core/src/`, 블록 `core/src/blocks/`), `platform/<os>/`(PAL: 소켓·TUN·이벤트 루프 등 OS 의존, 코어는 참조 금지), `tools/`, `tests/`, `adapters/`, `third_party/`, `patches/`
- `tests/unit|flow|regression|platform/test_*.cpp`는 CMake가 자동 수집. 하니스: `tests/support/pf_test.h` (`PF_TEST`, 비치명 `PF_CHECK`/`PF_CHECK_EQ`, 치명 `PF_REQUIRE`)
- 파서/디코더는 전수 테스트 또는 fuzz 타깃(`tests/fuzz/`)을 함께 둔다. 새 코드는 `-Werror`·ASan/UBSan 통과
- upstream 타입은 `adapters/`에서만 참조. 코어/Block은 우리 인터페이스에만 의존
- Block 결과 계약: `Drop`=입력 탓(사유 필수) / `Error`=우리 실패. Action은 Continue, Decision은 Yes/No. 새 block id는 재번호 금지
- 보안: 키는 DSL/Flow에 직접 저장하지 않고 Key Reference로만 다룬다

## Git

- 작업 브랜치: A4는 `claude/a4-development-afff2b`. master에는 요청 시 머지
- PR은 사용자가 요청할 때만 생성
