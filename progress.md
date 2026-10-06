# 진행 현황 (Progress)

> 이 파일이 **작업 추적의 기준**이다. 클라우드/로컬, 사람/Claude 모두 같은 파일을 본다.
> 마일스톤 정의와 종료 조건은 [docs/Milestones.md](docs/Milestones.md), 결정 이력은 [docs/DECISIONS.md](docs/DECISIONS.md).
> 마지막 갱신: 2026-10-06 (MVP 전체 완료 / Post-MVP: F-1·F-2·F-3 완료, PM-2 N0 — D-044, N1 — D-045, N2 — D-046, N3 STUN 클라이언트 — D-047)

범례: `[x]` 완료 · `[ ]` 미착수 · `[~]` 진행 중 · `[!]` 막힘(사유 기재)

## 지금 할 일 (Next)

- [x] **MVP-A / A3** — Control Plane 완료 (실제 서버와 제어·데이터 채널·keepalive·재협상 상호운용)
- [x] **MVP-A 완료** (A1~A4 + 공통 종료 조건; A4는 병렬 구현 2종을 D-037로 통합)
- [x] **MVP-B / B1** — Transport 인터페이스 + UDP loopback 테스트
- [x] **MVP-B / B2** — TCP Transport + 2.6 TCP 서버 상호운용
- [x] **MVP-B / B3** — UDP 차단 시 TCP 자동 폴백
- [x] **MVP-C / C1** — Flow JSON 스키마 v1 + 버전 관리/마이그레이션 규칙
- [x] **MVP-C / C2** — Block Registry + Validator
- [x] **MVP-C / C3** — MVP-A 정적 Flow를 JSON으로 로딩해 동일 결과(골든 동등성)
- [x] **MVP 전체 완료 (MVP-A + MVP-B + MVP-C)** — 다음은 Post-MVP(`docs/Milestones.md`): 진입할 항목 선택 필요
- [x] **Post-MVP 계획 정리**: NAT Traversal 계획을 PM-2 참고 계획으로 채택하고 적용안 작성([docs/PM2_NAT_Traversal_Scope.md](docs/PM2_NAT_Traversal_Scope.md), D-039), Flow 모델 확장 계획(순환은 State Machine 층에만, [plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md](plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md), D-040), 위협 모델 §8, 참고 자료 §10
- [x] **다음 Post-MVP 진입 항목 선택** → PM-4 F-1(State Machine)부터
- [x] **PM-4 / F-1 S0~S4** — State Machine v1: `MachineRunner`·Validator·`protocol-machine` v1·`KeepaliveTimer` 동등성 (D-041, [docs/Machine_JSON_Schema_v1.md](docs/Machine_JSON_Schema_v1.md))
- [x] **F-3 / S5 Trace** — `TraceSink`/`TraceRing`, `run_flow`·`MachineRunner` 기록, JSON Lines, `pf_client --trace` (D-042)
- [x] **F-2 / S6 FlowContext 일반화** — 프로토콜 슬롯 + 블록 컨텍스트 계약(consumes/produces) + `ContextNotProduced` 검사 (D-043)
- [x] **PM-2 진입 논의(N0)** — OpenVPN 호환 서버(PM-11 신설), 연결 서버 `pf_connectd`(STUN + 자체 TURN + rendezvous), coturn 양방향 상호운용, 순서 ① N1~N3 → ② PM-11 → ③ N4~N8 (D-044)
- [x] **PM-2b / N1 STUN 코덱** — RFC 8489 코덱 + RFC 5769 벡터 4개(바이트 단위 재현) + `StunSlot` + `is_stun`/`parse_stun` 블록 + fuzz (D-045)
- [x] **PM-2b / N2 메모리 NAT 시뮬레이터** — RFC 4787 `Nat` + realm 트리 `Network`(hairpin·CGN) + `NetworkTransport`, 9개 조합을 실제 STUN으로 검증 (D-046)
- [x] **PM-2b / N3 STUN 클라이언트** — Binding Machine(RFC 8489 재전송) + RFC 5780 탐지 + 응답기 + `pf_stun`, 시뮬레이터 27개 설정·수정 없는 coturn·실제 커널 NAT로 검증 (D-047)
- [ ] **다음: PM-2b ① 완료 → ② PM-11 OpenVPN 호환 서버** (진입 시 5가지 결정: 동시성 모델, 설정 형식, 클라이언트 인증, 관리 인터페이스, 플랫폼 — `docs/PM11_OpenVPN_Server_Scope.md` §5)
- [x] **A4 구현 중복 해소 (D-037)**: 병렬로 만든 `pf_client`(`TunnelSession`)와 `pf_vpn`(`DataPath`+`VpnClient`)을 `pf_client` 하나로 통합 — 세션은 `TunnelSession`(내부 Flow는 `DataPath` 재사용), PAL은 `platform/linux` 한 곳(TUN + UDP/TCP Transport + 폴백 이벤트 루프). 통합 후 7개 테스트 ASan/UBSan 통과, 처리량 동일 수준

## 요약

| 마일스톤 | 상태 |
|---|---|
| 기반 (문서·정책·CI) | ✅ 완료 |
| M0 하드닝 | ✅ 완료 |
| **MVP-A** Linux 클라이언트 + OpenVPN 2.6 상호운용 | ✅ 완료 (A1~A4, 공통 종료 조건) |
| MVP-B TCP + 폴백 | ✅ 완료 (B1~B3) |
| MVP-C Flow JSON + Validator | ✅ 완료 (C1~C3) |
| Post-MVP (PM-1 ~ PM-11, 공통 기반 F) | F-1·F-2·F-3 ✅, PM-2 진행 중(N0 ✅) |

---

## 기반

- [x] 참고 오픈소스/논문 정리 ([docs/References_OpenSource_Papers.md](docs/References_OpenSource_Papers.md))
- [x] 개발 계획서 3종 (`plans/`)
- [x] 멀티 플랫폼·Transport 계획 (TUN/TAP 독립 축, 폴백)
- [x] 오픈소스 확장 정책 ([docs/Upstream_Extension_Policy.md](docs/Upstream_Extension_Policy.md))
- [x] 위협 모델·키 관리·clean-room ([docs/Threat_Model_and_Key_Management.md](docs/Threat_Model_and_Key_Management.md))
- [x] OpenVPN 상호운용 프로파일 ([docs/OpenVPN_Interop_Profile.md](docs/OpenVPN_Interop_Profile.md))
- [x] 마일스톤 정리 / 설계 리뷰(Opus) 반영
- [x] 언어 C++17, TLS/암호 OpenSSL 3.x 확정 (D-013, D-014)
- [x] 상호운용 랩 `tools/interop/lab.sh` (수정 없는 OpenVPN 2.6.19, netns+veth, pcap)
- [x] 데이터 채널 AEAD nonce/AAD 독립 검증 `tools/interop/verify_aead.py` (D-017)
- [x] CI: ubuntu/windows/macos + ASan/UBSan + fuzz-smoke
- [x] CLAUDE.md / DECISIONS.md / 이 파일 (프로젝트 메모리)

## M0 — 하드닝 ✅

- [x] 헤더 파서 (opcode 1~11, legacy 분류, 전수 테스트)
- [x] device 지원 매트릭스(TUN/TAP), Transport 폴백 정책
- [x] 테스트 하니스, golden 회귀 테스트, libFuzzer 타깃
- [x] CMake 정적 라이브러리/경고/sanitizer 옵션

---

# MVP

## MVP-A — Linux 클라이언트 + OpenVPN 2.6 상호운용

### A1 — Block API, 오류·버퍼 모델 ✅  ([docs/Block_API.md](docs/Block_API.md))

- [x] 오류 모델: `Drop`(입력 탓, 사유 필수) vs `Error`(우리 실패)
- [x] `PacketBuffer` (headroom/tailroom, move-only, wipe)
- [x] `BlockRegistry` + Block 결과 계약 강제
- [x] `FlowBuilder` 검증 (순환, 미도달, 누락 edge, 중복 label)
- [x] `run_flow` 실행기 + 통계(`FlowStats`) + step 한도
- [x] OpenVPN RX 정적 Flow (파싱 → 정책 → 분기 → decap)

### A2 — Data Plane ✅  ([docs/Block_API.md](docs/Block_API.md) §8)

- [x] 랩 pcap + 테스트 세션 키로 **DATA_V2 골든 벡터** 17개 추출 (`tools/interop/extract_vectors.py`, 태그 검증 통과분만)
- [x] DATA_V2 헤더/packet-id 파싱 Block (`parse_data_v2`)
- [x] AES-256-GCM 복호 Block (OpenSSL 3.x, **제자리**, AAD = 헤더4‖packet-id4, nonce = packet-id‖tail8)
- [x] AES-256-GCM 암호 Block (TX, headroom 캡슐화) — 골든 평문을 재암호화하면 OpenVPN 바이트와 **정확히 일치**
- [x] packet-id **replay window** (64, check/commit 분리, 경계·큰 점프·최댓값 테스트)
- [x] 변조(태그/암호문/AAD/키/nonce)·잘림·키 없음·재생·packet-id 0 거부 테스트
- [x] DATA_V2 RX/TX Flow 통합 (가짜 Provider로 로직 검증 + 실제 OpenVPN 패킷으로 전체 Flow 검증)
- [x] 키 재료 `wipe` 검증 (`DataKey`, `secure_zero`, 인증 실패 시 평문 0 처리), TX nonce 고갈 정책
- [x] 변이 테스트로 nonce·AAD·wipe·window 크기 오류가 테스트에 잡히는지 확인
- [x] CI: OpenSSL 게이팅(ubuntu/macOS ON, Windows OFF), `fuzz_data_v2` 타깃 — 5개 잡 모두 통과 확인 (run 14)

### A3 — Control Plane (일반 코드, Flow 아님: D-009)  ([docs/OpenVPN_Control_Plane_Notes.md](docs/OpenVPN_Control_Plane_Notes.md))

- [x] **tls-crypt 와이어/키 배치 확정**: pcap + 테스트 키로 HMAC 태그 검증 (`tools/interop/verify_tls_crypt.py`). client tx=(K2,K3), rx=(K0,K1)
- [x] **tls-crypt wrap/unwrap 구현** (`TlsCryptChannel`: packet-id/net_time replay, 인증 후에만 상태 갱신, id 고갈 시 중단). 골든 14개 개봉 + **재봉인 시 OpenVPN과 바이트 일치**
- [x] 제어 패킷 평문 포맷 파싱/빌드 (`control_packet.h`): ACK 배열, 원격 세션ID, message_id, P_ACK_V1. 골든 14개 파싱→재빌드 바이트 일치
- [x] reliability layer (`reliable.h`): 수신 재정렬·중복 처리·ACK 큐(최신 우선), 송신 윈도우·지수 백오프·실패 판정, 시계 주입. 서버 메시지 0..5 순서 도착/ACK 커버리지를 실제 캡처로 검증
- [x] TLS 1.3 메모리 BIO 세션 (`tls_session.h`): feed/step/take_output 구동 방식, 1바이트 단위 전달·100KB 전송·단편화 검증, 피어 인증서 항상 검증 + EKU(serverAuth/clientAuth) 강제, TLS 1.3 전용, 티켓 비활성, 키 불일치/CA 없음 거부, exporter 노출. 테스트 PKI는 실행 시점에 생성(키 미커밋). *(실제 OpenVPN 서버와의 핸드셰이크는 A3-6에서)*
- [x] key-method 2 메시지 빌드/파싱 (`key_method2.h`): 문서화된 필드 순서, 클라이언트/서버 key source 차이, 선택 필드, 소비 바이트 보고(뒤따르는 PUSH 읽기용), 잘림/악성 길이 방어 *(실제 서버 수락 여부는 A3-6에서)*
- [x] PUSH_REPLY 파싱 (`push.h`): **실제 2.6.19 응답 문자열**로 검증, 라우트/미지 옵션 보존, 잘못된 값 거부, MVP 지원 여부 판정(AES-256-GCM·tls-ekm·subnet)
- [x] IV_PROTO = 14 광고 (`default_peer_info`, 테스트로 고정: 990/dyn-tls-crypt 미광고)
- [ ] 키 유도 (TLS exporter, `EXPORTER-OpenVPN-datakeys`) — **컨텍스트/크기/분할 `[검증]` 확정** (랩에서 복원한 nonce tail을 기대값으로)
- [x] `ControlClient` 상태머신(`control_client.h`, 순수 I/O 없음): hard reset → TLS → key-method 2 → PUSH_REPLY → 키 설치. 가짜 서버로 18개 시나리오 CI 검증(손실·중복·역순·분할·잘못된 키/인증서/푸시·AUTH_FAILED·PUSH_REQUEST 폴백·세션 바인딩). 변이 9개 모두 검출
- [x] **실제 서버로 상호운용** (`tools/pf_connect`, UDP): 수정 없는 OpenVPN 2.6.19와 핸드셰이크(~10ms) 성공, key-method 2 수락, 서버 응답의 선택 필드 3개 확인(계측으로 발견·수정)
- [x] **EKM 키 분할 확정** (D-026): 모든 오프셋 탐색에서 GCM 태그 검증되는 조합이 유일, tx는 서버가 핑을 수락
- [x] **데이터 채널 양방향 keepalive** 실제 서버와 교환 (우리 TX/RX 블록 사용: 송신 핑을 서버가 복호, 서버 핑을 우리가 replay 검사→복호)
- [x] **자동 상호운용 테스트** `tests/protocol/run_interop.sh` (CTest 라벨 `protocol`) + CI `interop` 잡(GH 러너 3시나리오 통과, 차단 잡으로 전환). 키 분할을 틀리게 바꾸면 실패함을 확인
- [x] **재협상(SOFT_RESET, key_id 회전)**: key_id별 key state, 서버·클라이언트 시작 모두, TX 전환, 이전 키 수신 유예(최대 1개), 실패 시 이전 키 유지. 가짜 서버 11개 시나리오 + 변이 11개 모두 검출. **실제 서버: 26초 동안 12회 재협상, key_id 7→1 순환 확인, 데이터 12/12 정상**
- [x] keepalive 스케줄링(`KeepaliveTimer`: ping / ping-restart)을 코어로. 변이 검출 확인
- [x] 상호운용 테스트 3 시나리오(`baseline`, `server-reneg`, `client-reneg`), 재협상/키 전환을 깨뜨리는 변이를 모두 검출
- [ ] keepalive(ping), 재협상(key_id 회전)
- [x] 수정 없는 OpenVPN 2.6 서버와 핸드셰이크 성공 (`tests/protocol`, 정적 tls-crypt 키로 전 구간 동작 확인 — dyn-tls-crypt 비광고)

### A4 — Linux 통합 (구현 2종을 D-037로 `pf_client` 하나로 통합. 아래 a/b는 이력)

**A4-a `pf_client`** — `TunnelSession` + `platform/linux` ([docs/Linux_Client_Notes.md](docs/Linux_Client_Notes.md), D-029)

- [x] `TunnelSession` (코어, sans-I/O): ControlClient + RX/TX Flow + KeepaliveTimer 결합. 수신 분류(핑/IP/기타), 연결 전 트래픽 거부, 재협상 후 새 key_id 전환. 가짜 서버 11개 테스트 + 변이 5개 모두 검출
- [x] Linux PAL `platform/linux`: connected UDP 소켓(논블로킹), TUN 장치(`IFF_TUN|IFF_NO_PI`), 주소/넷마스크/MTU/up, 푸시된 라우트
- [x] `pf_client`: 이벤트 루프, PUSH_REPLY 후 TUN 설정, SIGINT/SIGTERM 정상 종료, 세션 사망 시 종료 코드 2(재연결은 상위 감독자)
- [x] **터널 ping 성공** (수정 없는 OpenVPN 2.6.19, netns + 실제 TUN): 20회 + 1300바이트 ping 손실 0%, 주소·푸시 라우트 설치 확인
- [x] **재협상 중 트래픽**: 서버가 2초마다 재협상(≥8회, key_id 7→1 순환)하는 동안 연속 ping 손실 0%
- [x] 자동 테스트 `tests/protocol/run_tunnel.sh` (CTest `pf_tunnel_openvpn`, 라벨 `protocol`)
- [x] **1시간 연결 + 재협상 1회 이상** (서버 기본 `reneg-sec 3600`, 3700초): 재협상 1회 성공, 송수신 3622/3622 손실 0. (첫 실행은 스크립트가 pf_client 종료 후에도 ping을 보내 손실로 오판 → `ping -w`로 수정)
- [x] ASan/UBSan(-Werror) 빌드에서 unit/flow/regression 통과

**A4-b (구 `pf_vpn`, 현재 `pf_client`에 흡수)** — `DataPath` + `VpnClient` + Transport/폴백 (D-030 → D-037)

- [x] `DataPath`(코어, I/O 없음): A2 TX/RX Flow를 `seal`/`open`으로 감쌈. IP/Ping/Other 분류 — IP 아닌 인증 데이터는 TUN에 쓰지 않음. 변조·재생·미지 key_id·키 없음 테스트
- [x] `platform/linux`: `TunDevice`(ioctl로 주소·MTU·up·라우트, `ip` 불필요), `VpnClient`(UDP+TUN `poll()` 루프, 핑 송신/ping-restart 감시, 통계), 실행 파일 `pf_client` (D-030)
- [x] **터널 ping 성공**: `tests/protocol/run_transport_tunnel.sh` — 수정 없는 OpenVPN 2.6 서버, 클라이언트 netns의 TUN으로 ping(56B·1300B), 서버 `reneg-sec 3`에서 22초간 재협상 7회·패킷 손실 0
- [x] CTest `pf_transport_tunnel_openvpn`(라벨 protocol) + CI `interop` 잡에 ping 설치. `-Werror`+ASan/UBSan 빌드 통과
- [x] **1시간 연결 + 재협상 1회**: 3720초(기본 `reneg-sec` 3600), 수정 없는 OpenVPN 2.6.19. 재협상 1회(key_id 0→1), 실패 0, 복호 실패 0, 송신 실패 0, 양방향 7273패킷(1.66MB) 일치, ping 손실 0%. *(참고: 클라우드 컨테이너가 유휴 시 재시작되어 앞선 2회는 중단됨 — 코드 결함 아님)*
- [ ] `ping-restart` 후 재연결 정책 (제품 계층, A4 범위 밖으로 이관 검토)

### MVP-A 공통 종료 조건

- [x] 파서/디코더 fuzz·전수 테스트 통과, ASan/UBSan clean — fuzz 타깃 7개(`header`, `data_v2`, `control_packet`, `key_method2`, `push`, `tls_crypt`, `reliable`) 각 40초 실행(총 1.3억 회 이상) 크래시·불변식 위반 0, ASan/UBSan+`-Werror` 빌드의 unit/flow/regression 통과
- [x] **오픈소스 수정 0건** (`third_party/`·`patches/`는 README뿐, 상호운용은 수정 없는 OpenVPN 2.6.19 바이너리)
- [x] 성능 **기준선(baseline)** 측정 기록: [docs/Performance_Baseline.md](docs/Performance_Baseline.md) — 데이터 경로 ~2.4µs/패킷(고정비용 지배), 터널 TCP 517/752 Mbit/s로 stock 클라이언트(552/550)와 동급. 목표 수치는 이후 확정

## MVP-B — TCP 프레이밍 + Transport 폴백

- [x] B1 Transport 인터페이스 + UDP loopback 테스트 (D-032)
  - [x] `Transport`(코어, 패킷 단위 send/recv, 논블로킹, `TransportStatus`), 테스트용 `LoopbackTransport`(차단·드롭·용량·종료 시뮬레이션 — B3의 "UDP 차단" 재현용)
  - [x] `platform/linux/UdpTransport`(connected 소켓, `MSG_TRUNC`로 초과 데이터그램 감지, 다른 출처 패킷 필터링), `VpnClient`가 Transport만 사용
  - [x] 테스트: loopback 계약 7개(unit), 실제 127.0.0.1 UDP 5개(`pf_platform_tests`, root 불필요), 리팩터링 후 터널 테스트·ASan/UBSan 통과
- [x] B2 TCP Transport (2바이트 길이 프레이밍, 부분 읽기) + 2.6 TCP 서버 상호운용 (D-033)
  - [x] 코어 `ByteStream`(부분 읽기/쓰기 계약) + `FramedTransport`(프레이밍·재조립·송신 큐·역압, 소켓 없음). 읽기/쓰기 청크 1~100000바이트 전수, 프레임 중간 EOF/오류, 초과 프레임 폐기 후 정렬 유지, 큐 한도, 0바이트/65535바이트 프레임. 12개 + 변이 4개 모두 검출
  - [x] `platform/linux/TcpStream`(타임아웃 connect, `TCP_NODELAY`, `MSG_NOSIGNAL`) + 실제 127.0.0.1 TCP 테스트 3개(분할 세그먼트, 2.4MB 폭주 무손실·순서)
  - [x] `Transport`에 `has_pending_input`/`wants_write`/`flush` 추가, `VpnClient` 이벤트 루프 반영, `pf_client --proto tcp`
  - [x] **수정 없는 OpenVPN 2.6.19 `tcp-server`와 상호운용**: 터널 ping + 서버 reneg-sec 3에서 재협상 7회, 손실 0 (`run_transport_tunnel.sh`의 tcp 시나리오 2개, ASan/UBSan 빌드로도 통과)
  - [x] fuzz 타깃 `fuzz_tcp_framing`(임의 스트림×임의 청크) 60초 무결함
- [x] B3 UDP 차단 시 TCP 자동 폴백 (시뮬레이션 테스트) (D-034)
  - [x] 코어 `FallbackConnector`(정책 순회 UDP→TCP, 시도별 기록, 주입 시계·팩토리): 폴백 근거는 **경로 불량의 증거**뿐 — 연결 거부, transport 종료/오류, 제어 채널 무응답(`ControlClient::FailureKind::Unreachable`), 시도 제한 시간 초과. **서버가 답한 거절(`Rejected`: 인증서·AUTH_FAILED·미지원 푸시)은 폴백하지 않고 즉시 중단**
  - [x] 메모리 시뮬레이션 테스트 10개: UDP 정상(TCP 미개방), UDP 무음 차단→TCP(제한 시간만큼만 대기), 연결 거부 즉시 다음, 전부 차단 시 소진 보고, 재시도 횟수, 도중 종료, AUTH_FAILED 비폴백, 틀린 tls-crypt 키(차단과 구분 불가→폴백 후 실패), 제어 클라이언트 자체 포기=Unreachable. 변이 5개 모두 검출(1개는 테스트 보강 후)
  - [x] `VpnClient`가 `FallbackConnector`로 연결, `pf_client --proto udp|tcp|auto --tcp-port --connect-timeout`
  - [x] **실제 서버 + 실제 무음 UDP 차단**(nft가 UDP를 ICMP 없이 드롭, 카운터 확인): `--proto auto`에서 UDP 타임아웃 → TCP로 터널 up, ping 정상 (`fallback-udp-blocked`, ASan/UBSan 빌드로도 통과)

## MVP-C — Flow JSON v1 + Validator

- [x] C1 Flow JSON 스키마 v1 + 버전 관리/마이그레이션 규칙 (D-035, [docs/Flow_JSON_Schema_v1.md](docs/Flow_JSON_Schema_v1.md))
  - [x] 코어 엄격 JSON(`json.h`): RFC 8259 + 중복 키/잘못된 UTF-8/단독 서로게이트/`\u0000` 거부, 깊이·크기 한도, int64 정확 처리, 줄/열 오류 위치, 안정적 출력. 단위 11개, fuzz(왕복 불변식) 60초 무결함
  - [x] Flow JSON v1 로더/라이터(`flow_json.h`): 구조·타입·이름·한도·id 유일·알 수 없는 필드 오류(`x-` 확장은 보존), **키 재료 거부**(비밀 이름·PEM·`*Ref` 형식), 여러 오류를 JSON Pointer 경로와 함께 한 번에 보고, 정규 출력(고정점). 단위 16개 + fuzz 60초 무결함
  - [x] 버전 규칙: 새 버전은 거부, 구버전은 단계별 마이그레이터로 현재 스키마로 올린 뒤 검증, 경로 없음/실패는 오류, 쓰기는 항상 현재 버전. 합성 v1→v3 마이그레이션 테스트
  - [x] 골든 Flow 3개(`flow_openvpn_rx`, `flow_data_v2_rx/tx`) — C3에서 정적 Flow와 동등성 비교
  - [x] 변이 9개 검출(1개는 죽은 코드 제거로 정리)
- [x] C2 Block Registry + Validator (잘못된 Flow 사전 차단) (D-036)
  - [x] `BlockDescriptor`에 파라미터 선언(`ParamSpec`) 추가(기존 블록 등록 코드 무변경), `BlockRegistry::all()`
  - [x] `validate_flow`: 알 수 없는 블록(+가까운 이름 제안), 파라미터 선언 대조, 끊어진 엣지, 포트-블록 타입 불일치, 중복 엣지, Decision 출구 누락, 런타임, **순환(경로 출력)**, 도달 불가 — JSON Pointer 경로와 함께 한 번에 여러 개 보고
  - [x] `compile_flow`/`load_flow_json`: 텍스트 → 파싱·마이그레이션 → 검증 → 실행 가능한 `Flow`. 무효 문서는 Flow를 만들지 않음. 문법/의미 오류가 같은 `{code,path,message}` 형태
  - [x] 단위 13개 + 무작위 문서 6000개 **검증기-FlowBuilder 차등 테스트**(불일치 0) + 골든 3개를 실제 레지스트리로 로드. 변이 9개 모두 검출(테스트 결함 1건 수정: 이슈 없을 때 `issues[0]` 접근)
  - [x] fuzz `fuzz_flow_load`(텍스트→검증→컴파일→**실행**) 90초 무결함
- [x] C3 MVP-A 정적 Flow를 JSON으로 로딩해 동일 결과 (골든 동등성) (D-038)
  - [x] 골든 Flow 3개(`flow_openvpn_rx`, `flow_data_v2_rx/tx`)를 `load_flow_json`으로 로드한 Flow가 코드로 만든 정적 Flow와 **그래프 완전 동일**(라벨·블록·타입·핸들러·모든 엣지)
  - [x] **동작 동일**: 헤더 골든 전 행 + 모든 첫 바이트 256개, **실제 OpenVPN DATA_V2 골든 17개**(실제 AES-256-GCM)에서 FlowResult(결과·오류·단계 수·마지막 노드)·패킷 바이트·플래그·헤더가 같음. 복호 평문은 OpenVPN 원본과 일치, 재생·태그/암호문 변조·잘못된 key_id도 같은 사유로 같이 거부, TX는 **OpenVPN 와이어 바이트를 정확히 재현**
  - [x] 표기가 달라도(멤버 순서·공백·명시적 기본값·`x-` 확장) 같은 Flow. 골든 JSON을 일부러 망가뜨린 변이 5개(yes/no 교체, 노드 순서, 노드 삭제 ×2, 종료 엣지 삭제) 모두 그래프·동작 비교 양쪽에서 검출
  - [x] ASan/UBSan(`-Werror`) 통과

---

# Post-MVP (진입 조건: [docs/Milestones.md](docs/Milestones.md))

- [ ] PM-1 플랫폼 확장 (Windows → Android → macOS → iOS)
- [~] PM-2 네트워크 우회 — 범위 확정(D-044, [docs/PM2_NAT_Traversal_Scope.md](docs/PM2_NAT_Traversal_Scope.md) §6~§7). **2b 먼저**
  - [x] N0 진입 논의 (D-044)
  - ① STUN 기초
    - [x] N1 STUN 코덱 (D-045)
      - [x] 코덱(OpenSSL 없음): 헤더·속성 TLV·주소/XOR 주소·ERROR-CODE·UNKNOWN-ATTRIBUTES·FINGERPRINT(CRC-32)·빌더, MI 뒤 속성 무시 규칙, 미지 required 속성 보고
      - [x] `StunHmac`(OpenSSL): MI(HMAC-SHA1)·MI-SHA256(절단 허용) 검증·생성, 장기 자격증명 키(MD5/SHA-256)
      - [x] **RFC 5769 §2.1~2.4 벡터 4개**: 구조·주소·RFC 자격증명 검증·**빌더로 바이트 단위 재현**, 비트 반전 전수(FINGERPRINT·MI 영역)
      - [x] `looks_like_stun`(첫 바이트 0..3 + cookie, 256가지 전수, OpenVPN과 겹치지 않음), `StunSlot`(`ProtocolId` 2), 블록 13 `is_stun`·14 `parse_stun`, 오류 코드 `Malformed`·`ChecksumFailed`
      - [x] 공유 소켓 Flow 테스트: RFC 벡터는 STUN 쪽, 실제 OpenVPN 2.6.19 골든 패킷 17개는 OpenVPN 쪽
      - [x] 테스트 24개, `fuzz_stun` 120초 약 1,500만 회 무결함, 변이 14개 중 13개 검출(1개 동등 변이), ASan/UBSan·OpenSSL 없는 빌드 통과
      - [ ] 후속(필요 시): SASLprep/OpaqueString, USERHASH, PASSWORD-ALGORITHMS, ALTERNATE-SERVER
    - [x] N2 메모리 NAT 시뮬레이터 (D-046)
      - [x] `Nat`: 매핑 EIM/ADM/APDM × 필터링 EIF/ADF/APDF, 포트 Preserve/Sequential/Random(결정적), timeout(나감 갱신·들어옴 갱신 옵션·허용도 함께 만료), hairpin 옵션, overloading 없음, 고갈
      - [x] `Network`: 공용·사설 realm 트리, 같은 규칙으로 hairpin·**CGN 중첩**, 지연, 단조 시계, 이유별 drop 카운터 / `NetworkTransport`(connected UDP `Transport`)
      - [x] 테스트 14개: 9개 조합 매핑·필터링, 포트 할당, timeout·갱신, 고갈·재사용, **관찰 오라클 대비 무작위 300×120단계**, 라우팅·hairpin·CGN·지연·Transport, **N1 STUN Binding을 9개 조합에 통과**(매핑 주소·다른 주소/포트 응답 도착 여부)
      - [x] 변이 14개 중 13개 검출(나머지 1개는 검출되면 안 되는 대조군), ASan/UBSan·OpenSSL 없는 빌드·clang `-Werror` 통과
    - [x] N3 STUN 클라이언트 (D-047)
      - [x] Binding transaction = State Machine(RFC 8489 6.2.1: Rc 7, 두 배 RTO, Rm×RTO), Machine 타이머 `backoff` 호환 추가, 골든 `machine_stun_binding.machine.json`
      - [x] `BindingClient`: `RandomSource`의 transaction id(운영 OpenSSL, 테스트 결정적), 응답 검증(남의 것 / 버릴 것 / 오류 응답 구분), MAPPED-ADDRESS 대체 수용, trace
      - [x] `NatDiscovery`(RFC 5780, 필터링 먼저, CHANGE-REQUEST 무시 서버 불신, probe 타이밍 설정), `respond_to_binding`(RESPONSE-ORIGIN·OTHER-ADDRESS·CHANGE-REQUEST·420), `NatMapping`/`NatFiltering` 공용 헤더
      - [x] 시뮬레이터: **27개 설정 탐지 = 실제 설정**, NAT 없음, CGN 두 방향, RFC 5780 미지원, UDP 차단(39.5초), 고장 난 서버
      - [x] `pf_stun` + PAL `UdpSocket`, **수정 없는 coturn 4.6.1 + 실제 커널 NAT(nftables)**: Binding, NAT 없음 EIM+EIF, masquerade EIM+APDF, fully-random APDM+APDF (`pf_stun_coturn`, CI interop 잡에 coturn 추가 — GitHub 러너에서는 미검증)
      - [x] 테스트 18개 + `fuzz_stun_client` 80초 무결함, 변이 13개 모두 검출(2개는 테스트 보강 후), ASan/UBSan·OpenSSL 없는 빌드·clang `-Werror` 통과
  - ② PM-11 OpenVPN 호환 서버 (아래)
  - ③ 연결 서버 · hole punching · Relay
    - [ ] N4 TURN 클라이언트 → `Transport`, 폴백 `direct → turn`, coturn 상호운용, Relay 쪽 평문 없음
    - [ ] N5 연결 서버 `pf_connectd`: STUN 서버 + 자체 TURN 서버 + rendezvous (coturn `turnutils_uclient` 상호운용, 인증·한도)
    - [ ] N6 UDP hole punching Machine, 9×9 NAT 조합 예측 = 실측, 실패 시 Relay
    - [ ] N7 VPN 통합: NAT 뒤 우리 서버 등록 → 클라이언트 직접 연결 또는 Relay
    - [ ] N8 실제 NAT 랩 `tools/natlab/`(유저 공간 NAT 자체 구현) + 시나리오 JSON + 결과 리포트
  - [ ] PM-2a HTTP CONNECT / SOCKS5 / Reverse Connect (2b 뒤)
- [ ] PM-3 성능 최적화
- [~] PM-4 DSL / Compiler / IR — Control Plane 표현은 State Machine 층(F-1, D-040): **F-1 v1 완료(D-041)**, DSL/IR은 미착수
- [ ] PM-5 TAP / L2 Block
- [ ] PM-6 GUI Flow Editor — **n8n 코드는 사용하지 않음(라이선스), UX만 참고**(D-022). MVP-C 직후 에디터 PoC, Validator를 WASM으로 공유하는 방식 검토. **보안 관리자·운영자도 편집**(D-023): 역할별 권한, 승인 워크플로, 감사 로그, 버전·서명을 PoC부터 포함
- [ ] PM-7 MCP / AI 계층
- [ ] PM-8 🔧 OpenVPN DCO / Kernel Runtime (오픈소스 수정 가능성)
- [ ] PM-9 프로토콜 확장 (WireGuard / SDP / NAC)
- [ ] PM-10 암호 확장 (tls-crypt-v2, KCMVP 등)
- [ ] PM-11 OpenVPN 호환 서버 `pf_server` ([docs/PM11_OpenVPN_Server_Scope.md](docs/PM11_OpenVPN_Server_Scope.md), D-044) — 진입: PM-2b ① 뒤
  - [ ] V1 `ControlServer`(sans-I/O, 클라이언트 1개) — `fake_ovpn_server`를 정식 컴포넌트로
  - [ ] V2 다중 클라이언트·peer-id·인증 전 상태 최소화·한도
  - [ ] V3 서버 데이터 경로·TUN·주소 풀·라우팅
  - [ ] V4 TCP 서버 Transport
  - [ ] V5 `pf_server` + 수정 없는 OpenVPN 2.6 클라이언트 상호운용(UDP·TCP·재협상·동시 3개)
  - [ ] V6 1시간 soak, 성능 기준선, fuzz

### Post-MVP 공통 기반 ([plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md](plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md))

- [x] F-1 State Machine 층 v1 (D-041)
  - [x] S0 설계 확정: 평평한 상태, `packet`/`command`/`timer`/`auto` 이벤트, 카운터 guard, 5종 action, Dropped 비전이·Errored 실패, one-shot 타이머(동시 마감은 선언 순서)
  - [x] S1 `MachineRunner`(sans-I/O, 시계 주입) + `MachineBuilder` + `compile_machine`. 런타임 테스트 7개(재시도→실패, 위조 입력 비전이, 핸들러 오류, API 오용, action 순서·포화·auto 연쇄, 타이머 순서·재설정·final 해제, param 해석)
  - [x] S2 Machine Validator: 15개 테스트 + **무작위 Machine 3만 개 차등 테스트**(수락 5634개 모두 조용한 네트워크에서 유한 종료, 4125개 실행이 3회 이상 재시도 루프를 실제로 통과)
  - [x] S3 `protocol-machine` v1 로더/라이터(`upgrade_document`를 Flow JSON과 공유), 6개 테스트, fuzz 타깃 `fuzz_machine_load`(왕복 고정점 + StepLimit 없음 + 유한 종료 불변식) 150초 약 90만 회 무결함
  - [x] S4 `KeepaliveTimer` 동등성: 무작위 시나리오 4000개 동일(동시 마감 100건 이상 포함), 골든 파일에서 로드한 Machine도 동일, 변이 7개 모두 검출, 늦은 poll의 차이 1건은 문서화·테스트로 고정
  - [x] 변이 12개(Validator 규칙 6, 런타임 6) 모두 검출(1개는 테스트 보강 후), ASan/UBSan(`-Werror`) 통과
  - [ ] 후속: `spawn`/변수/Decision guard(첫 사용처에서), 난수 주입(S7), 런타임에서 `KeepaliveTimer` 교체 여부
- [x] F-2 `FlowContext` 일반화 v1 (S6, D-043)
  - [x] `ProtocolSlot`(태그 + 128B 고정 저장소, plain data만, 힙 없음) + `OvpnSlot`(`data_v2_valid` 추가). `FlowContext`에서 OpenVPN 전용 필드 제거, 파서는 항상 새 슬롯
  - [x] `BlockDescriptor::consumes`/`produces` + 등록 시 문법 검사, 기존 블록 12개에 선언(id·동작 무변경)
  - [x] `find_context_gaps`(FlowBuilder·Validator 공유), `FlowBuilder::input`, Flow JSON `flow.inputs`(v1 호환 추가), `BadInput`/`ContextNotProduced`. TX Flow 6곳·골든 `flow_data_v2_tx`에 입력 선언
  - [x] 테스트 8개: 슬롯, fact 문법, Builder/Validator 계약, 실제 OpenVPN 블록 배선 오류(decrypt 먼저·key 없이 replay·TX 입력 누락), JSON 왕복, **모든 경로 나열 오라클과 8000개 대조**, 패킷 간 슬롯 상태 비유출
  - [x] 오라클이 찾은 기존 불일치 수정: Decision 출구 `to: null`을 FlowBuilder도 허용
  - [x] C3 골든 동등성, 상호운용 3종(수정 없는 OpenVPN 2.6.19), ASan/UBSan, fuzz 3종 각 60초, DataPath 벤치 ±15% 이내. 변이 12개 모두 검출(2개는 테스트 보강 후)
- [x] F-3 Packet / Transition Trace v1 (S5, D-042)
  - [x] `TraceSink` + 고정 크기 `TraceRing`(할당 1회, 덮어쓰기 개수), 이름 복사·UTF-8 경계 안전 절단, JSON Lines(종류별 필드)
  - [x] `run_flow` 노드/종료 기록(끈 경로는 별도 인스턴스라 검사 없음), `MachineRunner` 이벤트·전이·출력·종료 기록(핸들러 Flow 포함, 시계 전달)
  - [x] 테스트: 링·JSON 3개, Flow/Machine 기록 순서·내용 5개(무작위 차등으로 trace가 동작을 바꾸지 않음 확인), **실제 OpenVPN 골든 17개로 키·nonce·평문 비노출** 1개. 변이 8개 모두 검출(1개는 테스트 보강 후)
  - [x] 성능: 끔 ≈ 18ns/8노드 실행(변경 전과 같음), 켬 ≈ 200ns, DataPath 벤치 변화 없음 (`docs/Performance_Baseline.md` §3)
  - [x] `pf_client --trace FILE [--trace-records N]`, `run_tunnel.sh` ping 시나리오에서 수정 없는 OpenVPN 2.6.19 상대로 검증(216개 기록, RX/TX 완료)
  - [x] `fuzz_flow_load`·`fuzz_machine_load`에 trace 불변식 추가, 각 80초 무결함, ASan/UBSan 통과
  - [ ] 후속: 주소 `meta`·마스킹(PM-2b), MCP Resource(PM-7), 에디터 표시(PM-6)

---

## 확인 필요 / 미결정

- [ ] A3에서 확정: TLS exporter 컨텍스트·바이트 수·방향별 키/nonce tail 분할
- [ ] 성능 목표 수치, iOS 메모리 상한 (MVP-A 기준선 이후)
- [x] Relay 구현 방식 → D-044: 자체 TURN 서버 + coturn 상호운용
- [x] 피어 역할·시그널링·순서 → D-044
- [ ] rendezvous 프로토콜 세부, TURN 자격증명 방식 (N5)
- [ ] PM-11 진입 시 5가지: 동시성 모델, 설정 형식, 클라이언트 인증, 관리 인터페이스, 플랫폼
- [ ] State Machine 세부: ~~계층 상태, guard 범위~~(D-041), `spawn`/변수, DSL 표기, 에디터 표시
- [ ] 모바일 TLS/암호 라이브러리 (PM-1 진입 전)
- [ ] Windows용 암호 라이브러리 연결 (현재 CI는 OpenSSL OFF, PM-1)
- [ ] MSVC `/WX` 적용 시점
- [ ] 법무 검토 (상용 배포 전, clean-room/GPL)
- [ ] `third_party` 무수정 검사 + upstream canary CI (의존성이 들어올 때)

---

## 이 파일 갱신 규칙

1. 작업을 시작하면 `[ ]` → `[~]`, 끝나면 `[x]`. **해당 변경과 같은 커밋**에 이 파일도 수정한다.
2. 새 작업·하위 항목은 해당 마일스톤 아래에 추가한다. 범위가 바뀌면 `docs/Milestones.md`와 `docs/DECISIONS.md`도 같이 갱신한다.
3. 막히면 `[!]`와 사유를 항목 옆에 적는다.
4. 맨 위 "지금 할 일"과 "마지막 갱신" 날짜를 항상 맞춘다.
5. 클라우드 세션의 임시 작업 목록(TaskCreate 등)은 보조 수단이다. **저장소의 이 파일이 정본**이다.
