# PM-2 네트워크 우회 — NAT Traversal 적용 범위 (초안)

- 작성일: 2026-10-06
- 상태: **참고 범위(D-039). 최종 범위·순서는 PM-2 진입 시 다시 논의해서 확정한다**
- 원 계획: `plans/Protocol_Flow_Engine_NAT_Traversal_Lab_Development_Plan.md` (이하 **[NAT 계획]**). 원 계획은 장기 비전 문서로 그대로 두고, 이 문서가 **우리 저장소의 결정·구조에 맞춘 적용안**이다.
- 공통 기반: `plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md` (F-1 State Machine, F-2 Context 일반화, F-3 Trace)

## 1. 위치

PM-2는 원래 "프록시(HTTP CONNECT/SOCKS5), Relay, Hole Punching, Reverse Connect"였다(`docs/Milestones.md`). [NAT 계획]은 이 중 Relay와 Hole Punching을 구체화한다. PM-2를 두 트랙으로 나눈다.

| 트랙 | 내용 | 비고 |
|---|---|---|
| **PM-2a** 프록시 / Reverse Connect | HTTP CONNECT, SOCKS5, Reverse Connect | 기존 범위. `Transport` 구현 추가, `FallbackPolicy`에 단계 추가 |
| **PM-2b** NAT Traversal | STUN, NAT 시뮬레이터, UDP hole punching, TURN Relay, NAT 랩 | 이 문서 |

제품 방향은 바꾸지 않는다(D-039). 주력은 계속 **멀티 플랫폼 Flow 기반 VPN 엔진**이다. NAT 랩은 처음에는 interop 랩(`tools/interop/`)처럼 **검증 인프라**로 키운다. "Protocol Lab"을 별도 제품 라인으로 둘지는 PM-6(에디터)·PM-7(MCP)이 갖춰진 뒤에 다시 결정한다.

## 2. 그대로 쓰는 기존 자산

| [NAT 계획] 항목 | 기존 자산 |
|---|---|
| Direct 실패 → TURN 전환 (§11) | `FallbackConnector`(D-034). 경로 불량의 증거가 있을 때만 폴백하고, 서버가 거절하면 폴백하지 않는다. TURN은 `FallbackPolicy`의 새 단계 |
| UDP/TCP Block (§4 Network) | `Transport`(D-032), `UdpTransport`, `TcpStream`, `FramedTransport`(D-033) |
| NAT 시뮬레이터 (§7) | `LoopbackTransport`(차단·드롭·용량 시뮬레이션)를 확장 |
| 실제 NAT 환경 (§6) | `tools/interop/lab.sh`(netns + veth), B3의 nftables 차단 |
| Scenario JSON (§19) | 엄격 JSON(`json.h`), JSON Pointer 오류 보고 |
| 재시도·Timeout (§5) | 지금은 `KeepaliveTimer`·`reliable.h` 방식의 sans-I/O 코드. F-1이 들어오면 State Machine |
| 파서 품질 | 파서마다 전수 테스트 또는 fuzz 타깃 규칙. STUN은 **RFC 5769 공식 테스트 벡터**를 골든으로 쓴다 |
| 상호운용 검증 | 수정 없는 OpenVPN 2.6을 상대로 한 방식(D-015)을 **수정 없는 coturn**에 그대로 적용 |

## 3. [NAT 계획]과 충돌하는 점과 해소 방법

| # | 충돌·누락 | 해소 |
|---|---|---|
| 1 | §5 Timer/State/Retry를 Flow 안에서 표현 → 현재 Flow는 DAG이고 순환 금지(D-009, D-036) | **두 층 모델(D-040)**: 순환은 State Machine 층에만 둔다. PM-4(F-1)가 아직이면 PM-2b의 제어 로직은 sans-I/O 일반 코드로 짜고, 나중에 동등성 테스트를 거쳐 Machine으로 옮긴다 |
| 2 | `FlowContext`가 OpenVPN 전용 | STUN Block을 넣기 전에 **F-2 Context 일반화**를 먼저 한다 |
| 3 | §24 VPN 통합: 수정 없는 OpenVPN 서버는 STUN/hole punching을 하지 않는다. 지금은 클라이언트 전용(D-008) | 양쪽에서 구멍을 뚫는 hole punching은 **양 끝이 우리 구현일 때만** 의미가 있다. **우리 쪽 서버나 P2P 역할을 둘지 별도 결정이 필요하다**(§7 Q1). 그 결정 없이 VPN에 바로 쓸 수 있는 것은 TURN Relay 경로뿐이다 |
| 4 | 시그널링 채널이 없다(§9 "Public Endpoint Info" 교환 방법 미정) | 랩용 최소 rendezvous 서버(후보 교환만, 인증 필수)를 N4 범위에 넣는다. 운영용 시그널링은 §7 Q2 |
| 5 | §21 디렉터리 구조(`protocols/`, `natlab/`, `transport/`, `compiler/` …)가 기존 규칙과 다르다 | **기존 구조에 맞춘다**(§5 매핑표). 새 최상위 트리를 만들지 않는다 |
| 6 | NAT 유형 용어를 RFC 3489(Cone/Symmetric)로 쓴다 | 기준 용어는 **RFC 4787**(매핑 3종 × 필터링 3종)과 **RFC 5780**(동작 탐지)로 한다. Cone 이름은 사람이 보는 별칭으로만 쓴다. RFC 3489식 "NAT 타입 판별"은 결과가 불안정해서 폐기된 방식이므로 판별 결과는 "관찰된 동작"으로 보고한다 |
| 7 | 실제 NAT 랩에서 4가지 유형을 모두 재현한다고 가정 | Linux netfilter 기본 동작은 Port Restricted Cone에 가깝고, `masquerade random-fully`는 Symmetric에 가깝다. **Full Cone·Restricted Cone은 표준 netfilter로 만들 수 없다**(트리 밖 커널 모듈은 🔧). 그래서 두 층으로 둔다: ① 메모리 시뮬레이터(모든 조합, 결정적), ② 실제 랩은 netfilter로 되는 조합 + 유저 공간 NAT 프로세스(TUN 기반)로 나머지 |
| 8 | §23 NAT MVP에 MCP Interface 포함 | PM-7의 진입 조건은 MVP-C + PM-6 설계다. **MCP는 PM-2b에서 뺀다.** 대신 trace와 시나리오 결과를 기계가 읽을 수 있는 JSON으로 남겨서 PM-7이 그대로 쓰게 한다 |
| 9 | §25 범용 플랫폼(SDP/NAC/DLP/TLS) | PM-9 범위다. PM-2에서 다루지 않는다 |
| 10 | 보안 항목 부재 | `docs/Threat_Model_and_Key_Management.md` §8에 추가했다(STUN 위조, 열린 TURN Relay, consent, UPnP 포트 개방, 자격증명) |

## 4. 같은 소켓에서 STUN과 OpenVPN 구분

hole punching으로 만든 NAT 매핑을 OpenVPN 데이터에 그대로 쓰려면 같은 UDP 소켓에서 두 프로토콜을 받아야 한다. 첫 바이트로 구분할 수 있다(RFC 7983과 같은 접근).

| 첫 바이트 | 프로토콜 | 근거 |
|---|---|---|
| `0x00`–`0x03` | STUN | 상위 2비트 0 (RFC 8489 §5). 추가로 4–7바이트의 magic cookie `0x2112A442`를 확인 |
| `0x08` 이상 | OpenVPN | `opcode << 3 | key_id`, opcode는 1–11 (`openvpn_header.h`) |
| 그 외 | Drop(`InvalidOpcode` 계열) | |

이것을 Decision Block(`is_stun`)으로 만들고, 수신 Flow의 맨 앞에 둔다. 전수 테스트(첫 바이트 256개)를 둔다.

## 5. 디렉터리 매핑 ([NAT 계획] §21 → 이 저장소)

| [NAT 계획] | 이 저장소 |
|---|---|
| `protocols/stun`, `turn`, `ice` | `core/include/pf/stun/`, `core/src/stun/` (코덱·sans-I/O 클라이언트). Block은 `core/src/blocks/stun_blocks.cpp` |
| `protocols/upnp`, `natpmp`, `pcp` | 코덱은 `core/`, 소켓·멀티캐스트는 `platform/<os>/` |
| `transport/udp`, `tcp`, `ipv6` | 이미 있음: `core/include/pf/transport.h`, `platform/linux/` |
| `natlab/simulator` | `core/include/pf/nat_sim.h`(메모리 시뮬레이터, `Transport` 위) — 테스트와 퍼저가 함께 쓰므로 코어에 둔다 |
| `natlab/topology`, `scenarios`, `controller`, `metrics` | `tools/natlab/` (netns 토폴로지 스크립트, 시나리오 JSON, 결과 리포트) |
| `test/simulator`, `replay` | `tests/unit`, `tests/flow`, `tests/protocol` (기존 라벨 체계) |
| `mcp/` | PM-7에서 결정 |
| `editor/` | PM-6에서 결정 |
| `compiler/` | PM-4에서 결정 |

## 6. 단계 (PM-2b 적용안)

각 단계는 TDD로 진행하고 종료 조건을 자동 테스트로 판정한다(진행 규칙은 `docs/Milestones.md`와 동일).

| 단계 | 내용 | 종료 조건 | 선행 |
|---|---|---|---|
| N0 | PM-2 진입 논의: §7 질문 결정, PM-2와 PM-4 순서, 이 문서 확정 | DECISIONS 기록 | — |
| N1 | STUN 코덱(RFC 8489): 헤더, 속성 TLV, XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY(-SHA256), FINGERPRINT | **RFC 5769 벡터 통과**, 전수/경계 테스트, fuzz 타깃 `fuzz_stun` | F-2 |
| N2 | 메모리 NAT 시뮬레이터: RFC 4787 매핑 3종 × 필터링 3종, 매핑 timeout, 포트 할당(보존/순차/무작위), hairpin 옵션 | 9개 조합 각각의 매핑·필터링 동작 테스트, 가짜 시계로 timeout | — |
| N3 | STUN 클라이언트(sans-I/O): 재전송(RFC 8489 RTO), transaction 검증, 공인 엔드포인트, RFC 5780 동작 탐지 | 시뮬레이터 9조합에서 기대한 관찰 결과, **수정 없는 coturn**과 netns 상호운용 | N1, N2 |
| N4 | UDP hole punching 상태머신 + 랩용 rendezvous: 후보 교환, 동시 probe, connectivity check, 재시도·timeout | 9×9 NAT 조합 매트릭스에서 **예측(RFC 4787 규칙으로 계산) = 실측**, 실패 조합은 timeout 안에 실패 보고 | N3 |
| N5 | TURN 클라이언트(RFC 8656): Allocate, 장기 자격증명(KeyRef), Refresh, CreatePermission, ChannelBind, ChannelData. **TURN Relay를 `Transport`로 구현** → `FallbackPolicy`에 `direct → turn` | coturn 상호운용, **Relay 쪽 캡처에서 평문 없음**(종단 간 암호화 확인), 할당 갱신·만료 테스트 | N3 |
| N6 | 실제 NAT 랩 + 시나리오: `tools/natlab/`(netns + nftables + 유저 공간 NAT), 시나리오 JSON([NAT 계획] §19 형식을 엄격 JSON으로), 결과 비교 리포트(§20) | 자동 매트릭스 실행, 결과 JSON, ctest 라벨 `protocol`(root, RESOURCE_LOCK) | N4, N5, F-3 |
| N7 | VPN 통합: hole punching 또는 TURN 위에서 OpenVPN 세션 | §7 Q1 결정에 따름. TURN 경로는 수정 없는 OpenVPN 서버로 검증 가능 | N5, Q1 |

뒤로 미루는 것(PM-2b 이후 별도 결정):

| 항목 | 이유 |
|---|---|
| ICE 전체(RFC 8445) | 후보 쌍 스케줄링이 F-1 State Machine에 크게 의존한다. N4·N5로 핵심 경로를 먼저 검증. 필요하면 ICE-lite부터 |
| TCP hole punching (RFC 6062, simultaneous open) | OS·NAT 의존성이 커서 결과가 불안정하다. 실험 항목으로만 |
| UPnP IGD / NAT-PMP(RFC 6886) / PCP(RFC 6887) | 사용자 공유기의 포트를 여는 기능이라 정책·위협 검토가 먼저다(위협 모델 §8) |
| IPv6 비교 실습 | PM-1 플랫폼 확장과 함께 |
| MCP 도구(`nat.configure`, `trace.analyze` …), AI 분석·리포트 | PM-7 |

## 7. PM-2 진입 시 결정할 질문

1. **피어 역할**: 우리 구현이 서버나 P2P 피어 역할을 할 것인가? (hole punching을 VPN에 쓰려면 필요. MVP는 클라이언트 전용, D-008)
2. **시그널링**: 운영용 rendezvous를 기존 표준(SIP, XMPP 등)으로 할지, 단순 HTTPS API로 자체 구현할지, 인증은 무엇으로 할지
3. **PM-2와 PM-4 순서**: PM-4(F-1)를 먼저 해서 PM-2b 제어 로직을 처음부터 Machine으로 쓸지, PM-2b를 일반 코드로 먼저 하고 나중에 옮길지
4. **Relay 운영**: TURN 표준 + 수정 없는 coturn으로 충분한지, 자체 Relay가 필요한지 (기존 미결 1번을 이 질문으로 대체)
5. **유저 공간 NAT 구현**: 랩에서 Full/Restricted Cone을 만들 유저 공간 NAT를 자체 구현할지, 기존 도구(수정 없이)를 쓸지

## 8. 참고 표준과 오픈소스

RFC와 오픈소스 목록은 `docs/References_OpenSource_Papers.md` §10에 정리했다. 구현 근거는 RFC로 한정한다(clean-room, D-010). 오픈소스는 상호운용 상대나 동작 비교용으로만 쓰고 코드를 복사하지 않는다.
