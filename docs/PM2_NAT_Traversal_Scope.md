# PM-2 네트워크 우회 — NAT Traversal 적용 범위

- 작성일: 2026-10-06
- 상태: **확정(D-044, 2026-10-06 PM-2 진입 논의 N0)**. 처음 범위는 D-039(참고 범위)였다. N0에서 서버 역할, 연결 서버, 자체 TURN 서버, 순서를 정했다(§7)
- 원 계획: `plans/Protocol_Flow_Engine_NAT_Traversal_Lab_Development_Plan.md` (이하 **[NAT 계획]**). 원 계획은 장기 비전 문서로 그대로 두고, 이 문서가 **우리 저장소의 결정·구조에 맞춘 적용안**이다.
- 공통 기반: `plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md` (F-1 State Machine, F-2 Context 일반화, F-3 Trace)

## 1. 위치

PM-2는 원래 "프록시(HTTP CONNECT/SOCKS5), Relay, Hole Punching, Reverse Connect"였다(`docs/Milestones.md`). [NAT 계획]은 이 중 Relay와 Hole Punching을 구체화한다. PM-2를 두 트랙으로 나눈다.

| 트랙 | 내용 | 비고 |
|---|---|---|
| **PM-2a** 프록시 / Reverse Connect | HTTP CONNECT, SOCKS5, Reverse Connect | 기존 범위. `Transport` 구현 추가, `FallbackPolicy`에 단계 추가 |
| **PM-2b** NAT Traversal | STUN, NAT 시뮬레이터, **연결 서버**(rendezvous + STUN + TURN), UDP hole punching, TURN Relay, NAT 랩 | 이 문서. **먼저 진행**(D-044) |

PM-2b는 **PM-11 OpenVPN 호환 서버**(`docs/Milestones.md`, D-044)와 맞물린다. hole punching은 양 끝이 모두 우리 구현일 때만 VPN에 쓸모가 있기 때문이다. 대표 사례: NAT 뒤에 있는 우리 VPN 서버(포트포워딩이 안 되는 사무실·가정)에 NAT 뒤의 우리 클라이언트가 직접 붙고, 안 되면 Relay로 붙는다.

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
| 2 | `FlowContext`가 OpenVPN 전용 | STUN Block을 넣기 전에 **F-2 Context 일반화**를 먼저 한다 → **완료(D-043)**: STUN은 `StunSlot`(새 `ProtocolId`)과 `stun.*` fact로 추가한다 |
| 3 | §24 VPN 통합: 수정 없는 OpenVPN 서버는 STUN/hole punching을 하지 않는다. 지금은 클라이언트 전용(D-008) | **해소(D-044)**: 우리가 **OpenVPN 호환 서버**(PM-11)를 만든다. 수정 없는 OpenVPN 2.6 클라이언트와 `pf_client`를 모두 받는다. NAT 기능(등록·hole punching·Relay)은 우리 서버와 우리 클라이언트 사이에서 쓰고, 수정 없는 클라이언트는 지금처럼 직접 연결한다 |
| 4 | 시그널링 채널이 없다(§9 "Public Endpoint Info" 교환 방법 미정) | **해소(D-044)**: 양쪽 모두 NAT 뒤이므로 공인 주소의 외부 서버가 반드시 필요하다. 우리 **연결 서버**(§6.1)가 rendezvous를 맡는다 |
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
| `protocols/stun`, `turn`, `ice` | 코덱 `core/include/pf/stun.h`·`core/src/stun.cpp`(기존처럼 평평한 파일 구조), 슬롯 `pf/stun_context.h`, HMAC `pf/crypto/stun_hmac.h`, 블록 `pf/blocks/stun_blocks.h` (N1, D-045). TURN·클라이언트 Machine도 같은 방식으로 둔다 |
| `protocols/upnp`, `natpmp`, `pcp` | 코덱은 `core/`, 소켓·멀티캐스트는 `platform/<os>/` |
| `transport/udp`, `tcp`, `ipv6` | 이미 있음: `core/include/pf/transport.h`, `platform/linux/` |
| `natlab/simulator` | `core/include/pf/nat_sim.h`(메모리 시뮬레이터, `Transport` 위) — 테스트와 퍼저가 함께 쓰므로 코어에 둔다 |
| `natlab/topology`, `scenarios`, `controller`, `metrics` | `tools/natlab/` (netns 토폴로지 스크립트, 시나리오 JSON, 결과 리포트) |
| `test/simulator`, `replay` | `tests/unit`, `tests/flow`, `tests/protocol` (기존 라벨 체계) |
| (신규) 연결 서버 | 프로토콜 로직(STUN/TURN 서버, rendezvous)은 `core/`(sans-I/O, State Machine), 소켓·이벤트 루프는 `platform/linux/`, 실행 파일은 `tools/pf_connectd/` |
| (신규) VPN 서버 | PM-11: `ControlServer` 등은 `core/`, 실행 파일은 `tools/pf_server/` (`docs/PM11_OpenVPN_Server_Scope.md`) |
| `mcp/` | PM-7에서 결정 |
| `editor/` | PM-6에서 결정 |
| `compiler/` | PM-4에서 결정 |

## 6. 단계 (확정, D-044)

각 단계는 TDD로 진행하고 종료 조건을 자동 테스트로 판정한다(진행 규칙은 `docs/Milestones.md`와 같다). 제어 로직(STUN 재전송, hole punching, TURN 할당·갱신, 등록)은 **처음부터 State Machine**(F-1, `protocol-machine`)으로 작성하고, 패킷 처리는 Flow로 작성한다. 모든 단계는 Trace(F-3)로 관찰할 수 있게 한다.

**① STUN 기초 (서버 없이 가능)**

| 단계 | 내용 | 종료 조건 | 선행 |
|---|---|---|---|
| N0 ✅ | PM-2 진입 논의 | D-044 | — |
| N1 ✅ | STUN 코덱(RFC 8489, D-045): 헤더, 속성 TLV, XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY(-SHA256), FINGERPRINT. `StunSlot`(새 `ProtocolId`)과 `stun.*` fact, STUN/OpenVPN 첫 바이트 구분 Decision 블록(§4) | **RFC 5769 벡터 통과**, 전수·경계 테스트, fuzz 타깃 `fuzz_stun` | F-2 ✅ |
| N2 | 메모리 NAT 시뮬레이터: RFC 4787 매핑 3종 × 필터링 3종, 매핑 timeout, 포트 할당(보존/순차/무작위), hairpin 옵션 | 9개 조합 각각의 매핑·필터링 동작 테스트, 가짜 시계로 timeout | — |
| N3 | STUN 클라이언트(binding transaction Machine): 재전송(RFC 8489 RTO), transaction 검증, 공인 엔드포인트, RFC 5780 동작 탐지. 난수 주입(F-1 후속) | 시뮬레이터 9조합에서 기대한 관찰 결과, **수정 없는 coturn**과 netns 상호운용 | N1, N2 |

N1 구현 노트(D-045):
- 구현한 것: 코덱, FINGERPRINT, MI/MI-SHA256 검증·생성, 장기 자격증명 키, 주소·오류 코드 디코더, `looks_like_stun`, `StunSlot`, 블록 `is_stun`(13)·`parse_stun`(14).
- 아직 없는 것: SASLprep/OpaqueString, USERHASH, PASSWORD-ALGORITHMS 협상, ALTERNATE-SERVER. N3 이후 필요할 때 추가한다.
- RFC 5769 벡터는 `tests/regression/golden/stun_rfc5769.golden`에 있다.

**② PM-11 OpenVPN 호환 서버** — 별도 마일스톤(`docs/Milestones.md` PM-11). NAT와 무관하게도 제품 가치가 있다.

**③ 연결 서버 + hole punching + Relay**

| 단계 | 내용 | 종료 조건 | 선행 |
|---|---|---|---|
| N4 | TURN 클라이언트(RFC 8656): Allocate, 장기 자격증명(KeyRef), Refresh, CreatePermission, ChannelBind, ChannelData. **TURN Relay를 `Transport`로 구현**하고 `FallbackPolicy`에 `direct → turn` 추가 | **수정 없는 coturn**과 상호운용, **Relay 쪽 캡처에 평문 없음**(종단 간 암호화 확인), 할당 갱신·만료 테스트. 수정 없는 OpenVPN 서버로도 검증 가능(서버는 Relay 주소로 응답) | N3 |
| N5 | **연결 서버** `pf_connectd`(§6.1): STUN 서버 + **자체 TURN 서버**(RFC 8656) + rendezvous(VPN 서버 등록, 클라이언트 조회·후보 교환) | 우리 TURN 서버 ↔ **coturn 테스트 클라이언트(`turnutils_uclient`)**, 우리 TURN 클라이언트 ↔ 우리 서버, STUN 서버 ↔ coturn STUN 클라이언트. 인증·할당 한도·permission 강제 테스트 | N4 |
| N6 | UDP hole punching Machine: 후보 수집(host/srflx/relay), rendezvous로 교환, 동시 probe, 인증된 connectivity check, 재시도·timeout, 실패 시 Relay | 9×9 NAT 조합 매트릭스에서 **예측(RFC 4787 규칙으로 계산) = 실측**, 실패 조합은 제한 시간 안에 Relay로 전환 | N5, PM-11 |
| N7 | VPN 통합: NAT 뒤의 우리 서버가 연결 서버에 등록 → 우리 클라이언트가 조회 → 직접 연결(punching) 또는 Relay → OpenVPN 세션. keepalive를 NAT 매핑 수명에 맞춤 | netns 랩: 양쪽 NAT 뒤에서 터널 ping 성공, punching 불가 조합에서는 Relay로 성공, 연결 서버는 평문을 보지 못함 | N6 |
| N8 | 실제 NAT 랩 + 시나리오: `tools/natlab/`(netns + nftables + 유저 공간 NAT, §7 Q5), 시나리오 JSON([NAT 계획] §19 형식을 엄격 JSON으로), 결과 비교 리포트(§20) | 자동 매트릭스 실행, 결과 JSON, ctest 라벨 `protocol`(root, RESOURCE_LOCK) | N6, F-3 ✅ |

### 6.1 연결 서버 (`pf_connectd`, 설계 방향)

공인 주소에 두는 서버 하나에 세 기능을 **통합**한다(D-044). 인증·한도·감사 로그를 한 곳에서 관리하고, 내부는 모듈로 나눠 따로 띄울 수도 있게 한다.

| 기능 | 하는 일 | 표준 |
|---|---|---|
| STUN | 공인 엔드포인트 알려주기(binding) | RFC 8489 |
| TURN | 직접 연결이 안 될 때 암호화된 패킷 중계. **키를 갖지 않는다** | RFC 8656 |
| rendezvous | 우리 VPN 서버가 이름으로 등록, 클라이언트가 조회해서 후보 주소 교환, punching 시작 신호 | 자체(아래) |

- **rendezvous 프로토콜(검토안, N5에서 확정)**: STUN 메시지 형식을 확장한 자체 메서드를 둔다(TURN이 STUN을 확장하는 것과 같은 방식). 이렇게 하면 한 포트·한 코덱(N1)·한 인증 방식(MESSAGE-INTEGRITY + 장기 자격증명)으로 세 기능을 모두 처리한다. 대안은 별도 HTTPS API다.
- **인증**:
  - 등록하는 VPN 서버와 조회하는 클라이언트 모두 자격증명이 필요하다(KeyRef로만 다룸).
  - 조회 권한: 어떤 클라이언트가 어떤 서버를 찾을 수 있는가.
  - TURN 자격증명: 장기 자격증명, 또는 coturn과 같은 공유 비밀 기반 단기 자격증명. N5에서 결정한다.
- **남용 방지**: 할당 수, 대역폭, 수명의 한도. permission은 rendezvous로 확인한 상대 주소에만 준다. 열린 Relay가 되지 않게 한다(위협 모델 §8.1).
- **신뢰**: 연결 서버는 **신뢰하지 않는 중간 노드**다. VPN 세션의 인증과 암호화는 종단 간(우리 클라이언트 ↔ 우리 서버)이다. 연결 서버가 장악돼도 터널 내용과 키는 노출되지 않는다. 노출되는 것은 "누가 누구에게 연결하는가"라는 메타데이터와 가용성이다.

뒤로 미루는 것(PM-2b 이후 별도 결정):

| 항목 | 이유 |
|---|---|
| ICE 전체(RFC 8445) | 후보 쌍 스케줄링이 F-1 State Machine에 크게 의존한다. N4~N6으로 핵심 경로를 먼저 검증. 필요하면 ICE-lite부터 |
| TCP hole punching (RFC 6062, simultaneous open) | OS·NAT 의존성이 커서 결과가 불안정하다. 실험 항목으로만 |
| UPnP IGD / NAT-PMP(RFC 6886) / PCP(RFC 6887) | 사용자 공유기의 포트를 여는 기능이라 정책·위협 검토가 먼저다(위협 모델 §8) |
| IPv6 비교 실습 | PM-1 플랫폼 확장과 함께 |
| MCP 도구(`nat.configure`, `trace.analyze` …), AI 분석·리포트 | PM-7 |

## 7. PM-2 진입 논의 결과 (N0, D-044)

| # | 질문 | 결정 |
|---|---|---|
| Q1 | 피어 역할 | **OpenVPN 호환 서버를 만든다**(PM-11). 클라이언트끼리의 P2P는 쓰임새가 약하므로 두지 않는다. 수정 없는 OpenVPN 2.6 클라이언트와 `pf_client`를 모두 받는다 |
| Q2 | 시그널링 | 공인 외부 서버가 필요하다. 우리 **연결 서버**의 rendezvous 기능으로 한다(§6.1). 프로토콜 세부(STUN 확장 메서드 또는 HTTPS)는 N5에서 정한다 |
| Q3 | PM-2와 PM-4 순서 | F-1이 끝났으므로 **PM-2b 제어 로직은 처음부터 State Machine**으로 작성한다. DSL/IR(PM-4 나머지)은 PM-2b를 막지 않는다 |
| Q4 | Relay 운영 | **자체 TURN 서버(RFC 8656)도 구현**한다(연결 서버에 포함). 수정 없는 coturn은 양방향 상호운용 상대로 쓴다(우리 클라이언트 ↔ coturn 서버, 우리 서버 ↔ coturn 테스트 클라이언트). 기존 미결 1번은 이것으로 닫는다 |
| Q5 | 유저 공간 NAT | **기술 기본값**: N2 메모리 시뮬레이터 코어를 재사용해 `tools/natlab/`에 자체 구현한다(TUN 기반). RFC 4787 조합을 설정할 수 있는 수정 없는 기존 도구가 마땅치 않기 때문이다. N8에서 확인한다 |
| — | 트랙 순서 | **PM-2b 먼저**, PM-2a(프록시)는 그 뒤 |
| — | 작업 순서 | **① STUN 기초(N1~N3) → ② PM-11 서버 → ③ TURN·연결 서버·punching·VPN 통합·랩(N4~N8)** |

## 8. 참고 표준과 오픈소스

RFC와 오픈소스 목록은 `docs/References_OpenSource_Papers.md` §10에 정리했다. 구현 근거는 RFC로 한정한다(clean-room, D-010). 오픈소스는 상호운용 상대나 동작 비교용으로만 쓰고 코드를 복사하지 않는다.
