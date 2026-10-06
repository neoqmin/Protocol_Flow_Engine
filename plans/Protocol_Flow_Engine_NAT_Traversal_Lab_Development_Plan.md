# Protocol Flow Engine — NAT Traversal Lab Extension Development Plan

## 1. 문서 목적

본 문서는 기존 **Protocol Flow Engine**을 VPN 이외의 네트워크 프로토콜 실습으로 확장하기 위한 **NAT Traversal Lab 개발계획**이다.

주요 대상:
- STUN
- NAT Type Detection
- UDP Hole Punching
- TCP Hole Punching
- TURN / Relay
- ICE
- UPnP IGD
- NAT-PMP
- PCP
- IPv4 / IPv6 Connectivity
- VPN/Tunnel 기반 NAT Traversal

핵심 방향은 NAT Traversal을 별도 하드코딩 프로그램으로 만드는 것이 아니라, **Block + Decision + State + Timer + Packet + Session**을 조합하여 다양한 traversal 방법을 실험하는 것이다.

---

## 2. 전체 구조

```text
                  Protocol Flow Engine
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
       VPN            NAT Traversal          TLS
        │                  │                  │
   OpenVPN/DCO       ┌─────┼─────┐            │
                     │     │     │
                    STUN   P2P   TURN
                     │     │     │
                    ICE Hole   Relay
                       Punch
```

최종적으로 다음과 같은 자연어 실습을 목표로 한다.

> Symmetric NAT 두 개를 구성하고 STUN으로 public endpoint를 확인한 뒤 UDP hole punching을 수행한다. 직접 연결이 실패하면 TURN으로 전환하고 모든 packet/Mapping/Flow trace를 기록한다.

---

## 3. 주요 개발 목표

### 3.1 UDP Hole Punching

```text
START
  ↓
BIND_UDP
  ↓
STUN_REQUEST
  ↓
GET_PUBLIC_ENDPOINT
  ↓
PEER_DISCOVERY
  ↓
UDP_HOLE_PUNCH
  ↓
CONNECTIVITY_CHECK
  │
  ├── YES → DIRECT_P2P
  └── NO  → TURN_ALLOCATE → RELAY
```

### 3.2 ICE

```text
GATHER_CANDIDATES
       ↓
EXCHANGE_CANDIDATES
       ↓
FORM_CANDIDATE_PAIRS
       ↓
CONNECTIVITY_CHECK
       ↓
SELECT_BEST_PAIR
       ↓
NOMINATE
       ↓
CONNECTED
```

---

## 4. Block Architecture

### Network

```text
UDP_BIND
UDP_SEND
UDP_RECEIVE
UDP_CLOSE

TCP_CONNECT
TCP_LISTEN
TCP_ACCEPT
TCP_SEND
TCP_RECEIVE

SOCKET_OPTION
SOCKET_CLOSE
```

### NAT

```text
STUN_REQUEST
STUN_RESPONSE_PARSE
DISCOVER_PUBLIC_ENDPOINT
NAT_TYPE_DETECT

PORT_MAPPING_REQUEST
PORT_MAPPING_RELEASE
```

### P2P

```text
PEER_DISCOVERY
PEER_ENDPOINT_UPDATE
UDP_HOLE_PUNCH
TCP_HOLE_PUNCH
CONNECTIVITY_CHECK
KEEPALIVE
```

### Relay

```text
TURN_ALLOCATE
TURN_PERMISSION
TURN_CHANNEL
TURN_SEND
TURN_RECEIVE
RELAY_CONNECTION
```

### ICE

```text
GATHER_CANDIDATES
CANDIDATE_PAIR
CONNECTIVITY_CHECK
PAIR_PRIORITY
SELECT_PAIR
NOMINATE_PAIR
```

### Gateway

```text
UPNP_DISCOVER
UPNP_ADD_MAPPING
UPNP_DELETE_MAPPING

NATPMP_MAP
NATPMP_UNMAP

PCP_MAP
PCP_DELETE
```

### Decision

```text
NAT_IS_FULL_CONE
NAT_IS_RESTRICTED
NAT_IS_PORT_RESTRICTED
NAT_IS_SYMMETRIC

DIRECT_CONNECTION_AVAILABLE
RELAY_REQUIRED
MAPPING_AVAILABLE
TIMEOUT
RETRY_REQUIRED
```

---

## 5. State / Timer Model

NAT traversal은 Packet Flow뿐 아니라 상태와 Timer가 핵심이다.

```text
IDLE
  ↓
DISCOVERING
  ↓
PUBLIC_ENDPOINT_KNOWN
  ↓
PEER_KNOWN
  ↓
PUNCHING
  ↓
CHECKING
  ├── CONNECTED
  └── FAILED → RELAY
```

필요한 Context:

```text
FLOW_CONTEXT
SESSION_CONTEXT
PEER_CONTEXT
NAT_CONTEXT
CANDIDATE_CONTEXT
TIMER_CONTEXT
```

Timer Block:

```text
TIMER_START
TIMER_STOP
TIMER_RESET
TIMER_EXPIRED
RETRY
TIMEOUT
```

예:

```text
UDP_HOLE_PUNCH
 ↓
WAIT 100ms
 ↓
RETRY
 ↓
WAIT 100ms
 ↓
RETRY
 ↓
TIMEOUT
```

---

## 6. NAT Lab

실제 공유기만 사용하는 것이 아니라 **NAT Simulator + 실제 NAT 환경**을 함께 지원한다.

기본 토폴로지:

```text
                    Internet
                       │
              ┌────────┴────────┐
              │                 │
           NAT-A             NAT-B
              │                 │
             PC-A              PC-B
```

확장 토폴로지:

```text
                    Router
                      │
             ┌────────┴────────┐
             │                 │
          NAT-A              NAT-B
             │                 │
            A1                 B1
```

---

## 7. NAT Simulator

다음 정책을 시뮬레이션한다.

```text
Endpoint Independent Mapping
Address Dependent Mapping
Address and Port Dependent Mapping

Endpoint Independent Filtering
Address Dependent Filtering
Address and Port Dependent Filtering
```

이를 조합하여 NAT 동작을 재현한다.

주요 유형:

```text
Full Cone
Restricted Cone
Port Restricted Cone
Symmetric NAT
```

또한 NAT mapping timeout, port allocation, filtering 정책도 조절할 수 있도록 한다.

---

## 8. STUN

### Client

```text
STUN_REQUEST
      ↓
UDP_SEND
      ↓
STUN_RESPONSE
      ↓
STUN_RESPONSE_PARSE
      ↓
PUBLIC_ENDPOINT
```

### Server

```text
STUN_SERVER
 ├── RECEIVE
 ├── PARSE
 ├── REFLEXIVE_ADDRESS
 └── RESPONSE
```

---

## 9. UDP Hole Punching 실습

```text
Peer A                         Peer B
  │                              │
  ├── STUN ────────→ Server     │
  │                              ├── STUN → Server
  │                              │
  ├────── Public Endpoint Info ──┤
  │                              │
  ├──────── UDP Probe ──────────→│
  │←──────── UDP Probe ──────────┤
  │                              │
  └──────── Direct P2P ─────────┘
```

Flow:

```text
BIND
 ↓
STUN
 ↓
PEER_DISCOVERY
 ↓
UDP_HOLE_PUNCH
 ↓
CONNECTIVITY_CHECK
 ↓
CONNECTED
```

---

## 10. TCP Hole Punching

UDP와 별도의 실험 Flow로 구성한다.

```text
TCP_BIND
 ↓
STUN
 ↓
PEER_DISCOVERY
 ↓
SIMULTANEOUS_CONNECT
 ↓
TCP_CONNECTIVITY_CHECK
 ↓
SUCCESS / FAIL
```

NAT 및 OS TCP stack 동작에 따라 결과가 달라질 수 있으므로 실험 결과를 자동 기록한다.

---

## 11. TURN Relay

직접 연결 실패 시 Relay로 전환한다.

```text
DIRECT P2P
    │
    │ FAIL
    ▼
TURN_ALLOCATE
    ↓
TURN_PERMISSION
    ↓
TURN_CHANNEL
    ↓
RELAY
```

예:

```text
STUN
 ↓
PEER_DISCOVERY
 ↓
HOLE_PUNCH
 ↓
CONNECTIVITY_CHECK
 ├── SUCCESS → P2P
 └── FAIL → TURN
```

---

## 12. ICE

ICE를 NAT Traversal 상위 Flow로 구현한다.

Candidate:

```text
HOST
SERVER_REFLEXIVE
RELAY
```

Flow:

```text
GATHER_CANDIDATES
       ↓
EXCHANGE_CANDIDATES
       ↓
FORM_CANDIDATE_PAIRS
       ↓
CONNECTIVITY_CHECK
       ↓
SELECT_BEST_PAIR
       ↓
NOMINATE
       ↓
CONNECTED
```

---

## 13. UPnP / NAT-PMP / PCP

NAT Gateway 제어 계열도 공통 Interface로 추상화한다.

```text
DISCOVER_GATEWAY
       ↓
REQUEST_PORT_MAPPING
       ↓
MAPPING_RESULT
       ↓
DIRECT_CONNECTION
```

Provider:

```text
PortMappingProvider
 ├── UPnP
 ├── NAT-PMP
 └── PCP
```

---

## 14. IPv6 실습

IPv4 NAT 환경과 IPv6 direct/firewall 환경을 비교한다.

```text
IPv4
A → NAT → Internet ← NAT ← B

IPv6
A ───────── Internet ───────── B
```

실습 대상:

```text
IPv4 Direct
IPv4 NAT Traversal
IPv6 Direct
IPv6 Firewall Traversal
```

---

## 15. Packet Trace

모든 Block 실행을 Trace한다.

예:

```text
[10:00:01.001]
STUN_REQUEST

[10:00:01.015]
STUN_RESPONSE

[10:00:01.016]
PUBLIC_ENDPOINT = x.x.x.x:49152

[10:00:01.100]
UDP_PROBE → peer

[10:00:01.103]
UDP_PROBE ← peer

[10:00:01.104]
CONNECTIVITY_CHECK = PASS
```

AI가 이 Trace를 분석할 수 있도록 MCP Resource로 제공한다.

---

## 16. MCP / AI 연계

NAT Lab은 기존 MCP 확장계획과 직접 연결한다.

```text
AI
 │
MCP
 │
 ├── block.search
 ├── flow.create
 ├── flow.validate
 ├── flow.compile
 ├── test.create
 ├── test.run
 ├── nat.configure
 ├── packet.capture
 └── trace.analyze
```

AI가 다음과 같은 요청을 수행할 수 있어야 한다.

> Full Cone NAT 환경에서 UDP Hole Punching을 테스트하는 Flow를 만들어줘.

또는:

> Symmetric NAT에서 직접 연결을 시도하고 실패하면 TURN Relay로 전환하도록 만들어줘.

---

## 17. AI 기반 NAT 분석

실험 결과를 AI가 분석한다.

입력:

```text
NAT Type
STUN Result
Mapping
Filtering
Packet Trace
Connectivity Result
```

예상 출력:

```text
Detected:
Symmetric NAT

Direct UDP Hole Punch:
FAILED

Reason:
Peer-specific mapping differs from STUN mapping.

Recommended:
TURN Relay
```

---

## 18. 자동 실험

여러 NAT 환경을 자동으로 순회한다.

```text
FOR NAT_TYPE
    CREATE_LAB
    DEPLOY_FLOW
    RUN_TEST
    CAPTURE
    ANALYZE
    STORE_RESULT
END
```

예:

```text
Full Cone       → PASS
Restricted      → PASS
Port Restricted → PASS
Symmetric       → DIRECT FAIL → TURN PASS
```

---

## 19. Scenario 관리

Scenario를 별도 객체로 정의한다.

```json
{
  "name": "udp-hole-punch-symmetric",
  "nat": {
    "a": "symmetric",
    "b": "symmetric"
  },
  "flow": "udp_hole_punch",
  "fallback": "turn",
  "timeout_ms": 3000
}
```

MCP:

```text
scenario.create()
scenario.run()
scenario.compare()
scenario.report()
```

---

## 20. 결과 비교

동일 Flow를 여러 NAT 환경에서 실행한다.

```text
Scenario A
Full Cone
PASS
42 ms

Scenario B
Restricted Cone
PASS
51 ms

Scenario C
Symmetric
DIRECT FAIL
TURN PASS
118 ms
```

AI가 결과 차이와 실패 원인을 설명하도록 한다.

---

## 21. 권장 프로젝트 구조

```text
protocol-flow-engine/
│
├── core/
│   ├── flow/
│   ├── block/
│   ├── context/
│   ├── state/
│   ├── timer/
│   ├── packet/
│   └── runtime/
│
├── protocols/
│   ├── openvpn/
│   ├── stun/
│   ├── turn/
│   ├── ice/
│   ├── natpmp/
│   ├── pcp/
│   └── upnp/
│
├── natlab/
│   ├── simulator/
│   ├── topology/
│   ├── scenarios/
│   ├── controller/
│   └── metrics/
│
├── transport/
│   ├── udp/
│   ├── tcp/
│   └── ipv6/
│
├── editor/
│   └── flow-studio/
│
├── compiler/
│   ├── ast/
│   ├── ir/
│   └── optimizer/
│
├── test/
│   ├── simulator/
│   ├── packet-generator/
│   └── replay/
│
├── mcp/
│   ├── server/
│   ├── tools/
│   ├── resources/
│   └── prompts/
│
└── docs/
```

---

## 22. 개발 단계

### Phase 0 — 기존 Engine 확장
- Timer
- Session Context
- Peer Context
- Packet Trace
- State Machine
- Retry/Timeout

### Phase 1 — UDP 기본 Block
- UDP Bind
- Send
- Receive
- Close
- Timer
- Packet Trace

### Phase 2 — STUN
- STUN Client
- STUN Server
- Public Endpoint Discovery
- Response Parser

### Phase 3 — NAT Simulator
- Mapping Policy
- Filtering Policy
- NAT Type
- Timeout
- Port Allocation

### Phase 4 — UDP Hole Punching
- Peer Discovery
- Probe
- Connectivity Check
- Retry
- Timeout

### Phase 5 — TURN
- Allocate
- Permission
- Channel
- Relay

### Phase 6 — ICE
- Candidate
- Candidate Pair
- Connectivity Check
- Pair Selection
- Nomination

### Phase 7 — TCP Hole Punching
- TCP simultaneous connect 실험
- NAT 환경별 결과 수집

### Phase 8 — UPnP / NAT-PMP / PCP
- Gateway Discovery
- Mapping
- Release

### Phase 9 — IPv6
- IPv6 Direct
- Firewall 환경
- IPv4/IPv6 비교

### Phase 10 — NAT Lab Automation
- Scenario
- Topology
- 자동 실행
- 결과 수집
- 비교

### Phase 11 — MCP
- NAT Resource
- Scenario Tool
- Packet Tool
- Trace Tool
- Test Tool

### Phase 12 — AI Protocol Copilot
- Natural Language → Flow
- NAT 환경 자동 구성
- 테스트 자동 생성
- 결과 분석
- 실패 원인 설명
- 개선 Flow 제안

---

## 23. MVP 범위

첫 MVP는 다음으로 제한한다.

```text
NAT Simulator
      │
      ├── Full Cone
      ├── Restricted
      ├── Port Restricted
      └── Symmetric
              │
              ▼
           STUN
              │
              ▼
      UDP Hole Punching
              │
        ┌─────┴─────┐
        ▼           ▼
       P2P         TURN
```

필수 기능:

1. UDP Block
2. Timer Block
3. STUN
4. NAT Simulator
5. UDP Hole Punch
6. Connectivity Check
7. TURN Fallback
8. Packet Trace
9. Scenario Test
10. MCP Interface

---

## 24. VPN과의 통합

NAT Traversal은 VPN Flow의 전처리/보조 Flow로 사용할 수 있다.

```text
NAT Traversal
      ↓
Connectivity Established
      ↓
VPN Session
      ↓
Encryption
      ↓
Tunnel
```

예:

```text
STUN
 ↓
UDP Hole Punch
 ↓
Connectivity Check
 ↓
OpenVPN Session
 ↓
Key Exchange
 ↓
Encrypted Tunnel
```

따라서 최종적으로 다음과 같은 복합 Flow도 가능하다.

```text
NAT Traversal Flow
        ↓
VPN Flow
        ↓
Security Policy Flow
        ↓
Application Traffic
```

---

## 25. 최종 플랫폼 방향

Protocol Flow Engine을 다음과 같은 **Network Protocol Laboratory + Runtime Platform**으로 확장한다.

```text
                    Protocol Flow Engine
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
   Protocol Lab          Security Flow       AI Copilot
       │                    │                    │
 ┌─────┼─────┐        ┌─────┼─────┐             │
 │     │     │        │     │     │             │
 VPN  NAT   TLS      SDP   NAC   DLP            MCP
 │     │     │        │     │     │             │
 └─────┴─────┘        └─────┴─────┘             │
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                       Flow Runtime
                            │
                    ┌───────┴───────┐
                    ▼               ▼
                User Mode        Kernel/DCO
```

핵심 제품 방향은 단순한 NAT 테스트 도구가 아니라,

> **네트워크 프로토콜을 Block과 Flow로 정의하고, 실제 NAT/네트워크 환경에서 실행·관찰·검증하며, MCP를 통해 AI가 프로토콜 설계와 실험까지 수행할 수 있는 Protocol Engineering Platform**

으로 정의한다.

---

## 26. 최종 개발 목표

다음 자연어 실습을 하나의 목표 시나리오로 삼는다.

```text
Symmetric NAT 두 개를 구성하고
각각 STUN 서버에 접속하게 한다.

UDP Hole Punching을 5초 동안 수행하고,
성공하면 직접 P2P 연결을 유지한다.

실패하면 TURN Relay로 전환한다.

각 단계의 Packet, NAT Mapping,
Connectivity Check 결과를 기록한다.

마지막으로 Full Cone NAT 환경과
결과를 비교하고 차이를 분석한다.
```

AI가 수행하는 전체 과정:

```text
Natural Language
       ↓
Scenario 생성
       ↓
NAT Lab 구성
       ↓
Flow 생성
       ↓
Validation
       ↓
Compile
       ↓
Experiment
       ↓
Packet Capture
       ↓
Trace Analysis
       ↓
Result Comparison
       ↓
AI Report
```

이 구조가 완성되면 Protocol Flow Engine은 단순한 **VPN 구현 프레임워크**를 넘어, **VPN / NAT Traversal / TLS / SDP / NAC / DLP 등의 프로토콜과 보안 흐름을 동일한 Flow 모델로 실험하고 AI가 이를 조작할 수 있는 범용 Protocol Engineering Platform**으로 확장될 수 있다.
