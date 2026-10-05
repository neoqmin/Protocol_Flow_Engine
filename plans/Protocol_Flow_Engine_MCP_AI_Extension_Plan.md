# Protocol Flow Engine — MCP / AI Protocol Engineering Extension Plan

> **범위 안내 (2026-10-05)**: 이 문서 전체는 **Post-MVP(PM-7)** 이다. MVP(`docs/Milestones.md`의 MVP-A~C)에는 포함하지 않으며, Flow JSON/Validator(MVP-C)가 안정된 이후 진행한다. 본문의 DCO/Kernel 관련 내용은 PM-8에 의존한다.

## 1. 문서 목적

본 문서는 기존 **Protocol Flow Engine + Flow Studio + OpenVPN/DCO** 개발계획을 확장하여, MCP(Model Context Protocol)를 통해 AI가 프로토콜의 정의·검증·컴파일·시험·운영을 지원하도록 하는 **AI Protocol Engineering Layer**의 개발계획을 정의한다.

핵심 방향은 다음과 같다.

```text
Natural Language
      ↓
     AI Agent
      ↓ MCP
AI Protocol Engineering Server
      ↓
Flow Workspace / Block Registry
      ↓
Validator
      ↓
Compiler / IR
      ↓
Test / Simulation
      ↓
Approval / Signing
      ↓
Runtime
 ┌───────────────┐
 │ User Runtime  │
 │ Kernel Runtime│
 └───────────────┘
```

AI가 직접 C/C++ 커널 코드를 생성하거나 실행하는 것이 아니라, **검증 가능한 Flow/Block/Policy 구조를 조작하도록 제한**하는 것이 핵심이다.

---

# 2. 목표

## 2.1 핵심 목표

AI가 다음 작업을 자연어 수준에서 수행할 수 있도록 한다.

- 프로토콜 Flow 생성
- 기존 Flow 분석
- Block 검색 및 설명
- Block 추가/삭제/연결
- 조건 및 분기 구성
- 암호화/복호화 처리 구성
- Session/Key Reference 연결
- Flow 검증
- Flow 컴파일
- 테스트 케이스 생성
- 패킷 시뮬레이션
- 캡처 패킷 분석
- 성능 테스트
- Flow 변경점 분석
- 버전 관리
- 승인 및 배포 준비

예:

```text
"OpenVPN 데이터 패킷 수신 후
Replay 검증하고 AES-GCM 복호화한 다음
Route를 거쳐 TUN으로 전달하는 Flow를 만들어줘."
```

AI는 이를 다음과 같은 구조로 변환한다.

```text
RECEIVE_PACKET
      ↓
PARSE_HEADER
      ↓
LOOKUP_SESSION
      ↓
VERIFY_REPLAY
      ↓
LOOKUP_KEY
      ↓
DECRYPT
      ↓
DECAP
      ↓
ROUTE
      ↓
DELIVER_TUN
```

---

# 3. 설계 원칙

## 3.1 AI는 Runtime을 직접 제어하지 않는다

다음 구조를 기본 원칙으로 한다.

```text
AI
 │
 │ MCP
 ▼
Flow Workspace
 │
 ▼
Schema Validation
 │
 ▼
Semantic Validation
 │
 ▼
Compile
 │
 ▼
Test / Simulation
 │
 ▼
Review / Approval
 │
 ▼
Sign
 │
 ▼
Deploy
 │
 ▼
Runtime
```

AI가 다음과 같은 작업을 직접 수행하도록 허용하지 않는다.

- 임의의 Kernel Code 실행
- 임의의 Native DLL 로딩
- 임의의 Kernel Driver 로딩
- Runtime 메모리 직접 변경
- 실제 암호키 추출
- 인증서/Private Key 원문 조회
- 검증되지 않은 Flow 즉시 배포

---

# 4. MCP Server 구조

## 4.1 전체 구조

```text
                    ┌────────────────────┐
                    │     AI Agent       │
                    └─────────┬──────────┘
                              │
                             MCP
                              │
                    ┌─────────▼──────────┐
                    │ Protocol MCP       │
                    │ Server             │
                    ├────────────────────┤
                    │ Flow API           │
                    │ Block API          │
                    │ Validation API     │
                    │ Compiler API       │
                    │ Test API           │
                    │ Runtime API        │
                    │ Capture API        │
                    │ Audit API          │
                    └─────────┬──────────┘
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
       Flow Workspace    Block Registry    Test Engine
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                       Flow Compiler
                              │
                              ▼
                       Runtime / DCO
```

---

# 5. MCP Resource 설계

MCP Resource는 AI가 읽을 수 있는 구조화된 정보로 사용한다.

## 5.1 Block Resource

예:

```text
protocol://blocks/DECRYPT
protocol://blocks/VERIFY_REPLAY
protocol://blocks/LOOKUP_SESSION
protocol://blocks/ROUTE
```

Block Resource에는 다음 정보를 제공한다.

```json
{
  "id": "DECRYPT",
  "version": "1.2",
  "category": "crypto",
  "inputs": [
    "EncryptedPacket",
    "KeyReference"
  ],
  "outputs": [
    "PlainPacket",
    "Error"
  ],
  "algorithms": [
    "AES-GCM",
    "AES-CBC"
  ],
  "security_level": "restricted"
}
```

실제 암호키 값은 Resource에 포함하지 않는다.

---

# 6. Flow Resource

Flow 자체를 Resource로 제공한다.

예:

```text
protocol://flows/openvpn_rx
protocol://flows/openvpn_tx
protocol://flows/tls_inspection
protocol://flows/sdp_gateway
```

Flow Resource 예:

```json
{
  "id": "openvpn_rx",
  "version": "0.1.0",
  "status": "validated",
  "entry": "RECEIVE_PACKET",
  "nodes": [
    "RECEIVE_PACKET",
    "PARSE_HEADER",
    "LOOKUP_SESSION",
    "VERIFY_REPLAY",
    "DECRYPT",
    "DECAP",
    "ROUTE",
    "DELIVER_TUN"
  ]
}
```

---

# 7. MCP Tool 설계

## 7.1 Block 조회

```text
protocol.list_blocks()
protocol.get_block(block_id)
protocol.search_blocks(query)
```

AI가 필요한 기능을 검색할 수 있다.

예:

```text
"Replay protection을 처리할 수 있는 Block을 찾아줘."
```

AI:

```text
search_blocks("replay protection")
```

---

# 8. Flow 생성/수정 API

## 8.1 Flow 생성

```text
flow.create(
    name,
    protocol,
    direction
)
```

예:

```json
{
  "name": "openvpn_rx",
  "protocol": "OpenVPN",
  "direction": "RX"
}
```

## 8.2 Block 추가

```text
flow.add_block(
    flow_id,
    block_id,
    parameters
)
```

## 8.3 Block 연결

```text
flow.connect(
    flow_id,
    source,
    source_port,
    destination,
    destination_port
)
```

## 8.4 Block 제거

```text
flow.remove_block(
    flow_id,
    block_instance_id
)
```

---

# 9. AI 자연어 → Flow 변환

AI는 자연어 요구사항을 바로 Native Code로 변환하지 않는다.

다음 단계를 거친다.

```text
Natural Language
       ↓
Intent
       ↓
Flow Plan
       ↓
Flow JSON
       ↓
Validation
       ↓
IR
       ↓
Runtime
```

예:

```text
사용자:

"OpenVPN RX 데이터 패킷에서
Replay를 검사하고
정상인 경우 AES-GCM 복호화 후
TUN으로 전달해."
```

AI가 생성하는 중간 표현:

```json
{
  "flow": "openvpn_rx",
  "steps": [
    {
      "block": "RECEIVE_PACKET"
    },
    {
      "block": "PARSE_HEADER"
    },
    {
      "block": "VERIFY_REPLAY"
    },
    {
      "block": "DECRYPT",
      "parameters": {
        "algorithm": "AES-GCM",
        "key": "SESSION_KEY"
      }
    },
    {
      "block": "DELIVER_TUN"
    }
  ]
}
```

---

# 10. Block Parameter와 Secret 분리

AI Protocol Engine에서 가장 중요한 보안 원칙 중 하나이다.

## 10.1 잘못된 방식

```json
{
  "block": "DECRYPT",
  "key": "001122334455..."
}
```

실제 암호키가 Flow JSON에 포함되어서는 안 된다.

## 10.2 권장 방식

```json
{
  "block": "DECRYPT",
  "key_ref": "SESSION_KEY"
}
```

Runtime에서:

```text
Key Reference
      ↓
Secure Key Provider
      ↓
Key Handle
      ↓
Crypto Provider
```

AI는 다음 정보까지만 접근할 수 있다.

```text
SESSION_KEY
KEY_ID
KEY_TYPE
ALGORITHM
KEY_STATE
```

실제 Key Material은 접근하지 않는다.

---

# 11. Validation MCP Tool

AI가 Flow를 생성한 뒤 반드시 검증하도록 한다.

```text
flow.validate(flow_id)
```

검증 단계:

```text
Schema Validation
       ↓
Graph Validation
       ↓
Type Validation
       ↓
Port Validation
       ↓
Parameter Validation
       ↓
Protocol Validation
       ↓
Security Validation
       ↓
Performance Validation
```

결과:

```json
{
  "valid": false,
  "errors": [
    {
      "block": "DECRYPT",
      "error": "KeyReference is not defined"
    }
  ],
  "warnings": [
    {
      "block": "PARSE_HEADER",
      "warning": "Potential variable-length parsing cost"
    }
  ]
}
```

AI는 오류를 보고 Flow를 자동 수정할 수 있다.

---

# 12. Compiler MCP Tool

검증된 Flow만 컴파일한다.

```text
flow.compile(flow_id)
```

구조:

```text
Flow JSON
   ↓
AST
   ↓
Semantic IR
   ↓
Optimization
   ↓
Runtime IR
   ↓
Native Runtime Plan
```

예:

```text
OpenVPN Flow
      ↓
Generic Flow IR
      ↓
User Runtime
      OR
Kernel Runtime
      OR
DCO Adapter
```

---

# 13. Test MCP Tool

AI가 Flow를 만든 직후 테스트를 생성할 수 있도록 한다.

## 13.1 기본 테스트

```text
test.create(flow_id)
test.run(test_id)
test.get_result(test_id)
```

## 13.2 자동 테스트 생성

예:

```text
"이 OpenVPN RX Flow에 대한 테스트를 만들어줘."
```

AI가 생성:

```text
TEST 1
Valid Data Packet

TEST 2
Invalid Authentication Tag

TEST 3
Replay Packet

TEST 4
Unknown Session

TEST 5
Invalid Header

TEST 6
Unsupported Cipher

TEST 7
Malformed Packet
```

---

# 14. Packet Simulation

실제 네트워크를 사용하지 않고 Flow를 검증할 수 있도록 한다.

```text
packet.create()
packet.inject()
packet.inspect()
```

구조:

```text
AI
 ↓
Packet Generator
 ↓
Flow Simulator
 ↓
Block Execution
 ↓
Trace
 ↓
Result
```

예:

```text
INPUT
  UDP packet
      ↓
PARSE_HEADER
      ↓
VERIFY_REPLAY = PASS
      ↓
DECRYPT = PASS
      ↓
DECAP = PASS
      ↓
ROUTE = TUN0
```

AI가 각 Block의 결과를 분석할 수 있다.

---

# 15. Packet Capture 분석

캡처 파일을 Flow Engine에 입력할 수 있도록 한다.

```text
capture.open()
capture.list_packets()
capture.inspect_packet()
capture.replay()
```

예:

```text
"이 pcap 파일을 OpenVPN RX Flow에 넣고
어느 단계에서 실패하는지 분석해줘."
```

AI:

```text
PCAP
 ↓
Packet Parser
 ↓
Flow Replay
 ↓
Block Trace
 ↓
Failure Analysis
```

---

# 16. Runtime MCP Tool

Runtime 정보는 기본적으로 Read-Only를 우선한다.

## 16.1 상태 조회

```text
runtime.status()
runtime.list_flows()
runtime.flow_stats(flow_id)
runtime.block_stats(block_id)
```

## 16.2 제한적인 제어

```text
runtime.start(flow_id)
runtime.stop(flow_id)
```

단, Production Runtime에서는 별도의 권한 검사를 거친다.

---

# 17. AI 권한 모델

MCP Tool을 권한 수준별로 분리한다.

## Level 0 — Read

```text
list_blocks
get_block
get_flow
runtime.status
runtime.stats
capture.inspect
```

## Level 1 — Design

```text
flow.create
flow.add_block
flow.connect
flow.remove_block
```

## Level 2 — Validate/Test

```text
flow.validate
flow.compile
test.create
test.run
packet.inject
```

## Level 3 — Deploy

```text
flow.sign
flow.deploy
runtime.start
runtime.stop
```

Production 환경에서는 Level 3을 별도 승인 대상으로 둔다.

---

# 18. Approval Workflow

AI가 생성한 Flow를 즉시 배포하지 않는다.

```text
AI Generated
     ↓
Draft
     ↓
Validated
     ↓
Compiled
     ↓
Tested
     ↓
Review Required
     ↓
Approved
     ↓
Signed
     ↓
Deployable
     ↓
Runtime
```

Flow 상태 예:

```text
DRAFT
VALIDATED
COMPILED
TESTED
REVIEW_REQUIRED
APPROVED
SIGNED
DEPLOYED
```

---

# 19. Flow Versioning

Flow는 Git과 유사한 버전 관리가 가능하도록 설계한다.

```text
openvpn_rx
 ├── v0.1
 ├── v0.2
 ├── v0.3
 └── v1.0
```

MCP:

```text
flow.history()
flow.diff(version1, version2)
flow.rollback(version)
```

AI는 다음과 같은 요청을 처리할 수 있다.

```text
"현재 Flow에서 변경된 부분을 보여줘."

"v0.2에서 Replay 검증이 어떻게 변경되었는지 설명해줘."

"지난 버전으로 되돌린 Flow를 만들어줘."
```

---

# 20. Audit Log

AI가 수행한 모든 변경은 기록한다.

```text
Timestamp
Agent ID
User ID
Flow ID
Operation
Before
After
Validation Result
Test Result
Approval
Signature
```

예:

```json
{
  "actor": "AI-Agent",
  "operation": "flow.add_block",
  "flow": "openvpn_rx",
  "block": "VERIFY_REPLAY",
  "result": "success"
}
```

보안 제품에서는 이 로그를 별도 감사 저장소로 전송할 수 있다.

---

# 21. MCP Prompt 활용

MCP Prompt를 이용해 반복적인 프로토콜 엔지니어링 작업을 표준화할 수 있다.

예:

```text
prompt.create_openvpn_flow
prompt.review_flow_security
prompt.optimize_flow
prompt.generate_protocol_tests
prompt.analyze_packet_capture
prompt.compare_flow_versions
```

예:

```text
/protocol-review openvpn_rx
```

AI는 다음 항목을 자동 점검한다.

```text
- Header validation
- Authentication
- Replay protection
- Session validation
- Key reference
- Encryption
- Error path
- Resource limits
- DoS resistance
- Kernel safety
```

---

# 22. AI Protocol Copilot

최종적으로는 별도의 AI Protocol Copilot을 구성할 수 있다.

```text
┌──────────────────────────────────────┐
│        Protocol Flow Studio          │
│                                      │
│  ┌──────────┐      ┌─────────────┐  │
│  │ Flow     │      │ AI Copilot  │  │
│  │ Editor   │◀────▶│             │  │
│  └────┬─────┘      └──────┬──────┘  │
│       │                   │         │
│       ▼                   ▼         │
│   Flow JSON             MCP        │
└───────┬───────────────────┬─────────┘
        │                   │
        └─────────┬─────────┘
                  ▼
          Protocol Flow Engine
```

AI Copilot의 역할:

- Flow 생성
- Flow 설명
- Block 추천
- 오류 수정
- 보안 검토
- 테스트 생성
- 패킷 분석
- 성능 분석
- 변경점 설명
- 문서 생성

---

# 23. Visual Editor와 MCP의 결합

기존 Rete.js 기반 Flow Studio와 MCP를 결합한다.

```text
                 AI
                 │
                MCP
                 │
        ┌────────▼────────┐
        │ Flow Workspace  │
        └────────┬────────┘
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
Visual Editor          Flow JSON
       │                   │
       └─────────┬─────────┘
                 ▼
             Validator
                 ▼
              Compiler
```

중요한 점은 Visual Editor와 AI가 동일한 Flow JSON/Workspace를 사용한다는 것이다.

즉:

```text
Human → GUI → Flow JSON
AI    → MCP → Flow JSON
```

두 방식이 동일한 검증 및 컴파일 경로를 사용한다.

---

# 24. AI와 인간의 역할 분리

## AI가 담당하기 좋은 작업

```text
Block 검색
Flow 초안 생성
반복적인 연결
테스트 생성
패킷 분석
오류 원인 분석
Flow 설명
문서 생성
성능 통계 분석
```

## 인간이 최종 결정해야 하는 작업

```text
보안 정책
암호 알고리즘 선택
Trust Boundary
Key Management 정책
Production Deployment
Kernel 권한
Network Isolation
인증 정책
```

즉:

```text
AI = Engineering Assistant
Human = Security / Deployment Authority
```

---

# 25. Kernel Runtime과 AI의 경계

Kernel Runtime은 AI와 직접 연결하지 않는 것을 원칙으로 한다.

```text
AI
 ↓
MCP
 ↓
Flow Workspace
 ↓
Validator
 ↓
Compiler
 ↓
Signed Flow
 ↓
User-mode Deployment Service
 ↓
Kernel Driver
```

Kernel에서는 오직 검증된 Runtime IR 또는 서명된 Flow만 받아들인다.

---

# 26. OpenVPN DCO 적용 (Post-MVP, PM-8 의존)

기존 OpenVPN DCO 연구와 결합하면 다음 구조가 가능하다.

```text
OpenVPN User Mode
 ├── TLS
 ├── Authentication
 ├── Session
 └── Key Negotiation
          │
          ▼
   Flow Configuration
          │
          ▼
      DCO Adapter
          │
          ▼
   Protocol Flow Engine
          │
          ▼
      Kernel Runtime
```

AI는 OpenVPN의 전체 구현을 다시 작성하는 것이 아니라:

```text
"OpenVPN RX 데이터 경로에서
Replay 검증 후
AES-GCM 복호화하고
TUN으로 전달하도록 구성해."
```

와 같은 요청을 처리한다.

---

# 27. Crypto Provider 구조

암호화 Block은 Flow와 분리한다.

```text
DECRYPT
   │
   ▼
Crypto Provider Interface
   │
   ├── AES
   ├── ARIA
   ├── ChaCha20
   └── Future Algorithm
```

또한 플랫폼별 구현을 분리한다.

```text
Crypto Core
 ├── Windows User
 ├── Windows Kernel
 ├── Linux User
 ├── Linux Kernel
 ├── macOS
 ├── Android
 └── iOS
```

AI는 알고리즘과 Provider Capability를 선택할 수 있지만 실제 Key Material에는 접근하지 않는다.

---

# 28. 보안 Guardrail

AI Protocol Engineering에서는 다음 제한을 기본 적용한다.

## 28.1 Raw Code 제한

AI가 임의의 C/C++ 코드를 생성하여 Runtime에 삽입하지 않는다.

```text
허용:

Flow
Block
Parameter
Policy
Expression

제한:

Native Code
Kernel Code
Driver Binary
DLL Injection
```

## 28.2 Secret 보호

```text
AI → Key Reference
Runtime → Key Material
```

## 28.3 Production 보호

```text
AI
 ↓
Draft
 ↓
Validation
 ↓
Test
 ↓
Human Approval
 ↓
Signature
 ↓
Deployment
```

---

# 29. MCP Tool 최소 MVP

초기 MVP에서는 다음 Tool만 구현한다.

```text
block.list
block.get

flow.create
flow.get
flow.add_block
flow.connect
flow.remove_block

flow.validate
flow.compile

test.create
test.run
test.result

runtime.status
```

이 정도만으로도 다음이 가능하다.

```text
자연어
  ↓
AI
  ↓
Flow 생성
  ↓
검증
  ↓
컴파일
  ↓
테스트
```

---

# 30. 개발 단계

## Phase 1 — MCP 기본 구조

- MCP Server
- Flow Resource
- Block Resource
- 기본 Tool
- 인증/권한 구조

## Phase 2 — Flow CRUD

- Create
- Read
- Update
- Delete
- Connect
- Disconnect
- Version

## Phase 3 — Validation

- Schema Validation
- Type Validation
- Graph Validation
- Protocol Validation
- Security Validation

## Phase 4 — Compiler 연계

```text
MCP
 ↓
Flow JSON
 ↓
Validator
 ↓
IR
 ↓
Runtime
```

## Phase 5 — Test Engine

- Packet Generator
- Packet Replay
- Flow Simulator
- Block Trace
- Negative Test

## Phase 6 — OpenVPN

- OpenVPN Flow
- DCO Adapter
- Crypto Provider
- Session/Key Reference

## Phase 7 — AI Copilot

- Natural Language → Flow
- Error Repair
- Test Generation
- Packet Analysis
- Flow Explanation

## Phase 8 — Production Security

- Approval
- Signing
- Audit
- RBAC
- Secret Isolation
- Deployment Control

---

# 31. 향후 확장

Protocol Flow Engine을 OpenVPN 전용으로 만들지 않고 범용 보안 Flow Engine으로 확장한다.

```text
                    Protocol Flow Engine
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
      VPN                 SDP                 NAC
        │                   │                   │
        ▼                   ▼                   ▼
      TLS                  DLP                N2SF
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                       Security Flow
```

AI/MCP에서는 동일한 방식으로 관리한다.

```text
AI
 │
 └── MCP
      ├── VPN Flow
      ├── TLS Flow
      ├── SDP Flow
      ├── NAC Flow
      ├── DLP Flow
      └── N2SF Flow
```

---

# 32. 최종 제품 구조

장기적으로 다음과 같은 제품 구성이 가능하다.

```text
┌──────────────────────────────────────────┐
│          AI Protocol Copilot             │
├──────────────────────────────────────────┤
│          MCP Protocol Interface           │
├──────────────────────────────────────────┤
│            Protocol Flow Studio           │
├──────────────────────────────────────────┤
│             Flow Workspace                │
├──────────────────────────────────────────┤
│             Block Registry                │
├──────────────────────────────────────────┤
│        Validator / Compiler / IR          │
├──────────────────────────────────────────┤
│              Test Engine                  │
├──────────────────────────────────────────┤
│             Flow Runtime                  │
├──────────────────────┬───────────────────┤
│     User Runtime     │   Kernel Runtime  │
└──────────────────────┴───────────────────┘
```

핵심 경쟁력은 단순한 "AI가 코드를 작성하는 제품"이 아니라,

> **AI가 검증 가능한 Protocol Flow를 설계하고, 테스트하고, 컴파일하여 실제 네트워크/보안 Runtime으로 연결하는 개발 플랫폼**

으로 정의할 수 있다.

---

# 33. 권장 MVP 범위 (MCP 계층의 범위, Post-MVP PM-7)

> 아래의 "OpenVPN DCO / Runtime" 배포는 PM-8 이후의 최종 경로이다. PM-7 단계에서는 배포 대상을 **User Runtime까지**로 한정하고, DCO/Kernel 배포는 PM-8 완료 후 확장한다.

첫 번째 구현은 범용 프로토콜 전체를 대상으로 하지 않고 다음으로 제한한다.

```text
OpenVPN Data Plane
       │
       ▼
Protocol Flow Engine
       │
       ├── Block Registry
       ├── Flow JSON
       ├── Validator
       ├── Compiler
       └── Test Engine
              │
              ▼
          MCP Server
              │
              ▼
           AI Agent
```

### MVP 성공 기준

다음 자연어 요청을 AI가 실제 실행 가능한 Flow로 변환할 수 있으면 1차 목표를 달성한 것으로 본다.

```text
"OpenVPN RX 데이터 패킷을 받아서
헤더를 검사하고,
Session을 찾고,
Replay를 검증하고,
AES-GCM으로 복호화한 후,
정상 패킷만 TUN으로 전달하는 Flow를 만들어줘.

그리고 정상/비정상/Replay 패킷 테스트도 생성하고
모든 테스트를 통과했는지 확인해줘."
```

최종적으로:

```text
Natural Language
       ↓
      MCP
       ↓
AI Protocol Copilot
       ↓
Flow JSON
       ↓
Validation
       ↓
Compilation
       ↓
Simulation/Test
       ↓
Approval
       ↓
Signed Flow
       ↓
OpenVPN DCO / Runtime
```

의 전체 경로를 완성하는 것을 목표로 한다.
