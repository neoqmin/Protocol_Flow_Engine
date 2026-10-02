# Protocol Flow Engine 개발 계획
## OpenVPN 기반 Block 조립형 VPN/보안 프로토콜 처리 엔진

- 문서 버전: 0.1
- 작성일: 2026-10-02
- 1차 목표: OpenVPN Data Plane을 Block/Flow 방식으로 구현
- 2차 목표: User/Kernel 공통 Runtime 및 OpenVPN DCO 연동
- 장기 목표: VPN / SDP / NAC / N2SF / DLP에 공통으로 사용할 Protocol Flow Engine 구축

---

# 1. 개발 목표

기존 VPN 구현은 다음과 같이 복잡한 상태 머신과 함수 호출이 여러 모듈에 분산되는 문제가 있다.

```text
Receive
  -> Parse
  -> Session Lookup
  -> Authentication
  -> Key Lookup
  -> Replay Check
  -> Decrypt
  -> Decapsulation
  -> Policy
  -> Route
  -> Deliver
```

이를 다음과 같은 **Protocol Block** 조립 구조로 전환한다.

```text
[Receive]
    |
[Parse]
    |
[Session Lookup]
    |
[Policy] ---- NO ----> [Drop]
    |
   YES
    |
[Key Lookup]
    |
[Decrypt]
    |
[Decap]
    |
[Route]
    |
[Deliver]
```

핵심 목표는 다음과 같다.

1. 프로토콜 처리를 작은 Block으로 분리
2. Block을 Edge로 연결하여 Flow 구성
3. YES/NO/ERROR 등의 Decision Flow 지원
4. DSL 또는 Flow Definition으로 프로토콜을 표현
5. DSL을 Runtime에서 직접 해석하지 않고 Compiler/IR을 거쳐 최적화
6. 동일한 Block을 User Mode와 Kernel Mode에서 재사용
7. 암호화 키 자체는 Flow/DSL에 포함하지 않고 Runtime Key Reference로 관리
8. OpenVPN DCO와 최소 변경으로 연동
9. 향후 WireGuard/SDP/N2SF 등의 프로토콜 및 보안 흐름에 확장

---

# 2. 전체 아키텍처

```text
                         Protocol Flow Engine
                                  |
             +--------------------+--------------------+
             |                    |                    |
       Block Library        Flow Definition       Key Manager
             |                    |                    |
       +-----+-----+        +-----+-----+              |
       |           |        |           |              |
    Parser      Crypto    DSL/JSON     GUI             |
       |           |        |           |              |
       +-----------+--------+-----------+--------------+
                                  |
                            Flow Compiler
                                  |
                            Intermediate
                             Representation
                                  |
                  +---------------+---------------+
                  |                               |
             User Runtime                   Kernel Runtime
                  |                               |
             OpenVPN Core                    DCO Adapter
                  |                               |
                  +---------------+---------------+
                                  |
                            Network Interface
```

---

# 3. 핵심 설계 원칙

## 3.1 Block은 하나의 명확한 기능만 담당

예:

```text
Parse OpenVPN Header
Lookup Session
Lookup Key
Replay Check
Decrypt
Decapsulate
Policy Check
Route
Encrypt
Encapsulate
Send
Drop
```

각 Block은 가능하면 상태를 직접 보유하지 않고 `Flow Context`를 입력/출력으로 사용한다.

---

## 3.2 Block과 Flow를 분리

Block:

```cpp
BLOCK_RESULT Block_Decrypt(FLOW_CONTEXT* ctx);
```

Flow:

```text
Parse
 -> KeyLookup
 -> ReplayCheck
 -> Decrypt
 -> Decap
 -> Route
```

즉 같은 `Decrypt` Block을 여러 Flow에서 재사용한다.

---

## 3.3 Decision을 First-Class Block으로 취급

```text
[Policy Check]
       |
   +---+---+
   |       |
 YES      NO
   |       |
 Encrypt   Drop
```

Decision Block의 결과:

```text
YES
NO
ERROR
```

또는 일반적인 조건식:

```text
IF ctx.session.authenticated == true
    YES -> Continue
    NO  -> Drop
```

---

# 4. Runtime Context

모든 Block의 공통 실행 컨텍스트를 정의한다.

```cpp
struct FLOW_CONTEXT
{
    PACKET*         packet;
    SESSION*        session;
    FLOW*            flow;

    KEY_REFERENCE    key_ref;

    uint32_t         flags;
    uint32_t         error;

    void*            user_context;
};
```

실제 구현에서는 Kernel/User Mode의 포인터 및 메모리 모델 차이를 고려하여 공통 ABI와 플랫폼별 Context를 분리한다.

```text
Common Flow Context
        |
   +----+----+
   |         |
User Context Kernel Context
```

---

# 5. Block API

초기 API 예:

```cpp
enum BLOCK_RESULT
{
    BLOCK_CONTINUE,
    BLOCK_YES,
    BLOCK_NO,
    BLOCK_DROP,
    BLOCK_ERROR
};

using BLOCK_HANDLER =
    BLOCK_RESULT (*)(FLOW_CONTEXT* ctx);
```

Block Descriptor:

```cpp
struct BLOCK_DESCRIPTOR
{
    BLOCK_ID        id;
    BLOCK_TYPE      type;
    BLOCK_HANDLER   execute;
};
```

Edge:

```cpp
struct BLOCK_EDGE
{
    BLOCK_RESULT result;
    BLOCK_ID     next;
};
```

최종적으로는 다음 형태를 목표로 한다.

```text
Block
 |
 +-- Execute()
 |
 +-- OnContinue
 +-- OnYes
 +-- OnNo
 +-- OnError
```

---

# 6. Flow Definition

## 6.1 초기 단계

C/C++ 정적 Flow부터 시작한다.

```cpp
FLOW vpn_rx =
{
    BLOCK_RECEIVE,
    BLOCK_PARSE_OPENVPN,
    BLOCK_LOOKUP_SESSION,
    BLOCK_LOOKUP_KEY,
    BLOCK_REPLAY_CHECK,
    BLOCK_DECRYPT,
    BLOCK_DECAP,
    BLOCK_ROUTE,
    BLOCK_DELIVER
};
```

이 단계에서 Runtime 구조와 성능을 먼저 검증한다.

---

## 6.2 DSL 단계

이후 작은 Protocol DSL을 도입한다.

예:

```text
flow openvpn_rx {

    packet = RECEIVE();

    header = OPENVPN_PARSE(packet);

    if header.type == DATA {
        key = KEY_LOOKUP(header.key_id);

        if REPLAY_CHECK(packet, key) == false {
            DROP();
        }

        packet = DECRYPT(packet, key);
        packet = DECAP(packet);

        ROUTE(packet);
        DELIVER(packet);
    }

    if header.type == CONTROL {
        CONTROL_PROCESS(packet);
    }
}
```

---

# 7. DSL 설계

## 7.1 목표

DSL은 일반 프로그래밍 언어가 아니라 **Protocol Flow를 표현하는 전용 언어**로 제한한다.

필수 기능:

- Block 호출
- 변수/Context 참조
- IF
- SWITCH
- YES/NO 분기
- ERROR 처리
- Flow 호출
- 반복 최소화
- Key Reference
- Timeout/Lifetime 등의 Flow metadata

---

## 7.2 권장 문법

```text
flow vpn_rx {

    RECEIVE
        -> PARSE_OPENVPN
        -> SESSION_LOOKUP
        -> POLICY_CHECK

    POLICY_CHECK {
        YES -> KEY_LOOKUP
        NO  -> DROP
    }

    KEY_LOOKUP
        -> REPLAY_CHECK

    REPLAY_CHECK {
        YES -> DECRYPT
        NO  -> DROP
    }

    DECRYPT
        -> DECAP
        -> ROUTE
        -> DELIVER
}
```

초기에는 JSON/YAML 기반 Flow Definition도 허용한다.

---

# 8. Flow Compiler

DSL을 Runtime에서 매번 해석하지 않는다.

```text
DSL
 |
 v
Parser
 |
 v
AST
 |
 v
Semantic Check
 |
 v
Flow IR
 |
 v
Optimization
 |
 v
Runtime Plan
 |
 v
C/C++ / Native Runtime
```

## Compiler 역할

- Block 존재 여부 확인
- Edge 유효성 검사
- Type 검사
- 순환 Flow 검사
- unreachable Block 검사
- 필수 Context 검사
- Kernel/User 지원 여부 검사
- 최적화
- Runtime Plan 생성

---

# 9. Intermediate Representation (IR)

예:

```text
FLOW:
  01 RECEIVE
  02 PARSE_OPENVPN
  03 SESSION_LOOKUP
  04 POLICY_CHECK

EDGE:
  04 YES -> 05
  04 NO  -> 99

  05 KEY_LOOKUP
  06 REPLAY_CHECK

EDGE:
  06 YES -> 07
  06 NO  -> 99

  07 DECRYPT
  08 DECAP
  09 ROUTE
  10 DELIVER
  99 DROP
```

Runtime에서는 가능한 한 직접적인 function pointer/table dispatch 또는 생성된 native code 형태로 실행한다.

---

# 10. 암호화/복호화 설계

## 10.1 키를 DSL에 직접 저장하지 않는다

금지:

```text
DECRYPT {
    algorithm = AES-GCM
    key = "0123456789abcdef..."
}
```

권장:

```text
DECRYPT {
    algorithm = AES-GCM
    key = SESSION_KEY
}
```

또는:

```text
key = KEY_LOOKUP(header.key_id)
DECRYPT(packet, key)
```

---

## 10.2 Key Reference와 Key Material 분리

```text
                 Key Manager
                     |
            +--------+--------+
            |                 |
       Key Reference      Key Material
            |                 |
       key_id / handle     secure memory
            |
            v
        Flow Runtime
```

Flow/DSL에는:

```text
key_id
key handle
session key reference
```

등만 존재한다.

실제 키는 Runtime의 secure memory 영역에서 관리한다.

---

# 11. Crypto Block 구조

공통 인터페이스:

```cpp
struct CRYPTO_PROVIDER
{
    CRYPTO_ALGORITHM algorithm;

    STATUS (*encrypt)(
        CRYPTO_CONTEXT* ctx,
        BUFFER* input,
        BUFFER* output);

    STATUS (*decrypt)(
        CRYPTO_CONTEXT* ctx,
        BUFFER* input,
        BUFFER* output);
};
```

Provider 예:

```text
Crypto Provider
 |
 +-- AES-GCM
 +-- AES-CTR/HMAC
 +-- ChaCha20-Poly1305
 +-- ARIA
 +-- Future Provider
```

KCMVP 대응이 필요할 경우 Crypto Provider 경계를 명확하게 유지하여 검증 대상 암호모듈과 Flow Engine을 분리한다.

---

# 12. OpenVPN 적용

OpenVPN을 첫 번째 Reference Protocol로 선택한다.

## 12.1 Control Plane

```text
[Receive Control]
       |
[TLS Process]
       |
[Authentication]
       |
[Peer Negotiation]
       |
[Key Derivation]
       |
[Install Session Key]
```

## 12.2 Data Plane RX

```text
[Receive]
    |
[Parse OpenVPN Header]
    |
[Session Lookup]
    |
[Key Lookup]
    |
[Replay Check]
    |
[Decrypt]
    |
[Decapsulate]
    |
[Route]
    |
[Deliver]
```

## 12.3 Data Plane TX

```text
[Capture]
    |
[Session Lookup]
    |
[Policy]
    |
[Key Lookup]
    |
[Encrypt]
    |
[OpenVPN Encapsulation]
    |
[Send]
```

---

# 13. OpenVPN DCO 연동 전략

기존 OpenVPN DCO 구현을 전면 재작성하지 않는다.

우선 다음 경계를 활용한다.

```text
OpenVPN User Mode
        |
        | Control / Key / Peer
        v
+-----------------------+
| DCO Adapter           |
+-----------+-----------+
            |
            v
+-----------------------+
| Protocol Flow Runtime |
+-----------+-----------+
            |
            v
+-----------------------+
| Kernel Blocks         |
|                       |
| Parse                 |
| Replay                |
| Crypto                |
| Route                 |
| Encapsulation         |
+-----------------------+
```

목표는 기존 DCO의 핵심 데이터 경로를 가능한 한 유지하면서 특정 처리 단계를 Flow Block으로 대체할 수 있게 만드는 것이다.

---

# 14. User/Kernel 공통 Block

모든 Block을 무조건 양쪽에서 실행하지 않는다.

Block Descriptor에 실행 영역을 지정한다.

```text
BLOCK_RUNTIME:

USER
KERNEL
BOTH
```

예:

```text
TLS_PROCESS        USER
KEY_NEGOTIATION    USER

OPENVPN_PARSE      BOTH
REPLAY_CHECK       KERNEL
DECRYPT            KERNEL
ROUTE              KERNEL
ENCRYPT             KERNEL

POLICY              BOTH
```

이렇게 하면 동일한 Flow 정의를 User/Kernel 환경에 맞게 컴파일할 수 있다.

---

# 15. Shared Memory Crypto Extension

향후 사용자가 검토한 User Mode 암호화 구조를 지원한다.

```text
Kernel
   |
   | Packet Descriptor
   v
Shared Memory Ring
   |
   v
User Crypto Worker
   |
   | Encrypted/Decrypted Buffer
   v
Shared Memory Ring
   |
   v
Kernel
```

Flow에서는:

```text
DECRYPT
```

하나의 Block으로 보이지만 Runtime Provider는:

```text
Kernel Crypto Provider
```

또는

```text
User Crypto Provider
```

로 선택할 수 있다.

---

# 16. Block Library

1차 Block 목록:

### Packet

```text
RECEIVE
SEND
COPY
DROP
```

### Parser

```text
PARSE_ETHERNET
PARSE_IP
PARSE_IPV6
PARSE_UDP
PARSE_TCP
PARSE_OPENVPN
```

### Session

```text
SESSION_LOOKUP
SESSION_CREATE
SESSION_DELETE
PEER_LOOKUP
```

### Security

```text
AUTH_CHECK
POLICY_CHECK
REPLAY_CHECK
DEVICE_CHECK
IDENTITY_CHECK
```

### Crypto

```text
KEY_LOOKUP
KEY_INSTALL
ENCRYPT
DECRYPT
MAC
VERIFY_TAG
```

### Tunnel

```text
ENCAPSULATE
DECAPSULATE
TUN_READ
TUN_WRITE
```

### Network

```text
ROUTE
NAT
FORWARD
```

---

# 17. Block Metadata

각 Block에 다음 정보를 가진다.

```cpp
struct BLOCK_METADATA
{
    BLOCK_ID        id;
    BLOCK_TYPE      type;

    RUNTIME_TYPE    runtime;
    INPUT_TYPE      input;
    OUTPUT_TYPE     output;

    uint32_t        flags;

    const char*     name;
    const char*     description;
};
```

예:

```text
Block: DECRYPT

Runtime:
    USER
    KERNEL

Input:
    EncryptedPacket
    KeyReference

Output:
    PlainPacket

Requires:
    Session
    Key

Produces:
    PlainPacket
```

이 정보는 GUI Flow Editor에서도 활용할 수 있다.

---

# 18. GUI Flow Editor

DSL이 안정화된 후 개발한다.

화면:

```text
+-------------------------------------------------------+
| Flow: OpenVPN RX                                      |
+-------------------------------------------------------+
|                                                       |
| [Receive]                                             |
|     |                                                 |
| [Parse OpenVPN]                                       |
|     |                                                 |
| [Session Lookup]                                      |
|     |                                                 |
| [Policy] ---- NO --------------------> [Drop]         |
|     |                                                 |
|    YES                                                |
|     |                                                 |
| [Key Lookup]                                          |
|     |                                                 |
| [Replay Check] ---- NO -------------> [Drop]          |
|     |                                                 |
|    YES                                                |
|     |                                                 |
| [Decrypt]                                             |
|     |                                                 |
| [Decap]                                               |
|     |                                                 |
| [Route]                                               |
|     |                                                 |
| [Deliver]                                             |
|                                                       |
+-------------------------------------------------------+
```

Block Palette:

```text
Packet
Parser
Session
Security
Crypto
Tunnel
Network
Decision
```

---

# 19. 개발 단계

## Phase 1 — Core Runtime

목표:

- Block interface
- Flow Context
- Block registry
- Edge
- Runtime executor
- Error handling

결과:

```text
C/C++ 코드로 Block을 연결하여 Flow 실행
```

---

## Phase 2 — Static OpenVPN Flow

목표:

- OpenVPN RX Flow
- OpenVPN TX Flow
- Parser Block
- Session Block
- Crypto Block
- Replay Block
- Route Block

결과:

```text
실제 패킷을 Block Flow로 처리
```

---

## Phase 3 — Crypto Provider

목표:

- Crypto abstraction
- Key Reference
- Session Key
- Provider interface
- Kernel Crypto
- User Crypto

결과:

```text
DECRYPT Block의 내부 구현 교체 가능
```

---

## Phase 4 — OpenVPN DCO Adapter

목표:

- 기존 DCO와 연결
- Peer 관리
- Key 관리
- Packet path 연결
- 기존 기능 회귀 테스트

중요 원칙:

```text
기존 OpenVPN/DCO 코드를 최대한 수정하지 않는다.
```

---

## Phase 5 — Flow DSL

목표:

```text
DSL
 -> Parser
 -> AST
 -> IR
 -> Runtime Plan
```

결과:

```text
개발자가 Flow를 코드 대신 DSL로 작성
```

---

## Phase 6 — Flow Compiler Optimization

목표:

- Direct dispatch
- Static branch optimization
- Block fusion
- Zero-copy path
- Batch processing
- CPU affinity
- Per-CPU context

특히 데이터 Plane에서는 다음을 우선한다.

```text
Function call 최소화
Memory copy 최소화
Lock 최소화
Branch 최소화
```

---

## Phase 7 — User/Kernel Dual Runtime

목표:

```text
동일 Flow
    |
    +-- User Runtime
    |
    +-- Kernel Runtime
```

환경별 지원 Block을 Compiler가 판별한다.

---

## Phase 8 — GUI Flow Editor

목표:

```text
Drag Block
    |
Connect Edge
    |
Validate
    |
Compile
    |
Deploy
```

GUI는 처음부터 만들지 않고 DSL/Compiler/Runtime이 안정화된 이후 개발한다.

---

# 20. 테스트 전략

## Unit Test

각 Block 독립 테스트:

```text
Parse
Session
Policy
Replay
Encrypt
Decrypt
Encapsulation
```

## Flow Test

```text
RX Flow
TX Flow
Control Flow
Error Flow
Timeout Flow
```

## Protocol Test

```text
OpenVPN Client
       ↕
Flow Engine
       ↕
OpenVPN Server
```

## Regression Test

기존 OpenVPN 결과와 Flow Engine 결과를 비교한다.

```text
Original OpenVPN
       |
       +---- Packet Capture

Flow Engine
       |
       +---- Packet Capture

Compare
```

---

# 21. 성능 측정 항목

최소한 다음을 측정한다.

```text
Packets/sec
Gbps
Latency
CPU usage
Memory usage
Context switch
Lock contention
Copy count
Block dispatch overhead
Crypto throughput
```

비교:

```text
OpenVPN Original
        VS
Flow Runtime
        VS
Compiled Flow Runtime
```

특히 최종 목표는:

```text
Compiled Flow Runtime overhead
        ≈
직접 작성한 C/C++ packet path overhead
```

에 가깝게 만드는 것이다.

---

# 22. 보안 설계

## 키

- DSL에 실제 Key Material 저장 금지
- Key Reference만 사용
- Runtime secure memory
- Key lifetime 관리
- Session별 Key isolation
- Zeroization
- Key rotation 지원

## Flow

- 검증된 Block만 사용
- 임의 native code 실행 금지
- Flow signature/version 관리
- 권한 없는 Block 사용 방지
- Kernel에서 실행 가능한 Block 제한

## Compiler

```text
Invalid Flow
   |
   +-- Undefined Block
   +-- Invalid Edge
   +-- Type mismatch
   +-- Unsupported Runtime
   +-- Unreachable Block
   +-- Loop violation
```

을 배포 전에 차단한다.

---

# 23. 향후 확장

OpenVPN 검증 이후 동일한 Engine에 다음을 추가할 수 있다.

```text
                Protocol Flow Engine
                       |
       +---------------+---------------+
       |               |               |
    OpenVPN         WireGuard          SDP
       |               |               |
       +---------------+---------------+
                       |
              Security Blocks
                       |
       +---------------+---------------+
       |               |               |
      NAC             DLP             N2SF
```

특히 공통으로 사용할 수 있는 Block:

```text
Identity
Device
Policy
Classification
Encryption
Route
Tunnel
Audit
Logging
Decision
```

따라서 장기적으로는 VPN 엔진이 아니라 **Security Flow Engine**으로 확장한다.

---

# 24. 권장 프로젝트 구조

```text
ProtocolFlow/
|
+-- core/
|   +-- flow/
|   +-- context/
|   +-- block/
|   +-- runtime/
|   +-- registry/
|
+-- compiler/
|   +-- lexer/
|   +-- parser/
|   +-- ast/
|   +-- ir/
|   +-- optimizer/
|
+-- blocks/
|   +-- packet/
|   +-- parser/
|   +-- session/
|   +-- security/
|   +-- crypto/
|   +-- tunnel/
|   +-- network/
|
+-- crypto/
|   +-- provider/
|   +-- key/
|   +-- session/
|
+-- runtime/
|   +-- user/
|   +-- kernel/
|
+-- protocols/
|   +-- openvpn/
|   +-- wireguard/
|   +-- sdp/
|
+-- adapters/
|   +-- openvpn-dco/
|
+-- tools/
|   +-- flowc/
|   +-- flowdump/
|   +-- flowtest/
|
+-- tests/
|   +-- unit/
|   +-- flow/
|   +-- protocol/
|   +-- performance/
|
+-- gui/
|   +-- flow-editor/
```

---

# 25. 1차 MVP 범위

처음부터 전체 DSL/GUI/Kernel을 만들지 않는다.

### MVP-1

```text
C++ Block API
    +
Static Flow
    +
OpenVPN RX/TX
```

### MVP-2

```text
Crypto Provider
    +
Key Reference
    +
OpenVPN DCO Adapter
```

### MVP-3

```text
Flow DSL
    +
Compiler
    +
IR
```

### MVP-4

```text
Kernel Runtime
    +
User Runtime
    +
Performance Optimization
```

### MVP-5

```text
GUI Flow Editor
```

---

# 26. 최종 목표

최종적으로 개발자가 VPN 프로토콜을 다음처럼 구현할 수 있도록 한다.

```text
flow openvpn_rx {

    RECEIVE
      -> PARSE_OPENVPN
      -> SESSION_LOOKUP
      -> POLICY_CHECK

    POLICY_CHECK {
        YES -> KEY_LOOKUP
        NO  -> DROP
    }

    KEY_LOOKUP
      -> REPLAY_CHECK

    REPLAY_CHECK {
        YES -> DECRYPT
        NO  -> DROP
    }

    DECRYPT
      -> DECAP
      -> ROUTE
      -> DELIVER
}
```

그리고 같은 Engine에서:

```text
flow sdp_access {

    RECEIVE
      -> IDENTITY_CHECK
      -> DEVICE_CHECK
      -> POLICY_CHECK

    POLICY_CHECK {
        YES -> ENCRYPT
        NO  -> DROP
    }

    ENCRYPT
      -> TUNNEL
      -> SEND
}
```

처럼 서로 다른 보안 프로토콜/정책 흐름을 조립할 수 있도록 한다.

**핵심 개발 철학은 "프로토콜을 코드로 작성한다"가 아니라 "검증된 Block을 조립하여 프로토콜을 정의하고, Compiler가 고성능 native runtime으로 변환한다"이다.**


---

# 27. 오픈소스 최대 활용 전략

이 프로젝트의 GUI/Flow Editor를 처음부터 자체 개발하지 않는다.

핵심 원칙:

```text
Open Source Editor
        ↓
우리의 Block Definition
        ↓
Protocol Flow JSON
        ↓
우리의 Validator / Compiler
        ↓
우리의 Runtime
```

즉 **화면과 편집 기능은 오픈소스를 최대한 활용하고, 프로토콜 의미/보안/Runtime은 자체 구현**한다.

---

# 28. Visual Flow Editor 후보

## 28.1 Rete.js — 1순위 후보

Rete.js는 TypeScript 기반의 visual programming / node editor framework이며 dataflow와 control-flow graph 처리를 지원한다. React, Vue, Angular, Svelte, Lit 등의 렌더러를 사용할 수 있고, Engine 및 code generation 관련 기능도 제공한다. MIT 라이선스이다.

공식:

- https://retejs.org/
- https://github.com/retejs/rete

특히 이 프로젝트와 잘 맞는 기능:

```text
Node Editor
Dataflow
Control Flow
Hybrid Flow
Custom Node
Custom Socket
Connection Validation
Minimap
Undo/Redo
Import/Export
Validation
Auto Arrange
React Integration
Code Generation
```

따라서 **1차 Prototype은 Rete.js를 우선 검토**한다.

### 주의

Rete.js의 일부 고급 플러그인은 별도 라이선스를 사용할 수 있으므로 실제 상용 제품에 포함하기 전 사용 플러그인의 라이선스를 개별 확인한다.

---

# 29. React Flow — 대안

React Flow는 React 기반 node editor / interactive diagram 라이브러리이며 MIT 라이선스이다.

공식:

- https://reactflow.dev/
- https://github.com/xyflow/xyflow

장점:

```text
간단한 Node Editor
빠른 UI 개발
React 생태계
Node / Edge 관리
Zoom / Pan
MiniMap
Controls
```

따라서 다음 경우에 적합하다.

```text
Rete.js
→ Flow 자체를 처리/실행하는 Graph Editor

React Flow
→ UI 중심의 Graph Editor
```

초기 PoC에서 두 프레임워크를 짧게 비교하고 하나를 선택한다.

---

# 30. Blockly — 보조 후보

Blockly는 Apache 2.0 라이선스의 오픈소스 block-based visual programming editor이다.

공식:

- https://developers.google.com/blockly
- https://github.com/RaspberryPiFoundation/blockly

Blockly의 장점:

```text
Drag & Drop Block
Typed Inputs
Conditional Blocks
Variables
Expressions
Code Generation
```

그러나 본 프로젝트의 핵심 UI는:

```text
[Packet]
    |
[Parser]
    |
[Decision]
  /     \
YES     NO
```

와 같은 **Graph/Flow 중심 구조**이다.

따라서 Blockly는 일반적인 프로그래밍 언어 편집기에는 매우 적합하지만, 1차 Protocol Flow Editor의 기본 프레임워크로는 Rete.js/React Flow를 먼저 검토한다.

---

# 31. 오픈소스 선택 전략

| 영역 | 우선 후보 | 역할 |
|---|---|---|
| Flow Editor | Rete.js | Node/Edge/Control Flow |
| UI | React | Editor Application |
| 대안 Editor | React Flow | Node Graph UI |
| Block Editor | Blockly | 필요 시 세부 Expression Editor |
| Layout | Rete Auto Arrange 또는 오픈소스 Graph Layout | 자동 배치 |
| Undo/Redo | Rete plugin 또는 자체 최소 구현 | Editor history |
| Validation UI | Rete validation 기능 + 자체 | Flow 오류 표시 |
| JSON | 표준 JSON | Flow 저장 포맷 |
| Compiler | 자체 C++/Rust/TypeScript 도구 | JSON → IR |
| Runtime | 자체 C/C++ | User/Kernel |
| Crypto | 검증된 Crypto Provider | 암복호화 |
| Protocol | OpenVPN/DCO 연동 | 1차 대상 |

오픈소스를 많이 사용하되 **Runtime과 Security Boundary는 자체 소유**한다.

---

# 32. Editor와 Runtime의 책임 분리

중요한 원칙:

```text
                  Flow Editor
                      |
                      v
                 Flow JSON
                      |
                 Validation
                      |
                 Flow Compiler
                      |
                      v
                  Flow IR
                      |
              +-------+-------+
              |               |
        User Runtime     Kernel Runtime
```

Editor가 Runtime을 직접 실행하지 않는다.

Editor는:

```text
설계
검증
저장
불러오기
시각화
```

를 담당한다.

Runtime은:

```text
Packet 처리
Session
Crypto
Policy
Routing
Memory
Performance
```

를 담당한다.

---

# 33. Flow JSON을 표준 내부 포맷으로 지정

초기에는 별도의 DSL보다 JSON을 먼저 사용한다.

예:

```json
{
  "format": "protocol-flow",
  "version": 1,
  "flow": {
    "name": "openvpn_rx",
    "runtime": ["user", "kernel"]
  },
  "nodes": [
    {
      "id": "receive",
      "type": "RECEIVE"
    },
    {
      "id": "parse",
      "type": "OPENVPN_PARSE"
    },
    {
      "id": "policy",
      "type": "POLICY_CHECK"
    },
    {
      "id": "decrypt",
      "type": "DECRYPT"
    },
    {
      "id": "drop",
      "type": "DROP"
    }
  ],
  "edges": [
    {
      "from": "receive",
      "to": "parse"
    },
    {
      "from": "parse",
      "to": "policy"
    },
    {
      "from": "policy",
      "port": "yes",
      "to": "decrypt"
    },
    {
      "from": "policy",
      "port": "no",
      "to": "drop"
    }
  ]
}
```

Editor가 저장하는 파일 자체가 1차 Flow DSL 역할을 한다.

---

# 34. DSL은 나중에 JSON 위에 추가

처음부터 별도의 DSL Parser를 만들지 않는다.

1단계:

```text
Visual Editor
      ↓
JSON
      ↓
Compiler
```

2단계:

```text
Visual Editor
      ↓
JSON
      ↕
Text DSL
      ↓
Compiler
```

3단계:

```text
Visual Editor
      ↕
JSON
      ↕
Text DSL
      ↓
Common IR
      ↓
Runtime
```

따라서 JSON과 DSL이 서로 다른 의미를 갖지 않도록 **Common IR을 단일 의미 모델**로 만든다.

---

# 35. Block Registry

Editor와 Runtime에서 동일한 Block Metadata를 사용한다.

예:

```json
{
  "id": "DECRYPT",
  "name": "Decrypt",
  "category": "crypto",
  "runtime": ["user", "kernel"],
  "inputs": [
    "EncryptedPacket",
    "KeyReference"
  ],
  "outputs": [
    "PlainPacket"
  ],
  "ports": [
    "success",
    "error"
  ]
}
```

이 metadata를 기반으로:

```text
Block Palette
Node UI
Connection Validation
Property Editor
Compiler
Runtime Registry
```

를 모두 구성한다.

---

# 36. GUI에서 잘못된 Flow를 사전에 차단

예:

```text
[Decrypt]
    |
    X
[Policy]
```

처럼 타입이 맞지 않는 연결은 Editor에서 허용하지 않는다.

Block Metadata:

```text
Decrypt

Input:
    EncryptedPacket
    KeyReference

Output:
    PlainPacket
```

다음 연결:

```text
[Parse] -> [Decrypt]
```

은 가능하지만,

```text
[Route] -> [Decrypt]
```

는 타입에 따라 차단한다.

이를 통해 Runtime에서 발생할 수 있는 오류를 개발 단계에서 제거한다.

---

# 37. Port Type System

Flow Engine에 간단한 타입 시스템을 도입한다.

예:

```text
Packet
EncryptedPacket
PlainPacket

Session
Peer
KeyReference
KeyMaterial

Boolean
Decision
RouteResult
Error
```

예:

```text
OPENVPN_PARSE
    Input: Packet
    Output: OpenVPNPacket

KEY_LOOKUP
    Input: KeyId
    Output: KeyReference

DECRYPT
    Input: EncryptedPacket + KeyReference
    Output: PlainPacket
```

Editor는 이 타입 정보를 사용하여 연결 가능 여부를 판단한다.

---

# 38. Decision Port

Decision Block은 일반 Output이 아니라 명시적인 Named Port를 가진다.

예:

```text
               +-- YES --> [Decrypt]
               |
[Policy Check]-+
               |
               +-- NO ---> [Drop]
               |
               +-- ERROR -> [Audit]
```

JSON:

```json
{
  "from": "policy",
  "port": "yes",
  "to": "decrypt"
}
```

이 방식으로 IF/ELSE뿐 아니라:

```text
AUTHENTICATED
AUTHORIZED
DEVICE_TRUSTED
REPLAY_VALID
KEY_VALID
```

등을 동일한 Flow 모델로 표현한다.

---

# 39. OpenVPN Block Library를 Editor에 직접 제공

1차 Block Palette:

```text
OpenVPN
├── Parse Header
├── Control Packet
├── Data Packet
├── Peer Lookup
├── Key Lookup
├── Encrypt
├── Decrypt
├── Replay Check
├── Encapsulate
└── Decapsulate

Packet
├── Receive
├── Send
├── Parse Ethernet
├── Parse IPv4
├── Parse IPv6
├── Parse UDP
└── Parse TCP

Security
├── Authentication
├── Authorization
├── Policy
├── Device Check
├── Identity Check
└── Audit

Crypto
├── Key Reference
├── Encrypt
├── Decrypt
├── Verify Tag
└── Crypto Provider

Network
├── Route
├── Forward
├── NAT
├── Tunnel Read
└── Tunnel Write
```

---

# 40. GUI Property Editor

Block을 선택하면 속성을 편집한다.

예:

```text
+----------------------------+
| DECRYPT                    |
+----------------------------+
| Algorithm:   AES-GCM       |
| Key:         SESSION_KEY   |
| Provider:    Kernel        |
| Fail:        DROP          |
+----------------------------+
```

실제 Key Material은 표시하거나 저장하지 않는다.

```text
Key:
    SESSION_KEY
```

까지만 Flow JSON에 저장한다.

---

# 41. Crypto Block 보안 원칙

다음 형태는 금지한다.

```json
{
  "type": "AES_GCM",
  "key": "actual-secret-key"
}
```

대신:

```json
{
  "type": "DECRYPT",
  "algorithm": "AES-GCM",
  "keyRef": "session.data_key"
}
```

Runtime:

```text
keyRef
  ↓
Key Manager
  ↓
Secure Key Material
  ↓
Crypto Provider
```

Flow 파일을 복사하거나 Git에 저장해도 실제 Session Key가 노출되지 않는 구조를 유지한다.

---

# 42. Open Source 활용 범위와 자체 개발 범위

## 최대한 재사용

```text
Editor Canvas
Node Rendering
Edge Rendering
Zoom/Pan
Selection
Minimap
Undo/Redo
Auto Layout
Context Menu
Import/Export
React Integration
Graph Visualization
```

## 자체 개발

```text
Protocol Block Definition
Block Metadata
Flow Schema
Flow Validation Rules
Security Validation
Flow Compiler
IR
Runtime
Crypto Key Management
OpenVPN Adapter
DCO Integration
Kernel Components
Performance Critical Path
```

즉 **보이는 부분은 오픈소스, 의미와 실행 부분은 자체 개발**한다.

---

# 43. Prototype 개발 방법

첫 번째 PoC에서는 OpenVPN 패킷을 실제로 처리하기 전에 단순 Flow부터 만든다.

```text
[Receive]
    |
[Parse]
    |
[Policy]
  /     \
YES     NO
 |       |
[Encrypt] [Drop]
 |
[Send]
```

Rete.js에서 이를 구성한다.

저장:

```text
openvpn_test.json
```

Compiler:

```text
flowc openvpn_test.json -o flow.bin
```

Runtime:

```text
flow-runtime flow.bin
```

이 단계에서는 실제 네트워크를 연결하지 않고 Mock Packet으로 테스트한다.

---

# 44. 두 번째 PoC — OpenVPN Data Flow

```text
[Receive UDP]
      |
[Parse OpenVPN]
      |
[Session Lookup]
      |
[Key Lookup]
      |
[Replay Check]
   /       \
 YES       NO
  |         |
[Decrypt] [Drop]
  |
[Decap]
  |
[Route]
  |
[Deliver]
```

이 Flow를 JSON으로 저장하고 Runtime에서 실제 Packet을 처리한다.

---

# 45. 세 번째 PoC — DCO Adapter

```text
Existing OpenVPN
       |
       +-- Control Plane
       |
       +-- Key / Peer
       |
       v
OpenVPN DCO
       |
       v
Flow Runtime
       |
       +-- Parse
       +-- Replay
       +-- Crypto
       +-- Route
       |
       v
Network
```

기존 DCO 전체를 Fork하여 대규모 수정하지 않고 **Adapter/Hook 경계부터 확인**한다.

---

# 46. Git/CI에 오픈소스 의존성 관리 추가

오픈소스를 최대한 사용하는 대신 공급망 관리도 개발 계획에 포함한다.

각 dependency에 대해:

```text
Name
Version
Repository
License
SPDX
Source Hash
Modification
Patch
Security Advisory
```

를 기록한다.

예:

```text
Rete.js
Version: x.y.z
License: MIT
Usage: Flow Editor
Modification: None
```

상용 배포 전에 모든 dependency의 실제 라이선스와 포함된 plugin 라이선스를 재검토한다.

---

# 47. 최종 개발 구조

```text
                    Protocol Flow Studio
                           |
                 +---------+---------+
                 |                   |
            Flow Editor          Flow Validator
          (Rete.js 등)               |
                 |                   |
                 +---------+---------+
                           |
                      Flow JSON
                           |
                +----------+----------+
                |                     |
             JSON DSL              Text DSL
                |                     |
                +----------+----------+
                           |
                        Parser
                           |
                           v
                          IR
                           |
                     Optimizer
                           |
                 +---------+---------+
                 |                   |
            User Runtime        Kernel Runtime
                 |                   |
          OpenVPN Core          DCO Adapter
                 |                   |
                 +---------+---------+
                           |
                       Network
```

---

# 48. 권장 최종 기술 선택

1차 구현 기준 권장안:

```text
Editor:
    Rete.js

UI:
    React + TypeScript

Flow Format:
    JSON

Compiler:
    C++ 또는 Rust 기반 별도 tool

Runtime:
    C++

Kernel:
    Windows Kernel / WDK

OpenVPN:
    기존 OpenVPN + ovpn-dco-win 최대 재사용

Crypto:
    Crypto Provider abstraction

Storage:
    JSON + versioning

Test:
    Unit + Flow + Packet replay + Performance

CI:
    기존 GitLab CI 활용
```

Rete.js는 control-flow/dataflow 엔진과 code generation 관련 기능을 제공하므로 단순 캔버스보다 본 프로젝트의 요구에 가까운 후보이다. citeturn0search3turn0search18

---

# 49. 개발 순서 수정

기존 계획을 다음 순서로 변경한다.

```text
Phase 0
오픈소스 검토
    ↓
Rete.js / React Flow / Blockly 비교
    ↓
Phase 1
Flow JSON Schema
    ↓
Phase 2
Rete.js 기반 Editor PoC
    ↓
Phase 3
Block Registry + Validator
    ↓
Phase 4
C++ Flow Runtime
    ↓
Phase 5
OpenVPN Static Flow
    ↓
Phase 6
Crypto / Key Reference
    ↓
Phase 7
OpenVPN DCO Adapter
    ↓
Phase 8
Flow Compiler / IR
    ↓
Phase 9
User / Kernel Runtime
    ↓
Phase 10
Performance Optimization
    ↓
Phase 11
Text DSL
    ↓
Phase 12
Production Flow Studio
```

이렇게 하면 **GUI를 먼저 완성하고 나중에 Runtime을 맞추는 실수를 피하면서도, 개발자가 실제 Flow를 눈으로 확인하며 Runtime을 개발할 수 있다.**

---

# 50. 최종 방향

이 프로젝트에서 가장 중요한 것은 자체 GUI를 만드는 것이 아니다.

```text
기존 오픈소스
       +
Protocol Block Model
       +
Flow JSON
       +
Compiler
       +
Runtime
```

을 결합하여 **프로토콜 개발 자체를 시각적인 Flow 조립 작업으로 바꾸는 것**이다.

따라서 오픈소스 활용 원칙은:

> **"Editor는 사서 쓰고, Protocol Model과 Runtime을 만든다."**

로 정한다.

이렇게 하면 개발 초기 비용을 크게 줄이면서도 최종 제품에서는 자체 Protocol Flow Engine을 보유할 수 있다.
