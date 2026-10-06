# Protocol Flow Engine — Flow 모델 확장 계획 (State Machine · Context 일반화 · Trace)

- 작성일: 2026-10-06
- 상태: **방향 확정(D-040). F-1 S0~S4 구현 완료(D-041, 2026-10-06)**: 형식은 `docs/Machine_JSON_Schema_v1.md`, 코드는 `core/include/pf/machine.h`·`machine_json.h`·`keepalive_machine.h`. 실제로 구현한 범위가 아래 초안과 다른 부분은 §3.2.1에 정리했다
- 관련: D-009(MVP Control Plane은 일반 코드), D-019(Block 결과 계약), D-035/D-036(Flow JSON v1·Validator), D-039(NAT 계획 채택 범위)
- 계기: `plans/Protocol_Flow_Engine_NAT_Traversal_Lab_Development_Plan.md` §5(State/Timer), §15(Packet Trace). 하지만 이 계획의 대상은 **NAT 전용이 아니다**. OpenVPN 제어 채널(재전송·재협상·keepalive), 폴백, 앞으로 들어올 모든 프로토콜에 똑같이 적용된다.

이 문서는 Post-MVP 공통 기반 세 가지를 다룬다.

| ID | 항목 | 왜 필요한가 | 마일스톤 |
|---|---|---|---|
| **F-1** | State Machine 층 (순환·타이머·상태) | 재시도·대기·재협상 같은 제어 로직을 Flow로 표현 | PM-4 |
| **F-2** | `FlowContext` 일반화 | OpenVPN 외의 프로토콜 Block(STUN 등)을 받으려면 필요 | 첫 비-OpenVPN 프로토콜 직전 (PM-2 또는 PM-9) |
| **F-3** | Packet / Transition Trace | 에디터 디버깅(PM-6), MCP Resource(PM-7), NAT 랩 결과 분석(PM-2) | PM-2·PM-6 중 먼저 오는 쪽 |

---

## 1. 현재 모델과 한계

현재 Flow(`core/include/pf/flow.h`, `docs/Block_API.md`)는 다음과 같다.

- **패킷 1개를 처리하는 DAG**다. 첫 노드에서 시작하고 Action/Decision을 거쳐 `Completed`, `Dropped`, `Errored` 중 하나로 끝난다.
- **순환은 금지**다. `FlowBuilder`와 Validator가 거부하고(`Cycle`), 실행 중에는 `max_steps`(1024)로 한 번 더 막는다. 그래서 패킷당 작업량이 유한하다.
- **상태와 시간이 없다.** 시간이 지나는 것, 이전 패킷의 결과, 재시도 횟수를 Flow가 알 수 없다.

그래서 D-009는 "타이머·재전송 상태머신은 DAG로 표현하기 곤란하므로 Control Plane은 일반 코드로 짠다"고 정했다. 지금 일반 코드로 짠 상태머신은 다음과 같다.

| 코드 | 상태·시간 요소 |
|---|---|
| `ControlClient` | hard reset → TLS → key-method 2 → PUSH_REPLY, 재협상, 실패 판정 |
| `reliable.h` | 송신 윈도우, 지수 백오프 재전송, 실패 판정 |
| `KeepaliveTimer` | ping 간격, ping-restart |
| `FallbackConnector` | 시도별 제한 시간, 정책 순회 |

NAT 계획의 STUN 재전송, hole punching 재시도, ICE connectivity check, TURN 할당 갱신도 모두 같은 종류다. 이것을 Flow로 표현하지 못하면 에디터(PM-6)와 AI(PM-7)가 다룰 수 있는 범위가 패킷 분류·암복호에서 멈춘다.

## 2. 결정: 두 층 모델

**패킷 Flow에는 순환을 허용하지 않는다. 순환은 그 위의 State Machine 층에만 둔다.**

```text
┌─ State Machine 층 (순환 허용, 이벤트 구동) ───────────────────────────────┐
│  상태:   IDLE → DISCOVERING → PUNCHING ⇄ RETRY_WAIT → CONNECTED            │
│                                  └────────→ FAILED → RELAY                │
│  이벤트: packet(분류 결과) · timer(이름) · command(외부) · child(하위 완료)   │
│  전이:   (상태, 이벤트, guard) → 핸들러 Flow 실행 → 다음 상태 + 출력 액션    │
└──────────────────────────────────────────────────────────────────────────┘
                 │ 전이마다 핸들러 Flow 1회 실행 (DAG, 반드시 종료)
┌─ Packet Flow 층 (지금 모델 그대로, 순환 금지) ─────────────────────────────┐
│  parse → classify → check → decrypt → ...   (Flow JSON v1, 기존 Validator)   │
└──────────────────────────────────────────────────────────────────────────┘
```

이렇게 나누는 이유:

1. **데이터 경로의 성능과 검증 가능성을 지킨다.** 패킷마다 도는 경로는 계속 DAG이고 step 한도가 있다. PM-8 커널 런타임과 eBPF식 검증기의 전제(종료가 보장되는 코드만 실행)와도 맞는다.
2. **순환은 시간을 사이에 둔 순환으로만 생긴다.** 재시도는 "타이머를 걸고 상태로 돌아간다"로 표현한다. 한 이벤트를 처리하는 동안에는 순환이 없다. 즉 한 번의 이벤트 처리는 항상 유한하고, 순환은 다음 이벤트(타이머 만료 등)가 있어야만 이어진다.
3. **이미 검증된 Flow v1 자산이 그대로 남는다.** Flow JSON v1, Validator, C3 골든 동등성, 블록 id를 건드리지 않는다.
4. **업계 선례와 같다.** P4 parser state machine, SCXML/Harel statechart, VPP의 제어/데이터 분리, OpenVPN 자체의 "제어 상태머신 + 데이터 경로" 구조.

검토했다가 채택하지 않은 대안:

| 대안 | 기각 이유 |
|---|---|
| 패킷 Flow 안에 상한 있는 루프(`loop max=N`) 허용 | 시간이 흐르는 동안의 대기(WAIT 100ms)를 표현할 수 없다. 패킷 처리 중 블로킹이 생기고 데이터 경로 검증이 어려워진다 |
| 제어 로직은 영원히 일반 코드(D-009 유지) | 에디터·AI가 제어 흐름을 다룰 수 없다. NAT 계획의 핵심 목표(§3, §26)를 달성하지 못한다 |
| 범용 스크립트 언어 내장(Lua 등) | 임의 코드 실행이 된다. MCP 계획의 "검증된 Flow/IR만 실행" 원칙과 충돌한다 |

## 3. 실행 의미 (초안 — PM-4에서 확정)

### 3.1 Sans-I/O 런타임

`ControlClient`·`TunnelSession`과 같은 방식이다. **런타임은 소켓·시계·난수를 직접 갖지 않는다.**

```text
MachineRunner::on_event(event, now_ms) → Step {
    transitions_taken,          // 실행한 전이 목록 (trace용)
    actions[]                   // send(transport, packet) · arm_timer(name, deadline) · cancel_timer(name)
                                // · emit(output) · spawn(child) · stop(result)
    state                       // 새 상태
}
MachineRunner::next_deadline_ms()   // 가장 이른 타이머 (호출자가 poll 대기 시간에 사용)
```

- 시계는 호출자가 넘긴다. 테스트는 가짜 시계로 재시도·timeout을 결정적으로 재현한다(`KeepaliveTimer`와 같음).
- 난수(STUN transaction id, ICE tie-breaker)는 주입되는 `RandomSource`를 쓴다. 운영에서는 OS CSPRNG, 테스트에서는 고정 시드를 쓴다.
- **run-to-completion**: 이벤트 하나를 끝까지 처리한 뒤 다음 이벤트를 받는다. 처리 중에 생긴 이벤트는 큐에 넣는다. 큐 길이에는 상한을 두고, 넘치면 `Error`로 끝낸다.

### 3.2 구성 요소

| 요소 | 규칙 |
|---|---|
| 상태 | 이름 유일. `initial` 정확히 1개, `final` 1개 이상(성공·실패를 구분: `result: ok/failed`) |
| 이벤트 | `packet:<분류>` (분류 Flow의 출력) · `timer:<이름>` · `command:<이름>` · `child:<이름>:ok/failed` |
| 전이 | `{from, on, guard?, run?, to}`. `run`은 핸들러 Flow 이름(Packet Flow 층, DAG). `guard`는 Decision 블록 하나 또는 카운터 비교 |
| 변수 | **선언한 것만** 쓴다. 타입은 `Integer/Bool/Endpoint/KeyRef`. 키 바이트는 변수에 둘 수 없다(KeyRef만) |
| 카운터 | `{name, max}` 필수. 증가는 전이 액션으로만 하고, `max`를 넘는 증가는 guard로 막아야 한다 |
| 타이머 | `{name, duration_ms | from_param}`. 범위 `[1ms, 24h]`. `arm`/`cancel`은 전이 액션으로만 한다 |
| 하위 Machine | `spawn`으로 실행하고 결과는 `child:*` 이벤트로 받는다. NAT Traversal → VPN Session 같은 합성(NAT 계획 §24)을 이렇게 표현한다 |

### 3.2.1 v1 구현 범위 (D-041)

위 표는 초안이다. v1에서 구현한 범위는 다음과 같다.
- 이벤트: `packet:`·`command:`·`timer:`·`auto`
- guard: 카운터 비교 `<` / `>=`만
- actions: `inc`/`reset`/`arm`/`cancel`/`emit`
- 나중으로 미룬 것(필요해지는 첫 사용처에서 결정): **변수(`Endpoint`/`KeyRef` 등), 하위 Machine `spawn`과 `child:` 이벤트, Decision 블록 guard**. 그때까지 분기는 "분류 Flow가 서로 다른 `packet:<분류>` 이벤트를 만든다"는 방식으로 표현한다.

### 3.3 기존 Block 결과 계약과의 관계

핸들러 Flow는 지금의 `run_flow` 그대로다. 결과는 이렇게 매핑한다.

| 핸들러 Flow 결과 | 전이 |
|---|---|
| `Completed` | 전이 수행 (`to` 상태로) |
| `Dropped` | **전이하지 않음.** 입력 탓이므로 현재 상태를 유지하고 패킷만 버린다. trace에 사유를 남긴다 |
| `Errored` | Machine 종료 (`final: failed`, 오류 코드 보존). 우리 쪽 실패이기 때문이다 |

`Drop`=입력 탓, `Error`=우리 실패라는 D-019 계약을 상태 층까지 그대로 끌고 가는 것이다. 위조 STUN 응답 하나 때문에 상태가 망가지면 안 된다. 그래서 `Dropped`는 전이를 일으키지 않는다.

## 4. Validator 규칙 (State Machine)

순환을 허용하는 대신 아래를 **실행 전에 정적으로** 검사한다. Flow v1 Validator와 똑같이 이슈는 `{code, path, message}`이고 한 번에 여러 개를 보고한다.

| code (안) | 규칙 |
|---|---|
| `UnknownState` / `UnknownEvent` / `UnknownFlow` | 참조 무결성 |
| `NoInitial` / `MultipleInitial` / `NoFinal` | 상태 구성 |
| `UnreachableState` | initial에서 도달할 수 없는 상태 |
| `NoExit` | **모든 상태에서 final(성공 또는 실패)에 도달 가능해야 한다.** 빠져나올 수 없는 순환(livelock)을 거부 |
| `ImmediateCycle` | 타이머·외부 이벤트를 거치지 않는 순환(같은 이벤트 처리 안에서 돌아오는 경로)을 거부. 순환에는 반드시 `timer:*`, `packet:*`, `command:*` 전이가 하나 이상 있어야 한다 |
| `UnboundedRetry` | `timer:*`로 이어진 순환은 상한 있는 카운터 guard를 거쳐야 하고, 상한에 닿으면 순환 밖으로 나가는 전이가 있어야 한다. 무한 재시도는 명시적으로 `max: unbounded` + 근거 주석이 있을 때만 허용한다(예: keepalive) |
| `WaitWithoutTimeout` | 패킷을 기다리는 상태(외부 이벤트만 받는 상태)에는 timeout 타이머 전이가 반드시 있어야 한다. 무응답에서 영원히 멈추지 않게 하기 위함 |
| `NondeterministicTransition` | 같은 (상태, 이벤트)에 guard 없는 전이가 2개 이상. guard가 있으면 선언 순서대로 평가 |
| `UnhandledEvent` | 경고 수준. 상태가 받지 않는 이벤트는 무시하고 trace에 남긴다 |
| `TimerRange` / `CounterRange` | 타이머·카운터 범위 위반 |
| `SecretLiteral` | Flow JSON v1과 같은 규칙. 변수·파라미터에 키 재료 금지 |

`NoExit`·`ImmediateCycle`·`UnboundedRetry`는 그래프 검사로 판정할 수 있다. 상태 그래프에서 강연결요소(SCC)를 구하고, 각 SCC 안에 타이머/외부 이벤트 전이가 있는지, 상한 guard와 탈출 전이가 있는지를 본다. 변수 값에 의존하는 일반적인 종료 증명은 하지 않는다. 그 대신 카운터라는 제한된 형태만 허용해서 판정 가능한 범위에 머문다.

## 5. 파일 형식 (권장안)

**Flow JSON v1을 바꾸지 않고, 별도 형식 `protocol-machine` v1을 둔다.**

```json
{
  "format": "protocol-machine",
  "version": 1,
  "machine": { "name": "stun_binding", "description": "RFC 8489 binding transaction" },
  "flows": ["stun_classify", "stun_send_request", "stun_accept_response"],
  "vars": [ { "name": "public_endpoint", "type": "Endpoint" } ],
  "counters": [ { "name": "tries", "max": 7 } ],
  "timers": [ { "name": "rto", "from_param": "rtoMs" } ],
  "states": [
    { "id": "idle", "initial": true },
    { "id": "waiting" },
    { "id": "done", "final": "ok" },
    { "id": "failed", "final": "failed" }
  ],
  "transitions": [
    { "from": "idle",    "on": "command:start",      "run": "stun_send_request", "actions": ["arm:rto", "inc:tries"], "to": "waiting" },
    { "from": "waiting", "on": "packet:stun_response", "run": "stun_accept_response", "actions": ["cancel:rto"], "to": "done" },
    { "from": "waiting", "on": "timer:rto", "guard": "tries < max", "run": "stun_send_request", "actions": ["arm:rto", "inc:tries"], "to": "waiting" },
    { "from": "waiting", "on": "timer:rto", "guard": "tries >= max", "to": "failed" }
  ]
}
```

- 참조하는 `flows`는 각각 Flow JSON v1 문서다. 기존 로더·Validator를 그대로 쓴다.
- 배포·서명(PM-6, D-023) 단위는 Machine 1개 + 참조 Flow 묶음(bundle)으로 둔다. 묶음 형식은 PM-6에서 정한다.
- **커널 런타임(PM-8)은 `protocol-flow`만 받는다.** State Machine은 사용자 모드에서만 실행한다. 데이터 경로만 커널로 내리는 구조와 맞는다.
- 따로 두는 이유: v1 문서의 의미가 바뀌지 않는다(마이그레이션 불필요). 데이터 경로 전용 소비자(커널, 성능 경로)가 Machine 개념을 몰라도 된다.

## 6. F-2 — `FlowContext` 일반화

현재 `FlowContext`에는 `OvpnHeader header`, `DataV2Packet data_v2`가 직접 들어 있다(Block_API §7의 알려진 한계). STUN·TURN Block이 이 구조에 필드를 계속 덧붙이면 모든 Flow가 모든 프로토콜의 상태를 들고 다니게 된다.

방향(안):

| 항목 | 안 |
|---|---|
| 공통 필드 | `packet`, `error`, `flags`, `key_ref`, 서비스 포인터(`keys`, `aead`, …), `user_context`는 유지 |
| 프로토콜별 결과 | 프로토콜마다 슬롯 구조체(`OvpnSlot`, `StunSlot`, …)를 만들고 컨텍스트에는 타입 태그 + 고정 크기 저장소로 둔다. 힙 할당 없음(PM-8 커널 ABI와 맞춤) |
| Block 선언 | `BlockDescriptor`에 `consumes`/`produces`(슬롯 이름)를 추가한다. Validator가 "parse 전에 decrypt" 같은 배선 오류를 실행 전에 거부한다(`ContextNotProduced`) |
| 호환 | 블록 id 재번호 금지(규칙 유지). 기존 OpenVPN 블록 등록 코드는 선언만 추가 |

종료 조건:
- C3 골든 동등성 테스트(실제 OpenVPN 패킷)가 그대로 통과한다.
- `docs/Performance_Baseline.md`의 데이터 경로 측정이 기준선 변동 범위(±15%) 안에 있다.
- ASan/UBSan을 통과한다.
- 새 Validator 규칙에 대해 유효/무효 테스트와 차등 테스트를 둔다.

### 6.1 v1 구현 (D-043)

- 슬롯: `ProtocolSlot`(`pf/protocol_slot.h`, 128B). OpenVPN은 `OvpnSlot`(`pf/ovpn_context.h`).
- 계약: `BlockDescriptor::consumes`/`produces`. 분석: `find_context_gaps`(FlowBuilder·Validator 공유). Flow 입력: `FlowBuilder::input`, Flow JSON `flow.inputs`.
- 위 표의 `ContextNotProduced` 외에 `BadInput`이 생겼다. fact는 "슬롯 이름"보다 잘게 나눴다: `ovpn.header`, `ovpn.data_v2`, `key`.
- 블록 설명은 `docs/Block_API.md` §11에 있다.

## 7. F-3 — Packet / Transition Trace

NAT 계획 §15의 trace, 에디터의 "어느 노드에서 Drop됐나" 표시, MCP의 `trace.analyze`가 모두 같은 데이터를 필요로 한다. 하나로 만든다.

| 항목 | 안 |
|---|---|
| 수집 지점 | `run_flow`(노드 실행마다)와 `MachineRunner`(이벤트·전이·타이머마다). 선택적 `TraceSink*` 인자로 받고, `nullptr`이면 비용이 0에 가깝다(측정으로 확인) |
| 레코드 | `{t_ms(주입 시계), kind(node/event/transition/timer/action), machine, state, flow, node, block, result, error, packet_len, meta}` |
| **기본 비공개 규칙** | 페이로드 바이트, 키, 평문, TURN/STUN 자격증명은 **절대 기록하지 않는다.** 주소·포트는 `meta`에 기록하되, 출력 시 마스킹 옵션을 둔다. 바이트 덤프가 필요하면 테스트 빌드 전용 sink만 허용한다 |
| 버퍼 | 고정 크기 링 버퍼. 넘치면 오래된 것부터 덮어쓰고 덮어쓴 개수를 센다. 할당하지 않는다 |
| 출력 | JSON Lines(정규 출력은 `json.h` 재사용). `pf_client --trace FILE`, 테스트 assertion, 이후 MCP Resource(PM-7) |
| 검증 | 키·평문이 trace에 나오지 않는지 테스트로 고정한다. 알려진 테스트 키 바이트와 평문 패턴을 trace 출력에서 검색해서 0건이어야 한다 |

### 7.1 v1 구현 범위 (D-042)

- 구현: `core/include/pf/trace.h`(`TraceSink`, `TraceRing`, JSON Lines), `run_flow(..., TraceSink*)`, `MachineRunner::set_trace`, `DataPath`/`TunnelSession::set_trace`, `pf_client --trace`.
- 레코드 종류: `node`, `flow_end`, `event`, `transition`, `emit`, `machine_end`. 위 표의 `timer`·`action` 종류는 따로 두지 않았다. 타이머 발생은 `event`(`timer:x`)로, action은 `emit`·`transition`으로 나타난다.
- 바이트를 담는 필드가 아예 없으므로 비공개 규칙은 구조로 보장된다. **주소 `meta`·마스킹·테스트 전용 덤프 sink는 v1에 없다.** 주소가 처음 생기는 PM-2b에서 결정한다.

## 8. D-009와의 관계, 이행 순서

- D-009는 **MVP 결정으로 그대로 둔다.** OpenVPN 제어 채널(`ControlClient`)은 State Machine 런타임이 동등성을 증명하기 전까지 일반 코드로 유지한다.
- 증명 방법은 C3와 같은 방식이다. **같은 기능을 Machine으로 다시 표현하고, 기존 코드와 차등 테스트로 동일함을 보인다.**
  - 1차 대상은 `KeepaliveTimer`다. 작고, 순수 로직이고, 테스트가 이미 있다.
  - 2차 대상은 `reliable.h`의 재전송 백오프다.
  - `ControlClient` 전체를 옮길지는 그 결과를 보고 결정한다(별도 결정).

## 9. 단계와 종료 조건

| 단계 | 내용 | 종료 조건 |
|---|---|---|
| S0 ✅ | 이 문서 리뷰, 실행 의미·Validator 규칙 확정 | DECISIONS에 PM-4 세부 결정 기록 (D-041) |
| S1 ✅ | `MachineRunner`(sans-I/O, 가짜 시계) + 코드로 정의하는 `MachineBuilder` | 단위 테스트: 전이, Drop 비전이, Error 종료, 타이머 순서, auto 연쇄 상한 (`tests/flow/test_machine_runner.cpp`). v1에는 내부 이벤트 큐가 없어서(이벤트를 만들어내는 action이 없음) 큐 상한도 필요 없다. 난수 주입은 첫 사용처(S7)에서 |
| S2 ✅ | Machine Validator (§4 전체, `tests/unit/test_machine_validator.cpp`) | 유효/무효 Machine 케이스 + **무작위 Machine 차등 테스트**(Validator가 통과시킨 것은 무작위 이벤트열에서 반드시 final 또는 정상 대기로 끝나야 함) |
| S3 ✅ | `protocol-machine` v1 로더/라이터 + 마이그레이션 규칙(Flow JSON v1 §7과 동일, `upgrade_document` 공유) | 스키마 테스트, fuzz 타깃(`fuzz_machine_load`) |
| S4 ✅ | 동등성: `KeepaliveTimer`를 Machine으로 표현 → 기존 코드와 차등 테스트 (`tests/flow/test_machine_keepalive.cpp`, 골든 `machine_keepalive.machine.json`) | 무작위 이벤트·시간열에서 출력 동일, 변이 검출 |
| S5 ✅ | F-3 Trace (`run_flow` + `MachineRunner`, D-042) | 비공개 규칙 테스트(실제 OpenVPN 골든), 성능 측정(trace 끔 상태 기준선 유지: `tests/performance/bench_flow_trace.cpp`) |
| S6 ✅ | F-2 Context 일반화 (D-043) | §6 종료 조건 — 모두 충족 |
| S7 | 첫 실제 사용처: STUN binding transaction Machine (PM-2 N3와 함께) | 실제 STUN 서버 상대 상호운용 |

S5·S6은 S1~S4와 독립이다. PM-2가 먼저 시작되면 S6 → S5 순서로 당겨서 할 수 있다(`docs/PM2_NAT_Traversal_Scope.md` §6 참고).

## 10. 열린 질문 (PM-4 진입 시 결정)

1. ~~계층 상태 지원 여부~~ → D-041: v1은 **평평한 상태만**. `spawn`(하위 Machine)은 첫 합성 사용처(PM-2 N7 또는 NAT→VPN)에서 결정
2. ~~guard 범위~~ → D-041: v1은 **카운터 비교(`<`, `>=`)만**. Decision 블록 guard는 필요해지면 추가(종료 판정에 영향 없음)
3. 텍스트 DSL(PM-4의 원래 범위)에서 Machine을 어떻게 표기할지
4. 에디터(PM-6)에서 상태 다이어그램과 패킷 Flow 캔버스를 한 화면에 둘지, 드릴다운으로 나눌지
5. 여러 Machine 인스턴스(ICE의 후보 쌍마다 하나)의 스케줄링과 자원 한도
