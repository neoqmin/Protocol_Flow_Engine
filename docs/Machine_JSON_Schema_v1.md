# Machine JSON 스키마 v1 (`protocol-machine`)

State Machine(F-1, D-040/D-041)을 저장·교환하는 파일 형식이다. 구현은 다음과 같다.
- 구조 검증: `core/include/pf/machine_json.h`
- 의미 검증·컴파일·실행: `core/include/pf/machine.h`
- 계획: `plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md`

정본 예시는 `tests/regression/golden/machine_keepalive.machine.json`이다. 이 파일은 `keepalive_machine_document()`의 정규 출력과 바이트 단위로 같아야 하고, 기존 `KeepaliveTimer`와 동작이 같다는 것이 테스트로 보장된다(`tests/flow/test_machine_keepalive.cpp`).

패킷 Flow(`protocol-flow`, `docs/Flow_JSON_Schema_v1.md`)는 바뀌지 않는다. Machine은 Flow를 **이름으로 참조**할 뿐이다. 커널 런타임(PM-8)은 `protocol-flow`만 받는다.

## 1. 문서 구조

```json
{
  "format": "protocol-machine",
  "version": 1,
  "machine": { "name": "stun_binding", "description": "RFC 8489 binding transaction" },
  "flows": ["send", "accept"],
  "events": ["command:start", "packet:response"],
  "outputs": ["done"],
  "counters": [ { "name": "tries", "max": 7 } ],
  "timers": [ { "name": "rto", "param": "rtoMs" } ],
  "states": [
    { "id": "idle", "initial": true },
    { "id": "waiting" },
    { "id": "done", "final": "ok" },
    { "id": "failed", "final": "failed" }
  ],
  "transitions": [
    { "from": "idle", "on": "command:start", "run": "send", "actions": ["arm:rto", "inc:tries"], "to": "waiting" },
    { "from": "waiting", "on": "packet:response", "run": "accept", "actions": ["cancel:rto", "emit:done"], "to": "done" },
    { "from": "waiting", "on": "timer:rto", "guard": { "counter": "tries", "op": "<", "value": 7 }, "run": "send", "actions": ["arm:rto", "inc:tries"], "to": "waiting" },
    { "from": "waiting", "on": "timer:rto", "guard": { "counter": "tries", "op": ">=", "value": 7 }, "to": "failed" }
  ],
  "meta": { "author": "qa" }
}
```

| 위치 | 필드 | 필수 | 규칙 |
|---|---|---|---|
| 최상위 | `format` | ✔ | 정확히 `"protocol-machine"` |
| | `version` | ✔ | 양의 정수 리터럴 |
| | `machine` | ✔ | `name`(ID 문법, 필수), `description`(≤ 4096바이트) |
| | `flows` | | 핸들러 Flow 이름(ID 문법). 실행할 때 Flow 라이브러리에 모두 있어야 한다 |
| | `events` | | 호출자가 넣는 이벤트: `"packet:<id>"` 또는 `"command:<id>"` |
| | `outputs` | | `emit:` 대상 이름(ID 문법) |
| | `counters` | | `{name, max}`. `max`는 1..1,000,000 |
| | `timers` | | `{name, ms}` 또는 `{name, param, allowDisabled?}`, 선택 `backoff` (§3) |
| | `states` | ✔ | `{id, initial?, final?}`. `final`은 `"ok"`/`"failed"` |
| | `transitions` | ✔ | §2 |
| | `meta` | | 문자열 값만, ≤ 64개 |
| `transitions[]` | `from`, `to` | ✔ | 상태 id. 같은 상태로 돌아가는 것도 허용 |
| | `on` | ✔ | `packet:<id>` · `command:<id>` · `timer:<id>` · `auto` |
| | `guard` | | `{counter, op: "<" | ">=", value}`. `value`는 0..해당 카운터의 `max` |
| | `run` | | 핸들러 Flow 이름(`flows`에 선언) |
| | `actions` | | ≤ 16개, 순서대로 실행: `inc:<counter>` · `reset:<counter>` · `arm:<timer>` · `cancel:<timer>` · `emit:<output>` |
| | `unbounded` | | 의도적으로 끝나지 않는 timer 순환일 때 **이유**(비어 있으면 오류). timer 전이에만 쓸 수 있다 |

**ID 문법**은 Flow JSON v1과 같다: `[A-Za-z_][A-Za-z0-9_-]{0,63}`. **알 수 없는 필드는 오류**이고, `x-`로 시작하는 확장은 모든 객체(최상위, `machine`, 카운터, 타이머, 상태, 전이)에 둘 수 있으며 보존된다. `guard`는 확장을 받지 않는다.
한도: 상태 ≤ 1024, 전이 ≤ 8192, 각 선언 목록 ≤ 256, 한 번에 보고하는 오류 ≤ 100.

## 2. 실행 의미 (`MachineRunner`)

- **sans-I/O**: 런타임은 소켓과 시계를 갖지 않는다. 호출자가 `now_ms`를 넘기고 `packet:`/`command:` 이벤트를 `on_event`로 넣는다. `next_deadline_ms()`까지 기다렸다가 `poll_timer`를 부르면 timer 이벤트가 발생한다. `emits`는 호출자가 할 일을 알려준다(예: `ping`을 보내라).
- `start()`가 initial 상태에 들어가고 그 상태의 `auto` 전이를 처리한다. 반드시 한 번만, 다른 호출보다 먼저 부른다.
- **전이 선택**: 현재 상태에서 그 이벤트를 받는 전이를 **선언 순서대로** 보고, guard가 참인 첫 번째 전이를 고른다. 해당하는 전이가 없으면 이벤트를 무시한다(`handled = false`).
- **핸들러**(`run`): 전이마다 Flow를 최대 1회 실행한다(DAG이므로 작업량이 유한하다).
  - `Completed`: actions를 실행하고 `to`로 간다.
  - `Dropped`: **전이하지 않는다.** 상태·카운터·타이머가 모두 그대로다. 위조 패킷 하나로 상태가 바뀌지 않게 하기 위함이다. `error`에 사유가 남는다.
  - `Errored`: Machine이 실패로 끝난다(`status = Failed`, 오류 코드 보존). 우리 쪽 실패이기 때문이다(D-019).
- **actions**는 선언 순서대로 실행한다.
  - `inc`는 `max`에서 멈춘다(포화).
  - `arm`은 `now + 지속시간`으로 (다시) 건다.
  - `cancel`은 해제한다.
  - `emit`은 출력을 순서대로 쌓는다.
- **auto 전이**: 상태에 들어간 직후 guard가 참인 `auto` 전이가 있으면 바로 탄다. auto로만 이루어진 순환은 Validator가 거부한다. 런타임도 한 이벤트 안에서 상태 수보다 많은 auto 전이가 일어나면 `StepLimit`으로 실패시킨다(2차 방어선).
- **타이머**는 한 번만 발생한다(one-shot). 발생하면 해제되고, 다시 쓰려면 다시 `arm`해야 한다. 마감이 같은 타이머가 여럿이면 **선언 순서**대로 발생한다. `poll_timer`는 한 번에 하나씩만 발생시킨다(호출자가 반복 호출).
- **final 상태**에 들어가면 `status`가 `Succeeded`(`"ok"`) 또는 `Failed`(`"failed"`)가 되고 모든 타이머가 해제된다. 그 뒤의 이벤트는 무시된다.
- **API 오용**은 실행하지 않고 `Error::Internal`로 보고한다. 해당하는 경우: `start` 전에 이벤트를 넣음, `start`를 두 번 부름, timer·`auto` 이벤트를 `on_event`로 넣음, 범위 밖 인덱스.

## 3. 타이머와 파라미터

- `ms`: 1..86,400,000(24시간) 리터럴.
- `backoff`(선택, D-047): 카운터 이름. `arm`할 때마다 지속시간 × 2^(카운터 값 − 1)을 쓴다(카운터 0은 1로 셈, 상한 24시간). STUN 재전송(RFC 8489 6.2.1)처럼 지수적으로 늘어나는 재시도용이다. 모르는 카운터면 `UnknownCounter`(`/timers/i/backoff`).
- `param`: 이름(`[a-z][A-Za-z0-9_]*`). 값은 `MachineRunner::create`에서 받는다. `allowDisabled: true`이면 값 0을 허용하고, 0이면 그 타이머는 "꺼짐"이다(`arm`이 아무 일도 하지 않는다). OpenVPN의 `ping 0`이 이 경우다.
- `create`는 **모든 param이 주어지고 다른 것은 주어지지 않아야** 성공한다. 오타가 조용히 무시되지 않게 하기 위함이다. 범위를 벗어난 값도 거부한다.

## 4. 의미 검증 (`validate_machine`)

모든 이슈는 `{code, path(JSON Pointer), message}`이고 한 번에 여러 개를 돌려준다. 그래프 검사는 참조 오류가 없을 때만 한다.

| code | 의미 |
|---|---|
| `DuplicateId` | 상태·카운터·타이머·출력·이벤트·Flow 이름 중복 |
| `NoInitial` / `MultipleInitial` / `NoFinal` / `BadFinal` | 상태 구성(initial은 final일 수 없음) |
| `UnknownState` / `UnknownEvent` / `UnknownTimer` / `UnknownCounter` / `UnknownOutput` / `UnknownFlow` | 참조 무결성 |
| `BadEvent` / `BadAction` | 형식 오류(`events`에는 `packet:`/`command:`만) |
| `MissingFlow` | 선언한 Flow가 라이브러리에 없음 |
| `BadGuard` / `CounterRange` / `TimerRange` | 값 범위 |
| `FinalHasTransitions` | final 상태에서 나가는 전이 |
| `NondeterministicTransition` | 같은 (상태, 이벤트)에 guard 없는 전이가 2개, 또는 같은 guard가 2개 |
| `ShadowedTransition` | guard 없는 전이 뒤에 있어서 절대 선택되지 않는 전이 |
| `TimerNeverArmed` | `timer:x` 전이가 있는데 `arm:x`가 어디에도 없음 |
| `Unreachable` | initial에서 도달할 수 없는 상태 |
| `NoExit` | 이 상태에서 final로 갈 길이 없음(livelock) |
| `ImmediateCycle` | `auto`로만 이루어진 순환(이벤트 없이 도는 루프). 메시지에 경로 `a -> b -> a` |
| `UnboundedRetry` | 순환 안의 timer 전이가 카운터로 묶여 있지 않음 |
| `GuardNotExhaustive` | timer 이벤트의 guard가 모두 거짓일 수 있음(발생해도 아무 일이 없어 멈춤) |
| `WaitWithoutTimeout` | 패킷을 기다리는 상태에 timer 전이가 없음(아무것도 안 오면 영원히 대기) |
| `BadUnbounded` | timer가 아닌 전이에 `unbounded` |
| `SecretLiteral` | 문자열에 PEM 재료 |

**순환 규칙(`UnboundedRetry`)의 정확한 정의**: 상태 그래프의 강연결요소(SCC) 안에 머무는 timer 전이는, `unbounded`가 없다면 다음 둘을 모두 만족해야 한다.
1. guard가 `c < N`이고 actions에 `inc:c`가 있다.
2. 같은 SCC 안의 timer·`auto` 전이가 그 `c`를 `reset`하지 않는다(`packet`·`command` 전이의 reset은 허용한다. 상대가 응답했으니 다시 세는 것이다).

이 규칙과 `ImmediateCycle`이 함께 보장하는 것은 이것이다. **네트워크가 조용하면(timer만 발생하면) Machine은 유한한 횟수 안에 끝나거나, 걸린 타이머가 없는 상태에서 멈춘다.** 이 보장은 무작위 Machine 차등 테스트(`tests/flow/test_machine_random.cpp`, Validator가 통과시킨 5천여 개)와 fuzz 타깃 `fuzz_machine_load`로 확인한다.

## 5. 버전 관리 / 정규 출력

Flow JSON v1 §7과 같은 규칙이고, 구현(`upgrade_document`)도 공유한다.
- **읽기**: 현재보다 새 버전은 거부하고, 구버전은 마이그레이터를 단계별로 적용한다.
- **쓰기**: 항상 현재 버전으로 쓴다. 멤버 순서는 고정이고 기본값은 생략한다(`initial: false`, 빈 `final`, `allowDisabled: false`, 빈 `actions`/`run`/`unbounded`, 빈 선택 목록).
- `parse(write(x)) == x`이고, 쓰기 결과는 다시 써도 같다(고정점).

## 6. 변경 이력

| 버전 | 날짜 | 내용 |
|---|---|---|
| 1 | 2026-10-06 | 최초: 평평한 상태, packet/command/timer/auto 이벤트, 카운터 guard, 5종 action, `unbounded` |
| 1 (호환 추가) | 2026-10-06 | 타이머 선택 필드 `backoff`(D-047). 같은 버전 안의 선택 필드 추가이므로 버전은 그대로다. 정본 예시 `machine_stun_binding.machine.json` 추가 |
