# Flow JSON 스키마 v1

Flow를 저장·교환하는 파일 형식. 구현: `core/include/pf/flow_json.h`(구조 검증), `json.h`(엄격 JSON). 의미 검증(블록 존재, 포트, 순환 등)은 C2 Validator 몫이다.
정본 예시: `tests/regression/golden/flow_*.flow.json` (정적 Flow와 동등해야 한다 — C3).

## 1. 문서 구조

```json
{
  "format": "protocol-flow",
  "version": 1,
  "flow": { "name": "openvpn_rx", "description": "...", "runtime": ["user"] },
  "nodes": [
    { "id": "parse", "block": "parse_ovpn_header" },
    { "id": "is_data", "block": "is_data_v2" },
    { "id": "decrypt", "block": "aead_decrypt", "params": { "algorithm": "AES-256-GCM", "keyRef": "session.data_key" } }
  ],
  "edges": [
    { "from": "is_data", "port": "yes", "to": "decrypt" },
    { "from": "is_data", "port": "no",  "to": null }
  ],
  "meta": { "author": "qa" }
}
```

| 위치 | 필드 | 필수 | 규칙 |
|---|---|---|---|
| 최상위 | `format` | ✔ | 정확히 `"protocol-flow"` |
| | `version` | ✔ | 양의 **정수 리터럴** (`1.0`, `"1"` 불가) |
| | `flow`, `nodes` | ✔ | |
| | `edges`, `meta` | | 생략 가능 |
| `flow` | `name` | ✔ | ID 문법 |
| | `description` | | ≤ 4096바이트 |
| | `runtime` | | 비어 있지 않은 배열, `"user"`/`"kernel"` 중복 없이. 기본 `["user"]`. `kernel`은 Post-MVP(PM-8)이며 데이터로만 허용 |
| `nodes[]` | `id` | ✔ | ID 문법, **문서 안에서 유일** |
| | `block` | ✔ | 블록 **이름**(레지스트리, 예 `parse_data_v2`). 이름 문법은 ID와 같음. 존재 여부는 C2 |
| | `params` | | 객체, §3 |
| `edges[]` | `from` | ✔ | 노드 id |
| | `to` | ✔ | 노드 id 또는 `null`(= 여기서 Flow 종료) |
| | `port` | | `"continue"`(기본, Action 출구) · `"yes"` · `"no"`(Decision 출구) |
| `meta` | 임의 키 | | 값은 문자열만, 최대 64개 |

**ID 문법**: `[A-Za-z_][A-Za-z0-9_-]{0,63}`.
**알 수 없는 필드는 오류**다(오타를 조용히 무시하지 않기 위해). 도구용 확장은 **`x-` 로 시작하는 키**로 모든 객체(최상위/`flow`/노드/엣지)에 둘 수 있고 **그대로 보존**된다(에디터 좌표 등).

## 2. 실행 의미 (C2/C3가 구현, 여기서 고정)

기존 `FlowBuilder`와 동일하다.
- 실행은 `nodes`의 **첫 노드**에서 시작한다.
- Action 노드에 `continue` 엣지가 없으면 **배열에서 다음 노드**로 이어지고, 마지막 노드면 종료한다. `continue` 엣지가 있으면 그 대상으로 간다(`to: null` = 종료).
- Decision 노드는 `yes`·`no` 엣지가 **둘 다 필요**하다.
- 순환, 도달 불가 노드, 중복 엣지, 존재하지 않는 id/블록 이름은 Validator가 거부한다.

## 3. 파라미터와 키 (보안 규칙)

- 값은 **문자열·숫자·불리언**만(중첩 객체/배열/`null` 불가). 이름은 `[a-z][A-Za-z0-9_]*`, 노드당 ≤ 64개, 문자열 ≤ 1024바이트.
- **Flow 파일에는 키 재료가 들어갈 수 없다.** `key`, `secret`, `password`, `psk`, `token`, `privateKey`, `sessionKey` 등(대소문자 무시) 이름의 파라미터는 `SecretLiteral` 오류. 어떤 문자열(파라미터·`description`·`meta`)에도 `-----BEGIN`(PEM)이 있으면 같은 오류. 인증서/키는 파일이 아니라 Key Manager에 둔다.
- 키는 **참조**로만 쓴다: 이름이 `Ref`로 끝나는 파라미터는 문자열이며 `[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*` 형식(`session.data_key`). 해석은 Runtime의 Key Manager가 한다 (`docs/Threat_Model_and_Key_Management.md`).

## 4. 한도 (DoS/실수 방어)

문서 ≤ 4MiB, JSON 중첩 ≤ 64, 노드 ≤ 4096, 엣지 ≤ 16384, 한 번에 보고하는 오류 ≤ 100개.

## 5. JSON 엄격성

RFC 8259 그대로: 주석·후행 쉼표·`NaN`/`Infinity`·BOM 불가. 추가로 **같은 객체의 중복 키 거부**(두 파서가 서로 다른 값을 고를 수 있어 보안 위험), 잘못된 UTF-8·단독 서로게이트·`\u0000` 거부. 정수 리터럴은 int64로 정확히 읽는다.

## 6. 오류 보고

모든 오류는 `{code, path, message}`이며 `path`는 JSON Pointer(예 `/nodes/2/params/keyRef`). 한 번의 로드에서 **여러 오류를 함께** 돌려준다(에디터가 한 번에 표시). 코드: `BadJson` `NotAnObject` `MissingField` `WrongType` `BadValue` `UnknownField` `DuplicateId` `TooMany` `SecretLiteral` `UnsupportedVersion` `MigrationFailed`.

## 7. 버전 관리 / 마이그레이션 규칙

1. `version`은 **정수 하나**. 파일 형식이 *호환되지 않게* 바뀔 때만 올린다.
2. **같은 버전 안에서는 호환 변경만**: 선택 필드 추가, 새 블록/포트 이름, 새 `x-` 확장. 필드 삭제·의미 변경·필수화·타입 변경은 새 버전.
3. **읽기**: `kFlowVersionMin..현재` 를 받는다. 오래된 파일은 `from → from+1` 마이그레이터를 **순서대로** 적용해 *현재 스키마로 올린 뒤* 검증한다(마이그레이터는 JSON을 다시 쓰고, 결과는 일반 검증을 그대로 통과해야 한다).
   - **현재보다 새로운 파일은 거부**(`UnsupportedVersion`, "소프트웨어를 업그레이드") — 모르는 형식을 추측해 읽지 않는다.
   - 최소 지원 미만이거나 중간 단계 마이그레이터가 없으면 `UnsupportedVersion`, 마이그레이터가 실패하면 `MigrationFailed`.
   - 마이그레이션이 일어났음은 `migrated_from`으로 알린다(도구가 "저장하면 vN으로 올라갑니다"를 표시).
4. **쓰기**: 항상 **현재 버전**, 정규 형식(고정 멤버 순서, 2칸 들여쓰기, 끝 개행, 기본값 `port:"continue"`·빈 `description`/`meta`/`edges` 생략). `parse(write(x)) == x`이고 쓰기는 고정점이다 → 버전 관리 diff에 잡음이 없다.
5. 새 버전을 올릴 때 **같은 변경에서**: ① `kFlowVersionCurrent`, ② 이전 버전 → 새 버전 마이그레이터와 테스트(이전 버전 골든 파일을 `tests/regression/golden/`에 **남겨둔다**), ③ 이 문서의 표와 변경 이력, ④ `docs/DECISIONS.md`.
6. 마이그레이션은 **정보 손실 없이**(확장 `x-`와 `meta` 보존) 해야 하며, 불가능하면 실패시킨다.

## 8. 변경 이력

| 버전 | 날짜 | 내용 |
|---|---|---|
| 1 | 2026-10-06 | 최초: `format/version/flow/nodes/edges/meta`, `keyRef` 규칙, `x-` 확장 |
