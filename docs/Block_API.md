# Block API (MVP-A / A1, A2)

구현: `core/include/pf/{error,packet_buffer,flow_context,block,flow}.h`, 블록 예: `core/include/pf/blocks/openvpn_blocks.h`.
테스트: `tests/unit/test_{error,packet_buffer,block_registry,flow_build}.cpp`, `tests/flow/test_{flow_runner,openvpn_rx_flow}.cpp`.

## 1. 구성

```text
BlockRegistry  : BlockDescriptor{id, name, type, execute} 등록/조회 (id·name 유일)
FlowBuilder    : 정적 Flow 정의 → build(registry) → 검증된 불변 Flow
run_flow       : 패킷 1개를 Flow로 실행 → FlowResult{outcome, error, steps, last_node}
FlowContext    : Block이 공유하는 패킷별 컨텍스트 (패킷 포인터, 헤더, KeyRef, flags, error)
PacketBuffer   : headroom/tailroom을 가진 단일 소유 버퍼 (zero-copy 캡슐화/해제)
```

## 2. 결과 계약 (오류 모델)

`BlockResult = Continue | Yes | No | Drop | Error`

| 결과 | 누가 | 의미 | ctx.error | Flow 결과 |
|---|---|---|---|---|
| `Continue` | Action | 다음 노드로 진행 | 변경 없음 | 계속 / 마지막이면 `Completed` |
| `Yes` / `No` | Decision | 분기 (오류 아님) | 변경 없음 | 해당 edge로 진행 |
| `Drop` | 둘 다 | **입력이 나쁘거나 원치 않아** 이 패킷을 버림. 정상적으로 기대되는 사건 | **반드시 사유 설정** | `Dropped` |
| `Error` | 둘 다 | **우리 쪽 실패**(버그, 자원 부족). 입력 탓이 아님 | 사유 설정(비어 있으면 `Internal`) | `Errored` |

러너가 강제하는 계약 위반은 모두 `Errored / Error::Internal`로 끝난다:
- Action이 `Yes/No` 반환, Decision이 `Continue` 반환
- `Drop`인데 `ctx.error == None`

예) 잘려 있는 패킷·재생 패킷·정책 거부 = `Drop`(사유별 카운터 `FlowStats::by_error`). `ctx.packet == nullptr` = `Error`.
러너는 시작 시 `ctx.error`를 `None`으로 초기화한다. `steps >= max_steps`(기본 1024)면 `Errored / StepLimit`.

## 3. Flow 정의와 빌드 시점 검증

- 노드는 추가한 순서대로 실행. Action의 기본 `Continue` edge = 다음 노드(마지막이면 종료). `on_continue(from, "")`은 명시적 종료.
- Decision은 `on_yes`/`on_no`가 **둘 다 필요**. Action의 YES/NO edge, Decision의 continue edge는 오류.
- `build()`는 모든 문제를 한꺼번에 보고한다: 빈 Flow, 알 수 없는 block id/label, 중복 label, 누락·불필요 edge, **순환**(계획서 §22 loop violation), **도달 불가 노드**.
- 빌드 성공한 Flow는 handler/type을 노드에 미리 해석해 두어 실행 시 조회가 없다(직접 dispatch).

## 4. 버퍼 모델

```text
[ headroom | data | tailroom ]      PacketBuffer 한 번의 할당
```

| 연산 | 용도 | 실패 시 |
|---|---|---|
| `pull_front(n)` | 헤더 제거 (decap) | `false`, 변화 없음 |
| `push_front(n)` | 헤더 추가 (encap), headroom 사용 | `nullptr`, 변화 없음 |
| `put(n)` | 뒤에 추가 | `nullptr` |
| `trim_back(n)` | 태그/트레일러 제거 | `false` |
| `wipe()` | 전체 영역 0으로 지우기 (평문/키 재료 잔존 방지) | - |

- 기본 headroom/tailroom 32B: DATA_V2 헤더 4 + packet-id 4, AEAD 태그 16이 복사 없이 들어간다.
- **재할당하지 않는다.** 공간이 부족하면 실패를 돌려준다(호출자가 `BufferTooSmall` 처리).
- **소유권**: `PacketBuffer`는 move-only, 소유자는 호출자. Block은 `FlowContext::packet`으로 빌려 쓰기만 한다. 복호화는 제자리(in-place)로 수행하는 것을 기본으로 한다(A2).

## 5. FlowContext

| 필드 | 설명 |
|---|---|
| `packet` | 빌린 패킷 포인터 (소유 안 함) |
| `header`, `header_valid` | 파싱된 OpenVPN 헤더 (MVP는 OpenVPN 전용 필드) |
| `key_ref` | 불투명 핸들. **키 바이트는 컨텍스트에 두지 않는다** |
| `flags` | 블록 간 신호 (예: `kFlagControlPacket`) |
| `error` | `Drop`/`Error` 사유 |
| `user_context` | 호출자 정의 포인터 |

## 6. 블록 id 규칙

`openvpn_blocks.h`의 id(1~5)는 Flow JSON(MVP-C)의 일부가 되므로 **재번호 금지**. 새 블록은 새 id를 부여한다. `register_openvpn_blocks`는 all-or-nothing.

## 7. 알려진 한계 / 후속

- `FlowContext`가 OpenVPN 헤더에 직접 의존한다(MVP 범위). 프로토콜 확장(PM-9) 시 일반화한다.
- 스레딩: `FlowContext`/`PacketBuffer`는 스레드 간 공유하지 않는다(패킷당 하나). Registry/Flow는 빌드 후 읽기 전용이라 공유 가능. 배칭·per-CPU 컨텍스트는 PM-3.
- Control Plane은 이 Flow가 아니라 일반 코드(D-009).
- 커널 런타임용 ABI(plain function pointer, 힙 없는 경로)는 PM-8에서 별도 정리.

---

# 8. Data Plane 블록 (A2)

구현: `core/include/pf/blocks/data_plane_blocks.h`, `core/src/blocks/data_plane_blocks.cpp`. 와이어 레이아웃은 `docs/OpenVPN_Interop_Profile.md` §2.3 (2.6.19에서 태그 검증까지 확인).

```text
RX:  parse_data_v2 → lookup_rx_key → replay_check → aead_decrypt → replay_commit
TX:  lookup_tx_key → aead_encrypt        (호출자가 ctx.header = {DataV2, key_id, peer_id} 설정)
```

| id | 블록 | 실패 시 |
|---|---|---|
| 6 | `parse_data_v2` | `Drop(Truncated)` (< 24B), `Drop(InvalidOpcode)` |
| 7 | `lookup_rx_key` | `Drop(UnknownKey)` |
| 8 | `replay_check` (읽기 전용) | `Drop(ReplayDetected)`, `Drop(InvalidPacketId)` |
| 9 | `aead_decrypt` (제자리, 성공 시 24B 오버헤드 제거) | `Drop(AuthFailed)` |
| 10 | `replay_commit` | - |
| 11 | `lookup_tx_key` | `Error(UnknownKey)` (우리 설정 문제) |
| 12 | `aead_encrypt` (packet-id 부여, headroom에 헤더 추가) | `Error(NonceExhausted)`, `Error(BufferTooSmall)` |

## 8.1 보안 규칙 (테스트로 고정)

- **replay window는 인증 성공 후에만 갱신한다.** `replay_check`는 읽기 전용이고 `replay_commit`이 마지막에 온다. 위조 패킷이 window를 앞으로 밀어 정상 패킷을 "too old"로 만드는 공격을 막는다. (`rx_forged_packet_does_not_advance_replay_window`)
- **인증되지 않은 평문을 내보내지 않는다.** `AeadProvider::decrypt`는 실패 시 버퍼를 0으로 지운다.
- **nonce 재사용 금지.** TX packet-id는 1부터 증가하며 `0xFFFFFFFF` 사용 뒤에는 `Error(NonceExhausted)`로 멈춘다(래핑 안 함). 호출자는 재협상으로 새 키를 설치해야 한다.
- 입력 탓의 실패는 `Drop`, 우리 쪽 문제(키 없음, 서비스 미연결, headroom 부족, nonce 고갈)는 `Error`.
- `ctx.keys`/`ctx.aead`가 없으면 `Error(Internal)` — 배선 버그를 입력 오류로 오인하지 않는다.
- 키 바이트는 `KeyStore` 안에만 있고 Block은 `KeyRef`만 다룬다. `DataKey`는 소멸/`remove` 시 지워진다(`secure_zero`).

## 8.2 Crypto Provider

- `AeadProvider`(`pf/crypto/aead_provider.h`): 플랫폼 독립 인터페이스, **제자리** 암복호, nonce 12B / key 32B / tag 16B.
- `make_openssl_aes256gcm()`(`pf/crypto/openssl_aes_gcm.h`): OpenSSL 3.x EVP 구현. **`PF_WITH_OPENSSL`이 켜진 빌드에서만** 컴파일된다(`AUTO`/`ON`/`OFF`). Blocks와 나머지 코어는 OpenSSL 없이 빌드된다.
- 테스트: 블록 로직은 가짜 Provider(`tests/flow/test_data_plane_flow.cpp`)로 OpenSSL 없이, 실제 암호·OpenVPN 골든은 `*_openssl.cpp`로 분리.

## 8.3 한계 / 후속

- OpenSSL 구현은 호출마다 `EVP_CIPHER_CTX`를 만든다. 성능 최적화(컨텍스트 재사용, 배칭)는 PM-3.
- 키 유도(exporter)와 재협상으로 `KeyStore`에 키를 설치하는 부분은 A3.
- 64비트 packet-id(epoch) 방식은 지원하지 않는다(2.6 프로파일 한정, D-017).
