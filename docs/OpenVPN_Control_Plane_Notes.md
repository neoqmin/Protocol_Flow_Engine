# OpenVPN 2.6 제어 채널 노트 (MVP-A / A3)

clean-room 원칙(D-010): 근거는 **공개 문서/공식 설명 + 수정 없는 OpenVPN 2.6.19의 관측**뿐이다. 표기는 `docs/OpenVPN_Interop_Profile.md`와 같다.
- **[문서]** 공식 문서·공식 doxygen·공식 설계 문서에서 확인
- **[관측·검증됨]** 독립 도구로 **암호학적 검증(HMAC/AEAD 태그)까지 통과**
- **[검증]** 아직 미확인 → 해당 단계의 상호운용 테스트로 확정

## 1. 제어 채널 구성 (바깥 → 안)

```text
UDP payload = tls-crypt 래핑된 제어 패킷
  └ 복호 후 평문 = reliability 헤더 + (CONTROL_V1이면) TLS 레코드
       └ TLS 1.3 핸드셰이크 후: key-method 2 메시지, PUSH_REQUEST/PUSH_REPLY, ...
```

## 2. tls-crypt 와이어 [관측·검증됨 + 문서]

```text
wire  = opcode<<3|key_id (1) | session_id (8) | packet_id (4, BE) | net_time (4, BE) | tag (32) | ciphertext
tag   = HMAC-SHA256(Ka, wire[0:17] || plaintext)
iv    = tag[0:16]
ciphertext = AES-256-CTR(Ke, iv, plaintext)           (길이 = plaintext 길이, 패딩 없음)
```

- 구조 [문서]: SIV 구성(tag로 IV를 만드는 nonce-오용 저항 AEAD), `HMAC-SHA256(Ka, header || msg)`, IV = tag 상위 128비트. 출처: tls-crypt 설계 문서(`doc/tls-crypt-v2.txt`의 SIV 설명, 공식 doxygen `group__tls__crypt` 검색 요약).
- **키 파일 배치 [관측·검증됨]** (static key V1, 256바이트 = 64B × 4 구간 `K0..K3`). 각 구간의 **앞 32바이트**를 쓴다:

| 방향 | 암호 키 Ke | HMAC 키 Ka |
|---|---|---|
| server → client | `K0[0:32]` | `K1[0:32]` |
| client → server | `K2[0:32]` | `K3[0:32]` |

  즉 **클라이언트: tx = (K2, K3), rx = (K0, K1)**, 서버는 반대. 근거: `tools/interop/verify_tls_crypt.py`가 16개 조합 중 위 조합에서만 실제 패킷의 태그가 검증됨(c2s 8/8, s2c 6/6, 초기 핸드셰이크 구간).
- `packet_id`는 1부터 증가, `net_time`은 epoch 초(관측: 1791182048). 이 둘이 tls-crypt의 replay 방지 필드다. 문서: 한 키로 방향당 2^48 메시지 이하 [문서].
- 복호된 첫 패킷(HARD_RESET_CLIENT_V2)의 평문 = `00 00000000` → reliability 헤더의 `ack_len=0`과 메시지 packet-id `0` [관측].

## 3. 제어 패킷(reliability) 헤더 [문서 + 관측]

복호된 평문의 필드 순서 [문서: 공식 프로토콜 개요, tls-auth 설명을 tls-crypt에 맞춰 적용]:

```text
[ack_len (1)] [ack packet-ids (4 * ack_len)] [remote session_id (8, ack_len > 0일 때만)] [message packet-id (4)] [TLS payload]
```
- `P_ACK_V1`에는 message packet-id와 TLS payload가 없다 [검증: pcap으로 확인 예정].
- `P_CONTROL_HARD_RESET_*`는 TLS payload가 비어 있다 [관측: client hard reset 평문 5바이트].
- 신뢰성: "acknowledge and retransmit" 모델, ACK는 `P_ACK_*` 또는 `P_CONTROL_*`에 얹힘 [문서].

## 4. dyn-tls-crypt [관측] — MVP는 비활성

스톡 클라이언트는 `IV_PROTO` 비트 9(DYN_TLS_CRYPT)를 광고해 핸드셰이크 이후 제어 채널 키가 TLS 세션에서 파생된 키로 바뀐다(랩에서 초기 핸드셰이크 이후 패킷 14개가 정적 키로 검증되지 않음). 우리 클라이언트는 이 비트를 광고하지 않으므로(D-018) **전 구간 정적 tls-crypt 키**를 쓴다. 상호운용 테스트(A3-6)에서 서버가 그렇게 응답하는지 확인한다.

## 5. 남은 `[검증]`

- 제어 패킷 평문 헤더의 정확한 필드 순서/크기(ACK 포함 케이스), P_ACK_V1 형식 → A3-3에서 pcap 복호 후 확정
- key-method 2 메시지 포맷, TLS exporter 컨텍스트/크기/분할 → A3-5
- 재전송 타이머·윈도우 크기 등 파라미터(동작 호환 범위) → A3-3/A3-6
