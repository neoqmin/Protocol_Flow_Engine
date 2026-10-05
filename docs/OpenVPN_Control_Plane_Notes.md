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

## 3. 제어 패킷(reliability) 평문 [관측·검증됨]

tls-crypt를 벗긴 평문의 필드 순서. 14개 실제 패킷을 파싱한 뒤 **다시 만들면 바이트가 100% 일치**함을 골든 테스트로 확인(`tests/regression/test_golden_control.cpp`). 공식 프로토콜 개요 문서의 순서와도 일치.

```text
ack_len(1) | ack ids(4 each, BE) | remote session_id(8, ack_len > 0일 때만) | [message_id(4, BE) | payload]
```

- `P_ACK_V1`: message_id·payload 없음, ack_len ≥ 1. 그 외 opcode는 message_id가 항상 있음.
- `HARD_RESET_CLIENT_V2`: `00 00000000` (ack 없음, id 0, payload 없음). `HARD_RESET_SERVER_V2`: 클라이언트 id 0을 ACK(원격 session_id = 클라이언트 session) + 자기 id 0, payload 없음.
- `CONTROL_V1`의 payload = TLS 레코드 바이트 (`16 03 01..` ClientHello, `16 03 03..` ServerHello, `14 03 03 00 01 01` CCS, `17 03 03..` 암호화된 핸드셰이크/앱 데이터).
- message_id는 방향별로 0부터 1씩 증가. 서버 메시지 0..5가 순서대로 도착(재정렬 불필요한 정상 경로).
- ACK 배열은 **최신 id가 앞**에 오고 직전 id들이 반복되어 나열됨(예 `[3,2,1,0]`, 관측 최대 6개). 파서는 순서와 무관하게 처리하고, 우리 빌더는 최신 우선으로 최대 8개.
- 모든 client→server 메시지가 서버 메시지 id를 ACK함(골든 테스트로 확인).

### 3.1 reliability 동작과 파라미터 (우리의 선택)

프로토콜이 요구하는 것은 "받은 메시지를 ACK하고, ACK되지 않은 메시지는 재전송"뿐이다 [문서]. 구체 값은 우리 구현의 선택이며 서버 상호운용(A3-6)에서 검증한다.

| 파라미터 | 값 | 비고 |
|---|---|---|
| 송신 윈도우 | 4 | 미확인 메시지 최대 개수 |
| 최초 재전송 시간 | 2000 ms, 시도마다 2배, 상한 16000 ms | |
| 최대 전송 시도 | 6회 후 세션 실패 | 약 46초 |
| 수신 윈도우 | next_expected + 8 | 범위 밖은 ACK하지 않음(상대가 재전송) |
| 중복 수신 | 다시 ACK (상대가 우리 ACK를 놓쳤을 수 있음) | |
| 시계 | 호출자가 `now_ms` 주입 | 순수 로직, 결정적 테스트 |

## 4. dyn-tls-crypt [관측] — MVP는 비활성

스톡 클라이언트는 `IV_PROTO` 비트 9(DYN_TLS_CRYPT)를 광고해 핸드셰이크 이후 제어 채널 키가 TLS 세션에서 파생된 키로 바뀐다(랩에서 초기 핸드셰이크 이후 패킷 14개가 정적 키로 검증되지 않음). 우리 클라이언트는 이 비트를 광고하지 않으므로(D-018) **전 구간 정적 tls-crypt 키**를 쓴다. 상호운용 테스트(A3-6)에서 서버가 그렇게 응답하는지 확인한다.

## 5. key-method 2와 PUSH [관측·검증됨: 실제 서버와 상호운용]

`pf_connect`(우리 `ControlClient`)가 **수정 없는 OpenVPN 2.6.19 서버**와 hard reset → tls-crypt → TLS 1.3 → key-method 2 → PUSH_REPLY까지 약 10 ms에 완료하고, 이후 데이터 채널 keepalive를 양방향으로 교환한다(`tests/protocol/run_interop.sh`, CTest 라벨 `protocol`).

- **우리가 보낸 key-method 2**: `literal 0 | 2 | pre_master(48)+random1(32)+random2(32) | options | username(빈) | password(빈) | peer info`. 서버가 수락하고 PUSH_REPLY를 보냄.
  - options: `V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client`
  - peer info: `IV_VER=2.6.0`(우리가 구현한 프로토콜 수준), `IV_PLAT=linux`, `IV_PROTO=14`, `IV_CIPHERS=AES-256-GCM`
- **서버의 key-method 2 응답**: 옵션 문자열이 우리 기대값(`...,tls-server`)과 **정확히 일치**. 옵션 뒤에 **선택 필드 3개**(username, password, peer info; 모두 빈 값 `00 00`씩)가 온다. 처음에 2개로 가정했을 때 `ignored_control_messages=2`(남은 0 바이트)로 드러나 3개로 수정했고, 수정 후 0.
- **PUSH_REPLY** (우리는 `cc-exit`/`dyn-tls-crypt`를 광고하지 않음): `PUSH_REPLY,route-gateway 10.77.0.1,topology subnet,ping 2,ping-restart 8,ifconfig 10.77.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,key-derivation tls-ekm`
  - `protocol-flags`는 오지 않고 **`key-derivation tls-ekm`** 으로 협상됨(공식 문서 설명대로). 파서는 둘 다 인식.
  - `REQUEST_PUSH`를 광고했으므로 서버가 PUSH_REQUEST 없이 스스로 PUSH_REPLY를 보냄(PUSH_REQUEST 폴백은 2초 후에만 동작).
- **정적 tls-crypt 키로 전 구간 동작**: dyn-tls-crypt를 광고하지 않으면 서버도 키를 바꾸지 않음.

## 6. 데이터 채널 키 유도 (tls-ekm) [관측·검증됨]

| 항목 | 확정 값 |
|---|---|
| exporter 라벨 | `EXPORTER-OpenVPN-datakeys` [문서] |
| 컨텍스트 | 없음 (빈 컨텍스트와 동일한 출력; 둘 다 검증됨) |
| 내보내는 바이트 수 | **256** (TLS 1.3 exporter는 길이가 출력에 영향을 주므로 256이어야 함) |
| 클라이언트 **rx** (서버→클라) | 암호 키 = `km[128:160]`, GCM nonce tail = `km[192:200]` |
| 클라이언트 **tx** (클라→서버) | 암호 키 = `km[0:32]`, GCM nonce tail = `km[64:72]` |
| 서버 | tx/rx를 바꿔서 사용 |

- rx 검증: 서버가 보낸 DATA_V2 패킷 3개에서 모든 (키 오프셋, tail 오프셋) 조합을 시도해 **GCM 태그가 검증되는 조합이 위 하나뿐**임을 확인(`pf_connect --probe-keys`).
- tx 검증: 우리가 보낸 핑을 서버가 복호화해 `RECEIVED PING PACKET`으로 기록. tx 오프셋을 틀리게 바꾸면 상호운용 테스트가 `server never accepted a data packet from us`로 실패함을 확인.
- 이 레이아웃은 `EkmLayout` 기본값이다. 키 방향은 OpenVPN의 `key2` 구조(2 × (cipher 64B + hmac 64B))와 일치하는 형태: 구간 0 = 클라이언트 송신, 구간 1 = 클라이언트 수신, nonce tail은 각 구간 hmac 슬롯의 앞 8바이트.

## 7. 남은 `[검증]` / 미구현

- 재협상(SOFT_RESET, key_id 회전): 서버는 `reneg-sec`(기본 3600초) 후 시작. 우리는 현재 SOFT_RESET을 **무시**한다(`stats.ignored_soft_resets`) → 다음 단계.
- keepalive 스케줄링(ping/ping-restart 타이머)을 코어에 구현(지금은 `pf_connect`의 데모 루프만).
- **인증은 통과하지만 핑이 아닌 데이터 패킷**: GitHub 러너의 첫 상호운용 실행에서 서버 패킷 1개가 이런 형태로 도착했다(로컬 30초 실행에서는 없음; 서버는 `occ` 활성). 오류가 아니므로 `received_other`로 별도 집계하고 길이/앞 8바이트를 CI 로그에 남겨 정체를 확인한다. 인증 실패·replay·키 없음만 실패로 본다.
- reliability 파라미터(윈도우 4, RTO 2초 등)는 실제 서버와 정상 동작했으나(손실 없는 로컬 링크), 손실/지연 환경 검증은 별도.
