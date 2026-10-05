# OpenVPN 상호운용 프로파일 (MVP 범위)

D-008. MVP가 "수정 없는 OpenVPN과 wire 호환"이라는 것은 **아래 프로파일 범위에 한정**된다.
> ⚠ 이 문서는 **초안**이다. 표기:
> - **[관측]** = 수정 없는 OpenVPN 2.6.19(Ubuntu 24.04 패키지)를 `tools/interop/lab.sh`로 실행해 로그/pcap에서 직접 확인한 사실 (2026-10-05). 관측 환경에서만 보증한다.
> - **[검증]** = 아직 공식 문서·pcap으로 확인하지 못한 항목. 구현 전에 확인한다. 확인 전에는 사실로 취급하지 않는다.

## 1. 상대(Peer)

| 항목 | 값 |
|---|---|
| 상대 | **수정하지 않은 OpenVPN 2.6.x 서버**. 관측 기준 버전: **2.6.19** (Ubuntu 24.04 `openvpn` 패키지, OpenSSL 3.0.13) |
| 우리 역할 | **클라이언트 전용** (서버 역할은 Post-MVP) |
| 플랫폼 | Linux (MVP-A) |
| 전송 | UDP (MVP-A), TCP (MVP-B) |
| 장치 | TUN (L3) |

## 2. 지원 범위 (In)

| 영역 | 내용 |
|---|---|
| Opcode | 3(SOFT_RESET), 4(CONTROL_V1), 5(ACK_V1), 7(HARD_RESET_CLIENT_V2), 8(HARD_RESET_SERVER_V2), 9(DATA_V2). **[관측]** 연결+재협상+데이터 구간 pcap에서 정확히 이 6개만 등장 |
| 제어 채널 보호 | **tls-crypt** (tls-auth는 제외) |
| TLS | TLS 1.3, 인증서 기반 인증 (메모리 BIO 방식으로 TLS 라이브러리 사용). **[관측]** `TLSv1.3 TLS_AES_256_GCM_SHA384`, X25519, EC P-256 인증서(ECDSA-SHA256) |
| 키 유도 | TLS Keying Material Exporter(**tls-ekm**). **[관측]** 스톡 클라이언트가 `IV_PROTO=990`을 보내면 서버가 PUSH_REPLY에 `protocol-flags cc-exit tls-ekm dyn-tls-crypt`를 보낸다. exporter 라벨/컨텍스트/키 분할 세부 `[검증]`. key-method 2 PRF 폴백은 필요 시 검토 |
| 데이터 채널 | AES-256-GCM, DATA_V2, peer-id. **[관측]** PUSH_REPLY에 `peer-id 0`, `cipher AES-256-GCM`. DATA_V2 헤더 4바이트 = opcode/key_id(1) + peer-id(3). 패킷 길이가 keepalive 40B, ICMP echo 108B로 `헤더4 + packet-id 4 + 태그 16 + 암호문` 레이아웃과 일치. AAD 구성·nonce(packet-id + implicit IV 등) 세부는 `[검증]` |
| Reliability | 제어 채널 packet-id, ACK 배열, 재전송, 세션 ID. **[관측]** 핸드셰이크에서 CONTROL_V1과 ACK_V1이 교차 |
| 옵션 | PUSH_REQUEST/PUSH_REPLY 파싱: `ifconfig`, `route`, `peer-id`, `cipher`, `keepalive` 등 필요한 최소 집합 |
| 유지 | keepalive(ping), key_id 회전을 통한 **재협상(renegotiation)**. **[관측]** `--reneg-sec 6` 환경에서 SOFT_RESET(opcode 3) 후 key_id가 0→1→2로 증가, 데이터 채널도 해당 key_id 사용 |
| NCP | 암호 협상은 AES-256-GCM만 선택하도록 제한 |

### 2.1 [관측]된 협상 부가 기능 처리 방침

스톡 클라이언트와 서버는 `cc-exit`(명시적 종료 알림), `dyn-tls-crypt`(핸드셰이크 후 제어 채널 키 전환)를 협상했다. 우리 클라이언트는 **IV_PROTO에서 이 기능들을 광고하지 않는 것**을 기본으로 한다(서버가 push하지 않음). 각 IV_PROTO 비트 의미는 `[검증]`. 필요해지면 PM-10에서 추가한다.

### 2.2 [관측] 기타 값

- PUSH_REPLY 예: `route-gateway`, `topology subnet`, `ping 2`, `ping-restart 8`, `ifconfig <ip> <mask>`, `peer-id 0`, `cipher AES-256-GCM`, `protocol-flags …`, `tun-mtu 1500`
- 옵션 문자열(`V4,…`)에 `key-method 2`, `link-mtu 1549`, `tun-mtu 1500`, `auth [null-digest]`, `keysize 256`
- 스톡 클라이언트 피어 정보: `IV_VER=2.6.19`, `IV_PLAT=linux`, `IV_CIPHERS=AES-256-GCM`, `IV_PROTO=990`, `IV_MTU=1600` 등

## 3. 제외 범위 (Out, MVP에서 구현하지 않음)

| 제외 | 이유/위치 |
|---|---|
| 서버 역할 | Post-MVP |
| static key(`--secret`) | 2.6에서 deprecated, 상호운용 가치 낮음 |
| tls-auth, tls-crypt-v2 (opcode 10/11) | PM-10 (파서는 opcode 11까지 인식) |
| Legacy opcode 1, 2, 6 | 파서는 인식, **Policy Block이 거부** |
| CBC 계열 / BF-CBC, 압축(comp-lzo, compress) | 보안/복잡도 |
| TAP, 브리징 | PM-5 |
| `auth-user-pass`, 플러그인 인증, 챌린지 | 인증서 인증만 |
| IPv6 터널 옵션, 고급 라우팅 옵션 | 필요 시 추가 |
| TCP | MVP-B |
| DCO 연동 | PM-8 |
| 프록시/Relay | PM-2 |

## 4. 검증 방법

0. **랩**: `tools/interop/lab.sh`가 수정 없는 OpenVPN 2.6 서버(호스트)와 클라이언트(network namespace)를 veth로 연결해 실행하고 pcap/로그를 남긴다(root 필요). 키/인증서는 실행마다 생성되며 커밋하지 않는다. 로그(verb 7)에는 **테스트용 세션 키**가 찍히므로 로그와 pcap은 저장소에 그대로 커밋하지 않는다.
1. **Golden pcap**: 수정 없는 OpenVPN 2.6 서버/클라이언트 간 실제 캡처를 `tests/regression/golden/`에 누적. 캡처 시 사용한 버전·설정 파일을 함께 보관한다.
2. **상호운용(protocol) 테스트**: `-DPF_PROTOCOL_TESTS=ON`에서 수정 없는 OpenVPN 서버 바이너리를 띄워 핸드셰이크·ping·재협상을 확인한다.
3. **퍼징/전수 테스트**: 파서와 제어 채널 메시지 디코더를 대상으로 한다.
4. 테스트 인증서/키는 테스트 전용으로 생성하고 저장소에 **개인 키를 커밋하지 않는다** (CI에서 생성).

## 5. 구현 원칙 (clean-room)

- 구현 근거는 **공개된 프로토콜 문서, RFC, pcap 관찰 결과**로 한정한다.
- OpenVPN 소스 코드를 보고 옮겨 적는 방식으로 구현하지 않는다. 확인이 필요하면 동작을 pcap/문서로 검증한다.
- 이 원칙의 이유와 라이선스 고려는 `docs/Threat_Model_and_Key_Management.md` §6 참고. (법률 자문이 아님)
