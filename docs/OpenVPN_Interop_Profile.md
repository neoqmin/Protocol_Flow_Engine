# OpenVPN 상호운용 프로파일 (MVP 범위)

D-008. MVP가 "수정 없는 OpenVPN과 wire 호환"이라는 것은 **아래 프로파일 범위에 한정**된다.
> ⚠ 이 문서는 **초안**이다. `[검증]` 표시 항목은 구현 전에 OpenVPN 2.6 공식 문서·소스 문서(프로토콜 설명)와 실제 pcap으로 확인해서 확정한다. 확인 전에는 사실로 취급하지 않는다.

## 1. 상대(Peer)

| 항목 | 값 |
|---|---|
| 상대 | **수정하지 않은 OpenVPN 2.6.x 서버** (정확한 패치 버전은 확정 시 기록) |
| 우리 역할 | **클라이언트 전용** (서버 역할은 Post-MVP) |
| 플랫폼 | Linux (MVP-A) |
| 전송 | UDP (MVP-A), TCP (MVP-B) |
| 장치 | TUN (L3) |

## 2. 지원 범위 (In)

| 영역 | 내용 |
|---|---|
| Opcode | 3(SOFT_RESET), 4(CONTROL_V1), 5(ACK_V1), 7(HARD_RESET_CLIENT_V2), 8(HARD_RESET_SERVER_V2), 9(DATA_V2) |
| 제어 채널 보호 | **tls-crypt** (tls-auth는 제외) |
| TLS | TLS 1.3, 인증서 기반 인증 (메모리 BIO 방식으로 TLS 라이브러리 사용) |
| 키 유도 | TLS Keying Material Exporter 방식 `[검증]` (2.6의 key-derivation 협상 및 IV_PROTO 플래그 확인). 폴백으로 key-method 2 PRF는 필요 시 검토 |
| 데이터 채널 | AES-256-GCM, DATA_V2, peer-id `[검증]` (nonce 구성: packet-id + implicit IV 등) |
| Reliability | 제어 채널 packet-id, ACK 배열, 재전송, 세션 ID |
| 옵션 | PUSH_REQUEST/PUSH_REPLY 파싱: `ifconfig`, `route`, `peer-id`, `cipher`, `keepalive` 등 필요한 최소 집합 |
| 유지 | keepalive(ping), key_id 회전을 통한 **재협상(renegotiation)** |
| NCP | 암호 협상은 AES-256-GCM만 선택하도록 제한 |

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

1. **Golden pcap**: 수정 없는 OpenVPN 2.6 서버/클라이언트 간 실제 캡처를 `tests/regression/golden/`에 누적. 캡처 시 사용한 버전·설정 파일을 함께 보관한다.
2. **상호운용(protocol) 테스트**: `-DPF_PROTOCOL_TESTS=ON`에서 수정 없는 OpenVPN 서버 바이너리를 띄워 핸드셰이크·ping·재협상을 확인한다.
3. **퍼징/전수 테스트**: 파서와 제어 채널 메시지 디코더를 대상으로 한다.
4. 테스트 인증서/키는 테스트 전용으로 생성하고 저장소에 **개인 키를 커밋하지 않는다** (CI에서 생성).

## 5. 구현 원칙 (clean-room)

- 구현 근거는 **공개된 프로토콜 문서, RFC, pcap 관찰 결과**로 한정한다.
- OpenVPN 소스 코드를 보고 옮겨 적는 방식으로 구현하지 않는다. 확인이 필요하면 동작을 pcap/문서로 검증한다.
- 이 원칙의 이유와 라이선스 고려는 `docs/Threat_Model_and_Key_Management.md` §6 참고. (법률 자문이 아님)
