# PM-11 OpenVPN 호환 서버 — 적용 범위 (초안)

- 작성일: 2026-10-06
- 상태: **방향 확정(D-044), 세부는 PM-11 진입 시 확정**. 순서는 PM-2b ① STUN 기초(N1~N3) 다음이고, ③ NAT 통합(N4~N8)보다 앞이다(`docs/PM2_NAT_Traversal_Scope.md` §6)
- 근거: PM-2 진입 논의(N0). hole punching을 VPN에 쓰려면 양 끝이 모두 우리 구현이어야 한다. 그리고 서버는 NAT와 무관하게도 제품 가치가 있다

## 1. 목표

**수정 없는 OpenVPN 2.6 클라이언트와 우리 `pf_client`를 모두 받는 Linux VPN 서버(`pf_server`)**를 만든다.
- 프로토콜 프로파일은 MVP와 같다(`docs/OpenVPN_Interop_Profile.md`): UDP/TCP, TLS 1.3 + tls-crypt + AES-256-GCM, TUN, `key-derivation tls-ekm`, DATA_V2(peer-id).
- 검증 방식은 MVP를 뒤집은 것이다. MVP는 "우리 클라이언트 ↔ 수정 없는 OpenVPN 서버"였고, 여기서는 **"우리 서버 ↔ 수정 없는 OpenVPN 2.6 클라이언트"**다(D-015 방식, netns 랩).
- NAT 뒤 동작(연결 서버 등록, hole punching, Relay)은 PM-2b N7에서 이 서버 위에 얹는다. 수정 없는 클라이언트는 지금처럼 직접 연결만 한다.
- 원칙은 그대로다: clean-room(D-010, 공개 문서·pcap·관찰만 근거), 오픈소스 수정 없음(D-005/D-006), 키는 KeyRef로만, TDD.

## 2. 재사용할 자산

| 필요 | 이미 있는 것 |
|---|---|
| tls-crypt(서버 방향 키) | `TlsCryptChannel`(D-024). 키 방향만 반대 |
| 제어 패킷·reliability | `control_packet.h`, `reliable.h`(D-025) |
| TLS 서버 역할 | `tls_session.h`(메모리 BIO, `TlsRole::Server`, 클라이언트 인증서 EKU 검증) |
| key-method 2 서버 측 | `key_method2.h`(클라이언트/서버 key source 차이 처리) |
| 키 유도 | `data_key_derivation.h`(EKM, 서버는 tx/rx가 반대, D-026) |
| 서버 쪽 프로토콜 흐름 | **테스트용 `tests/support/fake_ovpn_server.h`**: 메모리에서 서버 제어 채널을 이미 구현하고 있다. 이를 정식 코어 컴포넌트로 끌어올린다(테스트 전용 단순화는 걷어냄) |
| 데이터 경로 | `DataPath`(RX/TX Flow), `TunnelSession`의 분류 로직 |
| Transport | `UdpTransport`, `FramedTransport`/`TcpStream`(서버는 accept 쪽 추가) |
| 상태·타이머 | F-1 State Machine(세션 수명·재협상·keepalive를 Machine으로) |
| 관찰 | F-3 Trace |

## 3. 단계 (초안)

| 단계 | 내용 | 종료 조건 |
|---|---|---|
| V1 | `ControlServer`(코어, sans-I/O): 클라이언트 1개 세션 — HARD_RESET 응답, tls-crypt, TLS 서버, key-method 2 서버 측, PUSH_REPLY 생성(설정에서), 키 설치, 재협상(양쪽 시작), keepalive | 우리 `ControlClient` ↔ `ControlServer` 메모리 시나리오(손실·중복·역순·재협상), `fake_ovpn_server` 기반 테스트를 새 서버로 대체 |
| V2 | 다중 클라이언트: (주소, 세션 id)로 세션 표, **peer-id 할당**, DATA_V2 수신을 peer-id로 분배, 인증 전 상태 할당 최소화(tls-crypt 검증 실패 패킷은 상태를 만들지 않음), 세션 수·속도 한도 | 동시 다수 세션 시뮬레이션, 위조·재생 패킷이 세션을 만들거나 바꾸지 못함, 한도 초과 처리 |
| V3 | 서버 데이터 경로: TUN, **주소 풀**(subnet topology), 클라이언트별 라우팅(TUN → 어느 세션), push 라우트, client-to-client 기본 차단 | 메모리 테스트: 목적지 주소 → 세션 매핑, 풀 고갈·반환 |
| V4 | TCP 서버 Transport(accept, 연결별 `FramedTransport`) | 부분 읽기·다중 연결 테스트 |
| V5 | `pf_server` 실행 파일(`platform/linux`) + **수정 없는 OpenVPN 2.6 클라이언트 상호운용**(netns): UDP·TCP 터널 ping, 클라이언트·서버 재협상, 동시 3 클라이언트, `pf_client` ↔ `pf_server` | ctest 라벨 `protocol`(root, `RESOURCE_LOCK`) |
| V6 | 1시간 soak(재협상 1회 이상), 성능 기준선(stock 서버 대비, `docs/Performance_Baseline.md`), fuzz(서버 수신 경로) | 기록 |

## 4. 위협 (서버 추가분, `docs/Threat_Model_and_Key_Management.md` §8.3)

서버는 인터넷에서 오는 임의 패킷을 받는다. 클라이언트보다 공격면이 넓다.
- **인증 전 자원 소모**: tls-crypt HMAC을 먼저 검증하고, 실패한 패킷은 세션 상태를 만들지 않는다. 그 다음에 세션 수·IP별·속도 한도를 둔다.
- **세션 혼동**: 주소가 바뀐 클라이언트(float)는 인증된 패킷으로만 갱신한다. peer-id 위조는 AEAD 검증으로 거부한다.
- **클라이언트 신원 → 주소 매핑**: 인증서 신원별로 고정 주소를 줄지는 설정으로 정한다. 다른 클라이언트의 주소를 사칭하는 트래픽(소스 주소 위조)은 거부한다.
- **키 관리**: 서버 개인 키와 tls-crypt 키는 KeyRef로만 다룬다. 세션 키는 세션이 끝날 때 와이프한다.

## 5. PM-11 진입 시 정할 것

1. 동시성 모델: 단일 스레드 이벤트 루프로 시작할지, 처음부터 멀티스레드로 할지(PM-3와 연결)
2. 설정 형식: OpenVPN 서버 설정 일부와 호환할지, 자체 설정만 둘지
3. 클라이언트 인증: 인증서만 쓸지, CRL·사용자 이름/비밀번호(외부 인증 훅)까지 둘지
4. 관리 인터페이스: 세션 목록·강제 종료·통계(PM-6 에디터·운영자 요구 D-023과 연결)
5. 지원 플랫폼: Linux 우선(Windows 서버는 PM-1과 함께 검토)
