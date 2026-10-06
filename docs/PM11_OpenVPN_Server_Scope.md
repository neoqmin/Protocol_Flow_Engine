# PM-11 OpenVPN 호환 서버 — 적용 범위 (초안)

- 작성일: 2026-10-06
- 상태: **방향 확정(D-044), 진입 결정 확정(D-048)**. 순서는 PM-2b ① STUN 기초(N1~N3) 다음이고, ③ NAT 통합(N4~N8)보다 앞이다(`docs/PM2_NAT_Traversal_Scope.md` §6)
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

## 3. 단계 (D-048로 재편)

| 단계 | 내용 | 종료 조건 |
|---|---|---|
| V1 ✅ | `ControlServer`(코어, sans-I/O, 클라이언트 1개): HARD_RESET 응답, tls-crypt(서버 방향), TLS 서버(클라이언트 인증서 + **CRL**), key-method 2 서버 측, **클라이언트 능력 검사**(peer info `IV_PROTO`·`IV_CIPHERS`), **비동기 인증 결정**(인증서 신원 + 사용자 이름/비밀번호를 담은 `AuthRequest` → 호출자가 수락/거부, 거부 시 `AUTH_FAILED`), PUSH_REPLY 생성, 키 설치(인증 수락 뒤에만), 재협상(양쪽 시작, **같은 인증서·사용자 이름만 허용**), hand-window. 클라이언트 쪽 `auth-user-pass` 전송도 추가 | 우리 `ControlClient` ↔ `ControlServer` 메모리 시나리오(손실·중복·역순·재협상·인증 거부·폐기된 인증서·능력 부족). `FakeServer`는 결함 주입용 독립 구현으로 남긴다(§3.1) |
| V2 | 다중 클라이언트: (주소, 세션 id)로 세션 표, **peer-id 할당**, DATA_V2 수신을 peer-id로 분배, 인증 전 상태 할당 최소화(tls-crypt 검증 실패 패킷은 상태를 만들지 않음), 세션 수·IP별·속도 한도, TLS 컨텍스트 공유 | 동시 다수 세션 시뮬레이션, 위조·재생 패킷이 세션을 만들거나 바꾸지 못함, 한도 초과 처리 |
| V3 | 서버 데이터 경로: TUN, **주소 풀**(subnet topology), 클라이언트별 라우팅(TUN → 어느 세션), push 라우트, client-to-client 기본 차단, 소스 주소 위조 거부, 서버 쪽 keepalive(`ping`/`ping-restart`) | 메모리 테스트: 목적지 주소 → 세션 매핑, 풀 고갈·반환, 위조 소스 거부 |
| V4 | TCP 서버 Transport(accept, 연결별 `FramedTransport`) | 부분 읽기·다중 연결 테스트 |
| V5 | **설정 파서**(OpenVPN `server.conf` 부분집합, §5.2) + `pf_server` 실행 파일(`platform/linux`, 단일 스레드 이벤트 루프) + **수정 없는 OpenVPN 2.6 클라이언트 상호운용**(netns): UDP·TCP 터널 ping, 클라이언트·서버 재협상, 동시 3 클라이언트, `pf_client` ↔ `pf_server` | ctest 라벨 `protocol`(root, `RESOURCE_LOCK`), 설정 파서 fuzz |
| V6 | **외부 인증 훅**(`auth-user-pass-verify` via-file, §5.3) + **management 인터페이스 호환 부분집합**(§5.4) | 훅 프로세스 테스트(성공·거부·시간 초과·이상 입력), 수정 없는 클라이언트의 `auth-user-pass` 상호운용, management 명령 golden |
| V7 | 1시간 soak(재협상 1회 이상), 성능 기준선(stock 서버 대비, `docs/Performance_Baseline.md`), fuzz(서버 수신 경로) | 기록 |

### 3.0 V1 구현 메모 (D-048)

- `pf/control_server.h`(`core/src/crypto/control_server.cpp`): 클라이언트 1개의 제어 채널. `ControlClient`와 같은 sans-I/O 형태(`on_datagram`/`poll`/`next_wakeup_ms`). 상태: WaitReset → TlsHandshake → KeyExchange → (AuthPending) → Established, 실패는 Rejected(재전송만, linger 뒤 Closed) 또는 Closed.
- 세션 바인딩: 첫 패킷은 key_id 0, message 0, ACK 없는 HARD_RESET_CLIENT_V2여야 한다. 그 뒤로는 같은 session id이고, ACK가 있으면 우리 session id를 가리켜야 한다. **tls-crypt 재생 창은 바인딩을 통과한 패킷만 갱신한다**(`open_control_packet_deferred` + `commit_control_packet`). 잘못된 tls-crypt 키로 온 패킷에는 한 바이트도 답하지 않는다.
- 알 수 없는 key_id는 "Established이고 진행 중인 키 변경이 없을 때 정확히 다음 key_id의 SOFT_RESET"만 상태를 만든다.
- 키: 데이터 키는 인증 수락 뒤(첫 키) 또는 재협상 신원 확인 뒤에만 KeyStore에 들어간다. RX는 즉시, **TX는 그 키 상태로 보낸 것이 전부 ACK된 뒤** 옮긴다. 이전 키는 grace(기본 60초) 동안 RX만 남는다(최대 1개). `close()`와 소멸자는 모든 키를 와이프하고 바인딩을 푼다(KeyStore가 서버보다 오래 살아야 함).
- 재협상 실패 처리: 클라이언트 key-method 2를 받기 전이면 버린다(클라이언트가 새 키를 가질 수 없음). 받은 뒤 전환이 확인되지 않으면(시간 초과·ACK 없음) 세션을 닫는다.
- PUSH_REPLY: `ServerPush` → `build_push_reply`(관측한 2.6.19 순서, `protocol-flags tls-ekm`만; `cc-exit`·`dyn-tls-crypt`는 구현하지 않으므로 보내지 않음, 그러면 클라이언트도 정적 tls-crypt 키를 계속 씀). 1024바이트 상한(push-continuation 없음). 클라이언트가 `IV_PROTO`에 REQUEST_PUSH를 광고했거나 PUSH_REQUEST를 보냈으면 수락 즉시 보낸다.
- 테스트 리그: `tests/support/server_rig.h`(`ServerRig`, `ServerNet`, 실제 데이터 Flow로 키를 확인하는 `DataPathCheck`). 테스트 PKI에 두 번째 클라이언트, 폐기된 클라이언트, CRL을 추가했다.
- V2로 넘긴 것: 세션별 tls-crypt 재생 상태와 상태 없는 첫 패킷 처리(지금은 서버 1개 = 세션 1개), TLS 컨텍스트 공유(지금은 키 상태마다 `SSL_CTX`를 만듦), peer-id 할당.

### 3.1 `FakeServer`를 남기는 이유

처음 계획은 `fake_ovpn_server` 기반 테스트를 새 서버로 "대체"하는 것이었다. 진입 시 바꿨다(D-048). `FakeServer`는 일부러 잘못 동작하는 서버(키 교환 헤더 변조, 재협상 무응답, PUSH 대신 다른 메시지)를 만드는 결함 주입 도구이고, 클라이언트와 독립된 두 번째 구현이라 양쪽이 같은 실수를 공유하지 않는다는 근거도 된다. 정식 서버에 결함 주입 훅을 넣지 않기 위해 둘을 분리해 둔다. 대신 클라이언트의 정상 시나리오(손실·중복·역순·재협상)는 `ControlServer`를 상대로도 돈다.

## 4. 위협 (서버 추가분, `docs/Threat_Model_and_Key_Management.md` §8.3)

서버는 인터넷에서 오는 임의 패킷을 받는다. 클라이언트보다 공격면이 넓다.
- **인증 전 자원 소모**: tls-crypt HMAC을 먼저 검증하고, 실패한 패킷은 세션 상태를 만들지 않는다. 그 다음에 세션 수·IP별·속도 한도를 둔다.
- **세션 혼동**: 주소가 바뀐 클라이언트(float)는 인증된 패킷으로만 갱신한다. peer-id 위조는 AEAD 검증으로 거부한다.
- **클라이언트 신원 → 주소 매핑**: 인증서 신원별로 고정 주소를 줄지는 설정으로 정한다. 다른 클라이언트의 주소를 사칭하는 트래픽(소스 주소 위조)은 거부한다.
- **키 관리**: 서버 개인 키와 tls-crypt 키는 KeyRef로만 다룬다. 세션 키는 세션이 끝날 때 와이프한다.

## 5. 진입 결정 (D-048)

| 질문 | 결정 |
|---|---|
| 동시성 | **단일 스레드 이벤트 루프**. 코어는 sans-I/O라 나중에 세션 단위로 나눠 여러 스레드에 올릴 수 있다(PM-3) |
| 설정 형식 | **OpenVPN 서버 설정의 부분집합**(§5.2). 모르는 지시어와 지원하지 않는 값은 **오류**다(조용히 무시하지 않음) |
| 클라이언트 인증 | **인증서 + CRL + 사용자 이름/비밀번호**(외부 검증 훅, §5.3) |
| 관리 인터페이스 | **OpenVPN management 인터페이스 호환 부분집합**(§5.4) |
| 플랫폼 | **Linux 우선**. Windows 서버는 PM-1과 함께 검토 |

### 5.1 인증 모델 (V1에서 구현)

- 순서: tls-crypt → TLS(클라이언트 인증서가 `ca`에 연결되고 EKU clientAuth, **CRL에 없음**) → key-method 2 → 능력 검사 → **인증 결정** → PUSH_REPLY와 키 설치.
- 인증 결정은 비동기다. `ControlServer`는 `AuthRequest`(인증서 CN·SHA-256 지문, 사용자 이름, 비밀번호, peer info)를 내놓고 멈춘다. 호출자(V6의 외부 훅, management `client-auth`)가 `resolve_auth()`로 답한다. 답이 올 때까지 데이터 키는 설치되지 않으므로 인증 전에는 데이터 패킷이 하나도 받아들여지지 않는다.
- 사용자 이름/비밀번호 검사를 켜면 빈 사용자 이름은 훅을 부르지 않고 거부한다. 사용자 이름은 1~256바이트의 출력 가능한 문자만, 비밀번호는 1~1024바이트에 제어 문자(줄바꿈 포함)가 없어야 한다. 줄바꿈은 via-file 형식을 깨뜨리기 때문이다.
- 재협상: TLS가 인증서를 다시 검증하고(CRL 포함), **처음과 같은 인증서(SHA-256 지문)와 같은 사용자 이름**이어야 한다. 다르면 세션 전체를 끝낸다. 비밀번호는 다시 묻지 않는다(첫 인증이 세션 동안 유효, OpenVPN의 auth-token과 같은 효과). 매번 다시 묻는 방식은 V6에서 설정으로 검토한다.
- 거부: `AUTH_FAILED`를 보내고, 전달될 시간(기본 5초)만 재전송한 뒤 세션을 닫는다.

### 5.2 설정 부분집합 (V5)

`port`, `proto udp|tcp-server`, `dev tun`, `topology subnet`, `server <net> <mask>`, `ca`, `cert`, `key`, `crl-verify`, `tls-crypt`, `dh none`, `tls-version-min 1.3`, `cipher`/`data-ciphers AES-256-GCM`, `keepalive`, `reneg-sec`, `hand-window`, `push "route ..."`, `max-clients`, `auth-user-pass-verify <script> via-file`, `username-as-common-name`(검토), `management <ip> <port>`/`management <unix-path> unix`, `verb`, `persist-*`(무해, 받아들임), `user`/`group`(권한 내리기). 파일 경로만 받고 인라인 키(`<key>...</key>`)는 V5에서 결정한다. 파서는 fuzz 타깃을 둔다.

### 5.3 비밀번호 처리 (V1 코어 + V6 훅)

- 비밀번호는 로그·trace·management 출력·오류 메시지·`operator<<` 어디에도 나오지 않는다. 담는 버퍼는 쓰고 나면 와이프한다(`AuthRequest` 소멸 시, key-method 2 수신 버퍼 포함).
- 외부 훅은 **via-file만** 지원한다(via-env는 지원하지 않음). 개인 임시 디렉터리에 0600 파일(사용자 이름 줄, 비밀번호 줄)을 만들고, **셸 없이** `execve`로 스크립트를 실행해 파일 경로를 인자로 준다. 종료 코드 0 = 수락. 시간 제한을 넘기면 종료시키고 거부한다. 파일은 스크립트가 끝나면 덮어쓴 뒤 지운다.
- 사용자 이름은 훅의 인자나 환경 변수로 셸을 거치지 않는다. 인증 실패 사유는 클라이언트에게 일반 문구만 보낸다.

### 5.4 management 부분집합 (V6)

공개 문서(OpenVPN `management-notes`)의 형식을 따른다. 처음 목록: 접속 인사(`>INFO:`), `help`, `version`, `pid`, `state`, `status [1|2|3]`(`CLIENT_LIST` 등), `kill <cn|ip:port>`, `client-kill <cid>`, `load-stats`, `quit`/`exit`. `--management-client-auth`(`>CLIENT:CONNECT` → `client-auth`/`client-deny`)는 §5.1의 비동기 인증에 그대로 연결된다. 단, 비밀번호는 management로 보내지 않는 것이 기본이다(필요하면 명시적 설정). 리스너는 **localhost 또는 Unix 소켓만** 허용하고, `management` 비밀번호 파일을 지원한다.
