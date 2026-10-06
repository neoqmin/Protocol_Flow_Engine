# 프로젝트 결정 기록 (Decision Log)

새 결정은 **맨 아래에 추가**한다. 번복할 때는 기존 항목을 지우지 말고 `상태`를 `대체됨(D-xxx)`으로 바꾸고 새 항목을 추가한다.
세션/기기(클라우드, 로컬)가 바뀌어도 이 파일이 기준이다.

| ID | 날짜 | 결정 | 상태 |
|---|---|---|---|
| D-001 | 2026-10-05 | **멀티 플랫폼**: Windows, Linux, Android, macOS, iOS 모두 지원 목표. 코어는 플랫폼 독립, 플랫폼 차이는 PAL로 격리 | 확정 |
| D-002 | 2026-10-05 | **TDD 개발**: 테스트를 먼저 작성(Red→Green→Refactor). `tests/`에 unit/flow/protocol/regression/performance. 회귀는 golden vector로 누적, 기존 줄의 기대값은 사유 없이 변경 금지 | 확정 |
| D-003 | 2026-10-05 | **Device와 Transport는 독립 축**. TUN(L3)·TAP(L2) 모두 지원하되 기본은 TUN. TAP은 Linux/Windows만(macOS/Android/iOS 불가). 미지원 모드는 fallback 또는 명시적 오류 | 확정 |
| D-004 | 2026-10-05 | **Transport Fallback**: UDP → TCP → 프록시(HTTP CONNECT/SOCKS5) → Relay. 직접 연결이 안 되는 서버를 위한 우회. 사용자 관리 네트워크에서 정책에 맞게 쓰는 것을 전제 | 확정 |
| D-005 | 2026-10-05 | **오픈소스 활용 정책**: 기본은 오픈소스 사용, 부족하면 확장하되 upstream 업데이트를 방해하면 안 됨. 원본 수정 금지, Adapter 경유, 패치는 최후 수단(upstream 제안 우선). 상세: `docs/Upstream_Extension_Policy.md` | 확정 |
| D-006 | 2026-10-05 | **MVP에서는 오픈소스 수정/패치가 필요한 작업 제외**. DCO Adapter, Kernel Runtime, Shared Memory Crypto는 Post-MVP. MVP는 OpenVPN 프로토콜을 Block으로 독립 구현하고 수정 없는 OpenVPN과의 상호운용으로 검증 | 확정 |
| D-007 | 2026-10-05 | 구현 언어는 일단 **C++17**(CMake/CTest)로 시작 | 대체됨(D-013) |
| D-008 | 2026-10-05 | **MVP 프로토콜 프로파일 확정(초안)**: Linux 클라이언트 전용, 수정 없는 OpenVPN 2.6 서버 상대, UDP+TUN, TLS 1.3 + tls-crypt + AES-256-GCM. "wire 호환"은 이 프로파일 범위에 한정. 상세: `docs/OpenVPN_Interop_Profile.md` (`[검증]` 항목은 구현 전 확인) | 확정(범위) / 세부 검증 대기 |
| D-009 | 2026-10-05 | **MVP에서 Control Plane은 Flow가 아닌 일반 코드**로 구현 (타이머·재전송 상태머신은 DAG Flow로 표현 곤란). Flow 표현 여부는 PM-4에서 결정 | 확정 |
| D-010 | 2026-10-05 | **Clean-room 원칙**: 구현 근거는 공개 문서·RFC·pcap으로 한정, OpenVPN 소스 복사/전사 금지. iOS 빌드에는 GPL 코드 미포함. OpenVPN/DCO는 테스트 상대 또는 별도 프로세스로만 사용(링크 금지). 법무 검토 전제 | 확정 |
| D-011 | 2026-10-05 | **마일스톤 재편**: M0 하드닝 → MVP-A(Linux 클라이언트 상호운용) → MVP-B(TCP+폴백) → MVP-C(Flow JSON+Validator) → Post-MVP(PM-1~PM-10). MVP 밖 항목은 모두 `docs/Milestones.md`의 Post-MVP로 정리. DCO/Kernel은 PM-8(🔧) | 확정 |
| D-012 | 2026-10-05 | **설계 리뷰(Opus) 권고 반영(A안)**: 문서 정합화, 위협 모델·키 관리 초안(`docs/Threat_Model_and_Key_Management.md`), CI 하드닝(-Werror, ASan/UBSan, fuzz) | 반영 완료 |
| D-013 | 2026-10-05 | **구현 언어 확정: C++17** (Rust 병행 안 함). 필요 시 별도 결정으로 재검토 | 확정 |
| D-014 | 2026-10-05 | **TLS/암호 라이브러리: OpenSSL 3.x** (MVP-A, Linux). 수정 없이 링크, Provider 인터페이스 뒤에 둠. 모바일 라이브러리는 PM-1에서 별도 결정. 개발 환경 OpenSSL 3.0.13 확인 | 확정 |
| D-015 | 2026-10-05 | **상호운용 상대 환경**: 수정 없는 OpenVPN **2.6.19**(Ubuntu 24.04 패키지), `tools/interop/lab.sh`(netns+veth)로 pcap/로그 수집. 컨테이너에서 TUN/netns/veth 사용 가능 확인. 일부 `[검증]` 항목을 `[관측]`으로 확정(opcode 집합, key_id 회전, peer-id, tls-ekm 협상 등) | 확정 |
| D-016 | 2026-10-05 | CI 첫 실행 결과 확인: 5개 잡(ubuntu/windows/macos, sanitizers, fuzz-smoke) 모두 성공 → **fuzz-smoke를 blocking으로 전환** | 확정 |
| D-017 | 2026-10-05 | **데이터 채널 AEAD 레이아웃 확정(2.6.19, 32비트 packet-id)**: nonce = packet-id(4B) ‖ 방향·키별 tail 8B, AAD = 헤더4B ‖ packet-id4B, 태그가 암호문 앞. 독립 도구로 GCM 태그 검증까지 통과. 지원 버전은 **2.6.x로 한정**(2.7 등은 XOR 방식 논의가 있어 별도 검증 전까지 비지원) | 확정 |
| D-018 | 2026-10-05 | **IV_PROTO**: MVP 클라이언트는 `DATA_V2 \| REQUEST_PUSH \| TLS_KEY_EXPORT`(=14)만 광고하고 `cc-exit`/`dyn-tls-crypt`는 광고하지 않음. EKM 라벨 `EXPORTER-OpenVPN-datakeys`(공식 문서) | 확정(서버 응답은 A3에서 확인) |
| D-019 | 2026-10-05 | **A1 설계 확정(Block API)**: `Drop`(입력 탓, 사유 필수)과 `Error`(우리 쪽 실패)를 분리, Action/Decision별 허용 결과를 러너가 강제(위반 시 `Errored/Internal`). `PacketBuffer`는 headroom/tailroom + move-only + 재할당 없음 + `wipe()`. Flow는 빌드 시 순환·미도달·누락 edge를 검증하고 handler를 미리 해석(직접 dispatch). 상세: `docs/Block_API.md` | 확정 |
| D-020 | 2026-10-05 | **작업 추적 방식**: 저장소 루트 `progress.md`(`[ ]`/`[~]`/`[x]`/`[!]`)를 정본으로 하고 클라우드·로컬·사람·Claude가 공유. 작업 상태 변경은 해당 커밋에서 같이 갱신. 세션 내 작업 목록은 보조 | 확정 |
| D-021 | 2026-10-05 | **A2 Data Plane 설계 확정**: replay window는 인증 성공 후에만 갱신(check/commit 분리), 인증 실패 시 평문을 0으로 지움, TX nonce 고갈 시 래핑 대신 `NonceExhausted`로 중단, 키는 `KeyStore`의 `KeyRef`로만 접근. 암호는 `AeadProvider` 인터페이스 + OpenSSL 구현(`PF_WITH_OPENSSL=AUTO/ON/OFF`로 게이팅). Windows CI는 PM-1까지 OpenSSL OFF. 상세: `docs/Block_API.md` §8 | 확정 |
| D-022 | 2026-10-05 | **웹 Flow 에디터 방향**: 에디터는 제품의 핵심 포인트(계획서 §50). **n8n 코드/에셋은 사용하지 않는다** — Sustainable Use License(fair-code, 사내·비영리 목적에 한정, 상용 재배포 불가)가 판매·배포 제품과 충돌. n8n은 UX 아이디어(노드 팔레트, 자격증명 분리≈Key Reference, 노드별 테스트≈패킷 시뮬레이션, JSON 내보내기)만 참고. 캔버스는 MIT 계열(Rete.js/React Flow 등, 사용 전 LICENSE 확인). C++ Validator를 WASM으로 컴파일해 에디터와 런타임이 같은 검증을 쓰는 방안을 검토. **MVP-C 직후 에디터 PoC**를 앞당김. 에디터는 보안 정책 편집이므로 권한/승인/버전·서명을 PoC부터 고려 | 확정 (사용자 범위는 D-023) |
| D-023 | 2026-10-05 | **에디터 사용자 범위 확정**: 프로토콜 개발자뿐 아니라 **보안 관리자·운영자도 정책(Flow)을 편집**한다. 따라서 에디터 PoC부터 (1) 역할별 권한(보기/편집/검증/승인/배포 분리), (2) 변경 승인 워크플로(작성자≠승인자), (3) 감사 로그, (4) Flow 버전 관리와 서명, (5) 비개발자용 안전장치(위험한 Block 편집 제한, 검증 통과 전 배포 불가)를 요구사항에 포함한다. MCP 계획의 권한 모델(§17~§20)과 연계. 키 값은 어떤 역할에도 노출하지 않고 Key Reference만 다룬다 | 확정 |
| D-024 | 2026-10-05 | **tls-crypt 와이어/키 배치 확정(2.6.19)**: `wire = op_keyid(1)|session_id(8)|packet_id(4)|net_time(4)|tag(32)|ct`, `tag = HMAC-SHA256(Ka, wire[0:17]‖plaintext)`, IV = tag[0:16], AES-256-CTR. 정적 키 파일은 64B×4 구간(K0..K3)의 앞 32B씩 사용: **클라이언트 tx=(K2 암호, K3 HMAC), rx=(K0, K1)**. replay는 (net_time, packet_id)로, 인증 성공 후에만 상태 갱신. 근거: 실제 패킷의 HMAC 태그 검증. 상세: `docs/OpenVPN_Control_Plane_Notes.md`. 랩 출력 위치를 `build/`에서 `tools/interop/out/`으로 이동(빌드 디렉터리 삭제 시 유실 방지) | 확정 |
| D-025 | 2026-10-05 | **제어 패킷 평문 포맷 확정(2.6.19)**: `ack_len|acks(4B BE)|remote_sid(8, ack>0)|[message_id|payload]`, `P_ACK_V1`은 message 없음. 골든 14개 파싱→재빌드 일치. **reliability는 순수 로직(시계 주입)**: 송신 윈도우 4, RTO 2s×2 상한 16s, 6회 실패, 수신 윈도우 8, 중복은 재-ACK, ACK는 최신 우선 최대 8개. 파라미터는 우리 선택이며 A3-6 상호운용에서 검증 | 확정(포맷) / 파라미터는 상호운용 검증 대기 |
| D-026 | 2026-10-05 | **EKM 키 유도 레이아웃 확정**(실제 OpenVPN 2.6.19 서버로 검증): label `EXPORTER-OpenVPN-datakeys`, 컨텍스트 없음, **256바이트** export. 클라이언트 tx = key `[0:32]` + nonce tail `[64:72]`, rx = key `[128:160]` + tail `[192:200]`(서버는 반대). 근거: 서버 패킷의 모든 오프셋 조합 탐색에서 GCM 태그가 검증되는 조합이 유일, 서버가 우리 핑을 복호화해 수락, 오프셋을 틀리게 하면 상호운용 테스트 실패 | 확정 |
| D-027 | 2026-10-05 | **제어 채널 상호운용 확정**: key-method 2 메시지(옵션·peer info 값)가 수정 없는 서버에 수락됨. 서버 응답은 옵션 뒤에 **선택 필드 3개**(username, password, peer info; 빈 값). 서버는 `REQUEST_PUSH` 광고 시 PUSH_REQUEST 없이 PUSH_REPLY를 보내고 `key-derivation tls-ekm`으로 협상(`protocol-flags` 아님). `IV_VER`는 구현한 프로토콜 수준인 `2.6.0`. **자동 상호운용 테스트**(`tests/protocol/run_interop.sh`, CTest 라벨 `protocol`, root 필요)와 CI `interop` 잡(초기 비차단)을 추가 | 확정 |
| D-028 | 2026-10-05 | **재협상·keepalive 설계 확정(실제 서버로 검증)**: key_id별 `KeyState`(reliable+TLS 분리), 재협상은 SOFT_RESET으로 시작(서버/클라이언트 모두), key_id는 `0,1..7,1`로 순환, 키 교환 직후 TX 전환, **이전 키는 수신용 유예(기본 60초) 후 와이프·최대 1개**, 실패한 재협상은 폐기하고 이전 키 유지, 클라이언트도 `reneg_interval_ms`(기본 3600초) 후 시작. `KeepaliveTimer`: 마지막 송신 후 `ping`초에 핑, 마지막 수신 후 `ping-restart`초에 타임아웃. 상호운용 테스트에 `server-reneg`(8회 이상, 7→1 순환)·`client-reneg` 시나리오 추가. **A4는 별도 세션에서 진행** | 확정 |
| D-030 | 2026-10-05 | **A4 Linux 통합 구조**: (1) 코어에 I/O 없는 `DataPath`(A2 TX/RX Flow를 `seal`/`open` API로 감쌈, 페이로드를 Ip/Ping/Other로 분류 — **IP가 아닌 인증 데이터는 TUN에 쓰지 않음**). (2) 플랫폼 코드는 새 디렉터리 `pal/linux/`(PAL, 코어는 include 금지): `TunDevice`(IFF_TUN\|IFF_NO_PI, ioctl로 주소·MTU·up·라우트, 외부 `ip` 명령 불필요), `VpnClient`(UDP+TUN 단일 스레드 `poll()` 루프, 타이머로 대기 상한 결정). (3) 실행 파일 `pf_vpn`(제품 클라이언트 1차), `pf_connect`는 진단 도구로 유지. (4) TUN MTU 기본 **1400**(`--mtu`), 푸시된 라우트는 `route_gateway` 경유로 설치, `redirect-gateway`/DNS는 미지원(Post-MVP). (5) `ping-restart` 타임아웃은 종료 코드 5로 보고만 하고 **재연결 정책은 제품 계층 과제**로 남김. 검증: `tests/protocol/run_vpn_tunnel.sh`(실제 터널 ping, 서버 `reneg-sec 3` 재협상 중 손실 0) | 확정 |
| D-031 | 2026-10-06 | **MVP-A 종료**: A4 1시간 연결(재협상 1회) 통과, fuzz 타깃 7개 상시화, 성능 기준선 기록(`docs/Performance_Baseline.md`). 기준선은 Release 빌드·veth 환경이며 **목표 수치가 아님**(±15% 변동). 다음은 MVP-B(TCP 프레이밍 + 폴백). 운영 메모: 클라우드 컨테이너는 세션이 유휴이면 재시작되어 장시간 백그라운드 작업이 죽으므로, 1시간급 테스트는 턴을 열어 둔 채 감시한다 | 확정 |
| D-032 | 2026-10-06 | **Transport 인터페이스(B1)**: 패킷 단위 계약 — `send` 1회 = OpenVPN 패킷 1개, `recv` 1회 = 완전한 패킷 1개(UDP는 데이터그램 1:1, TCP는 B2에서 2바이트 길이 프레이밍·재조립을 같은 인터페이스 뒤에 숨김). 논블로킹, 상태 `Ok/WouldBlock/TooLarge/Closed/Error`, 대기는 `poll_fd()`로 호출자가 poll. **UDP 차단은 송신자에게 보이지 않는다**(손실) → 폴백은 오류가 아니라 제어 채널 타임아웃으로 판단(B3). 버퍼보다 큰 수신 패킷은 잘라 쓰지 않고 `TooLarge`로 버림(`MSG_TRUNC`). connected UDP 소켓이라 다른 출처 패킷은 커널이 걸러냄. 테스트용 `LoopbackTransport`(차단/드롭/용량/종료)를 코어에 둠. Device(TUN/TAP)와 무관 | 확정 |
| D-033 | 2026-10-06 | **TCP Transport(B2) 구조**: 프레이밍은 코어의 `FramedTransport`(2바이트 big-endian 길이 + 패킷, 최대 65535)가 `ByteStream`(부분 읽기/쓰기 계약) 위에서 수행 — 소켓 없이 청크 분할 전수 테스트. 규칙: (1) 초과 프레임은 **소비한 뒤** `TooLarge`로 버려 프레이밍 정렬 유지, (2) 스트림이 프레임 중간에 끝나면 `Closed`(버퍼의 완전한 프레임은 먼저 전달), (3) 송신은 큐잉하고 한도(기본 256KB) 초과 시 `WouldBlock` — **TCP에서는 패킷을 조용히 버리면 프레이밍이 깨지므로 절대 부분 기록·무음 드롭 금지**, (4) `Transport`에 `has_pending_input()`(이미 버퍼된 완전한 프레임이 있으면 이벤트 루프가 잠들면 안 됨)/`wants_write()`/`flush()` 추가. Linux `TcpStream`: connect 타임아웃, `TCP_NODELAY`, `MSG_NOSIGNAL`. TCP에서도 OpenVPN 제어 채널 reliability 계층은 그대로 동작(서버가 같은 방식으로 요구). 수정 없는 2.6.19 `tcp-server`와 터널·재협상 검증 | 확정 |
| D-034 | 2026-10-06 | **Transport 폴백(B3)**: `FallbackConnector`가 `FallbackPolicy`(기본 UDP→TCP)를 순회하며 시도마다 새 `ControlClient`와 transport를 만든다. **폴백 조건 = 경로가 나쁘다는 증거만**: 연결 거부/도달 불가, transport 종료·오류, 제어 채널 무응답(`FailureKind::Unreachable`: ACK 없음, PUSH_REPLY 없음), 시도 제한 시간(`connect_timeout_ms`, pf_vpn 기본 10초) 초과. **서버가 응답한 거절(`Rejected`: 인증서 오류, AUTH_FAILED, RESTART/HALT, 미지원 프로파일)은 폴백하지 않는다** — TCP로도 같은 답이 오므로 시간만 낭비하고 원인을 가린다. 알려진 한계: tls-crypt 키가 틀리면 서버가 침묵하므로 차단과 구분 불가(폴백을 모두 시도한 뒤 실패 보고 — 시도 이력이 모두 보임). TCP connect는 지금 시도 제한 시간만큼 블로킹(시작 시 1회, 비동기화는 필요 시). 옵션 문자열의 `proto`는 TCP 시도에서 `TCPv4_CLIENT`로 바꿔 보낸다. 검증: 메모리 시뮬레이션 10개 + 실제 서버 앞 nft 무음 UDP 드롭 | 확정 |
| D-035 | 2026-10-06 | **Flow JSON v1(C1)**: 외부 JSON 라이브러리 없이 코어에 **엄격 JSON**(중복 키·잘못된 UTF-8·단독 서로게이트 거부, 한도) 자체 구현 — 보안 파일 형식이라 파서 동작을 우리가 통제·fuzz한다. 스키마는 계획서 §33 형태(`format/version/flow/nodes/edges`)에 **노드 필드는 `block`(레지스트리 이름)**, 엣지 포트는 `continue/yes/no`, `to:null`=종료. 기존 `FlowBuilder`와 같은 실행 의미(Action은 다음 노드로 암묵 연결). **알 수 없는 필드는 오류**, 도구 확장은 `x-` 접두로 보존. **키 재료 금지**(비밀 이름·PEM 거부, `*Ref`만 허용, 계획서 §41). 로더는 구조만, 의미 검증은 C2. 버전: 새 파일 거부·구 파일은 단계별 마이그레이션 후 검증·쓰기는 항상 현재 버전·정규 출력. 상세는 `docs/Flow_JSON_Schema_v1.md` §7 | 확정 |
| D-036 | 2026-10-06 | **Validator(C2)**: 로더(구조)와 분리된 **의미 검증**, 모든 이슈는 `{code, path(JSON Pointer), message}`로 한 번에 여러 개. 블록은 `ParamSpec`으로 파라미터를 **선언**하고, **선언 없으면 파라미터 불가**(오타 무음 방지); Decision은 yes/no 둘 다 필요, Action은 continue만; **순환 금지**(패킷당 작업량 유한, 메시지에 루프 경로)·도달 불가 노드 거부; 알 수 없는 블록은 가까운 이름 제안. 그래프 검사는 엔드포인트·포트 오류가 없을 때만(`FlowBuilder`와 동일). `compile_flow`는 **검증 통과 문서만** `FlowBuilder`로 넘겨 Flow를 만들고, 둘의 불일치는 `Internal`(우리 버그)로 보고 — 무작위 6000개 차등 테스트로 불일치 0. 실행 의미는 `FlowBuilder`와 동일(Action은 다음 노드로 암묵 연결, `to:null`=종료) | 확정 |

## 미결정 사항 (Open Questions)

1. Relay 구현: 자체 서버 vs 기존 도구(수정 없이) 활용 (PM-2)
2. ~~구현 언어~~ → D-013 확정
3. 모바일 TLS/암호 라이브러리 (BoringSSL 등) (PM-1) — 데스크톱 MVP는 OpenSSL 3.x(D-014)
4. 플랫폼 지원 순서 (제안: Linux → Windows → Android → macOS → iOS)
5. OpenVPN 연동 경계 조사: management interface vs DCO 경계 (PM-8)
6. ~~남은 `[검증]` (exporter 등)~~ → D-026/D-027로 확정. 남은 것: 재협상(SOFT_RESET) 동작, 손실·지연 환경에서의 reliability 검증
7. 성능 목표 수치 (MVP-A 기준선 측정 후), iOS 메모리 상한
8. ~~오류 모델 / 버퍼 모델~~ → D-019 확정
9. ~~에디터 사용자 범위~~ → D-023 확정 (역할 목록·승인 단계 세부는 PM-6 진입 시 설계)
10. MSVC `/WX` 적용 시점 (현재 CI에서 `/W4`만, 검증 후 결정)

## 현재 진행 상황

작업 추적은 저장소 루트의 **`progress.md`**(체크박스)가 정본이다 (D-020). 이 문서는 결정만 기록한다.
