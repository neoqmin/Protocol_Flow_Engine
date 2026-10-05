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
