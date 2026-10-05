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

## 미결정 사항 (Open Questions)

1. Relay 구현: 자체 서버 vs 기존 도구(수정 없이) 활용 (PM-2)
2. ~~구현 언어~~ → D-013 확정
3. 모바일 TLS/암호 라이브러리 (BoringSSL 등) (PM-1) — 데스크톱 MVP는 OpenSSL 3.x(D-014)
4. 플랫폼 지원 순서 (제안: Linux → Windows → Android → macOS → iOS)
5. OpenVPN 연동 경계 조사: management interface vs DCO 경계 (PM-8)
6. 남은 `[검증]`: TLS exporter 컨텍스트/내보내는 바이트 수/방향별 키·nonce tail 분할 → A3 핸드셰이크 상호운용 테스트로 확정 (라벨, AEAD nonce/AAD, IV_PROTO 비트는 D-017/D-018로 확정)
7. 성능 목표 수치 (MVP-A 기준선 측정 후), iOS 메모리 상한
8. ~~오류 모델 / 버퍼 모델~~ → D-019 확정
9. MSVC `/WX` 적용 시점 (현재 CI에서 `/W4`만, 검증 후 결정)

## 현재 진행 상황

작업 추적은 저장소 루트의 **`progress.md`**(체크박스)가 정본이다 (D-020). 이 문서는 결정만 기록한다.
