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
| D-007 | 2026-10-05 | 구현 언어는 일단 **C++17**(CMake/CTest)로 시작 | 잠정 (Rust 병행 여부 미결정) |

## 미결정 사항 (Open Questions)

1. Relay 구현: 자체 서버 vs 기존 도구(수정 없이) 활용
2. 구현 언어: C++17 고정 vs Rust 병행
3. 모바일 TLS/암호 라이브러리 (BoringSSL 등)
4. 플랫폼 지원 순서 (제안: Linux → Windows → Android → macOS → iOS)
5. OpenVPN 연동 경계 조사 (Post-MVP: management interface vs DCO 경계)

## 현재 진행 상황

- 완료: 참고자료 정리, TDD 스캐폴드(CMake/CTest, CI 매트릭스), OpenVPN 헤더 파서, Device 지원 매트릭스, Transport Fallback 정책
- 다음: MVP-1 — Phase 1(Block API, Runtime Context, 실행기), Transport 인터페이스 + UDP loopback(M1)
