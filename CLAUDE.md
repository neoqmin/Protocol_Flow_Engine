# Protocol Flow Engine

OpenVPN 기반의 Block 조립형 VPN/보안 프로토콜 처리 엔진. 작은 Block을 Flow로 연결하고 Compiler/Runtime으로 실행한다.
클라우드 세션과 로컬 환경 모두에서 이 파일을 읽으므로, **결정이 바뀌면 이 파일과 `docs/DECISIONS.md`를 같이 갱신하고 커밋한다.**

## 문서 위치

- 개발 계획: `plans/Protocol_Flow_Engine_OpenVPN_Development_Plan.md`
- MCP/AI 확장: `plans/Protocol_Flow_Engine_MCP_AI_Extension_Plan.md`
- 멀티 플랫폼·Transport: `plans/Protocol_Flow_Engine_MultiPlatform_Transport_Plan.md`
- 오픈소스 정책: `docs/Upstream_Extension_Policy.md`
- 참고 자료: `docs/References_OpenSource_Papers.md`
- **전체 결정 기록: `docs/DECISIONS.md`** (@docs/DECISIONS.md)

## 핵심 결정 (요약)

- Windows/Linux/Android/macOS/iOS 멀티 플랫폼. 코어는 플랫폼 독립, 차이는 PAL로 격리
- TDD: 테스트 먼저. 버그는 재현 테스트/golden vector부터 추가
- Device(TUN/TAP)와 Transport(UDP/TCP/프록시/Relay)는 독립 축. TAP은 Linux/Windows만
- 오픈소스 원본 수정 금지, Adapter 경유, 패치는 최후 수단 (`third_party/`는 편집 금지)
- **MVP에서는 오픈소스 수정이 필요한 작업 제외** (DCO Adapter, Kernel Runtime은 Post-MVP)
- 언어는 C++17로 시작 (Rust 병행 여부 미결정)

## 빌드 / 테스트

```sh
cmake -S . -B build -G Ninja        # Ninja가 없으면 -G 생략
cmake --build build
ctest --test-dir build --output-on-failure
ctest --test-dir build -L unit      # unit | flow | regression | protocol | performance
./build/tests/pf_unit_tests <이름필터>
```

## 코드 규칙

- 구조: `core/`(헤더 `core/include/pf/`, 구현 `core/src/`), `tests/`, `adapters/`, `third_party/`, `patches/`
- `tests/unit|flow|regression/test_*.cpp`는 CMake가 자동 수집. 새 테스트 하니스는 `tests/support/pf_test.h` (`PF_TEST`, `PF_CHECK`, `PF_CHECK_EQ`)
- upstream 타입은 `adapters/`에서만 참조. 코어/Block은 우리 인터페이스에만 의존
- 보안: 키는 DSL/Flow에 직접 저장하지 않고 Key Reference로만 다룬다

## Git

- 작업 브랜치: `docs/references-collection` (현재). master에는 요청 시 머지
- PR은 사용자가 요청할 때만 생성
