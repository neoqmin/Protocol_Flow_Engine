# 마일스톤 (Milestones)

기준 결정: D-006(MVP에서 오픈소스 수정 제외), D-008(MVP 프로토콜 프로파일), 설계 리뷰(2026-10-05).
범위 상세는 `docs/OpenVPN_Interop_Profile.md`. 각 마일스톤은 **테스트를 먼저 작성(TDD)** 하고 종료 조건을 자동 테스트로 판정한다.

표기: 🔧 = 오픈소스 수정/패치가 필요할 수 있는 항목 (조사 후 결정, MVP 불가)

## 한눈에 보기

```text
M0 하드닝 ✅
  ↓
[MVP]  MVP-A  Linux 클라이언트 + OpenVPN 2.6 상호운용
       MVP-B  TCP 프레이밍 + Transport 폴백
       MVP-C  Flow JSON v1 + Validator
  ↓ ───────────────── MVP 경계 (여기까지 오픈소스 수정 없음) ─────────────────
[Post-MVP]
       PM-1 플랫폼 확장 (Windows → Android → macOS → iOS)
       PM-2 네트워크 우회 (프록시, Relay, Hole Punching)
       PM-3 성능 최적화
       PM-4 DSL / Compiler / IR
       PM-5 TAP / L2 Block
       PM-6 GUI Flow Editor
       PM-7 MCP / AI 계층
       PM-8 🔧 OpenVPN DCO / Kernel Runtime
       PM-9 프로토콜 확장 (WireGuard / SDP / NAC)
       PM-10 암호 확장 (tls-crypt-v2, KCMVP 등)
```

---

## M0 — 하드닝 ✅ 완료

- 헤더 파서 보강(opcode 11, legacy 분류), device/fallback API 정리
- 테스트 하니스 개선, golden 테스트 엄격화
- CMake: `pf_core` 정적 라이브러리, 경고, ASan/UBSan, libFuzzer 옵션
- CI: `-Werror`(MSVC 제외), sanitizer 잡, fuzz 스모크(비차단)

---

# MVP

## MVP-A — Linux 클라이언트 + OpenVPN 2.6 상호운용

대상: Linux, 클라이언트 전용, UDP + TUN, 유저 모드. (프로파일: `docs/OpenVPN_Interop_Profile.md`)

| 단계 | 내용 | 종료 조건(테스트) |
|---|---|---|
| A1 ✅ | Block API, Flow Context, **오류 모델, 버퍼 모델(headroom/소유권)**, 정적 Flow 실행기 | unit/flow 테스트, API 문서 확정 (`docs/Block_API.md`) |
| A2 ✅ | Data Plane Block: DATA_V2 파싱, AES-256-GCM, packet-id/replay | 실제 2.6 pcap 기반 golden 통과, replay·변조 패킷 거부 |
| A3 ✅ | Control Plane (**일반 코드**, Flow 아님): reliability layer, tls-crypt, TLS 1.3(메모리 BIO), 키 유도, PUSH_REPLY 파싱, keepalive, 재협상 | 수정 없는 OpenVPN 2.6 서버와 핸드셰이크 성공 |
| A4 ✅ | Linux UDP 소켓 + TUN 통합 (`pf_client` = `TunnelSession` + `platform/linux`, `docs/Linux_Client_Notes.md`, D-029/D-037) | 터널 통해 ping 성공, 1시간 연결 + 재협상 1회 이상 통과 |

공통 종료 조건: 파서 fuzz/전수 테스트 통과, ASan/UBSan clean, **오픈소스 수정 0건**, 성능 **기준선(baseline) 측정 기록** (목표 수치는 기준선 후 확정).

## MVP-B — TCP 프레이밍 + Transport 폴백

| 단계 | 내용 | 종료 조건 |
|---|---|---|
| B1 ✅ | Transport 인터페이스 + UDP loopback 테스트 | 가짜 Transport로 단위 테스트 |
| B2 ✅ | TCP Transport (2바이트 길이 프레이밍, 부분 읽기 처리) | OpenVPN 2.6 TCP 서버 상호운용 |
| B3 ✅ | 폴백 통합: UDP 차단 시 TCP로 자동 전환 | UDP 차단 환경 시뮬레이션 테스트 |

## MVP-C — Flow JSON v1 + Validator

| 단계 | 내용 | 종료 조건 |
|---|---|---|
| C1 ✅ | Flow JSON 스키마 v1 + **버전 관리/마이그레이션 규칙** | 스키마 테스트 |
| C2 ✅ | Block Registry + Validator (잘못된 Flow 사전 차단) | 유효/무효 Flow 케이스 테스트 |
| C3 ✅ | MVP-A의 정적 Flow를 JSON으로 로딩해 동일 결과 | 정적 Flow와 JSON Flow의 golden 동등성 |

---

# Post-MVP

각 마일스톤의 **진입 조건**은 선행 마일스톤 종료 + 해당 항목의 설계 문서이다.

| ID | 마일스톤 | 내용 | 진입 조건 | 🔧 | 출처 |
|---|---|---|---|---|---|
| PM-1 | 플랫폼 확장 | Windows(Wintun) → Android(VpnService/JNI) → macOS(Network Extension) → iOS(메모리 예산 준수). PAL Device 구현, 플랫폼별 키 저장소, CI 빌드 잡(NDK/Xcode) | MVP-A | | MultiPlatform §3,4,7 |
| PM-2 | 네트워크 우회 | HTTP CONNECT/SOCKS5, Relay(자체 구현 vs 기존 도구 수정 없이 사용: **미결**), Hole Punching, Reverse Connect | MVP-B | 🔧(기존 도구 패치 시) | MultiPlatform §5 |
| PM-3 | 성능 최적화 | zero-copy, batching, lock 최소화, per-CPU. 기준선 대비 목표 수치 확정 후 진행 | MVP-A 기준선 | | OpenVPN §19 Phase 6, §21 |
| PM-4 | DSL / Compiler / IR | Flow JSON 위 텍스트 DSL, IR, 최적화. Control Plane 표현 방식(루프/타이머) 결정 포함 | MVP-C | | OpenVPN §7~9, §19 Phase 5 |
| PM-5 | TAP / L2 | ETH_PARSE, ARP, BROADCAST_FILTER, MAC learning, Validator의 L2 규칙 | MVP-A | | MultiPlatform §6 |
| PM-6 | GUI Flow Editor | **MVP-C 직후 에디터 PoC**(OpenVPN RX Flow JSON 표시 + 실시간 검증 오류) → Production. 캔버스는 MIT 계열 라이브러리, n8n 코드 미사용(D-022). Validator WASM 공유 검토. 사용자에 보안 관리자·운영자 포함 → 권한/승인/감사/버전·서명 요구(D-023) | MVP-C | | OpenVPN §18, §27~, §49, D-022 |
| PM-7 | MCP / AI 계층 | MCP Server, 권한 모델, 승인/감사 로그. 자연어 → Flow → 검증 → User Runtime 배포까지(DCO 제외) | MVP-C + PM-6 설계 | | MCP 계획 전체 |
| PM-8 | 🔧 OpenVPN DCO / Kernel Runtime | DCO Adapter, Kernel Runtime(Linux/Windows), Shared Memory Crypto. **먼저 Adapter/IPC로 수정 없이 가능한지 조사**, 불가 시 패치는 upstream 제안 우선 | MVP-A + 경계 조사 | 🔧 | OpenVPN §13~15, §45 |
| PM-9 | 프로토콜 확장 | WireGuard, SDP, NAC, N2SF | MVP-C | | OpenVPN §23 |
| PM-10 | 암호 확장 | tls-crypt-v2(opcode 10/11), 다른 cipher, KCMVP Provider | MVP-A | | OpenVPN §11, §22 |

## 진행 규칙

1. 다음 마일스톤으로 넘어가기 전에 현재 마일스톤의 **종료 조건 테스트가 모두 CI에서 통과**해야 한다.
2. MVP 작업 중 오픈소스 수정이 필요해 보이면 구현하지 말고 PM-8 또는 해당 PM에 항목을 추가한다.
3. 마일스톤 범위가 바뀌면 이 문서와 `docs/DECISIONS.md`를 같이 갱신한다.
