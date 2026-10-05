# 진행 현황 (Progress)

> 이 파일이 **작업 추적의 기준**이다. 클라우드/로컬, 사람/Claude 모두 같은 파일을 본다.
> 마일스톤 정의와 종료 조건은 [docs/Milestones.md](docs/Milestones.md), 결정 이력은 [docs/DECISIONS.md](docs/DECISIONS.md).
> 마지막 갱신: 2026-10-05 (A2 완료)

범례: `[x]` 완료 · `[ ]` 미착수 · `[~]` 진행 중 · `[!]` 막힘(사유 기재)

## 지금 할 일 (Next)

- [~] **MVP-A / A3** — Control Plane. tls-crypt 완료 → 다음: 제어 패킷 포맷 + reliability layer (골든 평문으로 TDD)

## 요약

| 마일스톤 | 상태 |
|---|---|
| 기반 (문서·정책·CI) | ✅ 완료 |
| M0 하드닝 | ✅ 완료 |
| **MVP-A** Linux 클라이언트 + OpenVPN 2.6 상호운용 | 🔶 A1·A2 완료, A3 다음 |
| MVP-B TCP + 폴백 | ⬜ |
| MVP-C Flow JSON + Validator | ⬜ |
| Post-MVP (PM-1 ~ PM-10) | ⬜ |

---

## 기반

- [x] 참고 오픈소스/논문 정리 ([docs/References_OpenSource_Papers.md](docs/References_OpenSource_Papers.md))
- [x] 개발 계획서 3종 (`plans/`)
- [x] 멀티 플랫폼·Transport 계획 (TUN/TAP 독립 축, 폴백)
- [x] 오픈소스 확장 정책 ([docs/Upstream_Extension_Policy.md](docs/Upstream_Extension_Policy.md))
- [x] 위협 모델·키 관리·clean-room ([docs/Threat_Model_and_Key_Management.md](docs/Threat_Model_and_Key_Management.md))
- [x] OpenVPN 상호운용 프로파일 ([docs/OpenVPN_Interop_Profile.md](docs/OpenVPN_Interop_Profile.md))
- [x] 마일스톤 정리 / 설계 리뷰(Opus) 반영
- [x] 언어 C++17, TLS/암호 OpenSSL 3.x 확정 (D-013, D-014)
- [x] 상호운용 랩 `tools/interop/lab.sh` (수정 없는 OpenVPN 2.6.19, netns+veth, pcap)
- [x] 데이터 채널 AEAD nonce/AAD 독립 검증 `tools/interop/verify_aead.py` (D-017)
- [x] CI: ubuntu/windows/macos + ASan/UBSan + fuzz-smoke
- [x] CLAUDE.md / DECISIONS.md / 이 파일 (프로젝트 메모리)

## M0 — 하드닝 ✅

- [x] 헤더 파서 (opcode 1~11, legacy 분류, 전수 테스트)
- [x] device 지원 매트릭스(TUN/TAP), Transport 폴백 정책
- [x] 테스트 하니스, golden 회귀 테스트, libFuzzer 타깃
- [x] CMake 정적 라이브러리/경고/sanitizer 옵션

---

# MVP

## MVP-A — Linux 클라이언트 + OpenVPN 2.6 상호운용

### A1 — Block API, 오류·버퍼 모델 ✅  ([docs/Block_API.md](docs/Block_API.md))

- [x] 오류 모델: `Drop`(입력 탓, 사유 필수) vs `Error`(우리 실패)
- [x] `PacketBuffer` (headroom/tailroom, move-only, wipe)
- [x] `BlockRegistry` + Block 결과 계약 강제
- [x] `FlowBuilder` 검증 (순환, 미도달, 누락 edge, 중복 label)
- [x] `run_flow` 실행기 + 통계(`FlowStats`) + step 한도
- [x] OpenVPN RX 정적 Flow (파싱 → 정책 → 분기 → decap)

### A2 — Data Plane ✅  ([docs/Block_API.md](docs/Block_API.md) §8)

- [x] 랩 pcap + 테스트 세션 키로 **DATA_V2 골든 벡터** 17개 추출 (`tools/interop/extract_vectors.py`, 태그 검증 통과분만)
- [x] DATA_V2 헤더/packet-id 파싱 Block (`parse_data_v2`)
- [x] AES-256-GCM 복호 Block (OpenSSL 3.x, **제자리**, AAD = 헤더4‖packet-id4, nonce = packet-id‖tail8)
- [x] AES-256-GCM 암호 Block (TX, headroom 캡슐화) — 골든 평문을 재암호화하면 OpenVPN 바이트와 **정확히 일치**
- [x] packet-id **replay window** (64, check/commit 분리, 경계·큰 점프·최댓값 테스트)
- [x] 변조(태그/암호문/AAD/키/nonce)·잘림·키 없음·재생·packet-id 0 거부 테스트
- [x] DATA_V2 RX/TX Flow 통합 (가짜 Provider로 로직 검증 + 실제 OpenVPN 패킷으로 전체 Flow 검증)
- [x] 키 재료 `wipe` 검증 (`DataKey`, `secure_zero`, 인증 실패 시 평문 0 처리), TX nonce 고갈 정책
- [x] 변이 테스트로 nonce·AAD·wipe·window 크기 오류가 테스트에 잡히는지 확인
- [x] CI: OpenSSL 게이팅(ubuntu/macOS ON, Windows OFF), `fuzz_data_v2` 타깃 — 5개 잡 모두 통과 확인 (run 14)

### A3 — Control Plane (일반 코드, Flow 아님: D-009)  ([docs/OpenVPN_Control_Plane_Notes.md](docs/OpenVPN_Control_Plane_Notes.md))

- [x] **tls-crypt 와이어/키 배치 확정**: pcap + 테스트 키로 HMAC 태그 검증 (`tools/interop/verify_tls_crypt.py`). client tx=(K2,K3), rx=(K0,K1)
- [x] **tls-crypt wrap/unwrap 구현** (`TlsCryptChannel`: packet-id/net_time replay, 인증 후에만 상태 갱신, id 고갈 시 중단). 골든 14개 개봉 + **재봉인 시 OpenVPN과 바이트 일치**
- [ ] 제어 패킷 평문 포맷 파싱/빌드 (ACK 배열, 원격 세션ID, 패킷ID, P_ACK_V1 형식 확정)
- [ ] reliability layer (수신 재정렬·ACK 생성, 송신 재전송 타이머, 시계 주입)
- [ ] TLS 1.3 (메모리 BIO, OpenSSL) 핸드셰이크
- [ ] key-method 2 메시지, IV_PROTO = 14 광고
- [ ] 키 유도 (TLS exporter, `EXPORTER-OpenVPN-datakeys`) — **컨텍스트/크기/분할 `[검증]` 확정** (랩에서 복원한 nonce tail을 기대값으로)
- [ ] PUSH_REQUEST / PUSH_REPLY 파싱 (ifconfig, route, peer-id, cipher, keepalive) 후 `KeyStore`에 DataKey 설치
- [ ] keepalive(ping), 재협상(key_id 회전)
- [ ] 수정 없는 OpenVPN 2.6 서버와 핸드셰이크 성공 (`tests/protocol`, 정적 tls-crypt 키로 전 구간 동작 확인 — dyn-tls-crypt 비광고)

### A4 — Linux 통합

- [ ] UDP 소켓 + TUN 장치 연동
- [ ] 터널 ping 성공
- [ ] 1시간 연결 + 재협상 1회 이상

### MVP-A 공통 종료 조건

- [ ] 파서/디코더 fuzz·전수 테스트 통과, ASan/UBSan clean
- [ ] **오픈소스 수정 0건**
- [ ] 성능 **기준선(baseline)** 측정 기록 (OpenVPN 2.6 대비, 목표 수치는 이후 확정)

## MVP-B — TCP 프레이밍 + Transport 폴백

- [ ] B1 Transport 인터페이스 + UDP loopback 테스트
- [ ] B2 TCP Transport (2바이트 길이 프레이밍, 부분 읽기) + 2.6 TCP 서버 상호운용
- [ ] B3 UDP 차단 시 TCP 자동 폴백 (시뮬레이션 테스트)

## MVP-C — Flow JSON v1 + Validator

- [ ] C1 Flow JSON 스키마 v1 + 버전 관리/마이그레이션 규칙
- [ ] C2 Block Registry + Validator (잘못된 Flow 사전 차단)
- [ ] C3 MVP-A 정적 Flow를 JSON으로 로딩해 동일 결과 (골든 동등성)

---

# Post-MVP (진입 조건: [docs/Milestones.md](docs/Milestones.md))

- [ ] PM-1 플랫폼 확장 (Windows → Android → macOS → iOS)
- [ ] PM-2 네트워크 우회 (프록시, Relay, Hole Punching) — Relay 방식 미결
- [ ] PM-3 성능 최적화
- [ ] PM-4 DSL / Compiler / IR
- [ ] PM-5 TAP / L2 Block
- [ ] PM-6 GUI Flow Editor — **n8n 코드는 사용하지 않음(라이선스), UX만 참고**(D-022). MVP-C 직후 에디터 PoC, Validator를 WASM으로 공유하는 방식 검토. **보안 관리자·운영자도 편집**(D-023): 역할별 권한, 승인 워크플로, 감사 로그, 버전·서명을 PoC부터 포함
- [ ] PM-7 MCP / AI 계층
- [ ] PM-8 🔧 OpenVPN DCO / Kernel Runtime (오픈소스 수정 가능성)
- [ ] PM-9 프로토콜 확장 (WireGuard / SDP / NAC)
- [ ] PM-10 암호 확장 (tls-crypt-v2, KCMVP 등)

---

## 확인 필요 / 미결정

- [ ] A3에서 확정: TLS exporter 컨텍스트·바이트 수·방향별 키/nonce tail 분할
- [ ] 성능 목표 수치, iOS 메모리 상한 (MVP-A 기준선 이후)
- [ ] Relay 구현 방식 (PM-2 진입 전)
- [ ] 모바일 TLS/암호 라이브러리 (PM-1 진입 전)
- [ ] Windows용 암호 라이브러리 연결 (현재 CI는 OpenSSL OFF, PM-1)
- [ ] MSVC `/WX` 적용 시점
- [ ] 법무 검토 (상용 배포 전, clean-room/GPL)
- [ ] `third_party` 무수정 검사 + upstream canary CI (의존성이 들어올 때)

---

## 이 파일 갱신 규칙

1. 작업을 시작하면 `[ ]` → `[~]`, 끝나면 `[x]`. **해당 변경과 같은 커밋**에 이 파일도 수정한다.
2. 새 작업·하위 항목은 해당 마일스톤 아래에 추가한다. 범위가 바뀌면 `docs/Milestones.md`와 `docs/DECISIONS.md`도 같이 갱신한다.
3. 막히면 `[!]`와 사유를 항목 옆에 적는다.
4. 맨 위 "지금 할 일"과 "마지막 갱신" 날짜를 항상 맞춘다.
5. 클라우드 세션의 임시 작업 목록(TaskCreate 등)은 보조 수단이다. **저장소의 이 파일이 정본**이다.
