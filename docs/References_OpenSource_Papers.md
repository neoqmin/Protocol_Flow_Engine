# Protocol Flow Engine — 참고 오픈소스 / 논문 / 자료 정리

- 작성일: 2026-10-02
- 대상 계획서
  - `plans/Protocol_Flow_Engine_OpenVPN_Development_Plan.md` (이하 **[OVPN 계획]**)
  - `plans/Protocol_Flow_Engine_MCP_AI_Extension_Plan.md` (이하 **[MCP 계획]**)
- 수집 방법: 웹 검색 결과를 기반으로 정리. 링크 옆 표기
  - ✅ = 이번 검색 결과에서 직접 확인된 링크
  - ⚠️ = 검색에서 직접 확인하지 못하고 일반 지식으로 적은 공식 주소 (사용 전 접속 확인 필요)
- 라이선스/버전/기능 설명은 검색 요약 기준이므로, 상용 배포 전에 각 저장소의 LICENSE를 직접 확인할 것 (계획서 §46 의존성 관리 원칙).

---

## 0. 한눈에 보는 요약 (계획 단계별 추천)

| 계획 항목 | 가장 도움이 되는 자료 | 활용 포인트 |
|---|---|---|
| Block/Flow 모델 (OVPN §3~5) | Click Modular Router, VPP, DPDK graph, BESS | "Element/Node = Block, Edge = 연결" 구조의 선행 사례 |
| Flow Compiler / IR (OVPN §8~9) | P4 (논문+p4c), eBPF/XDP | 선언형 기술 → IR → 타깃별 컴파일 / 검증 후 실행 |
| Kernel Runtime 안전성 (OVPN §14, §22) | eBPF verifier, PREVAIL, ebpf-for-windows | "임의 코드 금지, 검증된 것만 커널 실행" 모델 |
| Parser Block 검증 (OVPN §16) | EverParse (3D) | 형식 검증된 zero-copy 파서 생성 |
| OpenVPN DCO 연동 (OVPN §13, §45) | ovpn-dco-win, Linux `ovpn` 모듈, OpenVPN 프로토콜 문서 | Adapter 경계 파악 |
| Replay Check Block | RFC 6479 | 비트 시프트 없는 anti-replay 윈도우 |
| Crypto Provider / KCMVP (OVPN §11) | Windows CNG(kernel), Linux Kernel Crypto API, KISA KCMVP | Provider 경계 설계 |
| Flow Editor (OVPN §27~) | Rete.js, React Flow, Blockly | 에디터 오픈소스 선택 |
| MCP Server (MCP §4~) | MCP 공식 스펙, MCP SDK | Tool/Resource/Prompt 설계 |
| AI 가드레일 (MCP §17, §28) | OWASP MCP Tool Poisoning, CSA 백서 | 권한 분리, 감사 로그, 승인 흐름 |
| Packet Simulation/Capture (MCP §14~15) | Wireshark OpenVPN dissector, Scapy | pcap 분석/테스트 패킷 생성 |
| AI 기반 프로토콜 분석/테스트 (MCP §13, §21) | ChatAFL, PSMBench, FlowFSM, NetConfEval | LLM로 프로토콜 구조/테스트 생성 |

---

## 1. Block/Flow 기반 패킷 처리 아키텍처 (선행 사례)

계획서의 "작은 Block을 Edge로 연결한 Flow"는 아래 시스템들과 구조가 거의 동일하다. 설계 검토 및 성능 기법(배치, prefetch 등) 참고용.

### 1.1 Click Modular Router (최우선 참고)
- 논문: *The Click Modular Router* (Kohler, Morris, Chen, Jannotti, Kaashoek, SOSP'99 / ACM TOCS 2000)
  - ✅ https://pdos.csail.mit.edu/archive/rtm/papers/click.pdf
  - ✅ https://vm-web.pdos.csail.mit.edu/papers/click:tocs00/paper.pdf
  - ✅ Kohler 박사논문: https://vm-web.pdos.csail.mit.edu/papers/click:kohler-phd/thesis.pdf
- 요점: 라우터 = element(정점)로 이루어진 방향 그래프, 패킷이 edge를 따라 흐름. push/pull 연결 개념, 설정 언어 존재.
- 계획 연결: Block Descriptor / Edge / Flow 정의(OVPN §5~6), 정적 설정 검증(OVPN §8).

### 1.2 FD.io VPP (Vector Packet Processing)
- ✅ 아키텍처 문서: https://s3-docs.fd.io/vpp/23.06/developer/corearchitecture/softwarearchitecture.html
- ✅ 그래프 설명: https://s3-docs.fd.io/vpp/24.02/aboutvpp/extensible.html
- 요점: 노드 그래프를 패킷 *벡터(최대 ~256개)* 단위로 순회 → I-cache/D-cache 효율. 플러그인으로 노드 추가/재배선.
- 계획 연결: OVPN Phase 6 (Batch processing, Block fusion, Per-CPU context) 최적화 설계.

### 1.3 DPDK Graph Library (`rte_graph`)
- ✅ https://doc.dpdk.org/guides/prog_guide/graph_lib.html
- 요점: 처리 함수를 node로 추상화하고 link로 연결, node의 init/process/fini 콜백, 런타임 edge 갱신/clone 지원.
- 계획 연결: Block API(`execute`, edge table) 및 `Direct dispatch` 설계 비교 대상.

### 1.4 BESS / NetBricks
- ✅ NetBricks (OSDI'16, Rust 기반 안전한 NFV, zero-copy software isolation): https://www.usenix.org/conference/osdi16/technical-sessions/presentation/panda
- ✅ BESS 관련 자료(Berkeley 기술보고서): https://www2.eecs.berkeley.edu/Pubs/TechRpts/2017/EECS-2017-141.html
- 계획 연결: 모듈형 파이프라인, 안전한 언어/타입 시스템으로 격리를 확보하는 접근 (Compiler 언어를 Rust로 할지 결정할 때 참고, OVPN §48).

---

## 2. DSL / Compiler / IR

### 2.1 P4
- ✅ 논문: *P4: Programming Protocol-Independent Packet Processors* (Bosshart et al.) — https://arxiv.org/pdf/1312.1719
- ⚠️ 언어 사양/컴파일러: https://p4.org/ , https://github.com/p4lang/p4c
- 요점: 프로토콜 독립 + 타깃 독립 + 현장 재구성. parser / match-action / control 구성, 하나의 선언을 여러 타깃으로 컴파일.
- 계획 연결: "같은 Flow를 User/Kernel/DCO로 컴파일"(OVPN §14, Phase 7), Block 타입 시스템(OVPN §37). p4c의 IR 구조를 Flow IR 설계 참고.

### 2.2 eBPF / XDP
- ✅ 논문: *The eXpress Data Path* (Høiland-Jørgensen et al., CoNEXT'18) — https://research.redhat.com/?p=22875 (PDF: https://courses.grainger.illinois.edu/ece598hpn/fa2023/papers/xdp.pdf)
- 요점: 커널이 안전한 실행 환경 제공, 바이트코드를 정적 분석 후 네이티브 변환, 단일 코어 최대 약 24Mpps.
- 계획 연결: "임의 native code 금지, 검증된 Flow/IR만 커널 실행"(OVPN §22, MCP §25)의 가장 가까운 실사례.

### 2.3 eBPF Verifier / PREVAIL / Windows
- ✅ eBPF for Windows (MIT, PREVAIL verifier + uBPF 사용): https://github.com/microsoft/ebpf-for-windows
- ✅ Windows 측 개요 블로그: https://opensource.microsoft.com/blog/2021/05/10/making-ebpf-work-on-windows
- ✅ eBPF verifier 안전성 논문(Brown Univ.): https://cs.brown.edu/~malte/pub/papers/2025-ebpf-verifier-safe.pdf
- ✅ *The eBPF Runtime in the Linux Kernel* (arXiv): https://www.arxiv.org/pdf/2409.07508
- ✅ BeePL (correct-by-compilation kernel extensions): https://arxiv.org/html/2507.09883v1
- 주의: 검색 결과에 PREVAIL 구버전의 검증기 결함 CVE가 보고되어 있음 → **검증기를 쓰더라도 Flow 자체 Validator를 이중으로 두는 것**이 안전(계획의 Validation 단계 유지 근거).
- 계획 연결: Windows Kernel Runtime(WDK)에서 Flow IR 실행기를 만들 때, ebpf-for-windows의 "검증 → JIT/인터프리터 → 커널 hook" 구조 참고.

### 2.4 EverParse (형식 검증 파서 생성)
- ✅ 논문: *EverParse: Verified Secure Zero-Copy Parsers for Authenticated Message Formats* — https://www.microsoft.com/en-us/research/publication/everparse/
- 요점: `.3d` 메시지 포맷 기술 → 메모리 안전·정합성이 증명된 zero-copy C 파서 생성. Windows 등 MS 코드베이스에서 실사용.
- 계획 연결: `PARSE_OPENVPN`, `PARSE_IP/UDP` 등 커널에서 도는 Parser Block을 직접 짜지 않고 생성/검증하는 옵션.

---

## 3. OpenVPN / DCO 연동

### 3.1 OpenVPN 프로토콜 문서
- ✅ 프로토콜 개요(공식 커뮤니티 문서): https://openvpn.net/community-docs/openvpn-protocol.html
- ✅ Doxygen 네트워크 프로토콜: https://build.openvpn.net/doxygen/network_protocol.html
- ✅ 패킷 헤더 소스(ssl_pkt.h): https://build.openvpn.net/doxygen/ssl__pkt_8h_source.html
- 핵심 사실: `P_DATA_V2` = `[5-bit opcode | 3-bit key_id][24-bit peer-id][payload]`. → `PARSE_OPENVPN`, `SESSION_LOOKUP(peer-id)`, `KEY_LOOKUP(key_id)` Block의 입출력 스키마에 그대로 반영 가능.

### 3.2 ovpn-dco-win (Windows DCO 드라이버)
- ✅ 저장소: https://github.com/OpenVPN/ovpn-dco-win
- ✅ DCO 개요 위키: https://community.openvpn.net/openvpn/wiki/DataChannelOffload
- ✅ 패치 시리즈 예시: https://patchwork.openvpn.net/patch/2483/
- 요점: 커널(Windows Kernel API)에서 crypto까지 처리. **client/p2p 모드만 지원, 서버 모드 미지원** (검색 요약 기준) → Adapter 범위 산정 시 반영.

### 3.3 Linux `ovpn` (DCO 커널 모듈, 메인라인)
- ✅ 공식 발표: https://blog.openvpn.net/openvpn-dco-added-to-linux-kernel-2025
- ✅ LWN: https://lwn.net/Articles/964387/
- ✅ Phoronix: https://phoronix.com/news/OpenVPN-Data-Channel-DCO-Soon
- 요점: 메인라인 Linux 6.16부터 포함(검색 요약 기준). Linux Kernel Runtime / DCO Adapter의 가장 좋은 구현 참조(peer 관리, key 설치, netlink 인터페이스 경계).
- ⚠️ 커널 소스 위치: `drivers/net/ovpn/` (kernel.org 트리에서 확인 필요)

### 3.4 Anti-Replay (REPLAY_CHECK Block)
- ✅ RFC 6479 *IPsec Anti-Replay Algorithm without Bit Shifting*: https://datatracker.ietf.org/doc/rfc6479/
- 요점: 비트 시프트 없이 윈도우 갱신 → 데이터 경로에서 lock/branch 최소화(OVPN Phase 6)에 적합.

### 3.5 Wireshark 디섹터 / pcap 도구
- ✅ Wireshark OpenVPN 위키: https://wiki.wireshark.org/OpenVPN
- ✅ 디섹터 추가 커밋 기록: https://gitea.osmocom.org/osmocom/wireshark/commit/42de9da8e3dafae85a7022f38f032a59b5bb77b4
- ✅ Scapy 새 프로토콜 레이어 작성법: https://scapy.readthedocs.io/en/stable/build_dissect.html
- ✅ pyopenvpn (Scapy 연동 파이썬 OpenVPN 구현, 커뮤니티): https://github.com/clement10601/pyopenvpn
- 계획 연결: OVPN §20 Regression Test(원본 OpenVPN vs Flow 캡처 비교), MCP §14~15 Packet Generator / Capture 분석의 기준 도구(golden reference).

---

## 4. Crypto Provider / 키 관리

- ✅ Windows CNG 기능 개요: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-features
- ✅ Windows 커널 암호 라이브러리(cng.sys) FIPS 인증 정보: https://sec-certs.org/fips/id/4766
- ✅ 커널 모드에서 CNG 키 저장소 제한 논의(NCrypt는 커널 불가): https://community.osr.com/t/re-cng-key-storage-support-in-kernel-mode/53660
- ✅ Linux Kernel Crypto API (AEAD 포함): https://docs.kernel.org/6.14/crypto/index.html
- ✅ KCMVP 관련 기사 (KISA 암호모듈 검증 컨설팅): https://byline.network/2025/03/24-415
- ⚠️ KISA 암호모듈검증(KCMVP) 공식 페이지: https://seed.kisa.or.kr (사용 전 확인)
- 계획 연결: `CRYPTO_PROVIDER` 인터페이스(OVPN §11), Key Reference ↔ Key Material 분리(OVPN §10). 커널에서는 NCrypt 키 저장소를 못 쓰므로 **Key Manager를 자체 보유**해야 한다는 근거.

### 4.1 VPN 프로토콜 형식 검증 (Flow Validator의 Protocol/Security 검증 규칙 참고)
- ✅ WireGuard 심볼릭 분석(NDSS'24): https://www.ndss-symposium.org/ndss-paper/a-unified-symbolic-analysis-of-wireguard/
- ✅ WireGuard 형식 검증 논문 모음: https://WWW.WIREGUARD.COM/papers/wireguard-formal-verification.pdf
- ✅ WireGuard 계산적 증명(CryptoVerif): https://WWW.WIREGUARD.COM/papers/lipp-computational-2018.pdf
- 계획 연결: 향후 WireGuard 확장(OVPN §23), 보안 검증 규칙(MCP §11) 설계 시 형식 모델 참고.

---

## 5. Visual Flow Editor (OVPN §27~§42)

| 후보 | 링크 | 라이선스/특이사항 |
|---|---|---|
| Rete.js (1순위) | ✅ npm 엔진: https://www.npmjs.com/package/rete-engine / ✅ README: https://cdn.jsdelivr.net/npm/rete@2.0.6/README.md / ⚠️ https://retejs.org/ , https://github.com/retejs/rete | 검색에서 확인된 core 및 area/context-menu/auto-arrange/engine/minimap/react 플러그인은 MIT. 단, 유료/별도 라이선스 플러그인 여부는 **직접 확인 필요**(계획서 §28 주의사항) |
| React Flow (xyflow) | ⚠️ https://reactflow.dev/ , https://github.com/xyflow/xyflow | MIT (계획서 §29 기준) |
| Blockly | ⚠️ https://developers.google.com/blockly , https://github.com/RaspberryPiFoundation/blockly | Apache 2.0 (계획서 §30 기준) — Expression 편집 보조용 |

- Rete.js 플러그인 라이선스 확인용: ✅ https://licenses.dev/npm/rete-minimap-plugin/2.0.2 , ✅ https://classic.yarnpkg.com/en/package/rete-area-plugin
- 권장: 계획서 Phase 0 PoC에서 Rete.js와 React Flow를 동일한 `openvpn_rx.json`으로 구현해 비교. 연결 검증(Port Type)·Named Port(yes/no/error) 지원 여부를 체크리스트로 사용.

---

## 6. MCP (Model Context Protocol) — [MCP 계획] 구현 근거

### 6.1 스펙/문서
- ✅ MCP 스펙 인덱스(2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/index.md
- ✅ 스펙 미러/요약: https://modelcontextprotocol.info/specification/2025-11-25/
- ⚠️ 공식 SDK: https://github.com/modelcontextprotocol (TypeScript / Python / C# / Java 등) — MCP Server 구현 시 사용
- 스펙 핵심: Resources / Prompts / Tools 구분, **Tool은 임의 코드 실행에 준하므로 호출 전 사용자 동의 필수**.
- 계획 연결
  - Block/Flow Resource(`protocol://blocks/...`) → MCP **Resources**
  - `flow.create/validate/compile` → MCP **Tools**
  - `/protocol-review` 등 → MCP **Prompts**
  - Level 3(Deploy) Tool에 대한 승인 → 스펙의 user consent / Elicitation 개념 활용

### 6.2 MCP 보안 (가드레일, 감사, RBAC)
- ✅ OWASP MCP Tool Poisoning: https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
- ✅ CSA 백서 *MCP Security: Tool Poisoning and the Confused Deputy Problem*: https://labs.cloudsecurityalliance.org/research-rb/csa-whitepaper-mcp-security-agentic-attack-surface-20260516/
- ✅ 관련 논문(arXiv): https://arxiv.org/pdf/2603.22489
- 권고사항 요약(검색 결과): ① Tool 정의를 공급망 산출물로 취급(버전·승인·무결성 검증) ② 토큰 passthrough 금지 + 호출 단위 최소권한 ③ 정책 강제는 **Tool 호출 경계**에서 ④ append-only 감사 로그 ⑤ 고권한 Tool은 외부 MCP 서버가 닿지 않는 별도 컨텍스트에서 실행
- 계획 연결: MCP §17(권한 Level 0~3), §18(Approval), §20(Audit), §28(Guardrail)과 거의 일치 → 설계가 업계 권고와 정합함을 근거로 활용. 추가로 **Flow 내용에 포함된 문자열(블록 설명, pcap 내 payload)이 프롬프트 인젝션 경로가 될 수 있음**을 위협 모델에 포함 권장.

---

## 7. LLM × 프로토콜 엔지니어링 연구 (AI Copilot, 테스트 생성)

| 주제 | 자료 | 계획 연결 |
|---|---|---|
| LLM 가이드 프로토콜 퍼징 | ✅ ChatAFL (NDSS'24): https://www.ndss-symposium.org/ndss-paper/large-language-model-guided-protocol-Fuzzing / 논문 PDF ✅ https://www.ndss-symposium.org/wp-content/uploads/2024-556-paper.pdf / ✅ 코드 https://github.com/liuxiaoxinxinxin/ChatAFL | LLM이 프로토콜 문법·메시지 시퀀스 생성 → MCP §13 자동 테스트(Malformed/Invalid 패킷), Flow 퍼징 |
| RFC → 상태머신 추출 | ✅ PSMBench (NeurIPS'25): https://papers.nips.cc/paper_files/paper/2025/hash/521bd9583b3a39e92f662ee57e81e5ce-Abstract-Datasets_and_Benchmarks_Track.html / ✅ FlowFSM: https://arxiv.org/pdf/2507.11222 | 자연어 요구 → Flow 초안(MCP §9), 프로토콜 사양 → Block/Flow 변환 평가 방법 |
| LLM 네트워크 설정 합성 | ✅ NetConfEval (CoNEXT'24): https://research.redhat.com/blog/publication/can-llms-facilitate-network-configuration/ / ✅ NetConfArena(폐루프 벤치마크): https://arxiv.org/pdf/2608.23179 | "자연어 → 형식 사양/API 호출 → 검증" 파이프라인. LLM이 저수준 설정을 직접 쓰기보다 **형식 중간표현을 생성**하는 쪽이 정확하다는 연구 방향과 MCP 계획이 일치 |
| 네트워크 LLM 벤치마크(IETF) | ✅ https://www.ietf.org/ietf-ftp/internet-drafts/draft-cui-nmrg-llm-benchmark-02.txt | MVP 성공 기준(MCP §33)을 측정 가능한 벤치마크로 만들 때 참고 |

- 활용 제안: MCP MVP 완료 기준(자연어 → Flow → 테스트 통과)을 NetConfEval/PSMBench 방식으로 **정량 평가 세트**(예: 자연어 요구 N개 → 유효 Flow 비율, 검증 통과율, 테스트 통과율)로 만들 것.

---

## 8. 계획서 항목별 추가 권장 사항 (조사 결과 기반)

1. **Flow IR 설계**: P4 컴파일러(p4c)의 "front-end → mid-end → back-end" 분리와 eBPF의 "검증 가능한 바이트코드" 모델을 결합. Runtime IR을 *제한된 명령 집합 + 정적 검증 가능*하게 정의하면 Kernel 신뢰 경계가 명확해짐.
2. **커널 안전성**: Kernel에 Flow IR 해석기를 넣는 경우 Validator를 컴파일 시점(user)과 로드 시점(kernel) 양쪽에 두기. eBPF 검증기 취약점 사례가 이중 검증의 근거.
3. **Parser Block**: 수작업 대신 EverParse(3D)로 `P_DATA_V2`, `P_CONTROL` 등 포맷을 기술하고 C 파서 자동 생성 검토.
4. **성능 최적화**: VPP/DPDK graph의 벡터(배치) 처리와 노드 단위 cache 지역성을 Phase 6의 "Block fusion / Batch" 설계에 반영.
5. **DCO 범위 확인**: ovpn-dco-win은 서버 모드 미지원 → MVP는 client/p2p 데이터 경로로 한정하거나, Linux `ovpn` 모듈을 서버 모드 참조로 병행.
6. **회귀 테스트 자산**: Wireshark OpenVPN 디섹터를 정답(oracle)으로, Scapy로 테스트 패킷 생성기 구축.
7. **MCP 위협 모델**: tool poisoning / confused deputy / 프롬프트 인젝션(패킷·Flow 메타데이터 경유)을 별도 위협 항목으로 추가.
8. **의존성 관리(OVPN §46)**: 위 목록의 모든 항목에 대해 Name/Version/License/SPDX/Hash를 `THIRD_PARTY.md`로 기록 (특히 Rete.js 플러그인, ebpf-for-windows 하위 모듈, EverParse).

---

## 9. 한계 및 후속 확인 필요 사항

- 일부 항목(⚠️)은 검색으로 직접 검증하지 못했으므로 접속/라이선스 확인이 필요.
- Linux `ovpn` 메인라인 포함 버전(6.16), ovpn-dco-win의 서버 모드 미지원 등은 검색 요약 기준이며, 최신 상태는 각 공식 저장소/릴리스 노트로 재확인할 것.
- 위 논문 중 2025~2026년 자료(PSMBench, NetConfArena, MCP 보안 논문 등)는 검색 스니펫 기준으로 정리했으며 본문 전체를 읽고 검증한 것은 아님.

---

## 10. NAT Traversal (PM-2b, `docs/PM2_NAT_Traversal_Scope.md`)

추가일: 2026-10-06. 아래 링크는 일반 지식으로 적은 공식 주소다(⚠️, 사용 전 접속·라이선스 확인). 구현 근거는 RFC로 한정한다(D-010). 오픈소스는 상호운용 상대·동작 비교용으로만 쓰고 코드를 복사하지 않는다.

### 10.1 표준

| RFC | 내용 | 쓰는 곳 |
|---|---|---|
| RFC 8489 | STUN | N1 코덱, N3 클라이언트 |
| RFC 5769 | STUN 테스트 벡터 | N1 골든 |
| RFC 4787 | NAT의 UDP 동작 요구사항(매핑·필터링 용어) | N2 시뮬레이터, 용어 기준 |
| RFC 5780 | STUN을 이용한 NAT 동작 탐지 | N3 |
| RFC 5128 | NAT 너머 P2P 통신 기법 현황(hole punching) | N4 |
| RFC 8656 | TURN | N5 |
| RFC 6062 | TURN TCP 할당 | 후속(TCP) |
| RFC 8445 | ICE | 후속 |
| RFC 7675 | STUN consent freshness | 위협 모델 §8.1 |
| RFC 7983 | 같은 포트 다중화(첫 바이트 구분) | STUN/OpenVPN 구분 Block |
| RFC 6886 / RFC 6887 | NAT-PMP / PCP | 후속 |
| RFC 6888 | CGN 요구사항 | 랩 토폴로지(이중 NAT) |

### 10.2 오픈소스 (상호운용 상대·비교용)

| 이름 | 용도 | 라이선스(확인 필요) | 링크 |
|---|---|---|---|
| coturn | STUN/TURN 서버, **수정 없이 상호운용 상대**로 사용 | BSD-3-Clause | ⚠️ https://github.com/coturn/coturn |
| Stuntman | RFC 5780 동작 탐지 서버/클라이언트 (동작 비교) | Apache-2.0 | ⚠️ https://github.com/jselbie/stunserver |
| libjuice | 경량 ICE/STUN/TURN (동작 비교) | MPL-2.0 | ⚠️ https://github.com/paullouisageneau/libjuice |
| libnice | ICE (GLib) (동작 비교) | LGPL-2.1 / MPL-1.1 | ⚠️ https://gitlab.freedesktop.org/libnice/libnice |
| pion (ice/stun/turn) | Go 구현, 테스트 피어 후보 | MIT | ⚠️ https://github.com/pion |
| miniupnpc | UPnP IGD 클라이언트 (후속 비교) | BSD-3-Clause | ⚠️ https://github.com/miniupnp/miniupnp |
