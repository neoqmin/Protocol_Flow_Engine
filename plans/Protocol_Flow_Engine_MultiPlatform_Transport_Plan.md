# Protocol Flow Engine — 멀티 플랫폼 / Device·Transport 확장 계획

## 1. 목적

1. Windows, Linux, Android, macOS, iOS에서 동일한 Flow 정의로 동작한다.
2. TUN(L3)과 TAP(L2)을 모두 지원하되, 플랫폼 제약을 명시적으로 처리한다.
3. 직접 연결이 불가능한 서버를 위해 Transport를 UDP 외에 TCP, 프록시, 릴레이로 확장한다.
4. 모든 기능은 TDD로 개발한다 (`tests/README.md` 참고).

> 본 문서의 우회 기능은 사용자가 관리하는 네트워크에서 해당 네트워크의 정책에 맞게
> 사용하는 것을 전제로 한다.

---

# 2. 핵심 원칙: Device와 Transport는 독립 축

```text
Device (무엇을 터널에 넣는가)     : TUN(L3) | TAP(L2)
Transport (어떻게 실어 나르는가)  : UDP | TCP | TCP via Proxy | Relay
```

TUN/TAP은 방화벽을 우회하지 않는다. 우회는 Transport 계층에서 해결한다.
두 축은 Flow에서 서로 독립적으로 선택한다.

```text
Device Block -> Encap -> Crypto -> Transport Block
                                         ^
                                 Fallback Policy
```

---

# 3. 플랫폼 지원 매트릭스

| 플랫폼 | Device 구현 | TUN | TAP | Kernel Runtime | 비고 |
|---|---|---|---|---|---|
| Linux | `/dev/net/tun` | O | O | O (DCO) | 1순위 |
| Windows | Wintun / tap-windows6 | O | O | O (ovpn-dco-win) | 2순위. TAP은 유지보수 모드 |
| Android | `VpnService` fd (JNI) | O | X | X | L3 전용 |
| macOS | utun (Network Extension) | O | X | X | kext 비권장 |
| iOS | `NEPacketTunnelProvider` | O | X | X | 확장 메모리 한도 약 50MB |

규칙:
- 기본값은 TUN. TAP은 L2 브리지가 필요한 경우에만 사용한다.
- 지원하지 않는 모드를 요청하면 (a) `allow_fallback=true`이면 TUN으로 대체,
  (b) 아니면 명시적 오류를 반환한다. 조용히 무시하지 않는다.
- 구현: `core/include/pf/device.h` (`device_supported`, `resolve_device`).

---

# 4. 플랫폼 추상화 계층 (PAL)

| 영역 | 추상화 대상 |
|---|---|
| Device | Linux tun, Windows Wintun/TAP, Apple utun, Android VpnService fd |
| 소켓/이벤트 루프 | epoll, IOCP, kqueue |
| 시간, 난수, 스레드 | 공통 인터페이스 |
| Key 저장 | Keychain, Android Keystore, DPAPI/CNG, Linux keyring |
| Crypto Provider | OpenSSL/BoringSSL 기본, 플랫폼별 교체 가능 |

원칙:
- Flow / Compiler / Block / Crypto 코어는 플랫폼 독립 코드로 유지한다.
- Kernel Runtime은 Linux/Windows 전용 최적화 옵션이다 (계획서 §14, Phase 7).
- 모바일은 유저 모드 Runtime만 사용한다.

---

# 5. Transport 설계

## 5.1 Transport 종류

| Transport | 용도 |
|---|---|
| UDP | 기본. 성능 최우선 |
| TCP (예: 443) | UDP가 차단된 환경. TCP-over-TCP 성능 저하 있음 |
| TCP via Proxy | HTTP CONNECT / SOCKS5만 허용되는 환경 |
| Relay | 서버가 인바운드를 받을 수 없는 환경 |

## 5.2 Fallback Policy

기본 순서:

```text
UDP -> TCP -> TCP via Proxy -> Relay
```

- 연결 실패(타임아웃, 거부)를 보고하면 다음 Transport로 넘어간다.
- 모든 Transport를 소진하면 오류로 종료한다 (`exhausted()`).
- 프록시만 허용되는 환경용 `proxy_only` 정책을 별도로 제공한다.
- 구현: `core/include/pf/transport_fallback.h` (순수 로직, I/O 없음).
- 정책은 Flow의 Policy Block으로 노출하여 DSL/GUI에서 설정할 수 있게 한다 (후속).

## 5.3 직접 연결이 불가능한 서버

| 상황 | 대응 |
|---|---|
| UDP 차단 | TCP 443 폴백 |
| 서버가 인바운드 차단 | Reverse Connect (서버가 먼저 외부로 연결) 또는 Relay |
| 양쪽 모두 NAT 뒤 | UDP Hole Punching 시도, 실패 시 Relay |
| 프록시만 허용 | HTTP CONNECT / SOCKS5 |

## 5.4 Relay (미정 사항)

Relay는 암호화된 패킷만 중계하며 복호화 키를 갖지 않는다.
**구현 방식은 미확정이다.** 후보:

1. 기존 도구 활용 (OpenVPN `--port-share`, 외부 릴레이)
2. 자체 Relay 서버 (Phase 후반)

초기에는 Transport 인터페이스만 정의하고 Relay 구현은 후속 결정한다.

---

# 6. TAP 전용 처리

TAP은 L2 프레임을 다루므로 TUN에 없는 Block이 필요하다.

```text
ETH_PARSE, ARP_HANDLE, BROADCAST_FILTER, MAC_LEARNING(브리지 시)
```

이 Block은 `device_layer == 2`인 Flow에서만 배치할 수 있도록 Validation에서 검사한다.

---

# 7. 빌드 / CI

- 빌드: CMake. 플랫폼은 toolchain 파일로 크로스 컴파일한다 (Android NDK, Xcode).
- CI 매트릭스: 현재 Linux / Windows / macOS (`.github/workflows/ci.yml`).
- 후속: Android(NDK) / iOS(Xcode) 빌드 잡 추가, 모바일은 빌드 검증 중심.
- 구현 언어는 C++17 (계획서 §25). Rust 병행 여부는 미결정.

---

# 8. TDD 개발 단계

각 단계는 테스트를 먼저 작성한다.

| 단계 | 내용 | 테스트 위치 |
|---|---|---|
| M0 (완료) | Device 지원 매트릭스, Fallback Policy | `tests/unit/test_device_support.cpp`, `test_transport_fallback.cpp` |
| M1 | Transport 인터페이스 + UDP(loopback) | `tests/unit`, `tests/flow` |
| M2 | TCP Transport (프레이밍 포함) | `tests/unit`, `tests/flow` |
| M3 | Fallback 통합: 가짜 Transport로 UDP 차단 시나리오 재현 | `tests/flow` |
| M4 | HTTP CONNECT / SOCKS5 | `tests/flow` |
| M5 | PAL Device: Linux TUN/TAP | `tests/protocol` (root 필요, opt-in) |
| M6 | Windows Wintun, Android/macOS/iOS 어댑터 | 플랫폼별 CI |
| M7 | Relay / Hole Punching | `tests/protocol` |
| M8 | TAP 전용 Block (ETH/ARP) + Validation | `tests/unit`, `tests/regression` |

회귀: TCP 프레이밍, 프록시 핸드셰이크 등은 golden vector로 `tests/regression/golden/`에 누적한다.

---

# 9. MVP 범위

MVP는 오픈소스 수정이 필요 없는 항목만 포함한다 (`docs/Upstream_Extension_Policy.md` §9).

| 단계 | MVP 포함 | 비고 |
|---|---|---|
| M0~M4 | O | Device 매트릭스, Fallback, UDP/TCP/프록시 Transport (모두 자체 구현) |
| M5, M6 | O | PAL Device: OS 공개 API 사용 (Wintun은 수정 없는 배포 바이너리) |
| M7 Relay / Hole Punching | 자체 구현 시에만 | 기존 도구를 **수정 없이** 쓰는 경우는 가능, 패치가 필요하면 Post-MVP |
| M8 TAP 전용 Block | O | |
| Kernel Runtime / DCO 연동 | X (Post-MVP) | OpenVPN 계획서 §25 참고 |

---

# 10. 미결정 사항

1. Relay를 자체 구현할지 기존 도구를 쓸지
2. 구현 언어: C++17 고정 vs Rust 병행
3. 모바일 TLS/암호 라이브러리 선택 (BoringSSL 등)
4. 우선 지원 순서 (제안: Linux -> Windows -> Android -> macOS -> iOS)
