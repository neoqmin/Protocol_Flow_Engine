# Tests

TDD 원칙: **실패하는 테스트를 먼저 작성(Red) → 최소 구현(Green) → 리팩터링**.
테스트 없는 Block/기능은 머지하지 않는다.

## 구조

| 폴더 | 목적 | CTest label |
|---|---|---|
| `unit/` | Block 단위 테스트 (Parse, Replay, Crypto …) | `unit` |
| `flow/` | RX/TX/Control/Error/Timeout Flow 테스트 | `flow` |
| `protocol/` | 실제 OpenVPN Client/Server 상호운용 (`-DPF_PROTOCOL_TESTS=ON`, root): `run_interop.sh`(제어·데이터·재협상), `run_vpn_tunnel.sh`(TUN 터널 ping, A4) | `protocol` |
| `pal/` | PAL 실제 소켓 테스트(127.0.0.1, root 불필요, Linux) | `unit` |
| `regression/` | Golden vector / 기존 OpenVPN 캡처와의 비교 | `regression` |
| `performance/` | packet path 벤치마크 | `performance` |
| `support/` | 의존성 없는 테스트 하니스 (모든 플랫폼 이식 가능) | - |

`test_*.cpp` 파일은 해당 폴더에 추가하면 CMake가 자동으로 수집한다.

## 실행

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure      # 전체
ctest --test-dir build -L unit                  # 라벨별
./build/tests/pf_unit_tests header_data_v2      # 이름 필터
```

## 회귀 테스트 규칙

- `regression/golden/*.golden`의 기존 줄은 **기대값을 바꾸지 않는다.** 바꿔야 한다면 리뷰에서 사유를 명시한다.
- 버그를 고칠 때는 먼저 재현하는 golden vector(또는 unit test)를 추가한다.
- 원본 OpenVPN 캡처 vs Flow Engine 캡처 비교(계획서 §20)는 이 폴더에 vector로 누적한다.

## 작성 규칙

- **테스트 파일 안의 보조 타입/구조체는 익명 네임스페이스에 둔다.** 같은 실행 파일에 묶이는 여러 `test_*.cpp`가 같은 이름(`Vec` 등)의 다른 구조체를 정의하면 ODR 위반으로 링커가 소멸자를 잘못 합쳐 크래시가 난다(실제로 한 번 겪음).
- OpenSSL이 필요한 테스트는 파일명을 `*_openssl.cpp`로 한다(OpenSSL이 없는 빌드에서는 자동 제외).
- 골든 벡터의 키는 일회용 테스트 키다. 개인 키/실제 자격증명은 어떤 경우에도 커밋하지 않는다.
