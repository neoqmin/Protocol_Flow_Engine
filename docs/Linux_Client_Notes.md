# Linux 클라이언트 (A4) 설계 노트

MVP-A의 마지막 단계: A3까지 만든 제어/데이터 채널을 **실제 UDP 소켓과 TUN 장치**에 연결해, 수정 없는 OpenVPN 2.6 서버를
통해 IP 트래픽(ping)이 오가게 한다. 결정 기록은 `docs/DECISIONS.md` D-029.

## 1. 구성

```
              ┌──────────────────────────── core/ (플랫폼 독립, I/O·시계 없음) ───────────────────────────┐
 UDP 소켓 ──► │ TunnelSession::on_datagram ─► ControlClient (제어 패킷)                                    │
 (PAL)        │                              └► RX Flow (DATA_V2 복호) ─► 핑이면 keepalive, IP면 TUN으로    │ ──► TUN 장치 (PAL)
 TUN 장치 ──► │ TunnelSession::encapsulate ─► TX Flow (DATA_V2 암호) ─► 와이어 데이터그램                   │ ──► UDP 소켓
              │ TunnelSession::poll        ─► 제어 재전송/ACK/재협상 + KeepaliveTimer(핑, ping-restart)      │
              └────────────────────────────────────────────────────────────────────────────────────────────┘
```

| 구성요소 | 위치 | 역할 |
|---|---|---|
| `TunnelSession` | `core/include/pf/tunnel_session.h`, `core/src/crypto/tunnel_session.cpp` | ControlClient + 데이터 Flow(RX/TX) + KeepaliveTimer를 묶는 **sans-I/O** 계층. 소켓·시계를 모른다 |
| `pal::UdpSocket`, `pal::TunDevice` | `platform/linux/` | Linux 전용(PAL). connected UDP(논블로킹), `/dev/net/tun`(`IFF_TUN\|IFF_NO_PI`), 주소/넷마스크/MTU/up, 푸시된 라우트(ioctl) |
| `pf_client` | `tools/pf_client/main.cpp` | `poll()` 이벤트 루프, 시그널 처리, 통계 출력 |
| `tests/flow/test_tunnel_session_openssl.cpp` | | 가짜 서버로 TunnelSession 단위 검증 (변이 5개 검출 확인) |
| `tests/protocol/run_tunnel.sh` | | 실제 OpenVPN 서버 + 네임스페이스 + 실제 TUN으로 터널 ping |

코어는 PAL을 참조하지 않는다(`platform/linux`는 `pf_client`만 링크). 다른 플랫폼은 같은 `TunnelSession` 위에 자기 PAL을 붙인다(PM-1).

## 2. 동작 규칙

- **수신 분류**: 제어 패킷은 ControlClient가 소비. 그 외는 RX Flow(파싱→키 조회→replay 검사→복호→replay 확정)를 통과해야 하며, 실패는 `rx_dropped`로 집계하고 TUN에는 아무것도 쓰지 않는다. 인증된 평문이 **핑이면** keepalive, **IP(버전 4/6)이면** TUN으로, 그 외(예: OCC)는 `rx_not_ip`로 집계 후 폐기.
- **연결 전 트래픽**: Established 전에는 TX 거부(`tx_before_established`), 데이터 패킷은 폐기. TUN은 PUSH_REPLY를 받은 뒤에야 만들고 설정한다.
- **TX**: 헤더의 key_id는 `ControlClient::tx_key_id()`(재협상 직후 새 키로 전환), peer-id는 PUSH_REPLY의 값. 평문 최대 65535바이트, 빈 패킷은 거부.
- **keepalive**: 푸시된 `ping N` / `ping-restart M`. 송신(데이터·제어 모두)이 있으면 핑 타이머가 미뤄지고, 인증된 수신(제어·데이터)이 있으면 ping-restart 타이머가 갱신된다. 위조 패킷은 타이머를 갱신하지 못한다(인증 후에만).
- **TUN 설정**: `ifconfig` 주소/넷마스크(subnet 토폴로지), MTU = `min(푸시된 tun-mtu, --mtu(기본 1400))`, 푸시된 `route`는 게이트웨이(없으면 `route-gateway`) 경유로 추가. 연결된 서브넷 라우트는 커널이 만든다. 기본 경로 변경(redirect-gateway)·DNS는 MVP 범위 밖.
- **MTU 1400 기본값**: 푸시된 tun-mtu 1500 + 24바이트 오버헤드 + UDP/IP 헤더가 링크 MTU(1500)를 넘어 IP 단편화되는 것을 피한다. 서버→클라이언트 패킷은 크기와 무관하게 받는다.
- **종료/재연결 정책**: SIGINT/SIGTERM → 정상 종료(TUN 제거). 제어 채널 실패 또는 ping-restart 타임아웃 → **종료 코드 2로 종료**. 재연결은 상위 감독자(systemd `Restart=` 등)가 맡는다(D-029).

## 3. 실행

```sh
cmake -S . -B build -G Ninja -DPF_WITH_OPENSSL=ON && cmake --build build
sudo build/pf_client --server <ip:port> --tls-crypt tc.key --ca ca.crt --cert client.crt --key client.key \
     [--tun-name pf0] [--mtu 1400] [--duration SEC] [--stats-interval SEC] [--reneg-seconds N]
```
root(또는 `CAP_NET_ADMIN`)가 필요하다. 자동 테스트: `ctest --test-dir build -L protocol` (pf_interop_openvpn + pf_tunnel_openvpn, 둘은 같은
네임스페이스 이름을 쓰므로 `RESOURCE_LOCK`으로 직렬화).

## 4. 검증 결과

| 시나리오 | 내용 | 결과 |
|---|---|---|
| `ping` | 터널 주소/라우트 설치, ping 20회 + 1300바이트 ping, 손실 0% | 통과 |
| `reneg-load` | 서버가 2초마다 재협상(≥8회, key_id 7→1 순환)하는 동안 연속 ping, 손실 0% | 통과 |
| `soak` (옵트인) | `PF_ONLY=soak PF_SOAK_SECONDS=3700`: 서버 기본 `reneg-sec 3600`, 1초 간격 ping | **통과**: 3700초 연결, 재협상 1회(key_id 0→1, 실패 0), 클라이언트 송수신 패킷 3622/3622(손실 0), rx_dropped=0, unknown_key_id=0 |

## 5. 알려진 한계 / 다음

- 단일 서버 주소(IPv4 리터럴) 하나, DNS 해석·IPv6 transport 없음.
- 푸시 옵션 중 `redirect-gateway`, `dhcp-option`(DNS), `route-ipv6`은 무시(미지원 옵션은 `PushReply::unknown_options`에 보존).
- explicit-exit-notify 미지원: 종료 시 서버는 `ping-restart`/keepalive 타임아웃으로 세션을 정리한다.
- 성능 기준선(OpenVPN 2.6 대비)은 MVP-A 공통 종료 조건으로 남아 있다.
