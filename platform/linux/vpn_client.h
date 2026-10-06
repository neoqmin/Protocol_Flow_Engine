#pragma once
#include <netinet/in.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "pf/control_client.h"
#include "pf/fallback_connector.h"
#include "pf/transport.h"

namespace pf::pal {

struct VpnOptions {
    sockaddr_in server{};                 // UDP endpoint
    sockaddr_in tcp_server{};             // TCP endpoint (often the same address and port as `server`)
    FallbackPolicy policy{{TransportKind::Udp}};   // transports to try, in order (connect_timeout_ms = per attempt)
    FallbackConnector::TransportFactory transport_factory;   // optional override (tests); default: Linux UDP/TCP
    ControlClientConfig control;          // tls-crypt key, PKI; `keys` is set by the client
    std::string tun_name;                 // TUN name hint ("" = kernel's choice)
    unsigned mtu_cap = 1400;              // TUN MTU = min(pushed tun-mtu, mtu_cap): outer UDP/IP + DATA_V2 overhead must fit the path
    int duration_s = 0;                   // 0 = until stopped; otherwise stop cleanly after this long (counted from tunnel up)
    int stats_interval_s = 60;            // periodic "stats:" lines
    bool install_routes = true;           // routes pushed by the server
};

// 0 clean stop; 2 the session was lost or never came up (control failure, no transport worked, ping-restart): the
// supervisor (systemd Restart=, a wrapper loop) reconnects (D-029); 4 usage / configuration / device error.
enum class VpnExit : int { Ok = 0, SessionLost = 2, ConfigError = 4 };

// Linux VPN client: transport fallback (UDP -> TCP ...) -> TunnelSession (control + data plane + keepalive) <-> TUN,
// in one single-threaded poll() loop whose timeout is bounded by the next timer.
class VpnClient {
public:
    // `stop` is polled between iterations (set from a signal handler).
    VpnExit run(VpnOptions opts, const std::atomic<bool>& stop);
    const std::string& error() const { return error_; }
    TransportKind transport_kind() const { return kind_; }            // which transport carried the session
    const std::vector<FallbackConnector::AttemptRecord>& attempts() const { return attempts_; }

private:
    std::string error_;
    TransportKind kind_ = TransportKind::Udp;
    std::vector<FallbackConnector::AttemptRecord> attempts_;
};

}  // namespace pf::pal
