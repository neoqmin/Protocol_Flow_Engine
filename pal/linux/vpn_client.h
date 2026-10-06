#pragma once
#include <netinet/in.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include <memory>

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
    std::string dev_name;                 // TUN name hint ("" = kernel's choice)
    int mtu = 1400;                       // TUN MTU (outer UDP/IP + DATA_V2 overhead must fit the path MTU)
    int duration_s = 0;                   // 0 = until stopped; otherwise stop cleanly after this long
    int stats_interval_s = 0;             // 0 = no periodic stats lines
    bool install_routes = true;           // routes pushed by the server
};

enum class VpnExit : int { Ok = 0, ControlFailed = 2, PingRestart = 5, DeviceError = 6, ConfigError = 4 };

struct VpnStats {
    uint64_t tun_to_net_packets = 0, tun_to_net_bytes = 0;
    uint64_t net_to_tun_packets = 0, net_to_tun_bytes = 0;
    uint64_t pings_sent = 0, pings_received = 0;
    uint64_t rx_dropped = 0;              // failed authentication / replay / unknown key
    uint64_t rx_other = 0;                // authenticated, not IP and not a ping (not delivered)
    uint64_t tx_failed = 0;
};

// Linux VPN client: UDP socket + TUN + ControlClient + DataPath + KeepaliveTimer in one poll() loop.
// Single-threaded; the only blocking call is poll() with a timeout bounded by the next timer.
class VpnClient {
public:
    // `stop` is polled between iterations (set from a signal handler).
    VpnExit run(VpnOptions opts, const std::atomic<bool>& stop);
    const VpnStats& stats() const { return stats_; }
    const ControlClient::Stats& control_stats() const { return control_stats_; }
    const std::string& error() const { return error_; }
    // Which transport carried the session (valid after the control channel came up).
    TransportKind transport_kind() const { return kind_; }
    const std::vector<FallbackConnector::AttemptRecord>& attempts() const { return attempts_; }

private:
    VpnStats stats_;
    ControlClient::Stats control_stats_;
    std::string error_;
    TransportKind kind_ = TransportKind::Udp;
    std::vector<FallbackConnector::AttemptRecord> attempts_;
};

}  // namespace pf::pal
