#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pf {

// Control messages sent as NUL-terminated strings inside the TLS session after key exchange.
enum class ControlMessageKind { PushRequest, PushReply, AuthFailed, Restart, Halt, Info, Unknown };

// Matches the leading keyword exactly (followed by end, ',' or - for INFO - '_').
ControlMessageKind classify_control_message(std::string_view msg);

struct PushedRoute {
    uint32_t network = 0;
    uint32_t netmask = 0;
    bool has_gateway = false;
    uint32_t gateway = 0;
};

// Parsed "PUSH_REPLY,opt,opt,...". Addresses are IPv4 in host byte order.
// Observed from OpenVPN 2.6.19:
//   PUSH_REPLY,route-gateway 10.77.0.1,topology subnet,ping 2,ping-restart 8,ifconfig 10.77.0.2 255.255.255.0,
//   peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500
struct PushReply {
    bool has_ifconfig = false;
    uint32_t ifconfig_ip = 0;
    uint32_t ifconfig_netmask = 0;           // second ifconfig argument (netmask with topology subnet)
    uint32_t route_gateway = 0;
    std::string topology;
    uint32_t ping_seconds = 0;
    uint32_t ping_restart_seconds = 0;
    bool has_peer_id = false;
    uint32_t peer_id = 0;                    // 24 bit
    std::string cipher;
    uint32_t tun_mtu = 0;
    std::vector<std::string> protocol_flags; // e.g. cc-exit, tls-ekm, dyn-tls-crypt
    std::string key_derivation;              // value of the "key-derivation" option, if pushed
    std::vector<PushedRoute> routes;
    std::vector<std::string> unknown_options;// everything we do not interpret, verbatim, in order

    bool key_derivation_tls_ekm() const;
    // MVP profile (D-008): AES-256-GCM, TLS-EKM key derivation, subnet topology, with an address and a peer-id.
    bool supported_by_mvp() const;
};

enum class PushStatus { Ok, NotPushReply, BadOption };

// `msg` without the trailing NUL. Unknown options are kept; malformed values of options we interpret are errors.
PushStatus parse_push_reply(std::string_view msg, PushReply& out);

// Strict dotted-quad IPv4 (no spaces, no leading zeros, each part 0..255).
bool parse_ipv4(std::string_view s, uint32_t& out);

}  // namespace pf
