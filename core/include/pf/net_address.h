#pragma once
#include <array>
#include <cstdint>
#include <string>

namespace pf {

// A UDP/TCP transport address (IPv4 or IPv6). Shared by STUN (stun::Address) and the server's session table.
struct NetAddress {
    enum class Family : uint8_t { V4 = 0x01, V6 = 0x02 };
    Family family = Family::V4;
    std::array<uint8_t, 16> ip{};     // V4 uses the first 4 bytes (network order); the rest is ignored
    uint16_t port = 0;
    bool operator==(const NetAddress& o) const;
    bool operator!=(const NetAddress& o) const { return !(*this == o); }
    bool operator<(const NetAddress& o) const;       // total order for maps
    bool same_ip(const NetAddress& o) const;         // ignores the port
    std::string to_string() const;    // "192.0.2.1:32853", "[2001:db8::1]:32853"
    static NetAddress v4(uint32_t host_order_ip, uint16_t port);
};

}  // namespace pf
