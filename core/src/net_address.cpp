#include "pf/net_address.h"

#include <cstring>

namespace pf {

bool NetAddress::operator==(const NetAddress& o) const {
    const size_t n = family == Family::V4 ? 4 : 16;
    return family == o.family && port == o.port && std::memcmp(ip.data(), o.ip.data(), n) == 0;
}

std::string NetAddress::to_string() const {
    std::string s;
    if (family == Family::V4) {
        for (int i = 0; i < 4; ++i) s += (i ? "." : "") + std::to_string(ip[i]);
        return s + ":" + std::to_string(port);
    }
    uint16_t g[8];
    for (int i = 0; i < 8; ++i) g[i] = static_cast<uint16_t>((ip[2 * i] << 8) | ip[2 * i + 1]);
    int best = -1, best_len = 0;                       // longest run of zero groups (>= 2) becomes "::" (RFC 5952)
    for (int i = 0; i < 8;) {
        if (g[i] != 0) { ++i; continue; }
        int j = i;
        while (j < 8 && g[j] == 0) ++j;
        if (j - i > best_len && j - i >= 2) { best = i; best_len = j - i; }
        i = j;
    }
    static const char* hex = "0123456789abcdef";
    auto group = [&](uint16_t v) {
        std::string h;
        bool lead = true;
        for (int k = 12; k >= 0; k -= 4) {
            const int d = (v >> k) & 0xF;
            if (lead && d == 0 && k != 0) continue;
            lead = false;
            h += hex[d];
        }
        return h;
    };
    s = "[";
    for (int i = 0; i < 8; ++i) {
        if (i == best) { s += "::"; i += best_len - 1; continue; }
        if (i > 0 && !(best >= 0 && i == best + best_len)) s += ":";
        s += group(g[i]);
    }
    return s + "]:" + std::to_string(port);
}

bool NetAddress::operator<(const NetAddress& o) const {
    if (family != o.family) return family < o.family;
    const size_t n = family == Family::V4 ? 4 : 16;
    const int c = std::memcmp(ip.data(), o.ip.data(), n);
    if (c != 0) return c < 0;
    return port < o.port;
}

bool NetAddress::same_ip(const NetAddress& o) const {
    const size_t n = family == Family::V4 ? 4 : 16;
    return family == o.family && std::memcmp(ip.data(), o.ip.data(), n) == 0;
}

NetAddress NetAddress::v4(uint32_t host_order_ip, uint16_t port) {
    NetAddress a;
    a.ip[0] = static_cast<uint8_t>(host_order_ip >> 24);
    a.ip[1] = static_cast<uint8_t>(host_order_ip >> 16);
    a.ip[2] = static_cast<uint8_t>(host_order_ip >> 8);
    a.ip[3] = static_cast<uint8_t>(host_order_ip);
    a.port = port;
    return a;
}

}  // namespace pf
