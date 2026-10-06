#include "pf/peer_info.h"

namespace pf {
namespace {

bool parse_u32(std::string_view s, uint32_t& out) {
    if (s.empty() || s.size() > 10) return false;
    uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    if (v > 0xFFFFFFFFull) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x = static_cast<char>(x - 32);
        if (y >= 'a' && y <= 'z') y = static_cast<char>(y - 32);
        if (x != y) return false;
    }
    return true;
}

}  // namespace

PeerInfoStatus parse_peer_info(std::string_view text, PeerInfo& out) {
    PeerInfo p;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        const std::string_view line = text.substr(start, end - start);
        start = end + 1;
        if (line.empty()) continue;
        for (const char c : line)
            if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) return PeerInfoStatus::Malformed;
        const size_t eq = line.find('=');
        if (eq == std::string_view::npos || eq == 0) return PeerInfoStatus::Malformed;
        if (static_cast<int>(p.values.size()) >= kMaxPeerInfoEntries) return PeerInfoStatus::Malformed;
        std::string key(line.substr(0, eq));
        const std::string_view value = line.substr(eq + 1);
        if (!p.values.emplace(key, std::string(value)).second) return PeerInfoStatus::Malformed;
        if (key == "IV_PROTO") {
            if (!parse_u32(value, p.iv_proto)) return PeerInfoStatus::Malformed;
            p.has_proto = true;
        } else if (key == "IV_CIPHERS") {
            size_t s = 0;
            while (s <= value.size()) {
                size_t e = value.find(':', s);
                if (e == std::string_view::npos) e = value.size();
                if (e > s) p.ciphers.emplace_back(value.substr(s, e - s));
                s = e + 1;
            }
        } else if (key == "IV_VER") {
            p.version = std::string(value);
        } else if (key == "IV_PLAT") {
            p.platform = std::string(value);
        }
    }
    out = std::move(p);
    return PeerInfoStatus::Ok;
}

std::string peer_info_unsupported_reason(const PeerInfo& p) {
    if (!p.has_proto) return "client does not announce IV_PROTO (OpenVPN 2.6 protocol required)";
    if (!(p.iv_proto & kIvProtoDataV2)) return "client does not support DATA_V2";
    if (!(p.iv_proto & kIvProtoTlsKeyExport)) return "client does not support TLS key export (tls-ekm)";
    for (const auto& c : p.ciphers)
        if (iequal(c, "AES-256-GCM")) return {};
    return "Data channel cipher negotiation failed (no shared cipher)";
}

}  // namespace pf
