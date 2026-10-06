#include "pf/push.h"

#include <algorithm>

namespace pf {
namespace {

bool starts_with_keyword(std::string_view msg, std::string_view kw, bool allow_underscore = false) {
    if (msg.substr(0, kw.size()) != kw) return false;
    if (msg.size() == kw.size()) return true;
    const char c = msg[kw.size()];
    return c == ',' || (allow_underscore && c == '_');
}

bool parse_uint(std::string_view s, uint64_t max, uint32_t& out) {
    if (s.empty() || s.size() > 10) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    if (v > max) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t e = s.find(sep, start);
        if (e == std::string_view::npos) e = s.size();
        out.push_back(s.substr(start, e - start));
        start = e + 1;
    }
    return out;
}

std::vector<std::string_view> words(std::string_view s) {
    std::vector<std::string_view> out;
    for (auto w : split(s, ' ')) if (!w.empty()) out.push_back(w);
    return out;
}

}  // namespace

ControlMessageKind classify_control_message(std::string_view msg) {
    if (starts_with_keyword(msg, "PUSH_REPLY")) return ControlMessageKind::PushReply;
    if (starts_with_keyword(msg, "PUSH_REQUEST")) return ControlMessageKind::PushRequest;
    if (starts_with_keyword(msg, "AUTH_FAILED")) return ControlMessageKind::AuthFailed;
    if (starts_with_keyword(msg, "RESTART")) return ControlMessageKind::Restart;
    if (starts_with_keyword(msg, "HALT")) return ControlMessageKind::Halt;
    if (starts_with_keyword(msg, "INFO", /*allow_underscore=*/true)) return ControlMessageKind::Info;
    return ControlMessageKind::Unknown;
}

bool parse_ipv4(std::string_view s, uint32_t& out) {
    uint32_t v = 0;
    int parts = 0;
    for (auto p : split(s, '.')) {
        if (++parts > 4 || p.empty() || p.size() > 3) return false;
        if (p.size() > 1 && p[0] == '0') return false;   // inet_aton would read this as octal: refuse
        uint32_t x = 0;
        if (!parse_uint(p, 255, x)) return false;
        v = (v << 8) | x;
    }
    if (parts != 4) return false;
    out = v;
    return true;
}

bool PushReply::key_derivation_tls_ekm() const {
    return key_derivation == "tls-ekm" ||
           std::find(protocol_flags.begin(), protocol_flags.end(), "tls-ekm") != protocol_flags.end();
}

bool PushReply::supported_by_mvp() const {
    return has_ifconfig && has_peer_id && cipher == "AES-256-GCM" && key_derivation_tls_ekm() &&
           (topology.empty() || topology == "subnet");
}

std::string format_ipv4(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 0xFF) + "." + std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

bool build_push_reply(const ServerPush& s, std::string& out) {
    if (s.ifconfig_ip == 0 || s.peer_id >= 0xFFFFFF) return false;
    std::string m = "PUSH_REPLY,route-gateway " + format_ipv4(s.route_gateway) + ",topology subnet";
    if (s.ping_seconds != 0) m += ",ping " + std::to_string(s.ping_seconds);
    if (s.ping_restart_seconds != 0) m += ",ping-restart " + std::to_string(s.ping_restart_seconds);
    for (const auto& r : s.routes) {
        m += ",route " + format_ipv4(r.network) + " " + format_ipv4(r.netmask);
        if (r.has_gateway) m += " " + format_ipv4(r.gateway);
    }
    m += ",ifconfig " + format_ipv4(s.ifconfig_ip) + " " + format_ipv4(s.ifconfig_netmask);
    m += ",peer-id " + std::to_string(s.peer_id) + ",cipher AES-256-GCM,protocol-flags tls-ekm";
    if (s.tun_mtu != 0) m += ",tun-mtu " + std::to_string(s.tun_mtu);
    if (m.size() > kMaxPushReply) return false;
    out = std::move(m);
    return true;
}

PushStatus parse_push_reply(std::string_view msg, PushReply& out) {
    if (classify_control_message(msg) != ControlMessageKind::PushReply) return PushStatus::NotPushReply;

    PushReply r;
    const size_t comma = msg.find(',');
    if (comma != std::string_view::npos) {
        for (auto item : split(msg.substr(comma + 1), ',')) {
            if (item.empty()) continue;
            const auto w = words(item);
            if (w.empty()) continue;
            const std::string_view name = w[0];
            bool known = true;
            if (name == "ifconfig") {
                if (w.size() != 3 || !parse_ipv4(w[1], r.ifconfig_ip) || !parse_ipv4(w[2], r.ifconfig_netmask)) return PushStatus::BadOption;
                r.has_ifconfig = true;
            } else if (name == "route-gateway") {
                if (w.size() != 2 || !parse_ipv4(w[1], r.route_gateway)) return PushStatus::BadOption;
            } else if (name == "topology") {
                if (w.size() != 2) return PushStatus::BadOption;
                r.topology = std::string(w[1]);
            } else if (name == "ping") {
                if (w.size() != 2 || !parse_uint(w[1], 0xFFFFFFFFu, r.ping_seconds)) return PushStatus::BadOption;
            } else if (name == "ping-restart") {
                if (w.size() != 2 || !parse_uint(w[1], 0xFFFFFFFFu, r.ping_restart_seconds)) return PushStatus::BadOption;
            } else if (name == "peer-id") {
                if (w.size() != 2 || !parse_uint(w[1], 0xFFFFFF, r.peer_id)) return PushStatus::BadOption;
                r.has_peer_id = true;
            } else if (name == "cipher") {
                if (w.size() != 2) return PushStatus::BadOption;
                r.cipher = std::string(w[1]);
            } else if (name == "tun-mtu") {
                if (w.size() != 2 || !parse_uint(w[1], 65535, r.tun_mtu)) return PushStatus::BadOption;
            } else if (name == "protocol-flags") {
                for (size_t i = 1; i < w.size(); ++i) r.protocol_flags.emplace_back(w[i]);
            } else if (name == "key-derivation") {
                if (w.size() != 2) return PushStatus::BadOption;
                r.key_derivation = std::string(w[1]);
            } else if (name == "route") {
                PushedRoute rt;
                if (w.size() < 3 || w.size() > 4 || !parse_ipv4(w[1], rt.network) || !parse_ipv4(w[2], rt.netmask))
                    return PushStatus::BadOption;
                if (w.size() == 4) {
                    if (!parse_ipv4(w[3], rt.gateway)) return PushStatus::BadOption;
                    rt.has_gateway = true;
                }
                r.routes.push_back(rt);
            } else {
                known = false;
            }
            if (!known) r.unknown_options.emplace_back(item);
        }
    }
    out = std::move(r);
    return PushStatus::Ok;
}

}  // namespace pf
