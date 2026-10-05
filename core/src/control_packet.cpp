#include "pf/control_packet.h"

#include <cstring>

namespace pf {
namespace {

uint32_t get_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
void put_be32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24)); v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));  v.push_back(static_cast<uint8_t>(x));
}

}  // namespace

ControlParseStatus parse_control(uint8_t op_keyid, const uint8_t session_id[kSessionIdLen],
                                 const uint8_t* pt, size_t n, ControlPacket& out) {
    const uint8_t opcode = op_keyid >> 3;
    if (!is_control_opcode(opcode)) return ControlParseStatus::WrongOpcode;
    if (pt == nullptr || n < 1) return ControlParseStatus::Truncated;

    ControlPacket p;
    p.opcode = opcode;
    p.key_id = op_keyid & 7;
    std::memcpy(p.session_id.data(), session_id, kSessionIdLen);

    const size_t ack_len = pt[0];
    size_t i = 1;
    if (n - i < ack_len * 4) return ControlParseStatus::Truncated;
    p.acks.reserve(ack_len);
    for (size_t k = 0; k < ack_len; ++k, i += 4) p.acks.push_back(get_be32(pt + i));
    if (ack_len > 0) {
        if (n - i < kSessionIdLen) return ControlParseStatus::Truncated;
        std::memcpy(p.remote_session_id.data(), pt + i, kSessionIdLen);
        i += kSessionIdLen;
    }

    if (opcode == static_cast<uint8_t>(OvpnOpcode::AckV1)) {
        if (ack_len == 0 || i != n) return ControlParseStatus::Malformed;   // must ack something and carry nothing else
    } else {
        if (n - i < 4) return ControlParseStatus::Truncated;
        p.has_message = true;
        p.message_id = get_be32(pt + i);
        i += 4;
        p.payload.assign(pt + i, pt + n);
    }
    out = std::move(p);
    return ControlParseStatus::Ok;
}

bool build_control_plaintext(const ControlPacket& p, std::vector<uint8_t>& out) {
    if (!is_control_opcode(p.opcode)) return false;
    if (p.acks.size() > kMaxAcksPerPacket) return false;
    const bool is_ack = p.opcode == static_cast<uint8_t>(OvpnOpcode::AckV1);
    if (is_ack ? (p.has_message || p.acks.empty() || !p.payload.empty()) : !p.has_message) return false;

    std::vector<uint8_t> v;
    v.push_back(static_cast<uint8_t>(p.acks.size()));
    for (uint32_t id : p.acks) put_be32(v, id);
    if (!p.acks.empty()) v.insert(v.end(), p.remote_session_id.begin(), p.remote_session_id.end());
    if (p.has_message) {
        put_be32(v, p.message_id);
        v.insert(v.end(), p.payload.begin(), p.payload.end());
    }
    out = std::move(v);
    return true;
}

}  // namespace pf
