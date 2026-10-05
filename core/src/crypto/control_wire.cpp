#include "pf/crypto/control_wire.h"

namespace pf {

bool seal_control_packet(TlsCryptChannel& ch, const ControlPacket& p, uint32_t net_time, std::vector<uint8_t>& datagram) {
    std::vector<uint8_t> pt;
    if (!build_control_plaintext(p, pt)) return false;
    const uint8_t op_keyid = static_cast<uint8_t>((p.opcode << 3) | (p.key_id & 7));
    return ch.wrap(op_keyid, p.session_id.data(), pt.data(), pt.size(), net_time, datagram);
}

OpenControlStatus open_control_packet(TlsCryptChannel& ch, const uint8_t* d, size_t n, ControlPacket& out) {
    if (d == nullptr || n < 1 || !is_control_opcode(d[0] >> 3)) return OpenControlStatus::NotControl;
    TlsCryptPlain plain;
    switch (ch.unwrap(d, n, plain)) {
        case TlsCryptStatus::Ok: break;
        case TlsCryptStatus::Replay: return OpenControlStatus::Replay;
        case TlsCryptStatus::Truncated:
        case TlsCryptStatus::AuthFailed: return OpenControlStatus::AuthFailed;
    }
    return parse_control(plain.op_keyid, plain.session_id, plain.payload.data(), plain.payload.size(), out) ==
                   ControlParseStatus::Ok
               ? OpenControlStatus::Ok
               : OpenControlStatus::Malformed;
}

}  // namespace pf
