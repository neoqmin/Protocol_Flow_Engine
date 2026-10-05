#include "pf/openvpn_header.h"

namespace pf {

ParseStatus parse_ovpn_header(const uint8_t* data, size_t len, OvpnHeader& out) {
    if (data == nullptr || len < 1) return ParseStatus::Truncated;

    const uint8_t op = data[0] >> 3;
    if (op < 1 || op > 11) return ParseStatus::InvalidOpcode;

    out.opcode = static_cast<OvpnOpcode>(op);
    out.key_id = data[0] & 0x07;
    out.peer_id = 0;

    if (out.opcode == OvpnOpcode::DataV2) {
        if (len < 4) return ParseStatus::Truncated;
        out.peer_id = (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
    }
    return ParseStatus::Ok;
}

}  // namespace pf
