#include "pf/data_v2.h"

#include <cstring>

namespace pf {

ParseStatus parse_data_v2(const uint8_t* data, size_t len, DataV2Packet& out) {
    OvpnHeader h{};
    ParseStatus st = parse_ovpn_header(data, len, h);
    if (st != ParseStatus::Ok) return st;
    if (h.opcode != OvpnOpcode::DataV2) return ParseStatus::InvalidOpcode;
    if (len < kDataV2Overhead) return ParseStatus::Truncated;

    out.header = h;
    out.packet_id = (uint32_t(data[4]) << 24) | (uint32_t(data[5]) << 16) |
                    (uint32_t(data[6]) << 8) | uint32_t(data[7]);
    std::memcpy(out.tag.data(), data + kDataV2AadLen, kDataV2TagLen);
    out.ciphertext_len = len - kDataV2Overhead;
    return ParseStatus::Ok;
}

bool build_data_v2_aad(uint8_t key_id, uint32_t peer_id, uint32_t packet_id,
                       uint8_t out[kDataV2AadLen]) {
    if (key_id > 7 || peer_id > 0xFFFFFFu) return false;
    out[0] = static_cast<uint8_t>((static_cast<uint8_t>(OvpnOpcode::DataV2) << 3) | key_id);
    out[1] = static_cast<uint8_t>(peer_id >> 16);
    out[2] = static_cast<uint8_t>(peer_id >> 8);
    out[3] = static_cast<uint8_t>(peer_id);
    out[4] = static_cast<uint8_t>(packet_id >> 24);
    out[5] = static_cast<uint8_t>(packet_id >> 16);
    out[6] = static_cast<uint8_t>(packet_id >> 8);
    out[7] = static_cast<uint8_t>(packet_id);
    return true;
}

}  // namespace pf
