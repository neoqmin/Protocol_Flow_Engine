#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

#include "pf/openvpn_header.h"

namespace pf {

// DATA_V2 + AES-256-GCM wire layout, verified against unmodified OpenVPN 2.6.19
// (docs/OpenVPN_Interop_Profile.md section 2.3):
//   header(4) = opcode<<3|key_id (1) + peer-id (3)
//   packet_id (4, big endian)
//   GCM tag (16)            <- precedes the ciphertext
//   ciphertext
// AAD = header(4) || packet_id(4); nonce = packet_id(4) || per-key tail(8).
inline constexpr size_t kDataV2HeaderLen = 4;
inline constexpr size_t kDataV2PacketIdLen = 4;
inline constexpr size_t kDataV2TagLen = 16;
inline constexpr size_t kDataV2AadLen = kDataV2HeaderLen + kDataV2PacketIdLen;
inline constexpr size_t kDataV2Overhead = kDataV2AadLen + kDataV2TagLen;

struct DataV2Packet {
    OvpnHeader header;
    uint32_t packet_id;
    std::array<uint8_t, kDataV2TagLen> tag;
    size_t ciphertext_len;
};

// Ok, Truncated (< 24 bytes), or InvalidOpcode (valid packet but not DATA_V2).
ParseStatus parse_data_v2(const uint8_t* data, size_t len, DataV2Packet& out);

// Writes header(4)||packet_id(4) (the AEAD AAD / start of the wire packet).
// Returns false if key_id > 7 or peer_id > 0xFFFFFF.
bool build_data_v2_aad(uint8_t key_id, uint32_t peer_id, uint32_t packet_id,
                       uint8_t out[kDataV2AadLen]);

}  // namespace pf
