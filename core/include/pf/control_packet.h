#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "pf/openvpn_header.h"

namespace pf {

// Control-channel packet AFTER tls-crypt is removed (docs/OpenVPN_Control_Plane_Notes.md section 3).
// Verified on 14 packets captured from unmodified OpenVPN 2.6.19:
//
//   plaintext = ack_len(1) | ack ids(4 each, BE) | remote session_id(8, only if ack_len > 0)
//               | message_id(4, BE) | payload            <- the last two are absent in P_ACK_V1
//
// `opcode`/`key_id`/`session_id` come from the tls-crypt wrapper (opcode byte and the sender's session id).
// Opcodes handled: SOFT_RESET(3), CONTROL_V1(4), ACK_V1(5), HARD_RESET_CLIENT_V2(7), HARD_RESET_SERVER_V2(8).
inline constexpr size_t kSessionIdLen = 8;
inline constexpr size_t kMaxAcksPerPacket = 8;   // our builder limit (peer packets seen with up to 6)

struct ControlPacket {
    uint8_t opcode = 0;                          // OvpnOpcode value (opcode byte >> 3)
    uint8_t key_id = 0;
    std::array<uint8_t, kSessionIdLen> session_id{};          // sender's session
    std::vector<uint32_t> acks;                               // message ids the sender acknowledges
    std::array<uint8_t, kSessionIdLen> remote_session_id{};   // receiver's session; valid iff !acks.empty()
    bool has_message = false;                    // false only for ACK_V1
    uint32_t message_id = 0;
    std::vector<uint8_t> payload;                // TLS record bytes for CONTROL_V1, empty for resets
};

enum class ControlParseStatus { Ok, Truncated, WrongOpcode, Malformed };

constexpr bool is_control_opcode(uint8_t opcode) {
    return opcode == static_cast<uint8_t>(OvpnOpcode::ControlSoftResetV1) ||
           opcode == static_cast<uint8_t>(OvpnOpcode::ControlV1) ||
           opcode == static_cast<uint8_t>(OvpnOpcode::AckV1) ||
           opcode == static_cast<uint8_t>(OvpnOpcode::ControlHardResetClientV2) ||
           opcode == static_cast<uint8_t>(OvpnOpcode::ControlHardResetServerV2);
}

// op_keyid = first wire byte, session_id = the 8 bytes after it (both authenticated by tls-crypt).
ControlParseStatus parse_control(uint8_t op_keyid, const uint8_t session_id[kSessionIdLen],
                                 const uint8_t* plaintext, size_t len, ControlPacket& out);

// Serializes the plaintext part. Returns false for inconsistent packets (ACK with a message or without
// acks, a non-ACK without a message, > kMaxAcksPerPacket acks, non-control opcode).
bool build_control_plaintext(const ControlPacket& p, std::vector<uint8_t>& out);

}  // namespace pf
