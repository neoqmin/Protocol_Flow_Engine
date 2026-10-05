#pragma once
#include <cstddef>
#include <cstdint>

namespace pf {

enum class OvpnOpcode : uint8_t {
    ControlHardResetClientV1 = 1,   // legacy
    ControlHardResetServerV1 = 2,   // legacy
    ControlSoftResetV1 = 3,
    ControlV1 = 4,
    AckV1 = 5,
    DataV1 = 6,                     // legacy
    ControlHardResetClientV2 = 7,
    ControlHardResetServerV2 = 8,
    DataV2 = 9,
    ControlHardResetClientV3 = 10,  // tls-crypt-v2
    ControlWkcV1 = 11,              // tls-crypt-v2 wrapped client key
};

struct OvpnHeader {
    OvpnOpcode opcode;
    uint8_t key_id;      // low 3 bits of first byte
    uint32_t peer_id;    // valid only for DataV2 (24 bit), otherwise 0
};

enum class ParseStatus { Ok, Truncated, InvalidOpcode };

// Wire-level parse of the OpenVPN packet header (opcode/key_id, plus peer-id
// for DATA_V2). Input is ONE datagram payload: for TCP transports the 2-byte
// length prefix must already be stripped (TCP framing is a Transport concern).
// Does not apply policy: legacy opcodes are parsed as Ok; use is_legacy_opcode().
ParseStatus parse_ovpn_header(const uint8_t* data, size_t len, OvpnHeader& out);

// Opcodes of deprecated protocol generations that a modern profile rejects.
constexpr bool is_legacy_opcode(OvpnOpcode op) {
    return op == OvpnOpcode::ControlHardResetClientV1 ||
           op == OvpnOpcode::ControlHardResetServerV1 ||
           op == OvpnOpcode::DataV1;
}

}  // namespace pf
