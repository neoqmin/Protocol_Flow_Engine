#pragma once
#include <cstddef>
#include <cstdint>

namespace pf {

enum class OvpnOpcode : uint8_t {
    ControlHardResetClientV1 = 1,
    ControlHardResetServerV1 = 2,
    ControlSoftResetV1 = 3,
    ControlV1 = 4,
    AckV1 = 5,
    DataV1 = 6,
    ControlHardResetClientV2 = 7,
    ControlHardResetServerV2 = 8,
    DataV2 = 9,
    ControlHardResetClientV3 = 10,
};

struct OvpnHeader {
    OvpnOpcode opcode;
    uint8_t key_id;      // low 3 bits of first byte
    uint32_t peer_id;    // valid only for DataV2 (24 bit)
};

enum class ParseStatus { Ok, Truncated, InvalidOpcode };

// Parses the OpenVPN packet header (opcode/key_id, plus peer-id for DATA_V2).
ParseStatus parse_ovpn_header(const uint8_t* data, size_t len, OvpnHeader& out);

}  // namespace pf
