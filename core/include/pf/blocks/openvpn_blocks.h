#pragma once
#include "pf/block.h"
#include "pf/ovpn_context.h"

namespace pf {

// Stable block ids for the OpenVPN RX path (ids are part of Flow JSON later: never renumber).
enum : BlockId {
    kBlockParseOvpnHeader = 1,      // Action:   parse opcode/key_id/peer-id into the OpenVPN slot (pf/ovpn_context.h)
    kBlockRejectLegacyOpcode = 2,   // Action:   Drop(LegacyOpcode) for deprecated opcodes (profile policy)
    kBlockIsDataV2 = 3,             // Decision: Yes if DATA_V2, No otherwise
    kBlockStripDataV2Header = 4,    // Action:   remove the 4-byte DATA_V2 header in place
    kBlockMarkControlPacket = 5,    // Action:   set kFlagControlPacket for the control-plane handler
};

inline constexpr uint32_t kFlagControlPacket = 1u << 0;

// Registers all blocks above. All-or-nothing: returns false (registering
// nothing) if any id or name is already taken.
bool register_openvpn_blocks(BlockRegistry& registry);

}  // namespace pf
