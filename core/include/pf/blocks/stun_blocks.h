#pragma once
#include "pf/block.h"
#include "pf/stun_context.h"

namespace pf {

// STUN blocks (PM-2b N1, D-045). Ids continue after data_plane_blocks.h (6..12): never renumber.
//
//   is_stun     Decision: does this datagram look like STUN (first byte 0..3 + magic cookie)? On a socket shared with
//               OpenVPN this splits the two protocols before any parsing (OpenVPN's first byte is opcode<<3 >= 0x08).
//   parse_stun  Action: full structural parse + FINGERPRINT check into the StunSlot; produces "stun.message".
//               Drop(Truncated | Malformed | ChecksumFailed). Integrity (needs a key) is checked later, not here.
enum : BlockId {
    kBlockIsStun = 13,
    kBlockParseStun = 14,
};

// All-or-nothing, like the other register_* functions.
bool register_stun_blocks(BlockRegistry& registry);

}  // namespace pf
