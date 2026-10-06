#pragma once
#include "pf/block.h"
#include "pf/ovpn_context.h"

namespace pf {

// Data-plane (DATA_V2 + AES-256-GCM) blocks. Ids continue after openvpn_blocks.h (1..5);
// they are part of Flow JSON later: never renumber.
//
// RX:  parse -> lookup_rx_key -> replay_check -> aead_decrypt -> replay_commit
//   After aead_decrypt the packet holds only the plaintext (24-byte overhead pulled off, in place).
//   replay_commit runs LAST so forged packets can never advance the replay window.
// TX:  lookup_tx_key -> aead_encrypt   (caller: set_ovpn_header(ctx, {DataV2, key_id, peer_id}); the TX flow
//      declares "ovpn.header" as a flow input)
//   Plaintext in ctx.packet (with >= 24 bytes headroom) becomes a complete wire packet.
//
// Needs ctx.keys (KeyStore) and ctx.aead (AeadProvider): missing = Error/Internal (wiring bug, not bad input).
enum : BlockId {
    kBlockParseDataV2 = 6,      // Action: parse overhead fields; Drop(Truncated | InvalidOpcode)
    kBlockLookupRxKey = 7,      // Action: key_id -> KeyRef; Drop(UnknownKey)
    kBlockReplayCheck = 8,      // Action: read-only window check; Drop(ReplayDetected | InvalidPacketId)
    kBlockAeadDecrypt = 9,      // Action: in-place GCM verify+decrypt; Drop(AuthFailed)
    kBlockReplayCommit = 10,    // Action: record packet-id after successful authentication
    kBlockLookupTxKey = 11,     // Action: key_id -> KeyRef; Error(UnknownKey) (our config, not input)
    kBlockAeadEncrypt = 12,     // Action: assign packet-id, add header, encrypt; Error(NonceExhausted | BufferTooSmall)
};

// All-or-nothing, like register_openvpn_blocks.
bool register_data_plane_blocks(BlockRegistry& registry);

}  // namespace pf
