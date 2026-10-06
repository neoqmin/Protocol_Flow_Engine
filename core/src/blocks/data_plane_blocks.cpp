#include "pf/blocks/data_plane_blocks.h"

#include "pf/crypto/aead_provider.h"
#include "pf/data_v2.h"
#include "pf/key_store.h"
#include "pf/ovpn_context.h"

namespace pf {
namespace {

BlockResult internal_error(FlowContext& ctx) {
    ctx.error = Error::Internal;
    return BlockResult::Error;
}

void make_nonce(uint32_t packet_id, const std::array<uint8_t, 8>& tail, uint8_t out[12]) {
    out[0] = static_cast<uint8_t>(packet_id >> 24);
    out[1] = static_cast<uint8_t>(packet_id >> 16);
    out[2] = static_cast<uint8_t>(packet_id >> 8);
    out[3] = static_cast<uint8_t>(packet_id);
    for (size_t i = 0; i < 8; ++i) out[4 + i] = tail[i];
}

BlockResult parse_data_v2_block(FlowContext& ctx) {
    if (!ctx.packet) return internal_error(ctx);
    OvpnSlot& s = ctx.proto.emplace<OvpnSlot>();            // a fresh parse: nothing of an earlier packet survives
    switch (parse_data_v2(ctx.packet->data(), ctx.packet->size(), s.data_v2)) {
        case ParseStatus::Ok:
            s.data_v2_valid = true;
            s.header = s.data_v2.header;
            s.header_valid = true;
            return BlockResult::Continue;
        case ParseStatus::Truncated: ctx.error = Error::Truncated; return BlockResult::Drop;
        case ParseStatus::InvalidOpcode: ctx.error = Error::InvalidOpcode; return BlockResult::Drop;
    }
    return internal_error(ctx);
}

BlockResult lookup_rx_key(FlowContext& ctx) {
    const OvpnHeader* h = ovpn_header(ctx);
    if (!ctx.keys || !h) return internal_error(ctx);
    KeyRef r = ctx.keys->rx_for_key_id(h->key_id);
    if (!r.valid()) { ctx.error = Error::UnknownKey; return BlockResult::Drop; }
    ctx.key_ref = r;
    return BlockResult::Continue;
}

// The parsed DATA_V2 fields, or nullptr (wiring bug: parse_data_v2 did not run on this packet).
const DataV2Packet* parsed(const FlowContext& ctx) {
    const OvpnSlot* s = ovpn_slot(ctx);
    return s && s->data_v2_valid ? &s->data_v2 : nullptr;
}

BlockResult replay_check(FlowContext& ctx) {
    const DataV2Packet* m = parsed(ctx);
    if (!ctx.keys || !m) return internal_error(ctx);
    const DataKey* dk = ctx.keys->get(ctx.key_ref);
    if (!dk) return internal_error(ctx);
    switch (dk->replay.check(m->packet_id)) {
        case ReplayStatus::Ok: return BlockResult::Continue;
        case ReplayStatus::Replay:
        case ReplayStatus::TooOld: ctx.error = Error::ReplayDetected; return BlockResult::Drop;
        case ReplayStatus::InvalidId: ctx.error = Error::InvalidPacketId; return BlockResult::Drop;
    }
    return internal_error(ctx);
}

BlockResult aead_decrypt(FlowContext& ctx) {
    const DataV2Packet* mp = parsed(ctx);
    if (!ctx.packet || !ctx.keys || !ctx.aead || !mp) return internal_error(ctx);
    const DataKey* dk = ctx.keys->get(ctx.key_ref);
    if (!dk) return internal_error(ctx);
    const DataV2Packet& m = *mp;
    if (ctx.packet->size() != kDataV2Overhead + m.ciphertext_len) return internal_error(ctx);  // not parsed / modified

    uint8_t nonce[12];
    make_nonce(m.packet_id, dk->nonce_tail, nonce);
    uint8_t* d = ctx.packet->data();
    // AAD = the first 8 wire bytes (header || packet_id); ciphertext follows the tag.
    if (!ctx.aead->decrypt(dk->key.data(), nonce, d, kDataV2AadLen, d + kDataV2Overhead,
                           m.ciphertext_len, m.tag.data())) {
        ctx.error = Error::AuthFailed;
        return BlockResult::Drop;
    }
    if (!ctx.packet->pull_front(kDataV2Overhead)) return internal_error(ctx);
    return BlockResult::Continue;
}

BlockResult replay_commit(FlowContext& ctx) {
    const DataV2Packet* m = parsed(ctx);
    if (!ctx.keys || !m) return internal_error(ctx);
    DataKey* dk = ctx.keys->get(ctx.key_ref);
    if (!dk) return internal_error(ctx);
    dk->replay.commit(m->packet_id);
    return BlockResult::Continue;
}

BlockResult lookup_tx_key(FlowContext& ctx) {
    const OvpnHeader* h = ovpn_header(ctx);
    if (!ctx.keys || !h) return internal_error(ctx);
    KeyRef r = ctx.keys->tx_for_key_id(h->key_id);
    if (!r.valid()) { ctx.error = Error::UnknownKey; return BlockResult::Error; }
    ctx.key_ref = r;
    return BlockResult::Continue;
}

BlockResult aead_encrypt(FlowContext& ctx) {
    const OvpnHeader* h = ovpn_header(ctx);
    if (!ctx.packet || !ctx.keys || !ctx.aead || !h) return internal_error(ctx);
    DataKey* dk = ctx.keys->get(ctx.key_ref);
    if (!dk || h->key_id > 7 || h->peer_id > 0xFFFFFFu) return internal_error(ctx);
    if (ctx.packet->headroom() < kDataV2Overhead) { ctx.error = Error::BufferTooSmall; return BlockResult::Error; }

    uint32_t pid = 0;
    if (!dk->next_tx_id(pid)) { ctx.error = Error::NonceExhausted; return BlockResult::Error; }

    uint8_t* d = ctx.packet->push_front(kDataV2Overhead);   // cannot fail: headroom checked
    if (!d || !build_data_v2_aad(h->key_id, h->peer_id, pid, d)) return internal_error(ctx);

    uint8_t nonce[12];
    make_nonce(pid, dk->nonce_tail, nonce);
    const size_t plain_len = ctx.packet->size() - kDataV2Overhead;
    if (!ctx.aead->encrypt(dk->key.data(), nonce, d, kDataV2AadLen, d + kDataV2Overhead, plain_len,
                           d + kDataV2AadLen))   // tag is written between AAD and ciphertext
        return internal_error(ctx);
    return BlockResult::Continue;
}

// Context contracts (consumes, produces): see block.h and pf/ovpn_context.h.
const BlockDescriptor kBlocks[] = {
    {kBlockParseDataV2, "parse_data_v2", BlockType::Action, parse_data_v2_block, nullptr, 0, nullptr, "ovpn.header,ovpn.data_v2"},
    {kBlockLookupRxKey, "lookup_rx_key", BlockType::Action, lookup_rx_key, nullptr, 0, "ovpn.header", "key"},
    {kBlockReplayCheck, "replay_check", BlockType::Action, replay_check, nullptr, 0, "key,ovpn.data_v2", nullptr},
    {kBlockAeadDecrypt, "aead_decrypt", BlockType::Action, aead_decrypt, nullptr, 0, "key,ovpn.data_v2", nullptr},
    {kBlockReplayCommit, "replay_commit", BlockType::Action, replay_commit, nullptr, 0, "key,ovpn.data_v2", nullptr},
    {kBlockLookupTxKey, "lookup_tx_key", BlockType::Action, lookup_tx_key, nullptr, 0, "ovpn.header", "key"},
    {kBlockAeadEncrypt, "aead_encrypt", BlockType::Action, aead_encrypt, nullptr, 0, "key,ovpn.header", nullptr},
};

}  // namespace

bool register_data_plane_blocks(BlockRegistry& registry) {
    for (const auto& b : kBlocks)
        if (registry.find(b.id) != nullptr || registry.find(std::string_view(b.name)) != nullptr)
            return false;
    for (const auto& b : kBlocks)
        if (registry.add(b) != BlockRegistry::AddStatus::Ok) return false;
    return true;
}

}  // namespace pf
