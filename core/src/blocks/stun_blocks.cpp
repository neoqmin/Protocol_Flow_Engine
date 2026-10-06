#include "pf/blocks/stun_blocks.h"

namespace pf {
namespace {

BlockResult internal_error(FlowContext& ctx) {
    ctx.error = Error::Internal;
    return BlockResult::Error;
}

BlockResult is_stun(FlowContext& ctx) {
    if (!ctx.packet) return internal_error(ctx);
    return stun::looks_like_stun(ctx.packet->data(), ctx.packet->size()) ? BlockResult::Yes : BlockResult::No;
}

uint16_t offset_of(const stun::Message& m, uint16_t type) {
    const stun::Attribute* a = m.find(type);
    return a ? static_cast<uint16_t>(a->offset) : 0;
}

BlockResult parse_stun(FlowContext& ctx) {
    if (!ctx.packet) return internal_error(ctx);
    StunSlot& s = ctx.proto.emplace<StunSlot>();             // a fresh parse: nothing of an earlier packet survives
    stun::Message m;
    switch (stun::parse(ctx.packet->data(), ctx.packet->size(), m)) {
        case stun::ParseStatus::Ok: break;
        case stun::ParseStatus::Truncated: ctx.error = Error::Truncated; return BlockResult::Drop;
        case stun::ParseStatus::BadFingerprint: ctx.error = Error::ChecksumFailed; return BlockResult::Drop;
        case stun::ParseStatus::NotStun:
        case stun::ParseStatus::BadLength:
        case stun::ParseStatus::BadAttribute:
        case stun::ParseStatus::TooManyAttributes:
        case stun::ParseStatus::AttributeAfterFingerprint: ctx.error = Error::Malformed; return BlockResult::Drop;
    }
    s.method = m.method;
    s.cls = m.cls;
    s.tid = m.tid;
    s.size = static_cast<uint16_t>(m.size);
    s.attribute_count = static_cast<uint8_t>(m.attributes.size());          // <= kMaxAttributes (64)
    s.unknown_required_count = static_cast<uint8_t>(m.unknown_required.size());
    s.xor_mapped_address = offset_of(m, stun::kAttrXorMappedAddress);
    s.mapped_address = offset_of(m, stun::kAttrMappedAddress);
    s.error_code = offset_of(m, stun::kAttrErrorCode);
    s.username = offset_of(m, stun::kAttrUsername);
    s.realm = offset_of(m, stun::kAttrRealm);
    s.nonce = offset_of(m, stun::kAttrNonce);
    s.message_integrity = offset_of(m, stun::kAttrMessageIntegrity);
    s.message_integrity_sha256 = offset_of(m, stun::kAttrMessageIntegritySha256);
    s.fingerprint = offset_of(m, stun::kAttrFingerprint);
    s.parsed = true;
    return BlockResult::Continue;
}

const BlockDescriptor kBlocks[] = {
    {kBlockIsStun, "is_stun", BlockType::Decision, is_stun},
    {kBlockParseStun, "parse_stun", BlockType::Action, parse_stun, nullptr, 0, nullptr, "stun.message"},
};

}  // namespace

bool register_stun_blocks(BlockRegistry& registry) {
    for (const auto& b : kBlocks)
        if (registry.find(b.id) != nullptr || registry.find(std::string_view(b.name)) != nullptr) return false;
    for (const auto& b : kBlocks)
        if (registry.add(b) != BlockRegistry::AddStatus::Ok) return false;
    return true;
}

}  // namespace pf
