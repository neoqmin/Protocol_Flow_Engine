#include "pf/blocks/openvpn_blocks.h"

#include "pf/openvpn_header.h"

namespace pf {
namespace {

constexpr size_t kDataV2HeaderLen = 4;  // opcode/key_id (1) + peer-id (3)

BlockResult internal_error(FlowContext& ctx) {
    ctx.error = Error::Internal;
    return BlockResult::Error;
}

BlockResult parse_header(FlowContext& ctx) {
    if (!ctx.packet) return internal_error(ctx);   // our bug, not bad input
    switch (parse_ovpn_header(ctx.packet->data(), ctx.packet->size(), ctx.header)) {
        case ParseStatus::Ok:
            ctx.header_valid = true;
            return BlockResult::Continue;
        case ParseStatus::Truncated:
            ctx.error = Error::Truncated;
            return BlockResult::Drop;
        case ParseStatus::InvalidOpcode:
            ctx.error = Error::InvalidOpcode;
            return BlockResult::Drop;
    }
    return internal_error(ctx);
}

BlockResult reject_legacy(FlowContext& ctx) {
    if (!ctx.header_valid) return internal_error(ctx);
    if (is_legacy_opcode(ctx.header.opcode)) {
        ctx.error = Error::LegacyOpcode;
        return BlockResult::Drop;
    }
    return BlockResult::Continue;
}

BlockResult is_data_v2(FlowContext& ctx) {
    if (!ctx.header_valid) return internal_error(ctx);
    return ctx.header.opcode == OvpnOpcode::DataV2 ? BlockResult::Yes : BlockResult::No;
}

BlockResult strip_data_v2_header(FlowContext& ctx) {
    if (!ctx.packet) return internal_error(ctx);
    if (!ctx.packet->pull_front(kDataV2HeaderLen)) {
        ctx.error = Error::Truncated;
        return BlockResult::Drop;
    }
    return BlockResult::Continue;
}

BlockResult mark_control(FlowContext& ctx) {
    ctx.flags |= kFlagControlPacket;
    return BlockResult::Continue;
}

const BlockDescriptor kBlocks[] = {
    {kBlockParseOvpnHeader, "parse_ovpn_header", BlockType::Action, parse_header},
    {kBlockRejectLegacyOpcode, "reject_legacy_opcode", BlockType::Action, reject_legacy},
    {kBlockIsDataV2, "is_data_v2", BlockType::Decision, is_data_v2},
    {kBlockStripDataV2Header, "strip_data_v2_header", BlockType::Action, strip_data_v2_header},
    {kBlockMarkControlPacket, "mark_control_packet", BlockType::Action, mark_control},
};

}  // namespace

bool register_openvpn_blocks(BlockRegistry& registry) {
    for (const auto& b : kBlocks)
        if (registry.find(b.id) != nullptr || registry.find(std::string_view(b.name)) != nullptr)
            return false;
    for (const auto& b : kBlocks)
        if (registry.add(b) != BlockRegistry::AddStatus::Ok) return false;
    return true;
}

}  // namespace pf
