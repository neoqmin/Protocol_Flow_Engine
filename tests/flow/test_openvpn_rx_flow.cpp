// Static OpenVPN RX flow built from real blocks, driven with wire bytes
// (headers observed from unmodified OpenVPN 2.6.19; see regression/golden).
#include "pf/blocks/openvpn_blocks.h"
#include "pf/flow.h"
#include "pf_test.h"

using namespace pf;

static Flow build_rx(const BlockRegistry& r) {
    FlowBuilder b("openvpn_rx");
    b.add("parse", kBlockParseOvpnHeader)
     .add("policy", kBlockRejectLegacyOpcode)
     .add("is_data", kBlockIsDataV2)
     .add("strip", kBlockStripDataV2Header)
     .add("control", kBlockMarkControlPacket);
    b.on_yes("is_data", "strip").on_no("is_data", "control");
    b.on_continue("strip", "");
    auto res = b.build(r);
    PF_REQUIRE(res.ok());
    return std::move(res.flow);
}

static FlowResult run(const Flow& f, const std::vector<uint8_t>& bytes, FlowContext& ctx, PacketBuffer& pkt) {
    pkt = PacketBuffer::from_bytes(bytes.data(), bytes.size());
    ctx = FlowContext{};
    ctx.packet = &pkt;
    return run_flow(f, ctx);
}

PF_TEST(registers_all_openvpn_blocks) {
    BlockRegistry r;
    PF_CHECK(register_openvpn_blocks(r));
    PF_CHECK_EQ(r.size(), size_t(5));
    PF_CHECK(!register_openvpn_blocks(r));   // second registration conflicts
}

PF_TEST(rx_data_v2_packet_has_header_stripped) {
    BlockRegistry r; register_openvpn_blocks(r);
    Flow f = build_rx(r);
    PacketBuffer pkt(0, 0); FlowContext ctx;
    // DATA_V2 key 1 peer 0, then packet-id + payload bytes
    auto res = run(f, {0x49, 0, 0, 0, 0xAA, 0xBB, 0xCC}, ctx, pkt);
    PF_CHECK(res.outcome == FlowOutcome::Completed);
    PF_CHECK(ctx.header_valid);
    PF_CHECK(ctx.header.opcode == OvpnOpcode::DataV2);
    PF_CHECK_EQ(ctx.header.key_id, 1);
    PF_CHECK_EQ(pkt.size(), size_t(3));
    PF_CHECK_EQ(pkt.data()[0], 0xAA);
    PF_CHECK((ctx.flags & kFlagControlPacket) == 0);
}

PF_TEST(rx_control_packet_is_marked_not_stripped) {
    BlockRegistry r; register_openvpn_blocks(r);
    Flow f = build_rx(r);
    PacketBuffer pkt(0, 0); FlowContext ctx;
    auto res = run(f, {0x20, 1, 2, 3}, ctx, pkt);   // CONTROL_V1
    PF_CHECK(res.outcome == FlowOutcome::Completed);
    PF_CHECK((ctx.flags & kFlagControlPacket) != 0);
    PF_CHECK_EQ(pkt.size(), size_t(4));
}

PF_TEST(rx_legacy_opcode_is_dropped_with_reason) {
    BlockRegistry r; register_openvpn_blocks(r);
    Flow f = build_rx(r);
    PacketBuffer pkt(0, 0); FlowContext ctx;
    auto res = run(f, {0x08}, ctx, pkt);            // HARD_RESET_CLIENT_V1
    PF_CHECK(res.outcome == FlowOutcome::Dropped);
    PF_CHECK(res.error == Error::LegacyOpcode);
}

PF_TEST(rx_invalid_opcode_is_dropped) {
    BlockRegistry r; register_openvpn_blocks(r);
    Flow f = build_rx(r);
    PacketBuffer pkt(0, 0); FlowContext ctx;
    auto res = run(f, {0xF8}, ctx, pkt);
    PF_CHECK(res.outcome == FlowOutcome::Dropped);
    PF_CHECK(res.error == Error::InvalidOpcode);
}

PF_TEST(rx_truncated_packets_are_dropped) {
    BlockRegistry r; register_openvpn_blocks(r);
    Flow f = build_rx(r);
    PacketBuffer pkt(0, 0); FlowContext ctx;
    PF_CHECK(run(f, {}, ctx, pkt).error == Error::Truncated);
    PF_CHECK(run(f, {0x48, 0x00}, ctx, pkt).error == Error::Truncated);  // DATA_V2 < 4 bytes
}

PF_TEST(rx_without_packet_is_an_internal_error_not_a_drop) {
    BlockRegistry r; register_openvpn_blocks(r);
    Flow f = build_rx(r);
    FlowContext ctx;                 // packet == nullptr: our bug, not bad input
    auto res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Errored);
    PF_CHECK(res.error == Error::Internal);
}
