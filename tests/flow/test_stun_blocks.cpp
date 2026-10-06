// PM-2b N1: STUN blocks in a Flow. One receive Flow for a socket shared by STUN and OpenVPN: is_stun splits the two
// before any parsing. Fed with the RFC 5769 vectors and every real OpenVPN 2.6.19 DATA_V2 golden packet.
#include <fstream>
#include <sstream>
#include <string>

#include "pf/blocks/openvpn_blocks.h"
#include "pf/blocks/stun_blocks.h"
#include "pf/flow_validator.h"
#include "pf_test.h"
#include "stun_vectors.h"

using namespace pf;

#ifndef GOLDEN_DIR
#define GOLDEN_DIR "tests/regression/golden"
#endif

namespace {

BlockRegistry registry() {
    BlockRegistry r;
    PF_REQUIRE(register_openvpn_blocks(r));
    PF_REQUIRE(register_stun_blocks(r));
    return r;
}

// demux: is_stun -yes-> parse_stun -> end ; -no-> parse_ovpn_header -> mark_control_packet -> end
const char* kDemuxJson = R"json({
  "format": "protocol-flow", "version": 1,
  "flow": { "name": "shared_socket_rx", "description": "STUN and OpenVPN on one UDP socket (RFC 7983 style first-byte split)" },
  "nodes": [
    { "id": "stun", "block": "is_stun" },
    { "id": "parse_stun", "block": "parse_stun" },
    { "id": "parse_ovpn", "block": "parse_ovpn_header" }
  ],
  "edges": [
    { "from": "stun", "port": "yes", "to": "parse_stun" },
    { "from": "stun", "port": "no", "to": "parse_ovpn" },
    { "from": "parse_stun", "to": null }
  ]
})json";

std::vector<std::vector<uint8_t>> openvpn_wire_packets() {
    std::vector<std::vector<uint8_t>> out;
    std::ifstream f(std::string(GOLDEN_DIR) + "/data_v2_gcm.golden");
    PF_REQUIRE(f.good());
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(cell);
        PF_REQUIRE(c.size() == 4);
        std::string h;
        for (char ch : c[2]) if (ch != ' ') h += ch;
        out.push_back(pf_test::stun_unhex(h));
    }
    PF_REQUIRE(out.size() >= 10);
    return out;
}

FlowResult run(const Flow& f, const std::vector<uint8_t>& bytes, FlowContext& ctx, PacketBuffer& pkt) {
    pkt = PacketBuffer::from_bytes(bytes.data(), bytes.size());
    ctx = FlowContext{};
    ctx.packet = &pkt;
    return run_flow(f, ctx);
}

}  // namespace

PF_TEST(stun_and_openvpn_share_a_socket_through_is_stun) {
    const BlockRegistry reg = registry();
    LoadedFlow l = load_flow_json(kDemuxJson, reg);
    for (const auto& i : l.issues) std::fprintf(stderr, "%s %s %s\n", i.code.c_str(), i.path.c_str(), i.message.c_str());
    PF_REQUIRE(l.ok());
    PacketBuffer pkt;
    FlowContext ctx;

    for (const auto& v : pf_test::load_stun_vectors(GOLDEN_DIR)) {
        const FlowResult r = run(l.flow, v.bytes, ctx, pkt);
        PF_CHECK(r.outcome == FlowOutcome::Completed);
        PF_CHECK_EQ(l.flow.node(r.last_node).label, std::string("parse_stun"));
        const StunSlot* s = stun_slot(ctx);
        PF_REQUIRE(s != nullptr);
        PF_CHECK(ovpn_slot(ctx) == nullptr);
        PF_CHECK_EQ(s->method, stun::kMethodBinding);
        PF_CHECK_EQ(s->size, static_cast<uint16_t>(v.bytes.size()));
        PF_CHECK(s->message_integrity != 0);
        PF_CHECK(std::equal(s->tid.begin(), s->tid.end(), v.bytes.begin() + 8));
    }
    size_t ovpn = 0;
    for (const auto& w : openvpn_wire_packets()) {
        const FlowResult r = run(l.flow, w, ctx, pkt);
        PF_CHECK(r.outcome == FlowOutcome::Completed);
        PF_CHECK_EQ(l.flow.node(r.last_node).label, std::string("parse_ovpn"));
        PF_CHECK(stun_slot(ctx) == nullptr);
        PF_CHECK(ovpn_header(ctx) != nullptr);
        ++ovpn;
    }
    PF_CHECK(ovpn >= 10);
}

PF_TEST(stun_slot_records_the_attributes_later_steps_need) {
    const BlockRegistry reg = registry();
    FlowBuilder b("stun_rx");
    b.add("parse", kBlockParseStun);
    auto built = b.build(reg);
    PF_REQUIRE(built.ok());
    PacketBuffer pkt;
    FlowContext ctx;
    for (const auto& v : pf_test::load_stun_vectors(GOLDEN_DIR)) {
        PF_REQUIRE(run(built.flow, v.bytes, ctx, pkt).outcome == FlowOutcome::Completed);
        const StunSlot* s = stun_slot(ctx);
        PF_REQUIRE(s != nullptr);
        stun::Message m;
        PF_REQUIRE(stun::parse(v.bytes.data(), v.bytes.size(), m) == stun::ParseStatus::Ok);
        auto off = [&](uint16_t t) { const stun::Attribute* a = m.find(t); return a ? static_cast<uint16_t>(a->offset) : uint16_t{0}; };
        PF_CHECK_EQ(s->xor_mapped_address, off(stun::kAttrXorMappedAddress));
        PF_CHECK_EQ(s->username, off(stun::kAttrUsername));
        PF_CHECK_EQ(s->realm, off(stun::kAttrRealm));
        PF_CHECK_EQ(s->nonce, off(stun::kAttrNonce));
        PF_CHECK_EQ(s->message_integrity, off(stun::kAttrMessageIntegrity));
        PF_CHECK_EQ(s->fingerprint, off(stun::kAttrFingerprint));
        PF_CHECK_EQ(s->attribute_count, static_cast<uint8_t>(m.attributes.size()));
        PF_CHECK_EQ(s->unknown_required_count, static_cast<uint8_t>(m.unknown_required.size()));
        if (s->xor_mapped_address) {                                    // decodable straight from packet + offset
            stun::Attribute a;
            a.type = stun::kAttrXorMappedAddress;
            a.length = static_cast<uint16_t>((pkt.data()[s->xor_mapped_address + 2] << 8) | pkt.data()[s->xor_mapped_address + 3]);
            a.value = pkt.data() + s->xor_mapped_address + 4;
            stun::Address addr;
            PF_CHECK(stun::decode_xor_address(a, s->tid, addr));
            PF_CHECK_EQ(addr.port, uint16_t{32853});
        }
    }
}

PF_TEST(stun_parse_block_drops_bad_input_with_reasons) {
    const BlockRegistry reg = registry();
    FlowBuilder b("stun_rx");
    b.add("parse", kBlockParseStun);
    auto built = b.build(reg);
    PF_REQUIRE(built.ok());
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    PacketBuffer pkt;
    FlowContext ctx;
    auto expect_drop = [&](std::vector<uint8_t> bytes, Error e) {
        const FlowResult r = run(built.flow, bytes, ctx, pkt);
        PF_CHECK(r.outcome == FlowOutcome::Dropped);
        PF_CHECK_EQ(r.error, e);
        PF_CHECK(stun_slot(ctx) == nullptr);                         // a failed parse leaves no "parsed" STUN state
    };
    auto fp = vs[0].bytes;
    fp.back() ^= 1;
    expect_drop(fp, Error::ChecksumFailed);
    expect_drop(std::vector<uint8_t>(vs[0].bytes.begin(), vs[0].bytes.begin() + 10), Error::Truncated);
    auto cookie = vs[0].bytes;
    cookie[5] ^= 1;
    expect_drop(cookie, Error::Malformed);
    auto len = vs[0].bytes;
    len[3] = static_cast<uint8_t>(len[3] - 4);                       // length says the message ends 4 bytes early
    expect_drop(len, Error::Malformed);

    // a slot of an earlier packet never survives a failed parse
    PF_REQUIRE(run(built.flow, vs[1].bytes, ctx, pkt).outcome == FlowOutcome::Completed);
    PF_REQUIRE(stun_slot(ctx) != nullptr);
    pkt = PacketBuffer::from_bytes(fp.data(), fp.size());
    ctx.packet = &pkt;
    PF_CHECK(run_flow(built.flow, ctx).outcome == FlowOutcome::Dropped);
    PF_CHECK(stun_slot(ctx) == nullptr);
}

PF_TEST(stun_blocks_registration_and_contract) {
    BlockRegistry r = registry();
    PF_CHECK(!register_stun_blocks(r));                                // all-or-nothing, no duplicates
    const BlockDescriptor* p = r.find(BlockId{kBlockParseStun});
    PF_REQUIRE(p != nullptr);
    PF_CHECK_EQ(std::string(p->produces), std::string(kFactStunMessage));
    PF_CHECK(r.find(std::string_view("is_stun"))->type == BlockType::Decision);
    // the parser needs a packet: a wiring bug is an Error, not a Drop
    FlowContext ctx;
    PF_CHECK(p->execute(ctx) == BlockResult::Error);
    PF_CHECK_EQ(ctx.error, Error::Internal);
}
