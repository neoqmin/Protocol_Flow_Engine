// F-2: protocol slot in the FlowContext, context facts on blocks, and the "consumed before produced" check shared by
// FlowBuilder and the Validator (D-043).
#include <set>
#include <string>
#include <vector>

#include "pf/blocks/data_plane_blocks.h"
#include "pf/blocks/openvpn_blocks.h"
#include "pf/flow_json.h"
#include "pf/flow_validator.h"
#include "pf/key_store.h"
#include "pf_test.h"

using namespace pf;

namespace {

struct TestSlot {
    static constexpr ProtocolId kProtocolId = 999;
    uint32_t a = 7;
    uint8_t b[16]{};
};

BlockResult go(FlowContext&) { return BlockResult::Continue; }
BlockResult yes(FlowContext&) { return BlockResult::Yes; }

// p_x/p_y produce, c_x/c_y/c_xy consume, d_x is a decision that produces x on both exits, d is a plain decision.
BlockRegistry contract_registry() {
    BlockRegistry r;
    PF_REQUIRE(r.add({1, "p_x", BlockType::Action, go, nullptr, 0, nullptr, "f.x"}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({2, "p_y", BlockType::Action, go, nullptr, 0, nullptr, "f.y"}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({3, "c_x", BlockType::Action, go, nullptr, 0, "f.x", nullptr}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({4, "c_y", BlockType::Action, go, nullptr, 0, "f.y", nullptr}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({5, "c_xy", BlockType::Action, go, nullptr, 0, "f.x,f.y", "f.z"}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({6, "d_x", BlockType::Decision, yes, nullptr, 0, nullptr, "f.x"}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({7, "d", BlockType::Decision, yes}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({8, "c_z", BlockType::Action, go, nullptr, 0, "f.z", nullptr}) == BlockRegistry::AddStatus::Ok);
    return r;
}

bool has(const FlowValidation& v, const std::string& code, const std::string& path = "") {
    for (const auto& i : v.issues) if (i.code == code && (path.empty() || i.path == path)) return true;
    return false;
}

FlowDocument doc(std::initializer_list<std::pair<const char*, const char*>> nodes) {
    FlowDocument d;
    d.name = "t";
    for (const auto& n : nodes) d.nodes.push_back({n.first, n.second, {}, {}});
    return d;
}
void edge(FlowDocument& d, const char* from, const char* port, const char* to) {
    d.edges.push_back({from, to ? std::optional<std::string>(to) : std::nullopt, port, {}});
}

}  // namespace

PF_TEST(protocol_slot_holds_one_protocol_at_a_time) {
    FlowContext ctx;
    PF_CHECK_EQ(ctx.proto.id(), kProtocolNone);
    PF_CHECK(ctx.proto.get<OvpnSlot>() == nullptr);
    PF_CHECK(ovpn_header(ctx) == nullptr);

    OvpnSlot& s = ctx.proto.emplace<OvpnSlot>();
    PF_CHECK(!s.header_valid);                                 // value-initialised
    PF_CHECK(!s.data_v2_valid);
    PF_CHECK(ovpn_header(ctx) == nullptr);                     // a slot without a parsed header is not a header
    set_ovpn_header(ctx, OvpnHeader{OvpnOpcode::DataV2, 3, 0x123456});
    PF_REQUIRE(ovpn_header(ctx) != nullptr);
    PF_CHECK_EQ(ovpn_header(ctx)->key_id, 3);
    PF_CHECK(ctx.proto.get<TestSlot>() == nullptr);            // the tag decides

    ctx.proto.as<OvpnSlot>().header.peer_id = 9;               // as<> keeps an existing slot
    PF_CHECK_EQ(ovpn_header(ctx)->peer_id, 9u);
    ctx.proto.emplace<OvpnSlot>();                             // emplace starts fresh
    PF_CHECK(ovpn_header(ctx) == nullptr);

    TestSlot& t = ctx.proto.as<TestSlot>();                    // switching protocol replaces the slot
    PF_CHECK_EQ(t.a, 7u);
    PF_CHECK_EQ(ctx.proto.id(), ProtocolId{999});
    PF_CHECK(ovpn_slot(ctx) == nullptr);

    FlowContext copy = ctx;                                    // plain data: copies with the context
    PF_REQUIRE(copy.proto.get<TestSlot>() != nullptr);
    PF_CHECK_EQ(copy.proto.get<TestSlot>()->a, 7u);
    ctx.proto.reset();
    PF_CHECK(ctx.proto.get<TestSlot>() == nullptr);
    static_assert(sizeof(OvpnSlot) <= kProtocolSlotBytes);
}

PF_TEST(block_fact_lists_are_validated_on_registration) {
    PF_CHECK(is_valid_fact("ovpn.header"));
    PF_CHECK(is_valid_fact("key"));
    PF_CHECK(!is_valid_fact(""));
    PF_CHECK(!is_valid_fact("Ovpn"));
    PF_CHECK(!is_valid_fact("a..b"));
    PF_CHECK(!is_valid_fact("a."));
    PF_CHECK(!is_valid_fact("a,b"));
    const auto f = split_facts("ovpn.header,key");
    PF_REQUIRE(f.size() == 2);
    PF_CHECK(f[0] == "ovpn.header" && f[1] == "key");
    PF_CHECK(split_facts(nullptr).empty());
    PF_CHECK(split_facts("").empty());
    PF_CHECK(split_facts("a,,b")[1].empty());

    BlockRegistry r;
    PF_CHECK(r.add({1, "x", BlockType::Action, go, nullptr, 0, "Bad", nullptr}) == BlockRegistry::AddStatus::InvalidDescriptor);
    PF_CHECK(r.add({1, "x", BlockType::Action, go, nullptr, 0, nullptr, "a,"}) == BlockRegistry::AddStatus::InvalidDescriptor);
    PF_CHECK(r.add({1, "x", BlockType::Action, go, nullptr, 0, "a.b", "c"}) == BlockRegistry::AddStatus::Ok);
}

PF_TEST(builder_rejects_consuming_before_producing) {
    const BlockRegistry r = contract_registry();
    FlowBuilder bad("t");
    bad.add("use", 3).add("make", 1);
    auto b1 = bad.build(r);
    PF_CHECK(!b1.ok());
    bool msg = false;
    for (const auto& e : b1.errors) msg |= e.find("needs context fact 'f.x'") != std::string::npos;
    PF_CHECK(msg);

    FlowBuilder good("t");
    good.add("make", 1).add("use", 3);
    PF_CHECK(good.build(r).ok());

    FlowBuilder input("t");                                    // the caller provides it
    input.input("f.x").add("use", 3);
    auto b3 = input.build(r);
    PF_CHECK(b3.ok());
    PF_CHECK(b3.flow.inputs() == std::vector<std::string>{"f.x"});
    FlowBuilder badinput("t");
    badinput.input("Not A Fact").add("use", 3);
    PF_CHECK(!badinput.build(r).ok());

    // produced on one branch only -> rejected; produced on both (or by the decision itself) -> fine
    FlowBuilder one("t");
    one.add("d", 7).add("px", 1).add("use", 3);
    one.on_yes("d", "px").on_no("d", "use");
    PF_CHECK(!one.build(r).ok());
    FlowBuilder both("t");
    both.add("d", 7).add("px", 1).add("px2", 1).add("use", 3);
    both.on_yes("d", "px").on_no("d", "px2").on_continue("px", "use");
    PF_CHECK(both.build(r).ok());
    FlowBuilder dec("t");
    dec.add("dx", 6).add("use", 3).add("use2", 3);
    dec.on_yes("dx", "use").on_no("dx", "use2").on_continue("use", "");
    PF_CHECK(dec.build(r).ok());

    // a decision exit may end the flow (Flow JSON "to": null) - the builder used to reject this while the validator
    // accepted it (found by the oracle test below)
    FlowBuilder ends("t");
    ends.add("d", 7).add("px", 1);
    ends.on_yes("d", "").on_no("d", "px");
    auto b5 = ends.build(r);
    PF_REQUIRE(b5.ok());
    FlowContext ctx;
    const FlowResult fr = run_flow(b5.flow, ctx);
    PF_CHECK(fr.outcome == FlowOutcome::Completed);
    PF_CHECK_EQ(fr.steps, size_t{1});

    // chains: c_xy needs x and y and produces z for c_z
    FlowBuilder chain("t");
    chain.add("px", 1).add("py", 2).add("xy", 5).add("z", 8);
    PF_CHECK(chain.build(r).ok());
    FlowBuilder broken("t");
    broken.add("px", 1).add("xy", 5).add("z", 8);
    auto b4 = broken.build(r);
    PF_CHECK(!b4.ok());
    PF_CHECK_EQ(b4.errors.size(), size_t{1});                   // y missing at xy; z is still counted as produced by xy
}

PF_TEST(validator_reports_context_gaps_with_paths_and_producers) {
    const BlockRegistry r = contract_registry();
    FlowDocument d = doc({{"use", "c_x"}, {"make", "p_x"}});
    const FlowValidation v = validate_flow(d, r);
    PF_CHECK(has(v, "ContextNotProduced", "/nodes/0/block"));
    bool producers = false;
    for (const auto& i : v.issues) producers |= i.message.find("produced by: p_x, d_x") != std::string::npos;
    PF_CHECK(producers);

    d.inputs = {"f.x"};
    PF_CHECK(validate_flow(d, r).ok());
    d.inputs = {"f.x", "Bad Input"};
    PF_CHECK(has(validate_flow(d, r), "BadInput", "/flow/inputs/1"));

    FlowDocument orphan = doc({{"z", "c_z"}});
    orphan.inputs = {};
    PF_CHECK(has(validate_flow(orphan, r), "ContextNotProduced", "/nodes/0/block"));
    FlowDocument branch = doc({{"d", "d"}, {"px", "p_x"}, {"use", "c_x"}});
    edge(branch, "d", "yes", "px");
    edge(branch, "d", "no", "use");
    PF_CHECK(has(validate_flow(branch, r), "ContextNotProduced", "/nodes/2/block"));
}

PF_TEST(real_openvpn_blocks_declare_their_contracts) {
    BlockRegistry r;
    PF_REQUIRE(register_openvpn_blocks(r));
    PF_REQUIRE(register_data_plane_blocks(r));
    FlowBuilder rx_wrong("rx");                                  // decrypt before parse: caught before anything runs
    rx_wrong.add("decrypt", kBlockAeadDecrypt).add("parse", kBlockParseDataV2);
    PF_CHECK(!rx_wrong.build(r).ok());
    FlowBuilder rx_nokey("rx");                                  // replay check without a key lookup
    rx_nokey.add("parse", kBlockParseDataV2).add("replay", kBlockReplayCheck);
    PF_CHECK(!rx_nokey.build(r).ok());
    FlowBuilder tx_noinput("tx");                                // TX without the caller-provided header
    tx_noinput.add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
    PF_CHECK(!tx_noinput.build(r).ok());
    FlowBuilder tx("tx");
    tx.input(kFactOvpnHeader).add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
    PF_CHECK(tx.build(r).ok());
    FlowBuilder legacy("rx");                                    // reject_legacy_opcode needs a parsed header
    legacy.add("legacy", kBlockRejectLegacyOpcode);
    PF_CHECK(!legacy.build(r).ok());
}

PF_TEST(flow_json_inputs_round_trip_and_are_checked) {
    const char* text = R"({"format":"protocol-flow","version":1,"flow":{"name":"tx","inputs":["ovpn.header","key"]},
        "nodes":[{"id":"e","block":"aead_encrypt"}]})";
    auto r = parse_flow_json(text);
    PF_REQUIRE(r.ok());
    PF_CHECK(r.doc.inputs == (std::vector<std::string>{"ovpn.header", "key"}));
    const std::string out = write_flow_json(r.doc);
    PF_CHECK(out.find("\"inputs\"") != std::string::npos);
    PF_CHECK(parse_flow_json(out).doc.inputs == r.doc.inputs);
    PF_CHECK(write_flow_json(parse_flow_json(out).doc) == out);
    FlowDocument none;
    none.name = "x";
    none.nodes.push_back({"a", "b", {}, {}});
    PF_CHECK(write_flow_json(none).find("inputs") == std::string::npos);      // omitted when empty

    auto bad = parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"tx","inputs":["Bad","key","key",3]},
        "nodes":[{"id":"e","block":"aead_encrypt"}]})");
    PF_CHECK(!bad.ok());
    auto code_at = [&](FlowJsonErrorCode c, const char* path) {
        for (const auto& e : bad.errors) if (e.code == c && e.path == path) return true;
        return false;
    };
    PF_CHECK(code_at(FlowJsonErrorCode::BadValue, "/flow/inputs/0"));
    PF_CHECK(code_at(FlowJsonErrorCode::BadValue, "/flow/inputs/2"));
    PF_CHECK(code_at(FlowJsonErrorCode::WrongType, "/flow/inputs/3"));
    PF_CHECK(!parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"tx","inputs":"key"},"nodes":[{"id":"e","block":"x"}]})").ok());
}

// Oracle: enumerate EVERY path from the entry (small random graphs) and collect (node, fact) pairs where the fact is
// consumed but was not produced earlier on that path. The validator's data-flow analysis must report exactly these.
PF_TEST(context_check_matches_a_brute_force_path_oracle) {
    const BlockRegistry reg = contract_registry();
    const char* names[] = {"p_x", "p_y", "c_x", "c_y", "c_xy", "d_x", "d", "c_z"};
    const char* all_facts[] = {"f.x", "f.y", "f.z"};
    uint64_t s = 0x2545F4914F6CDD1Dull;
    auto rnd = [&](uint64_t n) { s = s * 6364136223846793005ull + 1442695040888963407ull; return (s >> 33) % n; };
    size_t compared = 0, with_gaps = 0, clean = 0;
    for (int iter = 0; iter < 8000; ++iter) {
        FlowDocument d;
        d.name = "r";
        const size_t n = 1 + rnd(6);
        for (size_t i = 0; i < n; ++i) d.nodes.push_back({"n" + std::to_string(i), names[rnd(8)], {}, {}});
        for (const char* f : all_facts) if (rnd(4) == 0) d.inputs.push_back(f);
        // forward edges only (acyclic): decisions get yes/no, some actions jump forward or end
        for (size_t i = 0; i < n; ++i) {
            const bool decision = reg.find(std::string_view(d.nodes[i].block))->type == BlockType::Decision;
            auto target = [&]() -> const char* {
                const size_t t = i + 1 + rnd(n - i);
                static std::string buf[2];
                static int k = 0;
                if (t >= n) return nullptr;
                buf[k ^= 1] = "n" + std::to_string(t);
                return buf[k].c_str();
            };
            if (decision) {
                const char* y = target();
                std::string ys = y ? y : "";
                const char* no = target();
                edge(d, d.nodes[i].id.c_str(), "yes", ys.empty() ? nullptr : ys.c_str());
                edge(d, d.nodes[i].id.c_str(), "no", no);
            } else if (rnd(3) == 0) {
                edge(d, d.nodes[i].id.c_str(), "continue", target());
            }
        }
        const FlowValidation v = validate_flow(d, reg);
        bool other = false;
        std::set<std::pair<size_t, std::string>> got;
        for (const auto& i : v.issues) {
            if (i.code != "ContextNotProduced") { other = true; continue; }
            const size_t node = std::stoul(i.path.substr(7));
            const size_t a = i.message.find("context fact \"") + 14;
            got.insert({node, i.message.substr(a, i.message.find('"', a) - a)});
        }
        if (other) continue;                                     // unreachable etc.: the contract check does not run
        // successors with the implicit "next node" rule
        std::vector<std::vector<size_t>> succ(n);
        for (size_t i = 0; i < n; ++i) {
            bool has_cont = false;
            for (const auto& e : d.edges) {
                if (e.from != d.nodes[i].id) continue;
                if (e.port == "continue") has_cont = true;
                if (e.to) succ[i].push_back(std::stoul(e.to->substr(1)));
            }
            const bool decision = reg.find(std::string_view(d.nodes[i].block))->type == BlockType::Decision;
            if (!decision && !has_cont && i + 1 < n) succ[i].push_back(i + 1);
        }
        std::set<std::pair<size_t, std::string>> want;
        std::vector<std::pair<size_t, std::set<std::string>>> stack{{0, std::set<std::string>(d.inputs.begin(), d.inputs.end())}};
        while (!stack.empty()) {
            auto [v0, have] = stack.back();
            stack.pop_back();
            const BlockDescriptor* b = reg.find(std::string_view(d.nodes[v0].block));
            for (const auto f : split_facts(b->consumes)) if (!have.count(std::string(f))) want.insert({v0, std::string(f)});
            for (const auto f : split_facts(b->produces)) have.insert(std::string(f));
            for (size_t w : succ[v0]) stack.push_back({w, have});
        }
        PF_CHECK(got == want);
        if (got != want) { std::fprintf(stderr, "iteration %d: oracle and validator disagree\n", iter); break; }
        ++compared;
        want.empty() ? ++clean : ++with_gaps;
        auto c = compile_flow(d, reg);                           // and the builder agrees with the validator
        for (const auto& i : c.issues) {
            if (i.code == "Internal") std::fprintf(stderr, "%s\n%s", i.message.c_str(), write_flow_json(d).c_str());
            PF_REQUIRE(i.code != "Internal");
        }
        PF_CHECK(c.ok() == want.empty());
    }
    PF_CHECK(compared > 1000);
    PF_CHECK(with_gaps > 300);
    PF_CHECK(clean > 300);
}

// A parse starts a fresh slot (no state of an earlier packet survives a failed parse), and blocks that need the parsed
// DATA_V2 fields refuse a slot that only carries a header (TX-style) as OUR wiring bug, not as a bad packet.
PF_TEST(openvpn_slot_state_never_leaks_between_packets) {
    BlockRegistry r;
    PF_REQUIRE(register_openvpn_blocks(r));
    PF_REQUIRE(register_data_plane_blocks(r));
    const BlockDescriptor* parse_v2 = r.find(BlockId{kBlockParseDataV2});
    const BlockDescriptor* parse_hdr = r.find(BlockId{kBlockParseOvpnHeader});
    const BlockDescriptor* replay = r.find(BlockId{kBlockReplayCheck});
    const BlockDescriptor* commit = r.find(BlockId{kBlockReplayCommit});
    PF_REQUIRE(parse_v2 && parse_hdr && replay && commit);

    FlowContext ctx;
    set_ovpn_header(ctx, OvpnHeader{OvpnOpcode::DataV2, 1, 5});      // state left by an earlier packet
    ctx.proto.get<OvpnSlot>()->data_v2_valid = true;
    const uint8_t truncated[3] = {0x48, 0, 0};
    PacketBuffer pkt = PacketBuffer::from_bytes(truncated, sizeof truncated);
    ctx.packet = &pkt;
    PF_CHECK(parse_v2->execute(ctx) == BlockResult::Drop);
    PF_CHECK(ovpn_header(ctx) == nullptr);
    PF_REQUIRE(ovpn_slot(ctx) != nullptr);
    PF_CHECK(!ovpn_slot(ctx)->data_v2_valid);

    set_ovpn_header(ctx, OvpnHeader{OvpnOpcode::DataV2, 1, 5});
    const uint8_t bad_opcode[1] = {0xF8};
    PacketBuffer pkt2 = PacketBuffer::from_bytes(bad_opcode, sizeof bad_opcode);
    ctx.packet = &pkt2;
    ctx.error = Error::None;
    PF_CHECK(parse_hdr->execute(ctx) == BlockResult::Drop);
    PF_CHECK(ovpn_header(ctx) == nullptr);

    KeyStore keys;
    DataKey k;
    const KeyRef ref = keys.add(k);
    FlowContext tx;                                                    // header only, nothing parsed
    set_ovpn_header(tx, OvpnHeader{OvpnOpcode::DataV2, 1, 0});
    tx.keys = &keys;
    tx.key_ref = ref;
    PF_CHECK(replay->execute(tx) == BlockResult::Error);
    PF_CHECK_EQ(tx.error, Error::Internal);
    tx.error = Error::None;
    PF_CHECK(commit->execute(tx) == BlockResult::Error);
    PF_CHECK_EQ(tx.error, Error::Internal);
}
