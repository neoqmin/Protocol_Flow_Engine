#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>

#include "pf/blocks/data_plane_blocks.h"
#include "pf/blocks/openvpn_blocks.h"
#include "pf/flow_validator.h"
#include "pf_test.h"

using namespace pf;

#ifndef GOLDEN_DIR
#define GOLDEN_DIR "tests/regression/golden"
#endif

namespace {

BlockResult go(FlowContext&) { return BlockResult::Continue; }
BlockResult yes(FlowContext&) { return BlockResult::Yes; }

const ParamSpec kCryptParams[] = {
    {"algorithm", ParamType::String, true},
    {"keyRef", ParamType::KeyRef, true},
    {"window", ParamType::Integer, false},
    {"strict", ParamType::Bool, false},
    {"ratio", ParamType::Number, false},
};

// Fake registry: a, b, c are actions, d is a decision, crypt is an action with parameters.
BlockRegistry fake_registry() {
    BlockRegistry r;
    PF_REQUIRE(r.add({1, "act_a", BlockType::Action, go}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({2, "act_b", BlockType::Action, go}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({3, "act_c", BlockType::Action, go}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({4, "dec_d", BlockType::Decision, yes}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({5, "crypt", BlockType::Action, go, kCryptParams, 5}) == BlockRegistry::AddStatus::Ok);
    return r;
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
bool has(const FlowValidation& v, const std::string& code, const std::string& path = "") {
    for (const auto& i : v.issues) if (i.code == code && (path.empty() || i.path == path)) return true;
    return false;
}
std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
}  // namespace

PF_TEST(validator_accepts_a_plain_sequence_and_a_branching_flow) {
    auto reg = fake_registry();
    PF_CHECK(validate_flow(doc({{"x", "act_a"}, {"y", "act_b"}}), reg).ok());
    FlowDocument d = doc({{"x", "act_a"}, {"q", "dec_d"}, {"y", "act_b"}, {"z", "act_c"}});
    edge(d, "q", "yes", "y");
    edge(d, "q", "no", "z");
    edge(d, "y", "continue", nullptr);                       // y ends the flow instead of falling through to z
    PF_CHECK(validate_flow(d, reg).ok());
}

PF_TEST(validator_unknown_block_names_the_path_and_suggests_the_closest_block) {
    auto reg = fake_registry();
    auto v = validate_flow(doc({{"x", "act_a"}, {"y", "act_bb"}}), reg);
    PF_REQUIRE(has(v, "UnknownBlock", "/nodes/1/block"));
    PF_CHECK(v.issues[0].message.find("did you mean \"act_b\"") != std::string::npos);
    auto far = validate_flow(doc({{"x", "completely_different"}}), reg);
    PF_REQUIRE(has(far, "UnknownBlock"));
    PF_CHECK(far.issues[0].message.find("did you mean") == std::string::npos);        // no wild guesses
}

PF_TEST(validator_checks_ports_against_the_block_type) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "act_a"}, {"y", "act_b"}});
    edge(d, "x", "yes", "y");
    PF_CHECK(has(validate_flow(d, reg), "PortMismatch", "/edges/0/port"));            // action has no yes
    FlowDocument e = doc({{"q", "dec_d"}, {"y", "act_b"}});
    edge(e, "q", "continue", "y");
    auto v = validate_flow(e, reg);
    PF_CHECK(has(v, "PortMismatch", "/edges/0/port"));
    PF_CHECK(has(v, "MissingEdge", "/nodes/0"));                                      // and it still lacks yes+no
}

PF_TEST(validator_decisions_need_both_exits_and_exits_cannot_repeat) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"q", "dec_d"}, {"y", "act_a"}});
    edge(d, "q", "yes", "y");
    auto v = validate_flow(d, reg);
    PF_REQUIRE(has(v, "MissingEdge", "/nodes/0"));
    PF_CHECK(v.issues[0].message.find("\"no\"") != std::string::npos);
    FlowDocument no_yes = doc({{"q", "dec_d"}, {"y", "act_a"}});
    edge(no_yes, "q", "no", "y");
    auto vy = validate_flow(no_yes, reg);
    PF_REQUIRE(has(vy, "MissingEdge", "/nodes/0"));
    PF_CHECK(vy.issues[0].message.find("\"yes\"") != std::string::npos);
    FlowDocument dup = doc({{"x", "act_a"}, {"y", "act_b"}, {"z", "act_c"}});
    edge(dup, "x", "continue", "y");
    edge(dup, "x", "continue", "z");
    PF_CHECK(has(validate_flow(dup, reg), "DuplicateEdge", "/edges/1"));
}

PF_TEST(validator_edge_endpoints_must_exist) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "act_a"}});
    edge(d, "ghost", "continue", "x");
    edge(d, "x", "continue", "nowhere");
    auto v = validate_flow(d, reg);
    PF_CHECK(has(v, "EdgeUnknownSource", "/edges/0/from"));
    PF_CHECK(has(v, "EdgeUnknownTarget", "/edges/1/to"));
}

PF_TEST(validator_rejects_cycles_including_self_loops_and_prints_the_loop) {
    auto reg = fake_registry();
    FlowDocument self = doc({{"x", "act_a"}});
    edge(self, "x", "continue", "x");
    PF_CHECK(has(validate_flow(self, reg), "Cycle"));
    FlowDocument d = doc({{"x", "act_a"}, {"y", "act_b"}, {"z", "act_c"}});
    edge(d, "z", "continue", "x");                            // z -> x closes x -> y -> z -> x (sequence is implicit)
    auto v = validate_flow(d, reg);
    PF_REQUIRE(has(v, "Cycle"));
    PF_CHECK(v.issues[0].message.find("x -> y -> z -> x") != std::string::npos);
    FlowDocument branch = doc({{"q", "dec_d"}, {"a", "act_a"}});
    edge(branch, "q", "yes", "a");
    edge(branch, "q", "no", "q");                             // a decision looping back on itself
    PF_CHECK(has(validate_flow(branch, reg), "Cycle"));
}

PF_TEST(validator_rejects_unreachable_nodes) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "act_a"}, {"y", "act_b"}, {"z", "act_c"}});
    edge(d, "x", "continue", "z");                            // y is skipped and nothing points at it
    auto v = validate_flow(d, reg);
    PF_REQUIRE(has(v, "Unreachable", "/nodes/1"));
    PF_CHECK(!has(v, "Unreachable", "/nodes/2"));
    FlowDocument ends = doc({{"x", "act_a"}, {"y", "act_b"}});
    edge(ends, "x", "continue", nullptr);                     // x ends the flow: y is dead code
    PF_CHECK(has(validate_flow(ends, reg), "Unreachable", "/nodes/1"));
}

PF_TEST(validator_graph_checks_wait_until_the_graph_is_resolved) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "act_a"}, {"y", "bogus"}});
    edge(d, "x", "continue", "x");                            // would be a cycle, but the block error comes first
    auto v = validate_flow(d, reg);
    PF_CHECK(has(v, "UnknownBlock"));
    PF_CHECK(!has(v, "Cycle"));
}

PF_TEST(validator_checks_parameters_against_the_block_declaration) {
    auto reg = fake_registry();
    auto with = [&](std::vector<std::pair<std::string, JsonValue>> params, const char* block = "crypt") {
        FlowDocument d = doc({{"c", block}});
        d.nodes[0].params = std::move(params);
        return validate_flow(d, reg);
    };
    PF_CHECK(with({{"algorithm", JsonValue::string("AES-256-GCM")}, {"keyRef", JsonValue::string("session.data_key")}}).ok());
    PF_CHECK(with({{"algorithm", JsonValue::string("x")}, {"keyRef", JsonValue::string("k")}, {"window", JsonValue::integer(64)},
                   {"strict", JsonValue::boolean(true)}, {"ratio", JsonValue::number(0.5)}}).ok());
    auto missing = with({{"algorithm", JsonValue::string("x")}});
    PF_REQUIRE(has(missing, "MissingParam", "/nodes/0/params"));
    PF_CHECK(missing.issues[0].message.find("keyRef") != std::string::npos);
    PF_CHECK(has(with({{"algorithm", JsonValue::string("x")}, {"keyRef", JsonValue::string("k")}, {"typo", JsonValue::integer(1)}}), "UnknownParam", "/nodes/0/params/typo"));
    PF_CHECK(has(with({{"algorithm", JsonValue::integer(5)}, {"keyRef", JsonValue::string("k")}}), "ParamType", "/nodes/0/params/algorithm"));
    PF_CHECK(has(with({{"algorithm", JsonValue::string("x")}, {"keyRef", JsonValue::string("k")}, {"window", JsonValue::number(1.5)}}), "ParamType"));
    PF_CHECK(has(with({{"algorithm", JsonValue::string("x")}, {"keyRef", JsonValue::integer(1)}}), "ParamType"));
    PF_CHECK(has(with({{"anything", JsonValue::integer(1)}}, "act_a"), "UnknownParam"));          // blocks without declared params take none
}

PF_TEST(validator_requires_the_user_runtime) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "act_a"}});
    d.runtime = {"kernel"};
    PF_CHECK(has(validate_flow(d, reg), "RuntimeUnsupported", "/flow/runtime"));
    d.runtime = {"kernel", "user"};
    PF_CHECK(validate_flow(d, reg).ok());
}

PF_TEST(validator_reports_every_problem_in_one_pass) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "nope"}, {"q", "dec_d"}, {"y", "act_b"}});
    edge(d, "q", "continue", "y");
    edge(d, "q", "yes", "ghost");
    auto v = validate_flow(d, reg);
    PF_CHECK(has(v, "UnknownBlock"));
    PF_CHECK(has(v, "PortMismatch"));
    PF_CHECK(has(v, "EdgeUnknownTarget"));
    PF_CHECK(has(v, "MissingEdge"));
}

PF_TEST(compile_builds_an_executable_flow_with_the_documents_wiring) {
    auto reg = fake_registry();
    FlowDocument d = doc({{"x", "act_a"}, {"q", "dec_d"}, {"y", "act_b"}, {"z", "act_c"}});
    edge(d, "q", "yes", "y");
    edge(d, "q", "no", "z");
    edge(d, "y", "continue", nullptr);
    auto c = compile_flow(d, reg);
    PF_REQUIRE(c.ok());
    PF_REQUIRE(c.flow.node_count() == 4);
    PF_CHECK(c.flow.name() == "t");
    PF_CHECK_EQ(c.flow.node(0).on_continue, size_t(1));       // implicit sequence x -> q
    PF_CHECK_EQ(c.flow.node(1).on_yes, size_t(2));
    PF_CHECK_EQ(c.flow.node(1).on_no, size_t(3));
    PF_CHECK_EQ(c.flow.node(2).on_continue, kNoNode);         // explicit end
    PF_CHECK_EQ(c.flow.node(3).on_continue, kNoNode);         // last node ends
    auto bad = compile_flow(doc({{"x", "nope"}}), reg);
    PF_CHECK(!bad.ok());
    PF_CHECK_EQ(bad.flow.node_count(), size_t(0));            // an invalid document never yields a Flow
}

PF_TEST(load_flow_json_reports_syntax_and_semantic_problems_in_one_shape) {
    auto reg = fake_registry();
    auto syntax = load_flow_json("{", reg);
    PF_REQUIRE(!syntax.ok());
    PF_CHECK(syntax.issues[0].code == "BadJson");
    auto semantic = load_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"missing_block"}]})", reg);
    PF_REQUIRE(!semantic.ok());
    PF_CHECK(semantic.issues[0].code == "UnknownBlock" && semantic.issues[0].path == "/nodes/0/block");
    auto good = load_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"act_a"},{"id":"b","block":"act_b"}]})", reg);
    PF_REQUIRE(good.ok());
    PF_CHECK_EQ(good.flow.node_count(), size_t(2));
    auto secret = load_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"crypt","params":{"key":"abc"}}]})", reg);
    PF_REQUIRE(!secret.ok());
    PF_CHECK(secret.issues[0].code == "SecretLiteral");        // rejected at load, never reaches the validator
}

PF_TEST(golden_flows_load_against_the_real_block_registry) {
    BlockRegistry reg;
    PF_REQUIRE(register_openvpn_blocks(reg));
    PF_REQUIRE(register_data_plane_blocks(reg));
    for (const char* name : {"flow_openvpn_rx.flow.json", "flow_data_v2_rx.flow.json", "flow_data_v2_tx.flow.json"}) {
        auto l = load_flow_json(slurp(std::string(GOLDEN_DIR) + "/" + name), reg);
        if (!l.ok()) std::printf("%s: %s %s %s\n", name, l.issues[0].code.c_str(), l.issues[0].path.c_str(), l.issues[0].message.c_str());
        PF_CHECK(l.ok());
        PF_CHECK(l.flow.node_count() > 0);
    }
}

// Differential: the validator (which reports precise paths) and FlowBuilder (which builds) must never disagree.
// If they did, compile_flow would report "Internal" for a document the validator let through.
PF_TEST(validator_never_disagrees_with_the_builder_on_random_documents) {
    auto reg = fake_registry();
    uint64_t s = 0x9E3779B97F4A7C15ull;
    auto rnd = [&](uint64_t n) { s = s * 6364136223846793005ull + 1442695040888963407ull; return (s >> 33) % n; };
    const char* blocks[] = {"act_a", "act_b", "act_c", "dec_d"};
    const char* ports[] = {"continue", "yes", "no"};
    size_t accepted = 0, rejected = 0;
    for (int iter = 0; iter < 6000; ++iter) {
        FlowDocument d;
        d.name = "r";
        const size_t n = 1 + rnd(6);
        for (size_t i = 0; i < n; ++i) d.nodes.push_back({"n" + std::to_string(i), blocks[rnd(4)], {}, {}});
        const size_t m = rnd(8);
        for (size_t i = 0; i < m; ++i) {
            const size_t from = rnd(n + 1), to = rnd(n + 2);   // sometimes unknown ids
            d.edges.push_back({from == n ? "ghost" : "n" + std::to_string(from),
                               to >= n + 1 ? std::nullopt : std::optional<std::string>(to == n ? "ghost" : "n" + std::to_string(to)),
                               ports[rnd(3)], {}});
        }
        auto c = compile_flow(d, reg);
        for (const auto& i : c.issues) PF_REQUIRE(i.code != "Internal");
        c.ok() ? ++accepted : ++rejected;
    }
    PF_CHECK(accepted > 100);                                  // the generator reaches both sides
    PF_CHECK(rejected > 100);
}
