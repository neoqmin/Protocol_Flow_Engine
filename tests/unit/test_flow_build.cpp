#include <algorithm>
#include "pf/flow.h"
#include "pf_test.h"

using namespace pf;

static BlockResult act(FlowContext&) { return BlockResult::Continue; }
static BlockResult dec(FlowContext&) { return BlockResult::Yes; }

static BlockRegistry make_registry() {
    BlockRegistry r;
    r.add({1, "act_a", BlockType::Action, act});
    r.add({2, "act_b", BlockType::Action, act});
    r.add({3, "dec", BlockType::Decision, dec});
    return r;
}

static bool has_error(const FlowBuildResult& r, const char* needle) {
    return std::any_of(r.errors.begin(), r.errors.end(),
                       [&](const std::string& e) { return e.find(needle) != std::string::npos; });
}

PF_TEST(linear_flow_builds_with_default_continue_edges) {
    auto reg = make_registry();
    FlowBuilder b("lin");
    b.add("a", 1); b.add("b", 2);
    auto r = b.build(reg);
    PF_CHECK(r.ok());
    PF_CHECK_EQ(r.flow.node_count(), size_t(2));
    PF_CHECK_EQ(r.flow.node(0).on_continue, size_t(1));
    PF_CHECK_EQ(r.flow.node(1).on_continue, kNoNode);   // last node ends the flow
}

PF_TEST(decision_flow_with_both_edges_builds) {
    auto reg = make_registry();
    FlowBuilder b("dec");
    b.add("d", 3); b.add("yes_path", 1); b.add("no_path", 2);
    b.on_yes("d", "yes_path").on_no("d", "no_path");
    b.on_continue("yes_path", "");   // explicit end: yes path must not fall into no_path
    auto r = b.build(reg);
    PF_CHECK(r.ok());
    PF_CHECK_EQ(r.flow.node(0).on_yes, size_t(1));
    PF_CHECK_EQ(r.flow.node(0).on_no, size_t(2));
    PF_CHECK_EQ(r.flow.node(1).on_continue, kNoNode);
}

PF_TEST(empty_flow_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("empty");
    PF_CHECK(!b.build(reg).ok());
}

PF_TEST(unknown_block_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("a", 42);
    PF_CHECK(has_error(b.build(reg), "unknown block"));
}

PF_TEST(duplicate_label_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("a", 1); b.add("a", 2);
    PF_CHECK(has_error(b.build(reg), "duplicate label"));
}

PF_TEST(decision_missing_an_edge_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("d", 3); b.add("t", 1);
    b.on_yes("d", "t");
    PF_CHECK(has_error(b.build(reg), "missing NO edge"));
}

PF_TEST(action_with_yes_no_edge_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("a", 1); b.add("t", 2);
    b.on_yes("a", "t");
    PF_CHECK(has_error(b.build(reg), "not a decision"));
}

PF_TEST(edge_to_unknown_label_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("a", 1);
    b.on_continue("a", "ghost");
    PF_CHECK(has_error(b.build(reg), "unknown label"));
}

PF_TEST(cycle_is_rejected) {  // plan section 22: loop violation
    auto reg = make_registry();
    FlowBuilder b("loop");
    b.add("a", 1); b.add("b", 2);
    b.on_continue("b", "a");
    PF_CHECK(has_error(b.build(reg), "cycle"));
}

PF_TEST(unreachable_node_is_rejected) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("a", 1); b.add("orphan", 2);
    b.on_continue("a", "");      // explicit end, so orphan is unreachable
    PF_CHECK(has_error(b.build(reg), "unreachable"));
}

PF_TEST(build_collects_multiple_errors) {
    auto reg = make_registry();
    FlowBuilder b("x");
    b.add("a", 42); b.add("a", 43);
    PF_CHECK(b.build(reg).errors.size() >= 2);
}
