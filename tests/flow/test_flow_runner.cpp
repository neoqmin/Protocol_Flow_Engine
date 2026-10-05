#include <string>
#include "pf/flow.h"
#include "pf_test.h"

using namespace pf;

// Blocks record their name into a trace so tests can assert execution order.
static std::string g_trace;
static BlockResult b_a(FlowContext&) { g_trace += "a"; return BlockResult::Continue; }
static BlockResult b_b(FlowContext&) { g_trace += "b"; return BlockResult::Continue; }
static BlockResult b_c(FlowContext&) { g_trace += "c"; return BlockResult::Continue; }
static BlockResult b_yes(FlowContext&) { g_trace += "Y"; return BlockResult::Yes; }
static BlockResult b_no(FlowContext&) { g_trace += "N"; return BlockResult::No; }
static BlockResult b_drop(FlowContext& c) { g_trace += "D"; c.error = Error::PolicyDenied; return BlockResult::Drop; }
static BlockResult b_drop_noerr(FlowContext&) { g_trace += "d"; return BlockResult::Drop; }
static BlockResult b_fail(FlowContext& c) { g_trace += "E"; c.error = Error::Internal; return BlockResult::Error; }
static BlockResult b_action_says_yes(FlowContext&) { return BlockResult::Yes; }
static BlockResult b_decision_says_continue(FlowContext&) { return BlockResult::Continue; }

static BlockRegistry reg() {
    BlockRegistry r;
    r.add({1, "a", BlockType::Action, b_a});
    r.add({2, "b", BlockType::Action, b_b});
    r.add({3, "c", BlockType::Action, b_c});
    r.add({4, "yes", BlockType::Decision, b_yes});
    r.add({5, "no", BlockType::Decision, b_no});
    r.add({6, "drop", BlockType::Action, b_drop});
    r.add({7, "drop_noerr", BlockType::Action, b_drop_noerr});
    r.add({8, "fail", BlockType::Action, b_fail});
    r.add({9, "bad_action", BlockType::Action, b_action_says_yes});
    r.add({10, "bad_decision", BlockType::Decision, b_decision_says_continue});
    return r;
}

static Flow must_build(FlowBuilder& b, const BlockRegistry& r) {
    auto res = b.build(r);
    PF_REQUIRE(res.ok());
    return std::move(res.flow);
}

PF_TEST(runner_executes_linear_flow_in_order) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("lin"); b.add("a", 1).add("b", 2).add("c", 3);
    Flow f = must_build(b, r);
    FlowContext ctx;
    FlowResult res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Completed);
    PF_CHECK(g_trace == "abc");
    PF_CHECK_EQ(res.steps, size_t(3));
    PF_CHECK_EQ(res.last_node, size_t(2));
    PF_CHECK(res.error == Error::None);
}

PF_TEST(runner_follows_yes_branch) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("d");
    b.add("d", 4).add("t", 1).add("f", 2);
    b.on_yes("d", "t").on_no("d", "f").on_continue("t", "");
    Flow f = must_build(b, r);
    FlowContext ctx;
    PF_CHECK(run_flow(f, ctx).outcome == FlowOutcome::Completed);
    PF_CHECK(g_trace == "Ya");
}

PF_TEST(runner_follows_no_branch) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("d");
    b.add("d", 5).add("t", 1).add("f", 2);
    b.on_yes("d", "t").on_no("d", "f").on_continue("t", "");
    Flow f = must_build(b, r);
    FlowContext ctx;
    PF_CHECK(run_flow(f, ctx).outcome == FlowOutcome::Completed);
    PF_CHECK(g_trace == "Nb");
}

PF_TEST(drop_terminates_flow_and_reports_reason) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("x"); b.add("a", 1).add("drop", 6).add("c", 3);
    Flow f = must_build(b, r);
    FlowContext ctx;
    FlowResult res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Dropped);
    PF_CHECK(res.error == Error::PolicyDenied);
    PF_CHECK(g_trace == "aD");              // "c" never ran
    PF_CHECK_EQ(res.last_node, size_t(1));
}

PF_TEST(error_terminates_flow_as_errored) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("x"); b.add("fail", 8).add("c", 3);
    Flow f = must_build(b, r);
    FlowContext ctx;
    FlowResult res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Errored);
    PF_CHECK(res.error == Error::Internal);
    PF_CHECK(g_trace == "E");
}

PF_TEST(drop_without_reason_is_a_contract_violation) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("x"); b.add("drop_noerr", 7);
    Flow f = must_build(b, r);
    FlowContext ctx;
    FlowResult res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Errored);
    PF_CHECK(res.error == Error::Internal);
}

PF_TEST(action_returning_yes_is_a_contract_violation) {
    auto r = reg();
    FlowBuilder b("x"); b.add("bad", 9);
    Flow f = must_build(b, r);
    FlowContext ctx;
    FlowResult res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Errored);
    PF_CHECK(res.error == Error::Internal);
}

PF_TEST(decision_returning_continue_is_a_contract_violation) {
    auto r = reg();
    FlowBuilder b("x");
    b.add("bad", 10).add("t", 1);
    b.on_yes("bad", "t").on_no("bad", "t");
    Flow f = must_build(b, r);
    FlowContext ctx;
    PF_CHECK(run_flow(f, ctx).outcome == FlowOutcome::Errored);
}

PF_TEST(runner_clears_stale_error_before_running) {
    auto r = reg(); g_trace.clear();
    FlowBuilder b("x"); b.add("a", 1);
    Flow f = must_build(b, r);
    FlowContext ctx;
    ctx.error = Error::ReplayDetected;      // stale value from a previous packet
    FlowResult res = run_flow(f, ctx);
    PF_CHECK(res.outcome == FlowOutcome::Completed);
    PF_CHECK(res.error == Error::None);
    PF_CHECK(ctx.error == Error::None);
}

PF_TEST(step_limit_stops_runaway_flows) {
    auto r = reg();
    FlowBuilder b("x"); b.add("a", 1).add("b", 2).add("c", 3);
    Flow f = must_build(b, r);
    FlowContext ctx;
    FlowResult res = run_flow(f, ctx, nullptr, /*max_steps=*/2);
    PF_CHECK(res.outcome == FlowOutcome::Errored);
    PF_CHECK(res.error == Error::StepLimit);
    PF_CHECK_EQ(res.steps, size_t(2));
}

PF_TEST(stats_count_outcomes_and_drop_reasons) {
    auto r = reg();
    FlowBuilder ok("ok"); ok.add("a", 1);
    FlowBuilder dr("dr"); dr.add("drop", 6);
    FlowBuilder er("er"); er.add("fail", 8);
    Flow f_ok = must_build(ok, r), f_dr = must_build(dr, r), f_er = must_build(er, r);
    FlowStats st;
    FlowContext c;
    run_flow(f_ok, c, &st); run_flow(f_dr, c, &st); run_flow(f_dr, c, &st); run_flow(f_er, c, &st);
    PF_CHECK_EQ(st.completed, uint64_t(1));
    PF_CHECK_EQ(st.dropped, uint64_t(2));
    PF_CHECK_EQ(st.errored, uint64_t(1));
    PF_CHECK_EQ(st.by_error[static_cast<size_t>(Error::PolicyDenied)], uint64_t(2));
    PF_CHECK_EQ(st.by_error[static_cast<size_t>(Error::Internal)], uint64_t(1));
}
