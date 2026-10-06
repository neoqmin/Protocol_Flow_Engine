// F-3: what run_flow and MachineRunner record, in which order, and that tracing never changes behaviour.
#include <random>
#include <string>
#include <vector>

#include "pf/machine.h"
#include "pf/packet_buffer.h"
#include "pf/trace.h"
#include "pf_test.h"

using namespace pf;

namespace {

BlockResult t_go(FlowContext&) { return BlockResult::Continue; }
BlockResult t_is_odd(FlowContext& ctx) { return (ctx.flags & 1) ? BlockResult::Yes : BlockResult::No; }
BlockResult t_drop(FlowContext& ctx) { ctx.error = Error::ReplayDetected; return BlockResult::Drop; }
BlockResult t_trim(FlowContext& ctx) { ctx.packet->trim_back(4); return BlockResult::Continue; }
BlockResult t_bad(FlowContext&) { return BlockResult::Yes; }           // Action returning Yes: contract violation

BlockRegistry registry() {
    BlockRegistry r;
    PF_REQUIRE(r.add({921, "go", BlockType::Action, t_go}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({922, "is_odd", BlockType::Decision, t_is_odd}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({923, "drop", BlockType::Action, t_drop}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({924, "trim", BlockType::Action, t_trim}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({925, "bad", BlockType::Action, t_bad}) == BlockRegistry::AddStatus::Ok);
    return r;
}

// rx: start(go) -> odd?(is_odd) -yes-> cut(trim) -> end ; -no-> reject(drop)
Flow rx_flow(const BlockRegistry& r) {
    FlowBuilder b("rx");
    b.add("start", 921).add("odd", 922).add("cut", 924).add("reject", 923);
    b.on_yes("odd", "cut").on_no("odd", "reject").on_continue("cut", "");
    auto res = b.build(r);
    PF_REQUIRE(res.ok());
    return res.flow;
}

std::string brief(const TraceEntry& e) {
    std::string s = trace_kind_name(e.kind);
    s += " " + std::string(e.scope.view());
    if (!e.state.view().empty()) s += " [" + std::string(e.state.view()) + "]";
    if (!e.name.view().empty()) s += " " + std::string(e.name.view());
    if (!e.to.view().empty()) s += " -> " + std::string(e.to.view());
    if (e.error != Error::None) s += " !" + std::string(error_name(e.error));
    return s;
}
std::vector<std::string> briefs(const TraceRing& r) {
    std::vector<std::string> v;
    for (size_t i = 0; i < r.size(); ++i) v.push_back(brief(r.at(i)));
    return v;
}
void expect(const TraceRing& r, const std::vector<std::string>& want) {
    const auto got = briefs(r);
    PF_CHECK_EQ(got.size(), want.size());
    for (size_t i = 0; i < std::min(got.size(), want.size()); ++i) PF_CHECK_EQ(got[i], want[i]);
    if (got != want) for (const auto& g : got) std::fprintf(stderr, "  got: %s\n", g.c_str());
}

}  // namespace


PF_TEST(trace_flow_records_every_node_and_the_end) {
    const BlockRegistry reg = registry();
    const Flow f = rx_flow(reg);
    TraceRing ring(64);
    ring.now_ms = 777;
    PacketBuffer pkt = PacketBuffer::from_bytes(reinterpret_cast<const uint8_t*>("0123456789"), 10);
    FlowContext ctx;
    ctx.packet = &pkt;
    ctx.flags = 1;
    const FlowResult ok = run_flow(f, ctx, nullptr, kDefaultMaxSteps, &ring);
    PF_CHECK(ok.outcome == FlowOutcome::Completed);
    PF_REQUIRE(ring.size() == 4);
    PF_CHECK_EQ(std::string(ring.at(0).name.view()), std::string("start"));
    PF_CHECK_EQ(ring.at(0).block, BlockId{921});
    PF_CHECK_EQ(ring.at(0).value, uint32_t{10});              // packet length after the block
    PF_CHECK_EQ(ring.at(1).result, static_cast<uint8_t>(BlockResult::Yes));
    PF_CHECK_EQ(ring.at(2).value, uint32_t{6});               // after trim
    PF_CHECK(ring.at(3).kind == TraceKind::FlowEnd);
    PF_CHECK_EQ(std::string(ring.at(3).name.view()), std::string("cut"));
    PF_CHECK_EQ(ring.at(3).value, uint32_t{3});                // steps
    PF_CHECK_EQ(ring.at(3).t_ms, uint64_t{777});

    ring.clear();
    ctx.flags = 0;
    const FlowResult dropped = run_flow(f, ctx, nullptr, kDefaultMaxSteps, &ring);
    PF_CHECK(dropped.outcome == FlowOutcome::Dropped);
    PF_REQUIRE(ring.size() == 4);
    PF_CHECK_EQ(ring.at(2).error, Error::ReplayDetected);
    PF_CHECK_EQ(ring.at(3).result, static_cast<uint8_t>(FlowOutcome::Dropped));
    PF_CHECK_EQ(ring.at(3).error, Error::ReplayDetected);

    // contract violation and an empty flow still end with a FlowEnd record
    FlowBuilder b("broken");
    b.add("x", 925);
    auto br = b.build(reg);
    PF_REQUIRE(br.ok());
    ring.clear();
    PF_CHECK(run_flow(br.flow, ctx, nullptr, kDefaultMaxSteps, &ring).outcome == FlowOutcome::Errored);
    PF_REQUIRE(ring.size() == 2);
    PF_CHECK_EQ(ring.at(1).error, Error::Internal);
    ring.clear();
    run_flow(Flow(), ctx, nullptr, kDefaultMaxSteps, &ring);
    PF_REQUIRE(ring.size() == 1);
    PF_CHECK_EQ(ring.at(0).error, Error::FlowInvalid);
    PF_CHECK(ring.at(0).name.view().empty());
}

PF_TEST(trace_does_not_change_flow_results) {
    const BlockRegistry reg = registry();
    const Flow f = rx_flow(reg);
    std::mt19937 rng(5);
    TraceRing ring(16);                                         // small: overwrites constantly
    for (int i = 0; i < 2000; ++i) {
        const uint32_t flags = rng();
        const size_t len = 4 + rng() % 60;
        std::vector<uint8_t> bytes(len, static_cast<uint8_t>(i));
        PacketBuffer a = PacketBuffer::from_bytes(bytes.data(), bytes.size()), b = PacketBuffer::from_bytes(bytes.data(), bytes.size());
        FlowContext ca, cb;
        ca.packet = &a;
        cb.packet = &b;
        ca.flags = cb.flags = flags;
        FlowStats sa, sb;
        const FlowResult ra = run_flow(f, ca, &sa), rb = run_flow(f, cb, &sb, kDefaultMaxSteps, &ring);
        PF_CHECK(ra.outcome == rb.outcome && ra.error == rb.error && ra.steps == rb.steps && ra.last_node == rb.last_node);
        PF_CHECK(a.size() == b.size() && ca.error == cb.error && ca.flags == cb.flags);
        PF_CHECK(sa.completed == sb.completed && sa.dropped == sb.dropped);
    }
    PF_CHECK(ring.overwritten() > 0);
}

namespace {

BlockResult m_accept(FlowContext& ctx) {
    if (!(ctx.flags & 1)) { ctx.error = Error::AuthFailed; return BlockResult::Drop; }
    return BlockResult::Continue;
}

struct MachineRig {
    BlockRegistry reg;
    FlowLibrary lib;
    Machine m;
    MachineRig() {
        PF_REQUIRE(reg.add({931, "m_send", BlockType::Action, t_go}) == BlockRegistry::AddStatus::Ok);
        PF_REQUIRE(reg.add({932, "m_accept", BlockType::Action, m_accept}) == BlockRegistry::AddStatus::Ok);
        PF_REQUIRE(reg.add({933, "m_bad", BlockType::Action, t_bad}) == BlockRegistry::AddStatus::Ok);
        for (auto [name, id] : {std::pair<const char*, BlockId>{"send", 931}, {"accept", 932}, {"boom", 933}}) {
            FlowBuilder fb(name);
            fb.add("n", id);
            auto res = fb.build(reg);
            PF_REQUIRE(res.ok());
            lib.emplace(name, res.flow);
        }
        MachineBuilder b("stun");
        b.flow("send").flow("accept").flow("boom").event("command:start").event("packet:response").event("command:break").output("sent")
            .counter("tries", 2).timer_ms("rto", 100)
            .initial("idle").state("waiting").final_ok("done").final_failed("failed")
            .transition("idle", "command:start", "waiting").run("send").act({"arm:rto", "inc:tries", "emit:sent"})
            .transition("waiting", "packet:response", "done").run("accept").act({"cancel:rto"})
            .transition("waiting", "timer:rto", "waiting").when("tries", "<", 2).run("send").act({"arm:rto", "inc:tries", "emit:sent"})
            .transition("waiting", "timer:rto", "failed").when("tries", ">=", 2)
            .transition("waiting", "command:break", "done").run("boom");
        auto c = compile_machine(b.doc(), lib);
        PF_REQUIRE(c.ok());
        m = std::move(c.machine);
    }
};

}  // namespace

PF_TEST(trace_machine_records_events_transitions_emits_and_the_end) {
    MachineRig rig;
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    TraceRing ring(64);
    r->set_trace(&ring);
    FlowContext ctx;
    r->start(ctx, 0);
    r->on_event(*rig.m.find_event("packet:response"), ctx, 1);          // idle ignores it
    r->on_event(*rig.m.find_event("command:start"), ctx, 2);
    r->on_event(*rig.m.find_event("packet:response"), ctx, 50);         // forged: dropped by the handler
    r->poll_timer(ctx, 102);                                             // retry
    r->poll_timer(ctx, 202);                                             // give up
    r->on_event(*rig.m.find_event("command:start"), ctx, 300);          // finished: ignored
    r->on_event(*rig.m.find_event("timer:rto"), ctx, 301);              // misuse: rejected
    expect(ring, {
        "event stun [idle] packet:response",
        "event stun [idle] command:start",
        "node send n",
        "flow_end send n",
        "emit stun [idle] sent",
        "transition stun [idle] command:start -> waiting",
        "event stun [waiting] packet:response",
        "node accept n !AuthFailed",
        "flow_end accept n !AuthFailed",
        "event stun [waiting] timer:rto",
        "node send n",
        "flow_end send n",
        "emit stun [waiting] sent",
        "transition stun [waiting] timer:rto -> waiting",
        "event stun [waiting] timer:rto",
        "transition stun [waiting] timer:rto -> failed",
        "machine_end stun [failed]",
        "event stun [failed] command:start",
        "event stun [failed] timer:rto !Internal",
    });
    if (ring.size() == 19) {
        PF_CHECK_EQ(ring.at(0).result, static_cast<uint8_t>(TraceEvent::Ignored));
        PF_CHECK_EQ(ring.at(1).result, static_cast<uint8_t>(TraceEvent::Selected));
        PF_CHECK_EQ(ring.at(1).t_ms, uint64_t{2});
        PF_CHECK_EQ(ring.at(3).t_ms, uint64_t{2});                      // handler records carry the machine's clock
        PF_CHECK_EQ(ring.at(9).t_ms, uint64_t{102});
        PF_CHECK_EQ(ring.at(16).result, static_cast<uint8_t>(MachineStatus::Failed));
        PF_CHECK_EQ(ring.at(17).result, static_cast<uint8_t>(TraceEvent::Ignored));
        PF_CHECK_EQ(ring.at(18).result, static_cast<uint8_t>(TraceEvent::Rejected));
        PF_CHECK_EQ(ring.at(5).value, uint32_t{0});                      // transition index
        PF_CHECK_EQ(ring.at(15).value, uint32_t{3});
    }
}

PF_TEST(trace_machine_failure_by_handler_error_is_recorded) {
    MachineRig rig;
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    TraceRing ring(64);
    r->set_trace(&ring);
    FlowContext ctx;
    r->start(ctx, 0);
    r->on_event(*rig.m.find_event("command:start"), ctx, 1);
    ring.clear();
    r->on_event(*rig.m.find_event("command:break"), ctx, 2);
    expect(ring, {
        "event stun [waiting] command:break",
        "node boom n",
        "flow_end boom n !Internal",
        "machine_end stun [waiting] !Internal",      // failed where it was: no transition to "done"
    });
    if (ring.size() == 4) PF_CHECK_EQ(ring.at(3).result, static_cast<uint8_t>(MachineStatus::Failed));
}

PF_TEST(trace_does_not_change_machine_behaviour) {
    MachineRig rig;
    std::mt19937 rng(11);
    TraceRing ring(8);
    for (int round = 0; round < 300; ++round) {
        auto a = MachineRunner::create(rig.m, {});
        auto b = MachineRunner::create(rig.m, {});
        PF_REQUIRE(a && b);
        b->set_trace(&ring);
        FlowContext ca, cb;
        uint64_t now = 0;
        a->start(ca, now);
        b->start(cb, now);
        for (int k = 0; k < 20; ++k) {
            now += rng() % 80;
            const uint32_t flags = rng() & 1;
            ca.flags = cb.flags = flags;
            if (rng() & 1) {
                const size_t ev = rng() & 1 ? *rig.m.find_event("command:start") : *rig.m.find_event("packet:response");
                const MachineStep sa = a->on_event(ev, ca, now), sb = b->on_event(ev, cb, now);
                PF_CHECK(sa.handled == sb.handled && sa.dropped == sb.dropped && sa.emits == sb.emits && sa.transitions == sb.transitions);
            } else {
                const auto sa = a->poll_timer(ca, now);
                const auto sb = b->poll_timer(cb, now);
                PF_CHECK(sa.has_value() == sb.has_value());
            }
            PF_CHECK(a->state() == b->state() && a->status() == b->status() && a->next_deadline_ms() == b->next_deadline_ms());
        }
    }
}
