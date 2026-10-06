#include <string>

#include "pf/machine.h"
#include "pf_test.h"

using namespace pf;

namespace {

// Handler blocks. ctx.user_context -> Probe counts runs; ctx.flags bit 0 = "the response is authentic".
struct Probe { int sends = 0, accepts = 0; };
constexpr uint32_t kAuthentic = 1;

BlockResult blk_send(FlowContext& ctx) { static_cast<Probe*>(ctx.user_context)->sends++; return BlockResult::Continue; }
BlockResult blk_accept(FlowContext& ctx) {
    if (!(ctx.flags & kAuthentic)) { ctx.error = Error::AuthFailed; return BlockResult::Drop; }
    static_cast<Probe*>(ctx.user_context)->accepts++;
    return BlockResult::Continue;
}
BlockResult blk_broken(FlowContext& ctx) { ctx.error = Error::BufferTooSmall; return BlockResult::Error; }

FlowLibrary library() {
    BlockRegistry r;
    PF_REQUIRE(r.add({901, "t_send", BlockType::Action, blk_send}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({902, "t_accept", BlockType::Action, blk_accept}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({903, "t_broken", BlockType::Action, blk_broken}) == BlockRegistry::AddStatus::Ok);
    FlowLibrary lib;
    auto one = [&](const char* name, BlockId id) {
        FlowBuilder fb(name);
        fb.add("n", id);
        auto res = fb.build(r);
        PF_REQUIRE(res.ok());
        lib.emplace(name, res.flow);
    };
    one("send", 901);
    one("accept", 902);
    one("broken", 903);
    return lib;
}

MachineBuilder stun_like() {
    MachineBuilder b("stun_binding");
    b.flow("send").flow("accept").flow("broken")
        .event("command:start").event("packet:response").event("command:break")
        .counter("tries", 3).timer_ms("rto", 100)
        .initial("idle").state("waiting").final_ok("done").final_failed("failed")
        .transition("idle", "command:start", "waiting").run("send").act({"arm:rto", "inc:tries"})
        .transition("waiting", "packet:response", "done").run("accept").act({"cancel:rto"})
        .transition("waiting", "command:break", "done").run("broken")
        .transition("waiting", "timer:rto", "waiting").when("tries", "<", 3).run("send").act({"arm:rto", "inc:tries"})
        .transition("waiting", "timer:rto", "failed").when("tries", ">=", 3);
    return b;
}

struct Rig {
    FlowLibrary lib = library();
    Machine m;
    Probe probe;
    FlowContext ctx;
    explicit Rig(const MachineDocument& d) {
        auto c = compile_machine(d, lib);
        for (const auto& i : c.issues) std::fprintf(stderr, "%s %s %s\n", i.code.c_str(), i.path.c_str(), i.message.c_str());
        PF_REQUIRE(c.ok());
        m = std::move(c.machine);
        ctx.user_context = &probe;
    }
    size_t ev(const char* name) {
        auto e = m.find_event(name);
        PF_REQUIRE(e.has_value());
        return *e;
    }
    size_t st(const char* name) { return *m.find_state(name); }
};

}  // namespace

PF_TEST(machine_runner_param_resolution) {
    MachineBuilder b("m");
    b.event("command:go").timer_param("t", "periodMs").timer_param("opt", "optMs", true)
        .initial("a").final_ok("end")
        .transition("a", "command:go", "a").act({"arm:t", "arm:opt"})
        .transition("a", "timer:t", "end").transition("a", "timer:opt", "end");
    Rig rig(b.doc());
    std::string err;
    PF_CHECK(!MachineRunner::create(rig.m, {{"optMs", 0}}, &err));
    PF_CHECK(err.find("periodMs") != std::string::npos);
    PF_CHECK(!MachineRunner::create(rig.m, {{"periodMs", 10}, {"optMs", 0}, {"typo", 1}}, &err));
    PF_CHECK(err.find("typo") != std::string::npos);
    PF_CHECK(!MachineRunner::create(rig.m, {{"periodMs", 0}, {"optMs", 0}}, &err));          // not allowDisabled
    PF_CHECK(!MachineRunner::create(rig.m, {{"periodMs", kMachineTimerMaxMs + 1}, {"optMs", 0}}, &err));
    PF_CHECK(!MachineRunner::create(Machine(), {}, &err));                                     // never compiled

    auto r = MachineRunner::create(rig.m, {{"periodMs", 10}, {"optMs", 0}});
    PF_REQUIRE(r.has_value());
    r->start(rig.ctx, 0);
    r->on_event(rig.ev("command:go"), rig.ctx, 5);
    PF_CHECK(r->timer_deadline(0) == std::optional<uint64_t>(15));
    PF_CHECK(!r->timer_deadline(1).has_value());          // disabled: arm is a no-op
    PF_CHECK(r->next_deadline_ms() == std::optional<uint64_t>(15));
}

PF_TEST(machine_runner_retries_then_fails) {
    Rig rig(stun_like().doc());
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    PF_CHECK_EQ(r->start(rig.ctx, 1000).transitions.size(), size_t{0});
    PF_CHECK_EQ(r->state(), rig.st("idle"));
    PF_CHECK(!r->next_deadline_ms().has_value());

    const MachineStep s = r->on_event(rig.ev("command:start"), rig.ctx, 1000);
    PF_CHECK(s.handled);
    PF_CHECK_EQ(s.flow_runs, size_t{1});
    PF_CHECK_EQ(rig.probe.sends, 1);
    PF_CHECK_EQ(r->state(), rig.st("waiting"));
    PF_CHECK_EQ(r->counter(0), int64_t{1});
    PF_CHECK(r->next_deadline_ms() == std::optional<uint64_t>(1100));

    PF_CHECK(!r->poll_timer(rig.ctx, 1099).has_value());    // not due yet
    for (int k = 2; k <= 3; ++k) {
        const auto t = r->poll_timer(rig.ctx, 1000 + 100 * (k - 1));
        PF_REQUIRE(t.has_value());
        PF_CHECK_EQ(rig.probe.sends, k);
        PF_CHECK_EQ(r->counter(0), int64_t{k});
        PF_CHECK_EQ(r->state(), rig.st("waiting"));
    }
    const auto last = r->poll_timer(rig.ctx, 1300);
    PF_REQUIRE(last.has_value());
    PF_CHECK(last->status == MachineStatus::Failed);
    PF_CHECK_EQ(r->state(), rig.st("failed"));
    PF_CHECK_EQ(rig.probe.sends, 3);                        // no 4th send
    PF_CHECK(!r->next_deadline_ms().has_value());
    PF_CHECK(!r->poll_timer(rig.ctx, 99999).has_value());
    const MachineStep after = r->on_event(rig.ev("packet:response"), rig.ctx, 1400);
    PF_CHECK(!after.handled);                               // a finished machine ignores events
    PF_CHECK(after.status == MachineStatus::Failed);
}

PF_TEST(machine_runner_forged_input_does_not_move_the_machine) {
    Rig rig(stun_like().doc());
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    r->start(rig.ctx, 0);
    r->on_event(rig.ev("command:start"), rig.ctx, 0);

    rig.ctx.flags = 0;                                      // forged response: handler drops it
    const MachineStep forged = r->on_event(rig.ev("packet:response"), rig.ctx, 10);
    PF_CHECK(forged.handled);
    PF_CHECK(forged.dropped);
    PF_CHECK_EQ(forged.error, Error::AuthFailed);
    PF_CHECK(forged.transitions.empty());
    PF_CHECK_EQ(r->state(), rig.st("waiting"));
    PF_CHECK(r->next_deadline_ms() == std::optional<uint64_t>(100));   // the cancel:rto action did not run
    PF_CHECK(r->status() == MachineStatus::Running);

    rig.ctx.flags = kAuthentic;
    const MachineStep real = r->on_event(rig.ev("packet:response"), rig.ctx, 20);
    PF_CHECK(!real.dropped);
    PF_CHECK(real.status == MachineStatus::Succeeded);
    PF_CHECK_EQ(rig.probe.accepts, 1);
    PF_CHECK(!r->next_deadline_ms().has_value());
}

PF_TEST(machine_runner_handler_error_fails_the_machine) {
    Rig rig(stun_like().doc());
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    r->start(rig.ctx, 0);
    r->on_event(rig.ev("command:start"), rig.ctx, 0);
    const MachineStep s = r->on_event(rig.ev("command:break"), rig.ctx, 1);
    PF_CHECK(s.status == MachineStatus::Failed);
    PF_CHECK_EQ(s.error, Error::BufferTooSmall);
    PF_CHECK_EQ(r->error(), Error::BufferTooSmall);
    PF_CHECK_EQ(r->state(), rig.st("waiting"));             // it failed where it was, it did not reach "done"
    PF_CHECK(!r->next_deadline_ms().has_value());
}

PF_TEST(machine_runner_api_misuse_is_reported_not_executed) {
    Rig rig(stun_like().doc());
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    PF_CHECK_EQ(r->on_event(rig.ev("command:start"), rig.ctx, 0).error, Error::Internal);   // before start
    r->start(rig.ctx, 0);
    PF_CHECK_EQ(r->start(rig.ctx, 0).error, Error::Internal);                               // twice
    PF_CHECK_EQ(r->on_event(rig.ev("timer:rto"), rig.ctx, 0).error, Error::Internal);       // timers fire via poll_timer
    PF_CHECK_EQ(r->on_event(rig.ev("auto"), rig.ctx, 0).error, Error::Internal);
    PF_CHECK_EQ(r->on_event(9999, rig.ctx, 0).error, Error::Internal);
    PF_CHECK_EQ(r->state(), rig.st("idle"));
    PF_CHECK(r->status() == MachineStatus::Running);

    const MachineStep unhandled = r->on_event(rig.ev("packet:response"), rig.ctx, 0);       // idle ignores responses
    PF_CHECK(!unhandled.handled);
    PF_CHECK_EQ(unhandled.error, Error::None);
    PF_CHECK_EQ(r->state(), rig.st("idle"));
}

PF_TEST(machine_runner_actions_in_order_and_auto_chain) {
    MachineBuilder b("m");
    b.event("command:go").output("a").output("b").counter("n", 2)
        .initial("s").state("mid").final_ok("two").final_failed("one")
        .transition("s", "command:go", "mid").act({"emit:b", "inc:n", "emit:a", "inc:n", "inc:n"})   // inc saturates at max
        .transition("mid", "auto", "two").when("n", ">=", 2).act({"emit:a"})
        .transition("mid", "auto", "one").when("n", "<", 2);
    Rig rig(b.doc());
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    r->start(rig.ctx, 0);
    const MachineStep s = r->on_event(rig.ev("command:go"), rig.ctx, 0);
    PF_CHECK_EQ(s.emits.size(), size_t{3});
    if (s.emits.size() == 3) {
        PF_CHECK_EQ(rig.m.output_name(s.emits[0]), std::string("b"));
        PF_CHECK_EQ(rig.m.output_name(s.emits[1]), std::string("a"));
        PF_CHECK_EQ(rig.m.output_name(s.emits[2]), std::string("a"));
    }
    PF_CHECK_EQ(s.transitions.size(), size_t{2});
    PF_CHECK_EQ(r->counter(0), int64_t{2});
    PF_CHECK(s.status == MachineStatus::Succeeded);

    // auto transitions from the initial state run at start()
    MachineBuilder boot("m");
    boot.event("command:go").timer_ms("t", 7).initial("init").state("ready").final_ok("end")
        .transition("init", "auto", "ready").act({"arm:t"})
        .transition("ready", "timer:t", "end").transition("ready", "command:go", "end");
    Rig rig2(boot.doc());
    auto r2 = MachineRunner::create(rig2.m, {});
    PF_REQUIRE(r2.has_value());
    const MachineStep st = r2->start(rig2.ctx, 100);
    PF_CHECK_EQ(st.transitions.size(), size_t{1});
    PF_CHECK_EQ(r2->state(), rig2.st("ready"));
    PF_CHECK(r2->next_deadline_ms() == std::optional<uint64_t>(107));
}

PF_TEST(machine_runner_timer_order_and_rearm) {
    MachineBuilder b("m");
    b.event("command:kick").output("first").output("second").timer_ms("x", 50).timer_ms("y", 50)
        .initial("s").state("w").final_ok("end")
        .transition("s", "command:kick", "w").act({"arm:y", "arm:x"})
        .transition("w", "command:kick", "w").act({"arm:x"})
        .transition("w", "timer:x", "w").act({"emit:first"}).unbounded("test")
        .transition("w", "timer:y", "end").act({"emit:second"});
    Rig rig(b.doc());
    auto r = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r.has_value());
    r->start(rig.ctx, 0);
    r->on_event(rig.ev("command:kick"), rig.ctx, 0);
    const auto t1 = r->poll_timer(rig.ctx, 50);            // same deadline: declaration order (x before y)
    PF_REQUIRE(t1.has_value());
    PF_CHECK_EQ(rig.m.output_name(t1->emits.at(0)), std::string("first"));
    const auto t2 = r->poll_timer(rig.ctx, 50);
    PF_REQUIRE(t2.has_value());
    PF_CHECK_EQ(rig.m.output_name(t2->emits.at(0)), std::string("second"));
    PF_CHECK(t2->status == MachineStatus::Succeeded);

    // re-arming moves the deadline; a fired timer stays disarmed until armed again
    auto r2 = MachineRunner::create(rig.m, {});
    PF_REQUIRE(r2.has_value());
    r2->start(rig.ctx, 0);
    r2->on_event(rig.ev("command:kick"), rig.ctx, 0);
    r2->on_event(rig.ev("command:kick"), rig.ctx, 30);
    PF_CHECK(r2->timer_deadline(*rig.m.find_timer("x")) == std::optional<uint64_t>(80));
    PF_CHECK(r2->next_deadline_ms() == std::optional<uint64_t>(50));         // y
    r2->poll_timer(rig.ctx, 50);
    PF_CHECK(r2->status() == MachineStatus::Succeeded);
    PF_CHECK(!r2->timer_deadline(*rig.m.find_timer("x")).has_value());     // entering a final state disarms every timer
}
