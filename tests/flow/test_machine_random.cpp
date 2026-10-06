// Differential test of the Machine Validator against the runner (plan S2): for thousands of random machines, whatever
// the validator ACCEPTS must behave - no auto-transition runaway (StepLimit) and, once the network goes silent, the
// machine must stop on its own (finish, or have no timer left) after a bounded number of timer firings. This is the
// property UnboundedRetry / ImmediateCycle exist to guarantee.
#include <random>
#include <string>

#include "pf/machine.h"
#include "pf/machine_json.h"
#include "pf_test.h"

using namespace pf;

namespace {

BlockResult blk_pass(FlowContext&) { return BlockResult::Continue; }
BlockResult blk_drop(FlowContext& ctx) { ctx.error = Error::PolicyDenied; return BlockResult::Drop; }

FlowLibrary library() {
    BlockRegistry r;
    PF_REQUIRE(r.add({911, "r_pass", BlockType::Action, blk_pass}) == BlockRegistry::AddStatus::Ok);
    PF_REQUIRE(r.add({912, "r_drop", BlockType::Action, blk_drop}) == BlockRegistry::AddStatus::Ok);
    FlowLibrary lib;
    for (auto [name, id] : {std::pair<const char*, BlockId>{"pass", 911}, {"drop", 912}}) {
        FlowBuilder fb(name);
        fb.add("n", id);
        auto res = fb.build(r);
        PF_REQUIRE(res.ok());
        lib.emplace(name, res.flow);
    }
    return lib;
}

MachineDocument random_machine(std::mt19937& rng) {
    auto pick = [&](size_t n) { return static_cast<size_t>(std::uniform_int_distribution<size_t>(0, n - 1)(rng)); };
    auto coin = [&](int pct) { return static_cast<int>(pick(100)) < pct; };
    MachineBuilder b("rnd");
    b.flow("pass").flow("drop").event("packet:p").event("command:c").output("o");
    const size_t ncounters = pick(3), ntimers = pick(3), nstates = 2 + pick(5);
    std::vector<int64_t> maxes;
    for (size_t i = 0; i < ncounters; ++i) { maxes.push_back(1 + static_cast<int64_t>(pick(4))); b.counter("c" + std::to_string(i), maxes.back()); }
    for (size_t i = 0; i < ntimers; ++i) b.timer_ms("t" + std::to_string(i), 1 + static_cast<int64_t>(pick(50)));
    const size_t nfinal = 1 + pick(2);
    for (size_t s = 0; s < nstates; ++s) {
        const std::string id = "s" + std::to_string(s);
        if (s == 0) b.initial(id);
        else if (s + nfinal >= nstates) (coin(50) ? b.final_ok(id) : b.final_failed(id));
        else b.state(id);
    }
    const size_t nonfinal = nstates - nfinal;
    const size_t ntrans = 1 + pick(12);
    for (size_t k = 0; k < ntrans; ++k) {
        std::vector<std::string> ons{"packet:p", "command:c", "auto"};
        for (size_t i = 0; i < ntimers; ++i) ons.push_back("timer:t" + std::to_string(i));
        b.transition("s" + std::to_string(pick(nonfinal)), ons[pick(ons.size())], "s" + std::to_string(pick(nstates)));
        if (ncounters && coin(50)) {
            const size_t c = pick(ncounters);
            b.when("c" + std::to_string(c), coin(50) ? "<" : ">=", static_cast<int64_t>(pick(static_cast<size_t>(maxes[c]) + 1)));
        }
        if (coin(25)) b.run(coin(70) ? "pass" : "drop");
        const size_t nact = pick(4);
        for (size_t a = 0; a < nact; ++a) {
            const size_t kind = pick(5);
            if (kind <= 1 && ncounters) b.act({std::string(kind == 0 ? "inc:c" : "reset:c") + std::to_string(pick(ncounters))});
            else if (kind <= 3 && ntimers) b.act({std::string(kind == 2 ? "arm:t" : "cancel:t") + std::to_string(pick(ntimers))});
            else b.act({"emit:o"});
        }
    }
    return b.doc();
}

// Mostly-valid machines: work states that wait for packets, retry on timers with counter-bounded loops (self loops or
// two-state rings), forward auto transitions; then, sometimes, one random mutation (which often makes them invalid).
MachineDocument structured_machine(std::mt19937& rng) {
    auto pick = [&](size_t n) { return static_cast<size_t>(std::uniform_int_distribution<size_t>(0, n - 1)(rng)); };
    auto coin = [&](int pct) { return static_cast<int>(pick(100)) < pct; };
    MachineBuilder b("rnd");
    b.flow("pass").flow("drop").event("packet:p").event("command:c").output("o");
    const size_t work = 1 + pick(4), ncounters = 1 + pick(2), ntimers = 1 + pick(2);
    std::vector<int64_t> maxes;
    for (size_t i = 0; i < ncounters; ++i) { maxes.push_back(1 + static_cast<int64_t>(pick(4))); b.counter("c" + std::to_string(i), maxes.back()); }
    for (size_t i = 0; i < ntimers; ++i) b.timer_ms("t" + std::to_string(i), 1 + static_cast<int64_t>(pick(50)));
    b.initial("s0");
    for (size_t w = 1; w <= work; ++w) b.state("s" + std::to_string(w));
    b.final_ok("done").final_failed("fail");
    auto st = [](size_t i) { return "s" + std::to_string(i); };
    auto any_state = [&]() { const size_t k = pick(work + 2); return k < work ? st(1 + k) : (k == work ? std::string("done") : std::string("fail")); };
    auto timer = [&]() { return "t" + std::to_string(pick(ntimers)); };
    auto counter = [&]() { return pick(ncounters); };

    b.transition("s0", "command:c", st(1));
    for (size_t i = 0; i < ntimers; ++i) b.act({"arm:t" + std::to_string(i)});
    if (coin(50)) b.act({"reset:c" + std::to_string(counter())});
    for (size_t w = 1; w <= work; ++w) {
        b.transition(st(w), "packet:p", any_state());
        if (coin(40)) b.run(coin(70) ? "pass" : "drop");
        if (coin(40)) b.act({"reset:c" + std::to_string(counter()), "arm:" + timer()});
        if (coin(40)) b.transition(st(w), "command:c", any_state()).act({"arm:" + timer()});
        const std::string t = timer();
        const size_t c = counter();
        const std::string cn = "c" + std::to_string(c);
        const int64_t lim = 1 + static_cast<int64_t>(pick(static_cast<size_t>(maxes[c])));
        if (w < work && coin(30)) {                       // two-state ring w <-> w+1 on the same timer and counter
            b.transition(st(w), "timer:" + t, st(w + 1)).when(cn, "<", lim).act({"inc:" + cn, "arm:" + t});
            b.transition(st(w), "timer:" + t, "fail").when(cn, ">=", lim);
            b.transition(st(w + 1), "timer:" + t, st(w)).when(cn, "<", lim).act({"inc:" + cn, "arm:" + t, "emit:o"});
            b.transition(st(w + 1), "timer:" + t, coin(50) ? "fail" : "done").when(cn, ">=", lim);
        } else {
            b.transition(st(w), "timer:" + t, st(w)).when(cn, "<", lim).act({"inc:" + cn, "arm:" + t});
            if (coin(50)) b.run("pass");
            b.transition(st(w), "timer:" + t, coin(30) && w < work ? st(w + 1) : std::string("fail")).when(cn, ">=", lim).act({"arm:" + t});
        }
        if (w < work && coin(30)) b.transition(st(w), "auto", st(w + 1 + pick(work - w))).when(cn, ">=", lim);
    }
    MachineDocument d = b.doc();
    if (coin(35) && !d.transitions.empty()) {             // one mutation
        auto& tr = d.transitions[pick(d.transitions.size())];
        switch (pick(6)) {
            case 0: tr.guard.reset(); break;
            case 1: tr.actions.clear(); break;
            case 2: tr.actions.push_back("reset:c" + std::to_string(counter())); break;
            case 3: if (tr.guard) tr.guard->op = tr.guard->op == "<" ? ">=" : "<"; break;
            case 4: tr.to = any_state(); break;
            default: tr.on = coin(50) ? "auto" : "timer:" + timer(); break;
        }
    }
    return d;
}

// Delivers only timers (the network is silent). Returns firings, or -1 if the bound was exceeded.
long silence(MachineRunner& r, FlowContext& ctx, uint64_t& now, long bound) {
    long firings = 0;
    while (r.status() == MachineStatus::Running) {
        const auto d = r.next_deadline_ms();
        if (!d) break;
        now = *d;
        if (!r.poll_timer(ctx, now)) return -2;            // next_deadline must be pollable
        if (r.error() == Error::StepLimit) return -3;
        if (++firings > bound) return -1;
    }
    return firings;
}

}  // namespace

PF_TEST(machine_validator_accepted_machines_terminate_under_silence) {
    const FlowLibrary lib = library();
    std::mt19937 rng(20261006);
    size_t generated = 0, accepted = 0, with_timer_loops = 0;
    for (; generated < 30000; ++generated) {
        const MachineDocument doc = (generated % 3 == 0) ? random_machine(rng) : structured_machine(rng);
        auto c = compile_machine(doc, lib);
        if (!c.ok()) continue;
        ++accepted;
        auto r = MachineRunner::create(c.machine, {});
        PF_REQUIRE(r.has_value());
        FlowContext ctx;
        uint64_t now = 0;
        r->start(ctx, now);
        PF_CHECK(r->error() != Error::StepLimit);

        // Bound: every timer transition inside a loop increments a counter it is guarded by (each <= 4), so the number
        // of firings under silence is small. 10000 is far above any honest machine here and far below "forever".
        // Silence right away, and silence after a single command (which starts the work in the structured machines).
        long f = silence(*r, ctx, now, 10000);
        if (f < 0) { PF_CHECK(false); std::fprintf(stderr, "case %zu: silence result %ld\n%s", generated, f, write_machine_json(doc).c_str()); break; }
        auto r1 = MachineRunner::create(c.machine, {});
        PF_REQUIRE(r1.has_value());
        now = 0;
        r1->start(ctx, now);
        r1->on_event(*c.machine.find_event("command:c"), ctx, now);
        f = silence(*r1, ctx, now, 10000);
        if (f < 0) { PF_CHECK(false); std::fprintf(stderr, "case %zu (command): silence result %ld\n%s", generated, f, write_machine_json(doc).c_str()); break; }
        if (f > 2) ++with_timer_loops;

        // Then random traffic (packets/commands, timers delivered at their deadlines), then silence again.
        auto r2 = MachineRunner::create(c.machine, {});
        PF_REQUIRE(r2.has_value());
        now = 0;
        r2->start(ctx, now);
        const size_t p = *c.machine.find_event("packet:p"), cmd = *c.machine.find_event("command:c");
        for (int k = 0; k < 40 && r2->status() == MachineStatus::Running; ++k) {
            const uint64_t at = now + std::uniform_int_distribution<uint64_t>(0, 30)(rng);
            while (r2->next_deadline_ms() && *r2->next_deadline_ms() < at) { now = *r2->next_deadline_ms(); r2->poll_timer(ctx, now); }
            now = at;
            r2->on_event(rng() & 1 ? p : cmd, ctx, now);
            PF_CHECK(r2->error() != Error::StepLimit);
        }
        f = silence(*r2, ctx, now, 10000);
        if (f < 0) { PF_CHECK(false); std::fprintf(stderr, "case %zu (traffic): silence result %ld\n%s", generated, f, write_machine_json(doc).c_str()); break; }
        if (f > 2) ++with_timer_loops;
    }
    // The test is only meaningful if plenty of machines pass validation, including ones with bounded timer loops.
    std::fprintf(stderr, "random machines: %zu generated, %zu accepted, %zu runs with >2 timer firings under silence\n", generated, accepted, with_timer_loops);
    PF_CHECK(accepted >= 500);
    PF_CHECK(with_timer_loops >= 200);
}
