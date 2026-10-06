// F-1 S4: KeepaliveTimer (hand-written, used by TunnelSession) and the keepalive State Machine
// (pf/keepalive_machine.h, golden machine_keepalive.machine.json) must behave identically. Both are driven with the same
// random sequences of "sent"/"received" events and the clock; timers are delivered at their deadlines, as the event
// loop does. Mutated machines must be caught by the same comparison, so the test is known to be able to fail.
#include <random>
#include <string>

#include "pf/keepalive.h"
#include "pf/keepalive_machine.h"
#include "pf/machine_json.h"
#include "pf_test.h"

using namespace pf;

namespace {

struct Scenario {
    uint32_t ping_s = 0, restart_s = 0;
    uint64_t t0 = 0;
    struct Op { uint64_t dt; int kind; bool sent_after_ping; };   // kind: 0 none, 1 sent, 2 received
    std::vector<Op> ops;
};

Scenario random_scenario(std::mt19937& rng) {
    auto pick = [&](uint64_t lo, uint64_t hi) { return std::uniform_int_distribution<uint64_t>(lo, hi)(rng); };
    Scenario s;
    s.ping_s = static_cast<uint32_t>(pick(0, 6));
    s.restart_s = pick(0, 4) == 0 ? 0 : static_cast<uint32_t>(pick(1, 20));
    if (pick(0, 5) == 0) s.restart_s = s.ping_s;                 // equal periods: deadlines tie
    s.t0 = pick(0, 1u << 30);
    const size_t n = pick(1, 60);
    for (size_t i = 0; i < n; ++i) {
        const uint64_t mode = pick(0, 9);
        const uint64_t dt = mode == 0 ? 0 : mode <= 2 ? 1000 * pick(1, 8) : pick(0, 12000);   // whole seconds often
        s.ops.push_back({dt, static_cast<int>(pick(0, 2)), pick(0, 1) == 1});
    }
    return s;
}

// Returns "" when equivalent, else a description of the first difference.
std::string compare(const Machine& m, const Scenario& s) {
    KeepaliveTimer ka(s.ping_s, s.restart_s, s.t0);
    auto r = MachineRunner::create(m, {{"pingMs", int64_t{s.ping_s} * 1000}, {"restartMs", int64_t{s.restart_s} * 1000}});
    if (!r) return "runner not created";
    FlowContext ctx;
    r->start(ctx, s.t0);
    const size_t sent = *m.find_event("packet:sent"), received = *m.find_event("packet:received");
    bool ka_dead = false;
    uint64_t now = s.t0;
    auto check_deadline = [&](const char* where) -> std::string {
        if (ka_dead) return "";
        if (ka.next_deadline_ms() != r->next_deadline_ms())
            return std::string("next deadline differs ") + where + " at t=" + std::to_string(now - s.t0);
        return "";
    };
    if (auto e = check_deadline("after start"); !e.empty()) return e;

    for (const auto& op : s.ops) {
        const uint64_t at = now + op.dt;
        // timers due up to (and including) `at`, at their deadlines
        while (!ka_dead) {
            const auto d = ka.next_deadline_ms();
            if (!d || *d > at) break;
            now = *d;
            const KeepaliveTimer::Action a = ka.poll(now);
            const auto step = r->poll_timer(ctx, now);
            const bool m_ping = step && !step->emits.empty();
            const bool m_dead = r->status() == MachineStatus::Failed;
            const bool k_ping = a == KeepaliveTimer::Action::SendPing, k_dead = a == KeepaliveTimer::Action::Timeout;
            if (k_ping != m_ping || k_dead != m_dead)
                return "timer outcome differs at t=" + std::to_string(now - s.t0) + " (keepalive " + std::to_string(static_cast<int>(a)) +
                       ", machine ping=" + std::to_string(m_ping) + " dead=" + std::to_string(m_dead) + ")";
            if (k_dead) { ka_dead = true; break; }
            if (k_ping && op.sent_after_ping) { ka.on_sent(now); r->on_event(sent, ctx, now); }   // the ping went out
            if (auto e = check_deadline("after timer"); !e.empty()) return e;
        }
        if (ka_dead) break;
        now = at;
        if (op.kind == 1) { ka.on_sent(now); r->on_event(sent, ctx, now); }
        if (op.kind == 2) { ka.on_received(now); r->on_event(received, ctx, now); }
        if (auto e = check_deadline("after event"); !e.empty()) return e;
        if (r->status() != MachineStatus::Running) return "machine finished without a timeout";
    }
    return "";
}

Machine compile_doc(const MachineDocument& d) {
    auto c = compile_machine(d, {});
    for (const auto& i : c.issues) std::fprintf(stderr, "%s %s %s\n", i.code.c_str(), i.path.c_str(), i.message.c_str());
    PF_REQUIRE(c.ok());
    return std::move(c.machine);
}

// Index of the transition `from` --on--> in the keepalive document.
size_t tr(const MachineDocument& d, const char* from, const char* on) {
    for (size_t i = 0; i < d.transitions.size(); ++i) if (d.transitions[i].from == from && d.transitions[i].on == on) return i;
    PF_REQUIRE(false);
    return 0;
}

}  // namespace

PF_TEST(machine_keepalive_equivalent_to_keepalive_timer) {
    const Machine m = compile_doc(keepalive_machine_document());
    std::mt19937 rng(4242);
    size_t ties = 0, deaths = 0, pings = 0;
    for (int i = 0; i < 4000; ++i) {
        const Scenario s = random_scenario(rng);
        const std::string diff = compare(m, s);
        if (!diff.empty()) { PF_CHECK(false); std::fprintf(stderr, "scenario %d (ping %u, restart %u): %s\n", i, s.ping_s, s.restart_s, diff.c_str()); break; }
        ties += s.ping_s != 0 && s.ping_s == s.restart_s;
        deaths += s.restart_s != 0;
        pings += s.ping_s != 0;
    }
    PF_CHECK(ties > 100);
    PF_CHECK(deaths > 1000);
    PF_CHECK(pings > 1000);
}

PF_TEST(machine_keepalive_loaded_from_golden_file_is_equivalent) {
    const auto l = load_machine_json(write_machine_json(keepalive_machine_document()), {});
    PF_REQUIRE(l.ok());
    std::mt19937 rng(7);
    for (int i = 0; i < 500; ++i) {
        const std::string diff = compare(l.machine, random_scenario(rng));
        if (!diff.empty()) { PF_CHECK(false); std::fprintf(stderr, "%s\n", diff.c_str()); break; }
    }
}

PF_TEST(machine_keepalive_mutants_are_detected) {
    struct Mutant { const char* name; void (*apply)(MachineDocument&); };
    const Mutant mutants[] = {
        {"ping timer declared first (tie goes to ping)", [](MachineDocument& d) { std::swap(d.timers[0], d.timers[1]); }},
        {"sent re-arms restart", [](MachineDocument& d) { d.transitions[tr(d, "alive", "packet:sent")].actions = {"arm:restart"}; }},
        {"received does not re-arm", [](MachineDocument& d) { d.transitions[tr(d, "alive", "packet:received")].actions.clear(); }},
        {"ping does not re-arm", [](MachineDocument& d) { d.transitions[tr(d, "alive", "timer:ping")].actions = {"emit:ping"}; }},
        {"ping not emitted", [](MachineDocument& d) { d.transitions[tr(d, "alive", "timer:ping")].actions = {"arm:ping"}; }},
        {"ping not armed at start", [](MachineDocument& d) { d.transitions[tr(d, "init", "auto")].actions = {"arm:restart"}; }},
        {"restart uses the ping period", [](MachineDocument& d) { d.timers[0].param = "pingMs"; }},
        {"received re-arms ping", [](MachineDocument& d) { d.transitions[tr(d, "alive", "packet:received")].actions = {"arm:ping"}; }},
    };
    for (const auto& mu : mutants) {
        MachineDocument d = keepalive_machine_document();
        mu.apply(d);
        const Machine m = compile_doc(d);
        std::mt19937 rng(99);
        bool caught = false;
        for (int i = 0; i < 4000 && !caught; ++i) caught = !compare(m, random_scenario(rng)).empty();
        if (!caught) std::fprintf(stderr, "mutant not detected: %s\n", mu.name);
        PF_CHECK(caught);
    }
}

// Documented difference (pf/keepalive_machine.h): if the caller polls LATE, past both deadlines, the machine fires the
// timers in deadline order (one last ping, then dead) while KeepaliveTimer reports only the timeout.
PF_TEST(machine_keepalive_late_poll_difference_is_as_documented) {
    const Machine m = compile_doc(keepalive_machine_document());
    KeepaliveTimer ka(10, 15, 0);
    auto r = MachineRunner::create(m, {{"pingMs", 10000}, {"restartMs", 15000}});
    PF_REQUIRE(r.has_value());
    FlowContext ctx;
    r->start(ctx, 0);
    PF_CHECK(ka.poll(20000) == KeepaliveTimer::Action::Timeout);
    const auto first = r->poll_timer(ctx, 20000);
    PF_REQUIRE(first.has_value());
    PF_CHECK_EQ(first->emits.size(), size_t{1});            // the ping due at 10 s
    const auto second = r->poll_timer(ctx, 20000);
    PF_REQUIRE(second.has_value());
    PF_CHECK(second->status == MachineStatus::Failed);       // then the restart due at 15 s
}
