#include <string>

#include "pf/keepalive_machine.h"
#include "pf/machine.h"
#include "pf_test.h"

using namespace pf;

namespace {

// A STUN-like transaction: send, wait for the response, retry on timeout up to 3 times.
MachineBuilder stun_like() {
    MachineBuilder b("stun_binding");
    b.flow("send").flow("accept")
        .event("command:start").event("packet:response")
        .counter("tries", 3).timer_ms("rto", 100)
        .initial("idle").state("waiting").final_ok("done").final_failed("failed")
        .transition("idle", "command:start", "waiting").run("send").act({"arm:rto", "inc:tries"})
        .transition("waiting", "packet:response", "done").run("accept").act({"cancel:rto"})
        .transition("waiting", "timer:rto", "waiting").when("tries", "<", 3).run("send").act({"arm:rto", "inc:tries"})
        .transition("waiting", "timer:rto", "failed").when("tries", ">=", 3);
    return b;
}

FlowLibrary library() {
    FlowLibrary lib;
    lib.emplace("send", Flow());
    lib.emplace("accept", Flow());
    return lib;
}

bool has(const MachineValidation& v, const std::string& code, const std::string& path = "") {
    for (const auto& i : v.issues) if (i.code == code && (path.empty() || i.path == path)) return true;
    return false;
}
std::string dump(const MachineValidation& v) {
    std::string s;
    for (const auto& i : v.issues) s += i.code + " " + i.path + ": " + i.message + "\n";
    return s;
}
MachineValidation check(const MachineBuilder& b) {
    const FlowLibrary lib = library();
    return validate_machine(b.doc(), &lib);
}

}  // namespace

PF_TEST(machine_valid_documents_pass) {
    const auto v = check(stun_like());
    PF_CHECK(v.ok());
    if (!v.ok()) std::fprintf(stderr, "%s", dump(v).c_str());
    const auto k = validate_machine(keepalive_machine_document());
    PF_CHECK(k.ok());
    if (!k.ok()) std::fprintf(stderr, "%s", dump(k).c_str());
}

PF_TEST(machine_initial_and_final_states) {
    MachineBuilder none("m");
    none.state("a").final_ok("b").event("command:go").transition("a", "command:go", "b");
    PF_CHECK(has(validate_machine(none.doc()), "NoInitial", "/states"));

    MachineBuilder two = stun_like();
    two.doc().states[1].initial = true;
    PF_CHECK(has(check(two), "MultipleInitial", "/states/1/initial"));

    MachineBuilder nofinal = stun_like();
    nofinal.doc().states[2].final = "";
    nofinal.doc().states[3].final = "";
    PF_CHECK(has(check(nofinal), "NoFinal"));

    MachineBuilder bad = stun_like();
    bad.doc().states[2].final = "maybe";
    PF_CHECK(has(check(bad), "BadFinal", "/states/2/final"));
    MachineBuilder initfinal = stun_like();
    initfinal.doc().states[0].final = "ok";
    PF_CHECK(has(check(initfinal), "BadFinal", "/states/0"));
}

PF_TEST(machine_duplicate_names) {
    MachineBuilder b = stun_like();
    b.state("waiting").counter("tries", 2).timer_ms("rto", 5).event("packet:response").output("o").output("o").flow("send");
    const auto v = check(b);
    PF_CHECK(has(v, "DuplicateId", "/states/4/id"));
    PF_CHECK(has(v, "DuplicateId", "/counters/1/name"));
    PF_CHECK(has(v, "DuplicateId", "/timers/1/name"));
    PF_CHECK(has(v, "DuplicateId", "/events/2"));
    PF_CHECK(has(v, "DuplicateId", "/outputs/1"));
    PF_CHECK(has(v, "DuplicateId", "/flows/2"));
}

PF_TEST(machine_unknown_references) {
    MachineBuilder b = stun_like();
    b.transition("nowhere", "command:start", "void");
    b.transition("waiting", "packet:resp", "done");
    b.transition("waiting", "tick", "done");
    b.transition("waiting", "timer:nope", "done");
    b.transition("waiting", "command:start", "done").when("retries", "<", 1).run("missing").act({"inc:x", "arm:y", "emit:z", "jump:q", "inc"});
    b.event("timer:rto").event("auto");
    const auto v = check(b);
    PF_CHECK(has(v, "UnknownState", "/transitions/4/from"));
    PF_CHECK(has(v, "UnknownState", "/transitions/4/to"));
    PF_CHECK(has(v, "UnknownEvent", "/transitions/5/on"));
    PF_CHECK(has(v, "BadEvent", "/transitions/6/on"));
    PF_CHECK(has(v, "UnknownTimer", "/transitions/7/on"));
    PF_CHECK(has(v, "UnknownCounter", "/transitions/8/guard/counter"));
    PF_CHECK(has(v, "UnknownFlow", "/transitions/8/run"));
    PF_CHECK(has(v, "UnknownCounter", "/transitions/8/actions/0"));
    PF_CHECK(has(v, "UnknownTimer", "/transitions/8/actions/1"));
    PF_CHECK(has(v, "UnknownOutput", "/transitions/8/actions/2"));
    PF_CHECK(has(v, "BadAction", "/transitions/8/actions/3"));
    PF_CHECK(has(v, "BadAction", "/transitions/8/actions/4"));
    PF_CHECK(has(v, "BadEvent", "/events/2"));          // timer events are declared through `timers`
    PF_CHECK(has(v, "BadEvent", "/events/3"));

    FlowLibrary partial;
    partial.emplace("send", Flow());
    PF_CHECK(has(validate_machine(stun_like().doc(), &partial), "MissingFlow", "/flows/1"));
    PF_CHECK(validate_machine(stun_like().doc()).ok());   // no library: flow availability is not checked
}

PF_TEST(machine_guards_counters_timers) {
    MachineBuilder b = stun_like();
    b.doc().transitions[2].guard->op = "<=";
    b.doc().transitions[3].guard->value = 4;
    b.counter("zero", 0);
    b.timer_ms("none", 0).timer_ms("both", 5).timer_ms("huge", kMachineTimerMaxMs + 1).timer_param("bad", "BadName");
    b.doc().timers[2].param = "x";
    b.doc().timers[3].allow_disabled = true;
    const auto v = check(b);
    PF_CHECK(has(v, "BadGuard", "/transitions/2/guard/op"));
    PF_CHECK(has(v, "CounterRange", "/transitions/3/guard/value"));
    PF_CHECK(has(v, "CounterRange", "/counters/1/max"));
    PF_CHECK(has(v, "TimerRange", "/timers/1"));
    PF_CHECK(has(v, "TimerRange", "/timers/2"));
    PF_CHECK(has(v, "TimerRange", "/timers/3/ms"));
    PF_CHECK(has(v, "TimerRange", "/timers/3/allowDisabled"));
    PF_CHECK(has(v, "TimerRange", "/timers/4/param"));
}

PF_TEST(machine_final_states_have_no_transitions) {
    MachineBuilder b = stun_like();
    b.transition("done", "command:start", "waiting");
    PF_CHECK(has(check(b), "FinalHasTransitions", "/transitions/4/from"));
}

PF_TEST(machine_determinism_and_shadowing) {
    MachineBuilder two = stun_like();
    two.transition("waiting", "packet:response", "failed");
    PF_CHECK(has(check(two), "NondeterministicTransition", "/transitions/4"));

    MachineBuilder same = stun_like();
    same.transition("waiting", "timer:rto", "done").when("tries", "<", 3);
    PF_CHECK(has(check(same), "NondeterministicTransition", "/transitions/4"));

    MachineBuilder shadow = stun_like();
    shadow.transition("waiting", "packet:response", "failed").when("tries", ">=", 1);
    PF_CHECK(has(check(shadow), "ShadowedTransition", "/transitions/4"));
}

PF_TEST(machine_timer_never_armed) {
    MachineBuilder b = stun_like();
    b.doc().transitions[0].actions = {"inc:tries"};
    b.doc().transitions[2].actions = {"inc:tries"};
    PF_CHECK(has(check(b), "TimerNeverArmed", "/transitions/2/on"));
}

PF_TEST(machine_unreachable_and_no_exit) {
    MachineBuilder b = stun_like();
    b.state("orphan");
    b.state("trap").event("command:spin").timer_ms("t", 5)
        .transition("idle", "command:spin", "trap")
        .transition("trap", "command:spin", "trap")
        .transition("trap", "timer:t", "trap").act({"arm:t"}).unbounded("test");
    const auto v = check(b);
    PF_CHECK(has(v, "Unreachable", "/states/4"));
    PF_CHECK(has(v, "NoExit", "/states/5"));
}

PF_TEST(machine_auto_only_loop_is_rejected) {
    MachineBuilder b("m");
    b.event("command:go").initial("s").state("a").state("b").final_ok("end")
        .transition("s", "command:go", "a")
        .transition("a", "auto", "b")
        .transition("b", "auto", "a")
        .transition("b", "command:go", "end");
    const auto v = validate_machine(b.doc());
    PF_CHECK(has(v, "ImmediateCycle"));
    bool path = false;
    for (const auto& i : v.issues) if (i.code == "ImmediateCycle" && i.message.find("a -> b -> a") != std::string::npos) path = true;
    PF_CHECK(path);

    MachineBuilder self("m");
    self.event("command:go").initial("s").final_ok("end").transition("s", "auto", "s").transition("s", "command:go", "end");
    PF_CHECK(has(validate_machine(self.doc()), "ImmediateCycle", "/states/0"));
}

PF_TEST(machine_timer_loops_must_be_bounded) {
    MachineBuilder noguard = stun_like();
    noguard.doc().transitions[2].guard.reset();
    noguard.doc().transitions.pop_back();
    PF_CHECK(has(check(noguard), "UnboundedRetry", "/transitions/2"));

    MachineBuilder noinc = stun_like();
    noinc.doc().transitions[2].actions = {"arm:rto"};
    PF_CHECK(has(check(noinc), "UnboundedRetry", "/transitions/2"));

    MachineBuilder geguard = stun_like();
    geguard.doc().transitions[2].guard->op = ">=";
    geguard.doc().transitions[3].guard->op = "<";
    PF_CHECK(has(check(geguard), "UnboundedRetry", "/transitions/2"));

    // a reset inside the loop by a timer transition undoes the bound
    MachineBuilder reset = stun_like();
    reset.state("backoff").timer_ms("pause", 50)
        .transition("waiting", "timer:pause", "backoff").act({"arm:pause"}).unbounded("x");
    reset.doc().transitions.back().unbounded.clear();
    reset.doc().transitions.back().guard = MachineGuardDef{"tries", "<", 3};
    reset.doc().transitions.back().actions = {"arm:pause", "inc:tries"};
    reset.transition("waiting", "timer:pause", "failed").when("tries", ">=", 3);
    reset.transition("backoff", "timer:pause", "waiting").when("tries", "<", 3).act({"reset:tries", "inc:tries", "arm:rto"});
    reset.transition("backoff", "timer:pause", "failed").when("tries", ">=", 3);
    reset.transition("backoff", "packet:response", "done");
    PF_CHECK(has(check(reset), "UnboundedRetry", "/transitions/6"));

    // a reset on a packet transition is fine (the peer answered: start counting again)
    MachineBuilder packet_reset = stun_like();
    packet_reset.event("packet:busy").transition("waiting", "packet:busy", "waiting").act({"reset:tries", "arm:rto"});
    const auto ok = check(packet_reset);
    PF_CHECK(ok.ok());
    if (!ok.ok()) std::fprintf(stderr, "%s", dump(ok).c_str());

    // multi-state loop through timers, made explicit with `unbounded`
    MachineBuilder ring("m");
    ring.timer_ms("t", 10).event("command:stop").initial("a").state("b").final_ok("end")
        .transition("a", "auto", "b").act({"arm:t"})
        .transition("b", "timer:t", "c0").act({"arm:t"})
        .state("c0").transition("c0", "timer:t", "b").act({"arm:t"})
        .transition("b", "command:stop", "end").transition("c0", "command:stop", "end");
    PF_CHECK(has(validate_machine(ring.doc()), "UnboundedRetry", "/transitions/1"));
    PF_CHECK(has(validate_machine(ring.doc()), "UnboundedRetry", "/transitions/2"));
    ring.doc().transitions[1].unbounded = "heartbeat";
    ring.doc().transitions[2].unbounded = "heartbeat";
    PF_CHECK(validate_machine(ring.doc()).ok());
}

PF_TEST(machine_timer_guards_must_be_exhaustive) {
    MachineBuilder b = stun_like();
    b.doc().transitions.pop_back();     // only "tries < 3": at 3 the timer fires and nothing happens
    PF_CHECK(has(check(b), "GuardNotExhaustive", "/transitions/2/guard"));
    MachineBuilder fallback = stun_like();
    fallback.doc().transitions.back().guard.reset();   // "tries < 3" then an unguarded fallback: exhaustive
    PF_CHECK(check(fallback).ok());
}

PF_TEST(machine_waiting_for_packets_needs_a_timeout) {
    MachineBuilder b = stun_like();
    b.doc().transitions.pop_back();
    b.doc().transitions.pop_back();
    b.transition("waiting", "command:start", "failed");
    PF_CHECK(has(check(b), "WaitWithoutTimeout", "/states/1"));
}

PF_TEST(machine_unbounded_and_secrets) {
    MachineBuilder b = stun_like();
    b.doc().transitions[1].unbounded = "why";
    b.doc().description = "-----BEGIN PRIVATE KEY-----";
    b.doc().meta.emplace_back("note", "-----BEGIN CERTIFICATE-----");
    const auto v = check(b);
    PF_CHECK(has(v, "BadUnbounded", "/transitions/1/unbounded"));
    PF_CHECK(has(v, "SecretLiteral", "/machine/description"));
    PF_CHECK(has(v, "SecretLiteral", "/meta/note"));
}

PF_TEST(machine_compile_requires_a_valid_document) {
    const FlowLibrary lib = library();
    MachineBuilder b = stun_like();
    b.doc().transitions[0].to = "nowhere";
    const auto bad = compile_machine(b.doc(), lib);
    PF_CHECK(!bad.ok());
    PF_CHECK_EQ(bad.machine.state_count(), size_t{0});
    const auto good = compile_machine(stun_like().doc(), lib);
    PF_REQUIRE(good.ok());
    PF_CHECK_EQ(good.machine.state_count(), size_t{4});
    PF_CHECK(good.machine.find_event("timer:rto").has_value());
    PF_CHECK(good.machine.find_event("auto").has_value());
    PF_CHECK(!good.machine.find_event("timer:none").has_value());
}
