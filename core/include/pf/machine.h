#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pf/error.h"
#include "pf/flow.h"
#include "pf/flow_json.h"
#include "pf/flow_validator.h"

namespace pf {

// State Machine layer (F-1, D-040/D-041; plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md).
//
// Packet Flows stay acyclic. Loops, timers and state live HERE: an event-driven machine whose transitions each run at
// most one handler Flow (a DAG, so every event is handled in bounded work). A loop can only close through a later
// event (a timer firing, a packet, a command), and the validator rejects machines that could spin or wait forever:
//
//   event      packet:<name> | command:<name>   (declared in `events`, delivered by the caller)
//              timer:<name>                      (declared in `timers`, fired by poll_timer at its deadline)
//              auto                              (taken right after entering the state, if its guard holds)
//   guard      counter < value | counter >= value
//   actions    inc:<counter> reset:<counter> arm:<timer> cancel:<timer> emit:<output>   (run in order)
//   handler    `run` = Flow name; Completed -> take the transition, Dropped -> NO transition (bad input never moves the
//              machine), Errored -> the machine fails (our failure, D-019)
//
// Like the rest of the core this is sans-I/O: the caller passes the clock and delivers events; emits tell it what to do.

// ---- document (built in code or loaded from protocol-machine JSON, machine_json.h) ------------------------------------
struct MachineCounterDef {
    std::string name;
    int64_t max = 0;                 // 1 .. kMachineCounterMax
    Extensions extensions;
};

// Duration: either a literal `ms` (1 .. 24 h) or a `param` resolved when a runner is created. allow_disabled lets the
// param be 0, meaning "never fires" (arm is a no-op), e.g. OpenVPN's `ping 0`.
struct MachineTimerDef {
    std::string name;
    int64_t ms = 0;
    std::string param;
    bool allow_disabled = false;
    Extensions extensions;
};

struct MachineStateDef {
    std::string id;
    bool initial = false;
    std::string final;               // "" (not final) | "ok" | "failed"
    Extensions extensions;
};

struct MachineGuardDef {
    std::string counter;
    std::string op;                  // "<" | ">="
    int64_t value = 0;
};

struct MachineTransitionDef {
    std::string from;
    std::string on;                  // "packet:x" | "command:x" | "timer:x" | "auto"
    std::optional<MachineGuardDef> guard;
    std::string run;                 // handler Flow name, empty = none
    std::vector<std::string> actions;
    std::string to;
    std::string unbounded;           // non-empty: deliberate endless timer loop (keepalive) - the reason, required
    Extensions extensions;
};

struct MachineDocument {
    int64_t version = 1;
    std::string name;
    std::string description;
    std::vector<std::string> flows;      // handler Flow names this machine may run
    std::vector<std::string> events;     // "packet:x" / "command:x" the caller may deliver
    std::vector<std::string> outputs;    // emit targets
    std::vector<MachineCounterDef> counters;
    std::vector<MachineTimerDef> timers;
    std::vector<MachineStateDef> states;
    std::vector<MachineTransitionDef> transitions;
    std::vector<std::pair<std::string, std::string>> meta;
    Extensions machine_extensions;
    Extensions extensions;
};

// Fluent construction in code (tests, built-in machines). Modifiers after transition() apply to that transition.
// Nothing is checked here: validate_machine/compile_machine report every problem with a path.
class MachineBuilder {
public:
    explicit MachineBuilder(std::string name) { d_.name = std::move(name); }
    MachineBuilder& flow(std::string f) { d_.flows.push_back(std::move(f)); return *this; }
    MachineBuilder& event(std::string e) { d_.events.push_back(std::move(e)); return *this; }
    MachineBuilder& output(std::string o) { d_.outputs.push_back(std::move(o)); return *this; }
    MachineBuilder& counter(std::string c, int64_t max) { d_.counters.push_back({std::move(c), max, {}}); return *this; }
    MachineBuilder& timer_ms(std::string t, int64_t ms) { d_.timers.push_back({std::move(t), ms, "", false, {}}); return *this; }
    MachineBuilder& timer_param(std::string t, std::string param, bool allow_disabled = false) {
        d_.timers.push_back({std::move(t), 0, std::move(param), allow_disabled, {}});
        return *this;
    }
    MachineBuilder& state(std::string id) { d_.states.push_back({std::move(id), false, "", {}}); return *this; }
    MachineBuilder& initial(std::string id) { d_.states.push_back({std::move(id), true, "", {}}); return *this; }
    MachineBuilder& final_ok(std::string id) { d_.states.push_back({std::move(id), false, "ok", {}}); return *this; }
    MachineBuilder& final_failed(std::string id) { d_.states.push_back({std::move(id), false, "failed", {}}); return *this; }
    MachineBuilder& transition(std::string from, std::string on, std::string to) {
        MachineTransitionDef t;
        t.from = std::move(from);
        t.on = std::move(on);
        t.to = std::move(to);
        d_.transitions.push_back(std::move(t));
        return *this;
    }
    MachineBuilder& when(std::string counter, std::string op, int64_t value) { last().guard = MachineGuardDef{std::move(counter), std::move(op), value}; return *this; }
    MachineBuilder& run(std::string f) { last().run = std::move(f); return *this; }
    MachineBuilder& act(std::vector<std::string> actions) { for (auto& a : actions) last().actions.push_back(std::move(a)); return *this; }
    MachineBuilder& unbounded(std::string reason) { last().unbounded = std::move(reason); return *this; }

    const MachineDocument& doc() const { return d_; }
    MachineDocument& doc() { return d_; }

private:
    MachineTransitionDef& last() {
        if (d_.transitions.empty()) d_.transitions.emplace_back();   // misuse surfaces as validation issues, not UB
        return d_.transitions.back();
    }
    MachineDocument d_;
};

inline constexpr int64_t kMachineCounterMax = 1000000;
inline constexpr int64_t kMachineTimerMaxMs = 24LL * 60 * 60 * 1000;

// Handler Flows by name (each already compiled/validated as a protocol-flow).
using FlowLibrary = std::map<std::string, Flow>;

// ---- validation -------------------------------------------------------------------------------------------------------
// Static checks BEFORE anything runs; all issues at once, {code, JSON Pointer, message} like validate_flow.
//
//   DuplicateId              two states/counters/timers/outputs/events/flows with the same name
//   NoInitial / MultipleInitial / NoFinal / BadFinal
//   UnknownState / UnknownEvent / UnknownTimer / UnknownCounter / UnknownOutput / UnknownFlow / BadEvent / BadAction
//   MissingFlow              a declared flow is not in the FlowLibrary (when one is given)
//   BadGuard / CounterRange / TimerRange
//   FinalHasTransitions      final states end the machine
//   NondeterministicTransition  two unguarded (or identically guarded) transitions for the same state and event
//   ShadowedTransition       a transition after an unguarded one for the same state and event can never be taken
//   TimerNeverArmed          a timer:x transition exists but nothing arms x
//   Unreachable              state not reachable from the initial state
//   NoExit                   no final state reachable from this state (livelock)
//   ImmediateCycle           a loop made only of `auto` transitions (no event in between)
//   UnboundedRetry           a timer transition inside a loop that is not bounded by a counter (guard `c < N` + inc:c,
//                            and no reset:c by a timer/auto transition of the same loop), unless `unbounded` says why
//   GuardNotExhaustive       a timer event whose guards can all be false (the machine would stall when it fires)
//   WaitWithoutTimeout       a state that waits for packets but has no timer transition (would wait forever)
//   SecretLiteral            PEM material in a string
struct MachineValidation {
    bool ok() const { return issues.empty(); }
    std::vector<FlowIssue> issues;
};

MachineValidation validate_machine(const MachineDocument& doc, const FlowLibrary* flows = nullptr);

// ---- compiled machine ---------------------------------------------------------------------------------------------------
enum class MachineStatus { Running, Succeeded, Failed };

class Machine {
public:
    Machine() = default;
    const std::string& name() const { return name_; }

    size_t state_count() const { return states_.size(); }
    const std::string& state_name(size_t i) const { return states_[i]; }
    std::optional<size_t> find_state(std::string_view id) const { return find(states_, id); }
    std::optional<size_t> find_event(std::string_view e) const { return find(events_, e); }     // "packet:x" ...
    const std::string& event_name(size_t i) const { return events_[i]; }
    std::optional<size_t> find_output(std::string_view o) const { return find(outputs_, o); }
    const std::string& output_name(size_t i) const { return outputs_[i]; }
    std::optional<size_t> find_counter(std::string_view c) const { return find(counters_, c); }
    std::optional<size_t> find_timer(std::string_view t) const { return find(timers_, t); }
    size_t transition_count() const { return transitions_.size(); }

private:
    friend struct MachineCompiler;
    friend class MachineRunner;

    enum class ActionKind : uint8_t { Inc, Reset, Arm, Cancel, Emit };
    struct Action { ActionKind kind; size_t index; };
    struct Transition {
        size_t from = 0, event = 0, to = 0;
        bool guarded = false, guard_lt = true;
        size_t guard_counter = 0;
        int64_t guard_value = 0;
        std::optional<size_t> flow;
        std::vector<Action> actions;
    };
    struct Timer { int64_t ms = 0; std::string param; bool allow_disabled = false; size_t event = 0; };

    static std::optional<size_t> find(const std::vector<std::string>& v, std::string_view s) {
        for (size_t i = 0; i < v.size(); ++i) if (v[i] == s) return i;
        return std::nullopt;
    }

    std::string name_;
    std::vector<std::string> states_, events_, outputs_, counters_, timers_;
    std::vector<MachineStatus> final_;             // Running = not final
    std::vector<int64_t> counter_max_;
    std::vector<Timer> timer_;
    std::vector<Transition> transitions_;
    std::vector<std::vector<size_t>> by_state_;    // transitions leaving each state, in declaration order
    std::vector<Flow> flows_;
    size_t initial_ = 0, auto_event_ = 0;
};

struct MachineCompileResult {
    bool ok() const { return issues.empty(); }
    Machine machine;
    std::vector<FlowIssue> issues;
};

// Validates (with the library), then builds the executable machine. Machines only come from valid documents.
MachineCompileResult compile_machine(const MachineDocument& doc, const FlowLibrary& flows);

// ---- runner ---------------------------------------------------------------------------------------------------------------
using MachineParams = std::vector<std::pair<std::string, int64_t>>;

struct MachineStep {
    bool handled = false;            // the event selected a transition (it may still have been dropped by its handler)
    bool dropped = false;            // the handler Flow dropped the input: the machine did not move
    Error error = Error::None;       // drop reason, or why the machine failed
    size_t flow_runs = 0;
    std::vector<size_t> transitions; // indices of transitions taken (event + following auto), for trace
    std::vector<size_t> emits;       // output indices, in order
    MachineStatus status = MachineStatus::Running;
};

class MachineRunner {
public:
    // Resolves timer params (every timer param must be given, nothing else may be). The Machine must outlive the runner.
    static std::optional<MachineRunner> create(const Machine& m, const MachineParams& params, std::string* error = nullptr);

    // Enters the initial state and takes its auto transitions. Call once, before anything else.
    MachineStep start(FlowContext& ctx, uint64_t now_ms);
    // Delivers a packet:/command: event (timer events come only from poll_timer).
    MachineStep on_event(size_t event, FlowContext& ctx, uint64_t now_ms);
    // Fires the earliest timer whose deadline is <= now (ties: declaration order). nullopt = nothing due.
    std::optional<MachineStep> poll_timer(FlowContext& ctx, uint64_t now_ms);
    std::optional<uint64_t> next_deadline_ms() const;

    // Optional trace sink (pf/trace.h): Event, Transition, Emit and MachineEnd records, plus the handler Flows' own
    // Node/FlowEnd records. The runner stamps the sink's clock with every call's now_ms. nullptr = off.
    void set_trace(TraceSink* trace) { trace_ = trace; }

    size_t state() const { return state_; }
    MachineStatus status() const { return status_; }
    Error error() const { return error_; }
    int64_t counter(size_t i) const { return counters_[i]; }
    std::optional<uint64_t> timer_deadline(size_t i) const { return deadlines_[i]; }

private:
    explicit MachineRunner(const Machine& m) : m_(&m) {}
    void dispatch(size_t event, FlowContext& ctx, uint64_t now_ms, MachineStep& step);
    bool take(size_t t, FlowContext& ctx, uint64_t now_ms, MachineStep& step);
    std::optional<size_t> select(size_t event) const;
    void fail(Error e);
    void trace(TraceKind kind, std::string_view name, size_t state, std::string_view to = {}, uint8_t result = 0,
               Error error = Error::None, uint32_t value = 0);
    void stamp(uint64_t now_ms) { if (trace_) trace_->now_ms = now_ms; }

    const Machine* m_;
    TraceSink* trace_ = nullptr;
    size_t state_ = 0;
    bool started_ = false;
    MachineStatus status_ = MachineStatus::Running;
    Error error_ = Error::None;
    std::vector<int64_t> counters_;
    std::vector<uint64_t> duration_;                 // resolved, 0 = disabled
    std::vector<std::optional<uint64_t>> deadlines_;
};

}  // namespace pf
