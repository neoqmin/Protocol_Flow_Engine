#include "pf/machine.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <tuple>

namespace pf {

namespace {

bool looks_like_pem(const std::string& s) { return s.find("-----BEGIN") != std::string::npos; }

bool is_param_name(std::string_view s) {                    // [a-z][A-Za-z0-9_]{0,63}
    if (s.empty() || s.size() > 64 || !(s[0] >= 'a' && s[0] <= 'z')) return false;
    for (const char c : s) if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
    return true;
}

// "kind:name" with a valid id after the colon.
bool split_ref(const std::string& s, std::string& kind, std::string& name) {
    const size_t c = s.find(':');
    if (c == std::string::npos) return false;
    kind = s.substr(0, c);
    name = s.substr(c + 1);
    return is_valid_flow_id(name);
}

enum class On { Packet, Command, Timer, Auto, Bad };

On classify_on(const std::string& on, std::string& name) {
    if (on == "auto") return On::Auto;
    std::string kind;
    if (!split_ref(on, kind, name)) return On::Bad;
    if (kind == "packet") return On::Packet;
    if (kind == "command") return On::Command;
    if (kind == "timer") return On::Timer;
    return On::Bad;
}

// Strongly connected components (iterative Kosaraju). comp[v] = component id.
std::vector<size_t> scc(size_t n, const std::vector<std::vector<size_t>>& adj) {
    std::vector<std::vector<size_t>> radj(n);
    for (size_t v = 0; v < n; ++v) for (size_t w : adj[v]) radj[w].push_back(v);
    std::vector<size_t> order;
    std::vector<bool> seen(n, false);
    for (size_t s = 0; s < n; ++s) {
        if (seen[s]) continue;
        std::vector<std::pair<size_t, size_t>> st{{s, 0}};
        seen[s] = true;
        while (!st.empty()) {
            auto& [v, i] = st.back();
            if (i < adj[v].size()) {
                const size_t w = adj[v][i++];
                if (!seen[w]) { seen[w] = true; st.push_back({w, 0}); }
            } else {
                order.push_back(v);
                st.pop_back();
            }
        }
    }
    const size_t kNone = static_cast<size_t>(-1);
    std::vector<size_t> comp(n, kNone);
    size_t c = 0;
    for (size_t k = order.size(); k-- > 0;) {
        const size_t s = order[k];
        if (comp[s] != kNone) continue;
        std::vector<size_t> st{s};
        comp[s] = c;
        while (!st.empty()) {
            const size_t v = st.back();
            st.pop_back();
            for (size_t w : radj[v]) if (comp[w] == kNone) { comp[w] = c; st.push_back(w); }
        }
        ++c;
    }
    return comp;
}

std::vector<bool> reach(size_t n, const std::vector<std::vector<size_t>>& adj, const std::vector<size_t>& from) {
    std::vector<bool> r(n, false);
    std::vector<size_t> st;
    for (size_t s : from) if (!r[s]) { r[s] = true; st.push_back(s); }
    while (!st.empty()) {
        const size_t v = st.back();
        st.pop_back();
        for (size_t w : adj[v]) if (!r[w]) { r[w] = true; st.push_back(w); }
    }
    return r;
}

struct ParsedAction {
    std::string kind, name;
};

}  // namespace

// ======================================================================================================================
// Validation
// ======================================================================================================================

MachineValidation validate_machine(const MachineDocument& d, const FlowLibrary* lib) {
    MachineValidation out;
    bool refs_ok = true;                    // graph checks need a well-formed, fully resolved document
    auto issue = [&](const char* code, const std::string& path, const std::string& msg, bool structural = true) {
        out.issues.push_back({code, path, msg});
        if (structural) refs_ok = false;
    };
    auto names = [&](const std::vector<std::string>& v, const std::string& base, const char* what, std::map<std::string, size_t>& idx,
                     std::string (*field)(size_t)) {
        for (size_t i = 0; i < v.size(); ++i) {
            const std::string p = base + "/" + std::to_string(i) + field(i);
            if (!idx.emplace(v[i], i).second) issue("DuplicateId", p, std::string("duplicate ") + what + " \"" + v[i] + "\"");
        }
    };
    auto no_field = [](size_t) { return std::string(); };
    auto name_field = [](size_t) { return std::string("/name"); };
    auto id_field = [](size_t) { return std::string("/id"); };

    // --- declarations ------------------------------------------------------------------------------------------------
    std::map<std::string, size_t> state_idx, counter_idx, timer_idx, output_idx, event_idx, flow_idx;
    {
        std::vector<std::string> v;
        for (const auto& s : d.states) v.push_back(s.id);
        names(v, "/states", "state", state_idx, id_field);
        v.clear();
        for (const auto& c : d.counters) v.push_back(c.name);
        names(v, "/counters", "counter", counter_idx, name_field);
        v.clear();
        for (const auto& t : d.timers) v.push_back(t.name);
        names(v, "/timers", "timer", timer_idx, name_field);
    }
    names(d.outputs, "/outputs", "output", output_idx, no_field);
    names(d.events, "/events", "event", event_idx, no_field);
    names(d.flows, "/flows", "flow", flow_idx, no_field);

    for (size_t i = 0; i < d.events.size(); ++i) {
        std::string name;
        const On k = classify_on(d.events[i], name);
        if (k != On::Packet && k != On::Command)
            issue("BadEvent", "/events/" + std::to_string(i), "declared events are \"packet:<name>\" or \"command:<name>\" (timer events come from `timers`)");
    }
    if (lib)
        for (size_t i = 0; i < d.flows.size(); ++i)
            if (!lib->count(d.flows[i])) issue("MissingFlow", "/flows/" + std::to_string(i), "flow \"" + d.flows[i] + "\" is not available");

    size_t initials = 0;
    bool any_final = false;
    for (size_t i = 0; i < d.states.size(); ++i) {
        const auto& s = d.states[i];
        if (s.initial) {
            if (++initials > 1) issue("MultipleInitial", "/states/" + std::to_string(i) + "/initial", "only one state may be initial");
        }
        if (!s.final.empty()) {
            if (s.final != "ok" && s.final != "failed") issue("BadFinal", "/states/" + std::to_string(i) + "/final", "final must be \"ok\" or \"failed\"");
            else any_final = true;
            if (s.initial) issue("BadFinal", "/states/" + std::to_string(i), "the initial state cannot be final");
        }
    }
    if (initials == 0) issue("NoInitial", "/states", "exactly one state must be initial");
    if (!any_final) issue("NoFinal", "/states", "at least one final state (\"ok\" or \"failed\") is required");

    for (size_t i = 0; i < d.counters.size(); ++i)
        if (d.counters[i].max < 1 || d.counters[i].max > kMachineCounterMax)
            issue("CounterRange", "/counters/" + std::to_string(i) + "/max", "max must be 1.." + std::to_string(kMachineCounterMax));
    for (size_t i = 0; i < d.timers.size(); ++i) {
        const auto& t = d.timers[i];
        const std::string p = "/timers/" + std::to_string(i);
        const bool has_ms = t.ms != 0, has_param = !t.param.empty();
        if (has_ms == has_param) issue("TimerRange", p, "a timer needs exactly one of \"ms\" or \"param\"");
        else if (has_ms && (t.ms < 1 || t.ms > kMachineTimerMaxMs)) issue("TimerRange", p + "/ms", "ms must be 1.." + std::to_string(kMachineTimerMaxMs));
        else if (has_param && !is_param_name(t.param)) issue("TimerRange", p + "/param", "param names must match [a-z][A-Za-z0-9_]*");
        if (t.allow_disabled && !has_param) issue("TimerRange", p + "/allowDisabled", "allowDisabled applies to param timers only");
    }

    if (looks_like_pem(d.description)) issue("SecretLiteral", "/machine/description", "PEM material must never be stored in a machine file");
    for (const auto& kv : d.meta)
        if (looks_like_pem(kv.second)) issue("SecretLiteral", "/meta/" + kv.first, "PEM material must never be stored in a machine file");

    // --- transitions -----------------------------------------------------------------------------------------------------
    const size_t n = d.states.size();
    std::vector<On> kind(d.transitions.size(), On::Bad);
    std::vector<size_t> from(d.transitions.size(), 0), to(d.transitions.size(), 0);
    std::vector<std::vector<ParsedAction>> acts(d.transitions.size());
    std::set<std::string> armed;
    for (size_t i = 0; i < d.transitions.size(); ++i) {
        const auto& t = d.transitions[i];
        const std::string p = "/transitions/" + std::to_string(i);
        auto fs = state_idx.find(t.from), ts = state_idx.find(t.to);
        if (fs == state_idx.end()) issue("UnknownState", p + "/from", "unknown state \"" + t.from + "\"");
        else {
            from[i] = fs->second;
            if (!d.states[fs->second].final.empty()) issue("FinalHasTransitions", p + "/from", "final state \"" + t.from + "\" ends the machine: it cannot have transitions");
        }
        if (ts == state_idx.end()) issue("UnknownState", p + "/to", "unknown state \"" + t.to + "\"");
        else to[i] = ts->second;

        std::string name;
        kind[i] = classify_on(t.on, name);
        switch (kind[i]) {
            case On::Bad: issue("BadEvent", p + "/on", "event must be \"packet:<name>\", \"command:<name>\", \"timer:<name>\" or \"auto\""); break;
            case On::Timer: if (!timer_idx.count(name)) issue("UnknownTimer", p + "/on", "unknown timer \"" + name + "\""); break;
            case On::Packet: case On::Command: if (!event_idx.count(t.on)) issue("UnknownEvent", p + "/on", "event \"" + t.on + "\" is not declared in `events`"); break;
            case On::Auto: break;
        }
        if (t.guard) {
            auto c = counter_idx.find(t.guard->counter);
            if (c == counter_idx.end()) issue("UnknownCounter", p + "/guard/counter", "unknown counter \"" + t.guard->counter + "\"");
            if (t.guard->op != "<" && t.guard->op != ">=") issue("BadGuard", p + "/guard/op", "guard op must be \"<\" or \">=\"");
            if (c != counter_idx.end() && (t.guard->value < 0 || t.guard->value > d.counters[c->second].max))
                issue("CounterRange", p + "/guard/value", "guard value must be 0..max of counter \"" + t.guard->counter + "\"");
        }
        if (!t.run.empty() && !flow_idx.count(t.run)) issue("UnknownFlow", p + "/run", "flow \"" + t.run + "\" is not declared in `flows`");
        for (size_t k = 0; k < t.actions.size(); ++k) {
            const std::string ap = p + "/actions/" + std::to_string(k);
            ParsedAction a;
            if (!split_ref(t.actions[k], a.kind, a.name)) { issue("BadAction", ap, "action must be inc:|reset:|arm:|cancel:|emit:<name>"); continue; }
            if (a.kind == "inc" || a.kind == "reset") {
                if (!counter_idx.count(a.name)) issue("UnknownCounter", ap, "unknown counter \"" + a.name + "\"");
            } else if (a.kind == "arm" || a.kind == "cancel") {
                if (!timer_idx.count(a.name)) issue("UnknownTimer", ap, "unknown timer \"" + a.name + "\"");
                if (a.kind == "arm") armed.insert(a.name);
            } else if (a.kind == "emit") {
                if (!output_idx.count(a.name)) issue("UnknownOutput", ap, "unknown output \"" + a.name + "\"");
            } else {
                issue("BadAction", ap, "action must be inc:|reset:|arm:|cancel:|emit:<name>");
                continue;
            }
            acts[i].push_back(a);
        }
        if (!t.unbounded.empty()) {
            if (kind[i] != On::Timer) issue("BadUnbounded", p + "/unbounded", "`unbounded` only applies to timer transitions");
            if (looks_like_pem(t.unbounded)) issue("SecretLiteral", p + "/unbounded", "PEM material must never be stored in a machine file");
        }
    }
    if (!refs_ok || n == 0) return out;

    // --- per (state, event): ordering, determinism, exhaustiveness -------------------------------------------------------
    std::map<std::pair<size_t, std::string>, std::vector<size_t>> groups;
    for (size_t i = 0; i < d.transitions.size(); ++i) groups[{from[i], d.transitions[i].on}].push_back(i);
    for (const auto& [key, ts] : groups) {
        bool unguarded = false;
        std::set<std::tuple<std::string, std::string, int64_t>> guards;
        bool exhaustive = false;
        std::set<std::pair<std::string, int64_t>> lt, ge;
        for (size_t i : ts) {
            const auto& t = d.transitions[i];
            const std::string p = "/transitions/" + std::to_string(i);
            if (unguarded) {
                issue(t.guard ? "ShadowedTransition" : "NondeterministicTransition", p,
                      "an earlier transition from \"" + t.from + "\" on \"" + t.on + "\" has no guard, so this one is never taken", false);
                continue;
            }
            if (!t.guard) { unguarded = exhaustive = true; continue; }
            if (!guards.insert({t.guard->counter, t.guard->op, t.guard->value}).second)
                issue("NondeterministicTransition", p, "same guard as an earlier transition from \"" + t.from + "\" on \"" + t.on + "\"", false);
            (t.guard->op == "<" ? lt : ge).insert({t.guard->counter, t.guard->value});
        }
        for (const auto& g : lt) if (ge.count(g)) exhaustive = true;
        if (!exhaustive && kind[ts.front()] == On::Timer)
            issue("GuardNotExhaustive", "/transitions/" + std::to_string(ts.front()) + "/guard",
                  "when \"" + key.second + "\" fires in \"" + d.states[key.first].id + "\" every guard may be false and the machine would stall; add the complementary guard or an unguarded fallback", false);
    }
    for (size_t i = 0; i < d.transitions.size(); ++i) {
        std::string name;
        if (kind[i] == On::Timer && classify_on(d.transitions[i].on, name) == On::Timer && !armed.count(name))
            issue("TimerNeverArmed", "/transitions/" + std::to_string(i) + "/on", "timer \"" + name + "\" is never armed (no arm:" + name + " action)", false);
    }

    // --- graph ---------------------------------------------------------------------------------------------------------
    std::vector<std::vector<size_t>> adj(n), radj(n), auto_adj(n);
    for (size_t i = 0; i < d.transitions.size(); ++i) {
        adj[from[i]].push_back(to[i]);
        radj[to[i]].push_back(from[i]);
        if (kind[i] == On::Auto) auto_adj[from[i]].push_back(to[i]);
    }
    size_t initial = 0;
    std::vector<size_t> finals;
    for (size_t s = 0; s < n; ++s) {
        if (d.states[s].initial) initial = s;
        if (!d.states[s].final.empty()) finals.push_back(s);
    }
    const std::vector<bool> reachable = reach(n, adj, {initial});
    const std::vector<bool> exits = reach(n, radj, finals);
    for (size_t s = 0; s < n; ++s) {
        const std::string p = "/states/" + std::to_string(s);
        if (!reachable[s]) issue("Unreachable", p, "state \"" + d.states[s].id + "\" cannot be reached from the initial state", false);
        else if (!exits[s]) issue("NoExit", p, "no final state can be reached from \"" + d.states[s].id + "\" (the machine could never finish)", false);
    }

    // auto-only loops: DFS with colours, report one path per loop entry
    {
        std::vector<int> colour(n, 0);
        std::vector<size_t> parent(n, 0);
        for (size_t s = 0; s < n; ++s) {
            if (colour[s]) continue;
            std::vector<std::pair<size_t, size_t>> st{{s, 0}};
            colour[s] = 1;
            while (!st.empty()) {
                auto& [v, i] = st.back();
                if (i < auto_adj[v].size()) {
                    const size_t w = auto_adj[v][i++];
                    if (colour[w] == 0) { colour[w] = 1; parent[w] = v; st.push_back({w, 0}); }
                    else if (colour[w] == 1) {
                        std::string path = d.states[w].id;
                        std::vector<size_t> chain{v};
                        for (size_t x = v; x != w; x = parent[x]) chain.push_back(parent[x]);
                        std::reverse(chain.begin(), chain.end());
                        for (size_t k = 1; k < chain.size(); ++k) path += " -> " + d.states[chain[k]].id;
                        path += " -> " + d.states[w].id;
                        issue("ImmediateCycle", "/states/" + std::to_string(w), "loop of `auto` transitions with no event in between: " + path, false);
                    }
                } else {
                    colour[v] = 2;
                    st.pop_back();
                }
            }
        }
    }

    // timer loops must be bounded by a counter (or say why they are not)
    const std::vector<size_t> comp = scc(n, adj);
    std::map<size_t, std::set<std::string>> bounding;             // component -> counters bounding its timer loops
    for (size_t i = 0; i < d.transitions.size(); ++i) {
        if (comp[from[i]] != comp[to[i]] || kind[i] != On::Timer) continue;   // not inside a loop
        const auto& t = d.transitions[i];
        if (!t.unbounded.empty()) continue;
        bool ok = t.guard && t.guard->op == "<";
        if (ok) {
            ok = false;
            for (const auto& a : acts[i]) if (a.kind == "inc" && a.name == t.guard->counter) ok = true;
        }
        if (!ok) {
            issue("UnboundedRetry", "/transitions/" + std::to_string(i),
                  "timer transition \"" + t.on + "\" from \"" + t.from + "\" loops back without a bound: guard it with `" + "<counter> < N` and inc:<counter>, or set `unbounded` with the reason", false);
            continue;
        }
        bounding[comp[from[i]]].insert(t.guard->counter);
    }
    for (size_t i = 0; i < d.transitions.size(); ++i) {
        if (comp[from[i]] != comp[to[i]] || (kind[i] != On::Timer && kind[i] != On::Auto)) continue;
        const auto b = bounding.find(comp[from[i]]);
        if (b == bounding.end()) continue;
        for (const auto& a : acts[i])
            if (a.kind == "reset" && b->second.count(a.name))
                issue("UnboundedRetry", "/transitions/" + std::to_string(i),
                      "reset:" + a.name + " inside the loop it bounds would let the loop run forever (reset it on a packet/command transition or outside the loop)", false);
    }

    // states that wait for packets need a way out when nothing arrives
    for (size_t s = 0; s < n; ++s) {
        if (!reachable[s] || !d.states[s].final.empty()) continue;
        bool packet = false, timer = false;
        for (size_t i = 0; i < d.transitions.size(); ++i) {
            if (from[i] != s) continue;
            if (kind[i] == On::Packet) packet = true;
            if (kind[i] == On::Timer) timer = true;
        }
        if (packet && !timer)
            issue("WaitWithoutTimeout", "/states/" + std::to_string(s), "state \"" + d.states[s].id + "\" waits for packets but has no timer transition (it would wait forever if nothing arrives)", false);
    }
    return out;
}

// ======================================================================================================================
// Compile
// ======================================================================================================================

struct MachineCompiler {
    static MachineCompileResult run(const MachineDocument& d, const FlowLibrary& lib) {
        MachineCompileResult r;
        r.issues = validate_machine(d, &lib).issues;
        if (!r.issues.empty()) return r;
        Machine& m = r.machine;
        m.name_ = d.name;
        for (const auto& s : d.states) {
            m.states_.push_back(s.id);
            m.final_.push_back(s.final == "ok" ? MachineStatus::Succeeded : s.final == "failed" ? MachineStatus::Failed : MachineStatus::Running);
            if (s.initial) m.initial_ = m.states_.size() - 1;
        }
        m.events_ = d.events;
        for (const auto& c : d.counters) { m.counters_.push_back(c.name); m.counter_max_.push_back(c.max); }
        for (const auto& t : d.timers) {
            m.timers_.push_back(t.name);
            m.events_.push_back("timer:" + t.name);
            m.timer_.push_back({t.ms, t.param, t.allow_disabled, m.events_.size() - 1});
        }
        m.events_.push_back("auto");
        m.auto_event_ = m.events_.size() - 1;
        m.outputs_ = d.outputs;
        for (const auto& f : d.flows) m.flows_.push_back(lib.at(f));
        m.by_state_.resize(m.states_.size());
        for (const auto& t : d.transitions) {
            Machine::Transition x;
            x.from = *m.find_state(t.from);
            x.to = *m.find_state(t.to);
            x.event = *m.find_event(t.on);
            if (t.guard) {
                x.guarded = true;
                x.guard_lt = t.guard->op == "<";
                x.guard_counter = *m.find_counter(t.guard->counter);
                x.guard_value = t.guard->value;
            }
            if (!t.run.empty()) x.flow = *Machine::find(d.flows, t.run);
            for (const auto& a : t.actions) {
                std::string kind, name;
                split_ref(a, kind, name);
                if (kind == "inc") x.actions.push_back({Machine::ActionKind::Inc, *m.find_counter(name)});
                else if (kind == "reset") x.actions.push_back({Machine::ActionKind::Reset, *m.find_counter(name)});
                else if (kind == "arm") x.actions.push_back({Machine::ActionKind::Arm, *m.find_timer(name)});
                else if (kind == "cancel") x.actions.push_back({Machine::ActionKind::Cancel, *m.find_timer(name)});
                else x.actions.push_back({Machine::ActionKind::Emit, *m.find_output(name)});
            }
            m.by_state_[x.from].push_back(m.transitions_.size());
            m.transitions_.push_back(std::move(x));
        }
        return r;
    }
};

MachineCompileResult compile_machine(const MachineDocument& doc, const FlowLibrary& flows) { return MachineCompiler::run(doc, flows); }

// ======================================================================================================================
// Runner
// ======================================================================================================================

std::optional<MachineRunner> MachineRunner::create(const Machine& m, const MachineParams& params, std::string* error) {
    auto fail = [&](const std::string& e) -> std::optional<MachineRunner> { if (error) *error = e; return std::nullopt; };
    if (m.states_.empty()) return fail("machine was not compiled");
    MachineRunner r(m);
    std::set<std::string> used;
    for (const auto& t : m.timer_) {
        if (t.param.empty()) { r.duration_.push_back(static_cast<uint64_t>(t.ms)); continue; }
        const auto it = std::find_if(params.begin(), params.end(), [&](const auto& kv) { return kv.first == t.param; });
        if (it == params.end()) return fail("missing parameter \"" + t.param + "\"");
        used.insert(t.param);
        const int64_t v = it->second;
        if (v == 0 && t.allow_disabled) { r.duration_.push_back(0); continue; }
        if (v < 1 || v > kMachineTimerMaxMs)
            return fail("parameter \"" + t.param + "\" must be 1.." + std::to_string(kMachineTimerMaxMs) + (t.allow_disabled ? " or 0" : ""));
        r.duration_.push_back(static_cast<uint64_t>(v));
    }
    for (const auto& kv : params)
        if (!used.count(kv.first)) return fail("unknown parameter \"" + kv.first + "\"");
    r.counters_.assign(m.counters_.size(), 0);
    r.deadlines_.assign(m.timers_.size(), std::nullopt);
    r.state_ = m.initial_;
    return r;
}

void MachineRunner::trace(TraceKind kind, std::string_view name, size_t state, std::string_view to, uint8_t result, Error error,
                          uint32_t value) {
    if (!trace_) return;
    TraceRecord r;
    r.kind = kind;
    r.t_ms = trace_->now_ms;
    r.scope = m_->name_;
    r.name = name;
    r.state = m_->states_[state];
    r.to = to;
    r.result = result;
    r.error = error;
    r.value = value;
    trace_->record(r);
}

void MachineRunner::fail(Error e) {
    status_ = MachineStatus::Failed;
    error_ = e;
    for (auto& d : deadlines_) d.reset();
    trace(TraceKind::MachineEnd, {}, state_, {}, static_cast<uint8_t>(status_), e);
}

std::optional<size_t> MachineRunner::select(size_t event) const {
    for (size_t i : m_->by_state_[state_]) {
        const auto& t = m_->transitions_[i];
        if (t.event != event) continue;
        if (t.guarded) {
            const int64_t c = counters_[t.guard_counter];
            if (t.guard_lt ? !(c < t.guard_value) : !(c >= t.guard_value)) continue;
        }
        return i;
    }
    return std::nullopt;
}

// Runs the handler and, unless it dropped, applies the actions and enters the target. false = no move.
bool MachineRunner::take(size_t ti, FlowContext& ctx, uint64_t now_ms, MachineStep& step) {
    const auto& t = m_->transitions_[ti];
    if (t.flow) {
        ++step.flow_runs;
        const FlowResult fr = run_flow(m_->flows_[*t.flow], ctx, nullptr, kDefaultMaxSteps, trace_);
        if (fr.outcome == FlowOutcome::Dropped) { step.dropped = true; step.error = fr.error; return false; }
        if (fr.outcome == FlowOutcome::Errored) { fail(fr.error); step.error = fr.error; return false; }
    }
    for (const auto& a : t.actions) {
        switch (a.kind) {
            case Machine::ActionKind::Inc:
                if (counters_[a.index] < m_->counter_max_[a.index]) ++counters_[a.index];
                break;
            case Machine::ActionKind::Reset: counters_[a.index] = 0; break;
            case Machine::ActionKind::Arm:
                if (duration_[a.index] == 0) deadlines_[a.index].reset();          // disabled timer: never fires
                else deadlines_[a.index] = now_ms + duration_[a.index];
                break;
            case Machine::ActionKind::Cancel: deadlines_[a.index].reset(); break;
            case Machine::ActionKind::Emit:
                step.emits.push_back(a.index);
                trace(TraceKind::Emit, m_->outputs_[a.index], state_);
                break;
        }
    }
    step.transitions.push_back(ti);
    trace(TraceKind::Transition, m_->events_[t.event], t.from, m_->states_[t.to], 0, Error::None, static_cast<uint32_t>(ti));
    state_ = t.to;
    if (m_->final_[state_] != MachineStatus::Running) {
        status_ = m_->final_[state_];
        for (auto& d : deadlines_) d.reset();
        trace(TraceKind::MachineEnd, {}, state_, {}, static_cast<uint8_t>(status_));
    }
    return true;
}

void MachineRunner::dispatch(size_t event, FlowContext& ctx, uint64_t now_ms, MachineStep& step) {
    if (event != m_->auto_event_) {
        const auto t = status_ == MachineStatus::Running ? select(event) : std::nullopt;
        trace(TraceKind::Event, m_->events_[event], state_, {}, static_cast<uint8_t>(t ? TraceEvent::Selected : TraceEvent::Ignored));
        if (t) {
            step.handled = true;
            if (!take(*t, ctx, now_ms, step)) { step.status = status_; return; }
        }
    }
    // auto transitions: the validator rejects auto-only loops, the bound is a second line of defence
    for (size_t k = 0; status_ == MachineStatus::Running; ++k) {
        if (k > m_->states_.size()) { fail(Error::StepLimit); step.error = Error::StepLimit; break; }
        const auto t = select(m_->auto_event_);
        if (!t || !take(*t, ctx, now_ms, step)) break;
    }
    step.status = status_;
}

MachineStep MachineRunner::start(FlowContext& ctx, uint64_t now_ms) {
    MachineStep step;
    stamp(now_ms);
    if (started_) { step.error = Error::Internal; step.status = status_; return step; }
    started_ = true;
    dispatch(m_->auto_event_, ctx, now_ms, step);
    return step;
}

MachineStep MachineRunner::on_event(size_t event, FlowContext& ctx, uint64_t now_ms) {
    MachineStep step;
    step.status = status_;
    stamp(now_ms);
    const bool timer_event = std::any_of(m_->timer_.begin(), m_->timer_.end(), [&](const auto& t) { return t.event == event; });
    if (!started_ || event >= m_->events_.size() || event == m_->auto_event_ || timer_event) {
        step.error = Error::Internal;             // caller bug: not started, or not a packet/command event
        trace(TraceKind::Event, event < m_->events_.size() ? std::string_view(m_->events_[event]) : std::string_view(), state_, {},
              static_cast<uint8_t>(TraceEvent::Rejected), Error::Internal);
        return step;
    }
    dispatch(event, ctx, now_ms, step);
    return step;
}

std::optional<MachineStep> MachineRunner::poll_timer(FlowContext& ctx, uint64_t now_ms) {
    if (!started_ || status_ != MachineStatus::Running) return std::nullopt;
    stamp(now_ms);
    std::optional<size_t> due;
    for (size_t i = 0; i < deadlines_.size(); ++i)
        if (deadlines_[i] && *deadlines_[i] <= now_ms && (!due || *deadlines_[i] < *deadlines_[*due])) due = i;
    if (!due) return std::nullopt;
    deadlines_[*due].reset();                     // one-shot: re-arm explicitly
    MachineStep step;
    dispatch(m_->timer_[*due].event, ctx, now_ms, step);
    return step;
}

std::optional<uint64_t> MachineRunner::next_deadline_ms() const {
    std::optional<uint64_t> best;
    if (status_ != MachineStatus::Running) return best;
    for (const auto& d : deadlines_) if (d && (!best || *d < *best)) best = d;
    return best;
}

}  // namespace pf
