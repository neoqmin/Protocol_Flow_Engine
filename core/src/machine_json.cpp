#include "pf/machine_json.h"

namespace pf {

namespace {
constexpr size_t kMaxStates = 1024, kMaxTransitions = 8192, kMaxDecls = 256, kMaxActions = 16, kMaxMeta = 64, kMaxErrors = 100;
constexpr size_t kMaxIdLen = 64, kMaxRefLen = 160, kMaxScalarString = 1024, kMaxDescription = 4096;

bool looks_like_pem(const std::string& s) { return s.find("-----BEGIN") != std::string::npos; }
bool is_extension_key(const std::string& k) { return k.size() > 2 && k[0] == 'x' && k[1] == '-'; }

std::string pointer_escape(const std::string& s) {
    std::string o;
    for (const char c : s) { if (c == '~') o += "~0"; else if (c == '/') o += "~1"; else o += c; }
    return o;
}

class Loader {
public:
    explicit Loader(MachineJsonResult& r) : r_(r) {}

    void load(const JsonValue& root, MachineDocument& d) {
        check_keys(root, "", {"format", "version", "machine", "flows", "events", "outputs", "counters", "timers", "states", "transitions", "meta"}, d.extensions);
        std::string fmt;
        if (want_string(require(root, "format", ""), "/format", fmt) && fmt != kMachineFormat)
            error(FlowJsonErrorCode::BadValue, "/format", std::string("format must be \"") + kMachineFormat + "\"");
        if (const JsonValue* m = require(root, "machine", "")) load_header(*m, d);
        if (const JsonValue* v = root.find("flows")) load_ids(*v, "/flows", d.flows);
        if (const JsonValue* v = root.find("events")) load_refs(*v, "/events", d.events);
        if (const JsonValue* v = root.find("outputs")) load_ids(*v, "/outputs", d.outputs);
        if (const JsonValue* v = root.find("counters")) load_counters(*v, d);
        if (const JsonValue* v = root.find("timers")) load_timers(*v, d);
        if (const JsonValue* v = require(root, "states", "")) load_states(*v, d);
        if (const JsonValue* v = require(root, "transitions", "")) load_transitions(*v, d);
        if (const JsonValue* v = root.find("meta")) load_meta(*v, d);
    }

private:
    void error(FlowJsonErrorCode c, const std::string& path, const std::string& msg) {
        if (r_.errors.size() < kMaxErrors) r_.errors.push_back({c, path, msg});
    }
    const JsonValue* require(const JsonValue& obj, const char* key, const std::string& path) {
        const JsonValue* v = obj.find(key);
        if (!v) error(FlowJsonErrorCode::MissingField, path + "/" + key, std::string("required field \"") + key + "\" is missing");
        return v;
    }
    bool want_string(const JsonValue* v, const std::string& path, std::string& out, size_t max_len = kMaxScalarString) {
        if (!v) return false;
        if (!v->is_string()) { error(FlowJsonErrorCode::WrongType, path, "expected a string"); return false; }
        if (v->as_string().size() > max_len) { error(FlowJsonErrorCode::TooMany, path, "string too long"); return false; }
        out = v->as_string();
        return true;
    }
    bool want_id(const JsonValue* v, const std::string& path, std::string& out) {
        if (!want_string(v, path, out, kMaxIdLen + 1)) return false;
        if (!is_valid_flow_id(out)) { error(FlowJsonErrorCode::BadValue, path, "name must match [A-Za-z_][A-Za-z0-9_-]{0,63}"); return false; }
        return true;
    }
    bool want_int(const JsonValue* v, const std::string& path, int64_t& out) {
        if (!v) return false;
        if (!v->is_integer()) { error(FlowJsonErrorCode::WrongType, path, "expected an integer"); return false; }
        out = v->as_int();
        return true;
    }
    bool want_bool(const JsonValue* v, const std::string& path, bool& out) {
        if (!v) return false;
        if (!v->is_bool()) { error(FlowJsonErrorCode::WrongType, path, "expected true or false"); return false; }
        out = v->as_bool();
        return true;
    }
    bool want_array(const JsonValue& v, const std::string& path, size_t max) {
        if (!v.is_array()) { error(FlowJsonErrorCode::WrongType, path, "expected an array"); return false; }
        if (v.items().size() > max) { error(FlowJsonErrorCode::TooMany, path, "too many entries"); return false; }
        return true;
    }
    bool want_object(const JsonValue& v, const std::string& path) {
        if (!v.is_object()) { error(FlowJsonErrorCode::WrongType, path, "expected an object"); return false; }
        return true;
    }
    void check_keys(const JsonValue& obj, const std::string& path, std::initializer_list<const char*> allowed, Extensions& ext) {
        for (const auto& m : obj.members()) {
            if (is_extension_key(m.first)) { ext.push_back(m); continue; }
            bool ok = false;
            for (const char* a : allowed) if (m.first == a) ok = true;
            if (!ok) error(FlowJsonErrorCode::UnknownField, path + "/" + pointer_escape(m.first), "unknown field \"" + m.first + "\" (extensions must start with \"x-\")");
        }
    }
    void check_text(const std::string& s, const std::string& path) {
        if (looks_like_pem(s)) error(FlowJsonErrorCode::SecretLiteral, path, "PEM material must never be stored in a machine file");
    }

    void load_header(const JsonValue& m, MachineDocument& d) {
        if (!want_object(m, "/machine")) return;
        check_keys(m, "/machine", {"name", "description"}, d.machine_extensions);
        want_id(require(m, "name", "/machine"), "/machine/name", d.name);
        if (const JsonValue* v = m.find("description"))
            if (want_string(v, "/machine/description", d.description, kMaxDescription)) check_text(d.description, "/machine/description");
    }
    void load_ids(const JsonValue& v, const std::string& path, std::vector<std::string>& out) {
        if (!want_array(v, path, kMaxDecls)) return;
        for (size_t i = 0; i < v.items().size(); ++i) {
            std::string s;
            if (want_id(&v.items()[i], path + "/" + std::to_string(i), s)) out.push_back(s);
        }
    }
    // "kind:name" strings; their meaning is checked by the validator (same codes for code-built and loaded machines).
    void load_refs(const JsonValue& v, const std::string& path, std::vector<std::string>& out, size_t max = kMaxDecls) {
        if (!want_array(v, path, max)) return;
        for (size_t i = 0; i < v.items().size(); ++i) {
            std::string s;
            if (want_string(&v.items()[i], path + "/" + std::to_string(i), s, kMaxRefLen)) out.push_back(s);
        }
    }
    void load_counters(const JsonValue& v, MachineDocument& d) {
        if (!want_array(v, "/counters", kMaxDecls)) return;
        for (size_t i = 0; i < v.items().size(); ++i) {
            const std::string p = "/counters/" + std::to_string(i);
            const JsonValue& o = v.items()[i];
            if (!want_object(o, p)) continue;
            MachineCounterDef c;
            check_keys(o, p, {"name", "max"}, c.extensions);
            want_id(require(o, "name", p), p + "/name", c.name);
            want_int(require(o, "max", p), p + "/max", c.max);
            d.counters.push_back(std::move(c));
        }
    }
    void load_timers(const JsonValue& v, MachineDocument& d) {
        if (!want_array(v, "/timers", kMaxDecls)) return;
        for (size_t i = 0; i < v.items().size(); ++i) {
            const std::string p = "/timers/" + std::to_string(i);
            const JsonValue& o = v.items()[i];
            if (!want_object(o, p)) continue;
            MachineTimerDef t;
            check_keys(o, p, {"name", "ms", "param", "allowDisabled"}, t.extensions);
            want_id(require(o, "name", p), p + "/name", t.name);
            if (const JsonValue* x = o.find("ms")) {
                if (want_int(x, p + "/ms", t.ms) && t.ms == 0) error(FlowJsonErrorCode::BadValue, p + "/ms", "ms must be positive");
            }
            if (const JsonValue* x = o.find("param")) want_string(x, p + "/param", t.param, kMaxIdLen + 1);
            if (const JsonValue* x = o.find("allowDisabled")) want_bool(x, p + "/allowDisabled", t.allow_disabled);
            d.timers.push_back(std::move(t));
        }
    }
    void load_states(const JsonValue& v, MachineDocument& d) {
        if (!want_array(v, "/states", kMaxStates)) return;
        for (size_t i = 0; i < v.items().size(); ++i) {
            const std::string p = "/states/" + std::to_string(i);
            const JsonValue& o = v.items()[i];
            if (!want_object(o, p)) continue;
            MachineStateDef s;
            check_keys(o, p, {"id", "initial", "final"}, s.extensions);
            want_id(require(o, "id", p), p + "/id", s.id);
            if (const JsonValue* x = o.find("initial")) want_bool(x, p + "/initial", s.initial);
            if (const JsonValue* x = o.find("final")) {
                if (want_string(x, p + "/final", s.final, 16) && s.final != "ok" && s.final != "failed")
                    error(FlowJsonErrorCode::BadValue, p + "/final", "final must be \"ok\" or \"failed\"");
            }
            d.states.push_back(std::move(s));
        }
    }
    void load_transitions(const JsonValue& v, MachineDocument& d) {
        if (!want_array(v, "/transitions", kMaxTransitions)) return;
        for (size_t i = 0; i < v.items().size(); ++i) {
            const std::string p = "/transitions/" + std::to_string(i);
            const JsonValue& o = v.items()[i];
            if (!want_object(o, p)) continue;
            MachineTransitionDef t;
            check_keys(o, p, {"from", "on", "guard", "run", "actions", "to", "unbounded"}, t.extensions);
            want_id(require(o, "from", p), p + "/from", t.from);
            want_string(require(o, "on", p), p + "/on", t.on, kMaxRefLen);
            if (const JsonValue* g = o.find("guard")) {
                if (want_object(*g, p + "/guard")) {
                    MachineGuardDef gd;
                    Extensions unused;
                    check_keys(*g, p + "/guard", {"counter", "op", "value"}, unused);
                    for (const auto& x : unused) error(FlowJsonErrorCode::UnknownField, p + "/guard/" + pointer_escape(x.first), "guards take no extensions");
                    want_id(require(*g, "counter", p + "/guard"), p + "/guard/counter", gd.counter);
                    want_string(require(*g, "op", p + "/guard"), p + "/guard/op", gd.op, 4);
                    want_int(require(*g, "value", p + "/guard"), p + "/guard/value", gd.value);
                    t.guard = gd;
                }
            }
            if (const JsonValue* x = o.find("run")) want_id(x, p + "/run", t.run);
            if (const JsonValue* x = o.find("actions")) load_refs(*x, p + "/actions", t.actions, kMaxActions);
            want_id(require(o, "to", p), p + "/to", t.to);
            if (const JsonValue* x = o.find("unbounded")) {
                if (want_string(x, p + "/unbounded", t.unbounded)) {
                    if (t.unbounded.empty()) error(FlowJsonErrorCode::BadValue, p + "/unbounded", "give the reason the loop is deliberately endless");
                    check_text(t.unbounded, p + "/unbounded");
                }
            }
            d.transitions.push_back(std::move(t));
        }
    }
    void load_meta(const JsonValue& m, MachineDocument& d) {
        if (!want_object(m, "/meta")) return;
        if (m.members().size() > kMaxMeta) { error(FlowJsonErrorCode::TooMany, "/meta", "too many meta entries"); return; }
        for (const auto& kv : m.members()) {
            const std::string p = "/meta/" + pointer_escape(kv.first);
            std::string s;
            if (!want_string(&kv.second, p, s)) continue;
            check_text(s, p);
            d.meta.emplace_back(kv.first, s);
        }
    }

    MachineJsonResult& r_;
};

JsonValue strings(const std::vector<std::string>& v) {
    JsonValue a = JsonValue::array();
    for (const auto& s : v) a.push(JsonValue::string(s));
    return a;
}

}  // namespace

MachineJsonResult parse_machine_json(std::string_view text, const FlowMigrations* migrations, int64_t current_version, int64_t min_version) {
    MachineJsonResult r;
    JsonParseResult jp = parse_json(text);
    if (!jp.ok) {
        r.errors.push_back({FlowJsonErrorCode::BadJson, "", "line " + std::to_string(jp.error.line) + ", column " + std::to_string(jp.error.column) + ": " + jp.error.message});
        return r;
    }
    JsonValue& root = jp.value;
    if (!root.is_object()) { r.errors.push_back({FlowJsonErrorCode::NotAnObject, "", "a machine file must be a JSON object"}); return r; }
    if (!upgrade_document(root, migrations, current_version, min_version, r.errors, r.migrated_from)) return r;
    Loader(r).load(root, r.doc);
    r.doc.version = current_version;
    return r;
}

std::string write_machine_json(const MachineDocument& d) {
    JsonValue root = JsonValue::object();
    root.set("format", JsonValue::string(kMachineFormat));
    root.set("version", JsonValue::integer(kMachineVersionCurrent));
    JsonValue m = JsonValue::object();
    m.set("name", JsonValue::string(d.name));
    if (!d.description.empty()) m.set("description", JsonValue::string(d.description));
    for (const auto& x : d.machine_extensions) m.set(x.first, x.second);
    root.set("machine", std::move(m));
    if (!d.flows.empty()) root.set("flows", strings(d.flows));
    if (!d.events.empty()) root.set("events", strings(d.events));
    if (!d.outputs.empty()) root.set("outputs", strings(d.outputs));
    if (!d.counters.empty()) {
        JsonValue a = JsonValue::array();
        for (const auto& c : d.counters) {
            JsonValue o = JsonValue::object();
            o.set("name", JsonValue::string(c.name));
            o.set("max", JsonValue::integer(c.max));
            for (const auto& x : c.extensions) o.set(x.first, x.second);
            a.push(std::move(o));
        }
        root.set("counters", std::move(a));
    }
    if (!d.timers.empty()) {
        JsonValue a = JsonValue::array();
        for (const auto& t : d.timers) {
            JsonValue o = JsonValue::object();
            o.set("name", JsonValue::string(t.name));
            if (t.ms != 0) o.set("ms", JsonValue::integer(t.ms));
            if (!t.param.empty()) o.set("param", JsonValue::string(t.param));
            if (t.allow_disabled) o.set("allowDisabled", JsonValue::boolean(true));
            for (const auto& x : t.extensions) o.set(x.first, x.second);
            a.push(std::move(o));
        }
        root.set("timers", std::move(a));
    }
    JsonValue states = JsonValue::array();
    for (const auto& s : d.states) {
        JsonValue o = JsonValue::object();
        o.set("id", JsonValue::string(s.id));
        if (s.initial) o.set("initial", JsonValue::boolean(true));
        if (!s.final.empty()) o.set("final", JsonValue::string(s.final));
        for (const auto& x : s.extensions) o.set(x.first, x.second);
        states.push(std::move(o));
    }
    root.set("states", std::move(states));
    JsonValue ts = JsonValue::array();
    for (const auto& t : d.transitions) {
        JsonValue o = JsonValue::object();
        o.set("from", JsonValue::string(t.from));
        o.set("on", JsonValue::string(t.on));
        if (t.guard) {
            JsonValue g = JsonValue::object();
            g.set("counter", JsonValue::string(t.guard->counter));
            g.set("op", JsonValue::string(t.guard->op));
            g.set("value", JsonValue::integer(t.guard->value));
            o.set("guard", std::move(g));
        }
        if (!t.run.empty()) o.set("run", JsonValue::string(t.run));
        if (!t.actions.empty()) o.set("actions", strings(t.actions));
        o.set("to", JsonValue::string(t.to));
        if (!t.unbounded.empty()) o.set("unbounded", JsonValue::string(t.unbounded));
        for (const auto& x : t.extensions) o.set(x.first, x.second);
        ts.push(std::move(o));
    }
    root.set("transitions", std::move(ts));
    if (!d.meta.empty()) {
        JsonValue mm = JsonValue::object();
        for (const auto& kv : d.meta) mm.set(kv.first, JsonValue::string(kv.second));
        root.set("meta", std::move(mm));
    }
    for (const auto& x : d.extensions) root.set(x.first, x.second);
    return write_json(root, true);
}

LoadedMachine load_machine_json(std::string_view text, const FlowLibrary& flows, const FlowMigrations* migrations) {
    LoadedMachine out;
    MachineJsonResult pr = parse_machine_json(text, migrations);
    out.migrated_from = pr.migrated_from;
    if (!pr.ok()) {
        for (const auto& e : pr.errors) out.issues.push_back({flow_json_error_name(e.code), e.path, e.message});
        return out;
    }
    MachineCompileResult cr = compile_machine(pr.doc, flows);
    out.doc = std::move(pr.doc);
    if (!cr.ok()) { out.issues = std::move(cr.issues); return out; }
    out.machine = std::move(cr.machine);
    return out;
}

}  // namespace pf
