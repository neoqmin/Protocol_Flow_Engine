#include "pf/flow_json.h"

#include "pf/block.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <set>

namespace pf {

namespace {
constexpr size_t kMaxNodes = 4096, kMaxEdges = 16384, kMaxParams = 64, kMaxMeta = 64, kMaxErrors = 100;
constexpr size_t kMaxIdLen = 64, kMaxScalarString = 1024, kMaxDescription = 4096;

std::string lower(std::string_view s) {
    std::string o(s);
    for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return o;
}

// Names a parameter must not have: their values are secrets. Use "<something>Ref" with a key reference instead.
bool is_secret_param_name(const std::string& name) {
    static const char* const kNames[] = {"key", "secret", "password", "passwd", "passphrase", "token", "psk", "privatekey", "private_key",
                                         "apikey", "api_key", "sessionkey", "session_key", "datakey", "data_key", "masterkey", "master_key",
                                         "tlscryptkey", "tls_crypt_key", "cipherkey", "cipher_key"};
    const std::string l = lower(name);
    for (const char* n : kNames) if (l == n) return true;
    return false;
}

bool is_param_name(std::string_view s) {                    // [a-z][A-Za-z0-9_]{0,63}
    if (s.empty() || s.size() > kMaxIdLen || !(s[0] >= 'a' && s[0] <= 'z')) return false;
    for (const char c : s) if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
    return true;
}

bool is_key_ref(std::string_view s) {                       // segments of [a-z][a-z0-9_]* separated by '.'
    if (s.empty() || s.size() > 128) return false;
    bool start = true;
    for (const char c : s) {
        if (start) { if (!(c >= 'a' && c <= 'z')) return false; start = false; continue; }
        if (c == '.') { start = true; continue; }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return !start;
}

bool ends_with_ref(const std::string& name) { return name.size() > 3 && name.compare(name.size() - 3, 3, "Ref") == 0; }
bool looks_like_pem(const std::string& s) { return s.find("-----BEGIN") != std::string::npos; }
bool is_extension_key(const std::string& k) { return k.size() > 2 && k[0] == 'x' && k[1] == '-'; }

std::string pointer_escape(const std::string& s) {
    std::string o;
    for (const char c : s) { if (c == '~') o += "~0"; else if (c == '/') o += "~1"; else o += c; }
    return o;
}

class Loader {
public:
    explicit Loader(FlowJsonResult& r) : r_(r) {}

    void error(FlowJsonErrorCode c, const std::string& path, const std::string& msg) {
        if (r_.errors.size() < kMaxErrors) r_.errors.push_back({c, path, msg});
    }

    // Typed member access with a path for the message.
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
    void check_keys(const JsonValue& obj, const std::string& path, std::initializer_list<const char*> allowed, Extensions& ext) {
        for (const auto& m : obj.members()) {
            if (is_extension_key(m.first)) { ext.push_back(m); continue; }
            bool ok = false;
            for (const char* a : allowed) if (m.first == a) ok = true;
            if (!ok) error(FlowJsonErrorCode::UnknownField, path + "/" + pointer_escape(m.first), "unknown field \"" + m.first + "\" (extensions must start with \"x-\")");
        }
    }

    void load(const JsonValue& root, FlowDocument& d) {
        if (!root.is_object()) { error(FlowJsonErrorCode::NotAnObject, "", "a Flow file must be a JSON object"); return; }
        check_keys(root, "", {"format", "version", "flow", "nodes", "edges", "meta"}, d.extensions);

        std::string fmt;
        if (want_string(require(root, "format", ""), "/format", fmt) && fmt != kFlowFormat)
            error(FlowJsonErrorCode::BadValue, "/format", std::string("format must be \"") + kFlowFormat + "\"");
        d.version = root.find("version") && root.find("version")->is_integer() ? root.find("version")->as_int() : 0;

        if (const JsonValue* f = require(root, "flow", "")) load_flow(*f, d);
        if (const JsonValue* n = require(root, "nodes", "")) load_nodes(*n, d);
        if (const JsonValue* e = root.find("edges")) load_edges(*e, d);
        if (const JsonValue* m = root.find("meta")) load_meta(*m, d);
    }

private:
    void load_flow(const JsonValue& f, FlowDocument& d) {
        if (!f.is_object()) { error(FlowJsonErrorCode::WrongType, "/flow", "expected an object"); return; }
        check_keys(f, "/flow", {"name", "description", "runtime", "inputs"}, d.flow_extensions);
        if (const JsonValue* in = f.find("inputs")) {
            if (!in->is_array()) error(FlowJsonErrorCode::WrongType, "/flow/inputs", "expected an array of context facts");
            else if (in->items().size() > 64) error(FlowJsonErrorCode::TooMany, "/flow/inputs", "too many inputs");
            else
                for (size_t i = 0; i < in->items().size(); ++i) {
                    const std::string p = "/flow/inputs/" + std::to_string(i);
                    std::string s;
                    if (!want_string(&in->items()[i], p, s, 64 + 1)) continue;
                    if (!is_valid_fact(s)) error(FlowJsonErrorCode::BadValue, p, "a context fact looks like \"ovpn.header\" ([a-z][a-z0-9_]* segments joined by '.')");
                    else if (std::find(d.inputs.begin(), d.inputs.end(), s) != d.inputs.end()) error(FlowJsonErrorCode::BadValue, p, "duplicate input");
                    else d.inputs.push_back(s);
                }
        }
        std::string name;
        if (want_string(require(f, "name", "/flow"), "/flow/name", name)) {
            if (!is_valid_flow_id(name)) error(FlowJsonErrorCode::BadValue, "/flow/name", "name must match [A-Za-z_][A-Za-z0-9_-]{0,63}");
            d.name = name;
        }
        if (const JsonValue* v = f.find("description")) {
            if (want_string(v, "/flow/description", d.description, kMaxDescription) && looks_like_pem(d.description))
                error(FlowJsonErrorCode::SecretLiteral, "/flow/description", "PEM material must never be stored in a Flow file");
        }
        if (const JsonValue* rt = f.find("runtime")) {
            if (!rt->is_array() || rt->items().empty()) { error(FlowJsonErrorCode::WrongType, "/flow/runtime", "expected a non-empty array"); return; }
            d.runtime.clear();
            for (size_t i = 0; i < rt->items().size(); ++i) {
                const std::string p = "/flow/runtime/" + std::to_string(i);
                std::string s;
                if (!want_string(&rt->items()[i], p, s)) continue;
                if (s != "user" && s != "kernel") error(FlowJsonErrorCode::BadValue, p, "runtime must be \"user\" or \"kernel\"");
                else if (std::find(d.runtime.begin(), d.runtime.end(), s) != d.runtime.end()) error(FlowJsonErrorCode::BadValue, p, "duplicate runtime");
                else d.runtime.push_back(s);
            }
        }
    }

    void check_scalar_text(const std::string& s, const std::string& path) {
        if (looks_like_pem(s)) error(FlowJsonErrorCode::SecretLiteral, path, "PEM material must never be stored in a Flow file (reference it with a keyRef)");
    }

    void load_params(const JsonValue& p, const std::string& path, FlowNodeDef& n) {
        if (!p.is_object()) { error(FlowJsonErrorCode::WrongType, path, "expected an object"); return; }
        if (p.members().size() > kMaxParams) { error(FlowJsonErrorCode::TooMany, path, "too many parameters"); return; }
        for (const auto& m : p.members()) {
            const std::string pp = path + "/" + pointer_escape(m.first);
            if (is_secret_param_name(m.first)) {                       // checked first: the reason must be "secret", not "bad name"
                error(FlowJsonErrorCode::SecretLiteral, pp, "\"" + m.first + "\" looks like key material: Flow files hold key REFERENCES only (use a \"...Ref\" parameter)");
                continue;
            }
            if (!is_param_name(m.first)) { error(FlowJsonErrorCode::BadValue, pp, "parameter names must match [a-z][A-Za-z0-9_]*"); continue; }
            const JsonValue& v = m.second;
            if (v.is_string()) {
                if (v.as_string().size() > kMaxScalarString) { error(FlowJsonErrorCode::TooMany, pp, "string too long"); continue; }
                check_scalar_text(v.as_string(), pp);
                if (ends_with_ref(m.first) && !is_key_ref(v.as_string())) {
                    error(FlowJsonErrorCode::BadValue, pp, "a *Ref parameter must be a reference like \"session.data_key\" ([a-z][a-z0-9_]* segments joined by '.')");
                    continue;
                }
            } else if (ends_with_ref(m.first)) {
                error(FlowJsonErrorCode::WrongType, pp, "a *Ref parameter must be a string reference");
                continue;
            } else if (v.is_number()) {
                if (!v.is_integer() && !std::isfinite(v.as_double())) { error(FlowJsonErrorCode::BadValue, pp, "number must be finite"); continue; }
            } else if (!v.is_bool()) {
                error(FlowJsonErrorCode::WrongType, pp, "parameter values must be string, number or boolean");
                continue;
            }
            n.params.push_back(m);
        }
    }

    void load_nodes(const JsonValue& ns, FlowDocument& d) {
        if (!ns.is_array()) { error(FlowJsonErrorCode::WrongType, "/nodes", "expected an array"); return; }
        if (ns.items().empty()) error(FlowJsonErrorCode::BadValue, "/nodes", "a flow needs at least one node");
        if (ns.items().size() > kMaxNodes) { error(FlowJsonErrorCode::TooMany, "/nodes", "too many nodes"); return; }
        std::set<std::string> seen;
        for (size_t i = 0; i < ns.items().size(); ++i) {
            const std::string path = "/nodes/" + std::to_string(i);
            const JsonValue& nv = ns.items()[i];
            if (!nv.is_object()) { error(FlowJsonErrorCode::WrongType, path, "expected an object"); continue; }
            FlowNodeDef n;
            check_keys(nv, path, {"id", "block", "params"}, n.extensions);
            if (want_string(require(nv, "id", path), path + "/id", n.id, kMaxIdLen + 1)) {
                if (!is_valid_flow_id(n.id)) error(FlowJsonErrorCode::BadValue, path + "/id", "id must match [A-Za-z_][A-Za-z0-9_-]{0,63}");
                else if (!seen.insert(n.id).second) error(FlowJsonErrorCode::DuplicateId, path + "/id", "duplicate node id \"" + n.id + "\"");
            }
            if (want_string(require(nv, "block", path), path + "/block", n.block, kMaxIdLen + 1) && !is_valid_flow_id(n.block))
                error(FlowJsonErrorCode::BadValue, path + "/block", "block must be a block name like \"parse_data_v2\"");
            if (const JsonValue* p = nv.find("params")) load_params(*p, path + "/params", n);
            d.nodes.push_back(std::move(n));
        }
    }

    void load_edges(const JsonValue& es, FlowDocument& d) {
        if (!es.is_array()) { error(FlowJsonErrorCode::WrongType, "/edges", "expected an array"); return; }
        if (es.items().size() > kMaxEdges) { error(FlowJsonErrorCode::TooMany, "/edges", "too many edges"); return; }
        for (size_t i = 0; i < es.items().size(); ++i) {
            const std::string path = "/edges/" + std::to_string(i);
            const JsonValue& ev = es.items()[i];
            if (!ev.is_object()) { error(FlowJsonErrorCode::WrongType, path, "expected an object"); continue; }
            FlowEdgeDef e;
            check_keys(ev, path, {"from", "to", "port"}, e.extensions);
            if (want_string(require(ev, "from", path), path + "/from", e.from, kMaxIdLen + 1) && !is_valid_flow_id(e.from))
                error(FlowJsonErrorCode::BadValue, path + "/from", "not a valid node id");
            if (const JsonValue* t = require(ev, "to", path)) {
                if (t->is_null()) e.to.reset();
                else {
                    std::string to;
                    if (want_string(t, path + "/to", to, kMaxIdLen + 1)) {
                        if (!is_valid_flow_id(to)) error(FlowJsonErrorCode::BadValue, path + "/to", "not a valid node id (use null to end the flow)");
                        e.to = to;
                    }
                }
            }
            if (const JsonValue* p = ev.find("port")) {
                if (want_string(p, path + "/port", e.port) && e.port != "continue" && e.port != "yes" && e.port != "no")
                    error(FlowJsonErrorCode::BadValue, path + "/port", "port must be \"continue\", \"yes\" or \"no\"");
            }
            d.edges.push_back(std::move(e));
        }
    }

    void load_meta(const JsonValue& m, FlowDocument& d) {
        if (!m.is_object()) { error(FlowJsonErrorCode::WrongType, "/meta", "expected an object"); return; }
        if (m.members().size() > kMaxMeta) { error(FlowJsonErrorCode::TooMany, "/meta", "too many meta entries"); return; }
        for (const auto& kv : m.members()) {
            const std::string p = "/meta/" + pointer_escape(kv.first);
            if (!kv.second.is_string()) { error(FlowJsonErrorCode::WrongType, p, "meta values must be strings"); continue; }
            if (kv.second.as_string().size() > kMaxScalarString) { error(FlowJsonErrorCode::TooMany, p, "string too long"); continue; }
            check_scalar_text(kv.second.as_string(), p);
            d.meta.emplace_back(kv.first, kv.second.as_string());
        }
    }

    FlowJsonResult& r_;
};

}  // namespace

const char* flow_json_error_name(FlowJsonErrorCode c) {
    switch (c) {
        case FlowJsonErrorCode::BadJson: return "BadJson";
        case FlowJsonErrorCode::NotAnObject: return "NotAnObject";
        case FlowJsonErrorCode::MissingField: return "MissingField";
        case FlowJsonErrorCode::WrongType: return "WrongType";
        case FlowJsonErrorCode::BadValue: return "BadValue";
        case FlowJsonErrorCode::UnknownField: return "UnknownField";
        case FlowJsonErrorCode::DuplicateId: return "DuplicateId";
        case FlowJsonErrorCode::TooMany: return "TooMany";
        case FlowJsonErrorCode::SecretLiteral: return "SecretLiteral";
        case FlowJsonErrorCode::UnsupportedVersion: return "UnsupportedVersion";
        case FlowJsonErrorCode::MigrationFailed: return "MigrationFailed";
    }
    return "Unknown";
}

bool is_valid_flow_id(std::string_view s) {
    if (s.empty() || s.size() > kMaxIdLen) return false;
    if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) return false;
    for (const char c : s) if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') return false;
    return true;
}

bool upgrade_document(JsonValue& root, const FlowMigrations* migrations, int64_t current_version, int64_t min_version,
                      std::vector<FlowJsonError>& errors, int64_t& migrated_from) {
    const JsonValue* ver = root.find("version");
    if (!ver) { errors.push_back({FlowJsonErrorCode::MissingField, "/version", "required field \"version\" is missing"}); return false; }
    if (!ver->is_integer() || ver->as_int() < 1) { errors.push_back({FlowJsonErrorCode::WrongType, "/version", "version must be a positive integer"}); return false; }
    int64_t v = ver->as_int();
    if (v > current_version) {
        errors.push_back({FlowJsonErrorCode::UnsupportedVersion, "/version",
                          "file version " + std::to_string(v) + " is newer than this build supports (" + std::to_string(current_version) + "): upgrade the software"});
        return false;
    }
    if (v < min_version) {
        errors.push_back({FlowJsonErrorCode::UnsupportedVersion, "/version", "file version " + std::to_string(v) + " is older than the oldest supported (" + std::to_string(min_version) + ")"});
        return false;
    }
    const int64_t original = v;
    while (v < current_version) {
        const FlowMigrations::Migrator* step = migrations ? migrations->find(v) : nullptr;
        if (!step) {
            errors.push_back({FlowJsonErrorCode::UnsupportedVersion, "/version", "no migration from version " + std::to_string(v) + " to " + std::to_string(v + 1)});
            return false;
        }
        std::string why;
        if (!(*step)(root, why)) {
            errors.push_back({FlowJsonErrorCode::MigrationFailed, "", "migration " + std::to_string(v) + " -> " + std::to_string(v + 1) + " failed: " + why});
            return false;
        }
        ++v;                                                    // the engine tracks the version; the "version" member is not read again
    }
    if (original != current_version) migrated_from = original;
    return true;
}

FlowJsonResult parse_flow_json(std::string_view text, const FlowMigrations* migrations, int64_t current_version, int64_t min_version) {
    FlowJsonResult r;
    JsonParseResult jp = parse_json(text);
    if (!jp.ok) {
        r.errors.push_back({FlowJsonErrorCode::BadJson, "", "line " + std::to_string(jp.error.line) + ", column " + std::to_string(jp.error.column) + ": " + jp.error.message});
        return r;
    }
    JsonValue& root = jp.value;
    if (!root.is_object()) { r.errors.push_back({FlowJsonErrorCode::NotAnObject, "", "a Flow file must be a JSON object"}); return r; }

    // Version first: an old or new file may have a different shape, so it cannot be judged against this schema yet.
    if (!upgrade_document(root, migrations, current_version, min_version, r.errors, r.migrated_from)) return r;

    Loader(r).load(root, r.doc);
    r.doc.version = current_version;
    return r;
}

std::string write_flow_json(const FlowDocument& d) {
    JsonValue root = JsonValue::object();
    root.set("format", JsonValue::string(kFlowFormat));
    root.set("version", JsonValue::integer(kFlowVersionCurrent));
    JsonValue flow = JsonValue::object();
    flow.set("name", JsonValue::string(d.name));
    if (!d.description.empty()) flow.set("description", JsonValue::string(d.description));
    JsonValue rt = JsonValue::array();
    for (const auto& s : d.runtime) rt.push(JsonValue::string(s));
    flow.set("runtime", std::move(rt));
    if (!d.inputs.empty()) {
        JsonValue in = JsonValue::array();
        for (const auto& s : d.inputs) in.push(JsonValue::string(s));
        flow.set("inputs", std::move(in));
    }
    for (const auto& x : d.flow_extensions) flow.set(x.first, x.second);
    root.set("flow", std::move(flow));

    JsonValue nodes = JsonValue::array();
    for (const auto& n : d.nodes) {
        JsonValue o = JsonValue::object();
        o.set("id", JsonValue::string(n.id));
        o.set("block", JsonValue::string(n.block));
        if (!n.params.empty()) {
            JsonValue p = JsonValue::object();
            for (const auto& kv : n.params) p.set(kv.first, kv.second);
            o.set("params", std::move(p));
        }
        for (const auto& x : n.extensions) o.set(x.first, x.second);
        nodes.push(std::move(o));
    }
    root.set("nodes", std::move(nodes));

    JsonValue edges = JsonValue::array();
    for (const auto& e : d.edges) {
        JsonValue o = JsonValue::object();
        o.set("from", JsonValue::string(e.from));
        if (e.port != "continue") o.set("port", JsonValue::string(e.port));
        o.set("to", e.to ? JsonValue::string(*e.to) : JsonValue::null());
        for (const auto& x : e.extensions) o.set(x.first, x.second);
        edges.push(std::move(o));
    }
    if (!d.edges.empty()) root.set("edges", std::move(edges));           // optional: no edges = plain sequence
    if (!d.meta.empty()) {
        JsonValue m = JsonValue::object();
        for (const auto& kv : d.meta) m.set(kv.first, JsonValue::string(kv.second));
        root.set("meta", std::move(m));
    }
    for (const auto& x : d.extensions) root.set(x.first, x.second);
    return write_json(root, true);
}

}  // namespace pf
