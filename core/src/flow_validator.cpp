#include "pf/flow_validator.h"

#include <algorithm>
#include <map>
#include <set>

namespace pf {

namespace {

size_t edit_distance(const std::string& a, const std::string& b) {
    std::vector<size_t> prev(b.size() + 1), cur(b.size() + 1);
    for (size_t j = 0; j <= b.size(); ++j) prev[j] = j;
    for (size_t i = 1; i <= a.size(); ++i) {
        cur[0] = i;
        for (size_t j = 1; j <= b.size(); ++j)
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)});
        std::swap(prev, cur);
    }
    return prev[b.size()];
}

std::string suggest(const std::string& name, const BlockRegistry& reg) {
    size_t best = 3;                                   // only suggest when reasonably close
    std::string hit;
    for (const auto& b : reg.all()) {
        const size_t d = edit_distance(name, b.name);
        if (d < best) { best = d; hit = b.name; }
    }
    return hit.empty() ? "" : " (did you mean \"" + hit + "\"?)";
}

bool ends_with_ref(const std::string& n) { return n.size() > 3 && n.compare(n.size() - 3, 3, "Ref") == 0; }

}  // namespace

FlowValidation validate_flow(const FlowDocument& doc, const BlockRegistry& reg) {
    FlowValidation out;
    auto issue = [&](const char* code, const std::string& path, const std::string& msg) { out.issues.push_back({code, path, msg}); };

    if (std::find(doc.runtime.begin(), doc.runtime.end(), "user") == doc.runtime.end())
        issue("RuntimeUnsupported", "/flow/runtime", "this build executes only the \"user\" runtime; add \"user\" to flow.runtime");

    // --- nodes: blocks and parameters --------------------------------------------------------------------------
    std::map<std::string, size_t> index;                       // id -> position
    std::vector<const BlockDescriptor*> desc(doc.nodes.size(), nullptr);
    for (size_t i = 0; i < doc.nodes.size(); ++i) {
        const FlowNodeDef& n = doc.nodes[i];
        const std::string path = "/nodes/" + std::to_string(i);
        index.emplace(n.id, i);                                // ids are unique (loader), but stay safe for hand-built docs
        const BlockDescriptor* d = reg.find(std::string_view(n.block));
        if (!d) { issue("UnknownBlock", path + "/block", "unknown block \"" + n.block + "\"" + suggest(n.block, reg)); continue; }
        desc[i] = d;

        std::set<std::string> given;
        for (const auto& kv : n.params) {
            given.insert(kv.first);
            const ParamSpec* spec = nullptr;
            for (size_t k = 0; k < d->param_count; ++k) if (kv.first == d->params[k].name) spec = &d->params[k];
            const std::string pp = path + "/params/" + kv.first;
            if (!spec) { issue("UnknownParam", pp, "block \"" + n.block + "\" has no parameter \"" + kv.first + "\""); continue; }
            const JsonValue& v = kv.second;
            bool ok = true;
            switch (spec->type) {
                case ParamType::String: ok = v.is_string(); break;
                case ParamType::KeyRef: ok = v.is_string() && ends_with_ref(kv.first); break;
                case ParamType::Integer: ok = v.is_integer(); break;
                case ParamType::Number: ok = v.is_number(); break;
                case ParamType::Bool: ok = v.is_bool(); break;
            }
            if (!ok) issue("ParamType", pp, "parameter \"" + kv.first + "\" has the wrong type for block \"" + n.block + "\"");
        }
        for (size_t k = 0; k < d->param_count; ++k)
            if (d->params[k].required && !given.count(d->params[k].name))
                issue("MissingParam", path + "/params", "block \"" + n.block + "\" requires parameter \"" + d->params[k].name + "\"");
    }

    // --- edges: endpoints, ports, duplicates ---------------------------------------------------------------------
    struct Exits { bool cont = false, yes = false, no = false; };
    std::vector<Exits> exits(doc.nodes.size());
    std::vector<size_t> cont_to(doc.nodes.size(), SIZE_MAX), yes_to(doc.nodes.size(), SIZE_MAX), no_to(doc.nodes.size(), SIZE_MAX);   // SIZE_MAX = end
    for (size_t i = 0; i < doc.edges.size(); ++i) {
        const FlowEdgeDef& e = doc.edges[i];
        const std::string path = "/edges/" + std::to_string(i);
        auto from = index.find(e.from);
        if (from == index.end()) { issue("EdgeUnknownSource", path + "/from", "edge starts at unknown node \"" + e.from + "\""); continue; }
        size_t target = SIZE_MAX;
        if (e.to) {
            auto to = index.find(*e.to);
            if (to == index.end()) issue("EdgeUnknownTarget", path + "/to", "edge points to unknown node \"" + *e.to + "\"");
            else target = to->second;
        }
        const size_t f = from->second;
        if (!desc[f]) continue;                                // block unknown: its ports cannot be judged, already reported
        const bool decision = desc[f]->type == BlockType::Decision;
        if (decision && e.port == "continue")
            issue("PortMismatch", path + "/port", "node \"" + e.from + "\" is a decision (\"" + doc.nodes[f].block + "\"): use port \"yes\" or \"no\", not \"continue\"");
        else if (!decision && e.port != "continue")
            issue("PortMismatch", path + "/port", "node \"" + e.from + "\" is an action (\"" + doc.nodes[f].block + "\"): it only has the \"continue\" port, not \"" + e.port + "\"");
        else {
            bool& seen = e.port == "yes" ? exits[f].yes : e.port == "no" ? exits[f].no : exits[f].cont;
            if (seen) { issue("DuplicateEdge", path, "node \"" + e.from + "\" already has an edge on port \"" + e.port + "\""); continue; }
            seen = true;
            (e.port == "yes" ? yes_to : e.port == "no" ? no_to : cont_to)[f] = target;
        }
    }
    for (size_t i = 0; i < doc.nodes.size(); ++i) {
        if (!desc[i] || desc[i]->type != BlockType::Decision) continue;
        if (!exits[i].yes) issue("MissingEdge", "/nodes/" + std::to_string(i), "decision \"" + doc.nodes[i].id + "\" has no \"yes\" edge");
        if (!exits[i].no) issue("MissingEdge", "/nodes/" + std::to_string(i), "decision \"" + doc.nodes[i].id + "\" has no \"no\" edge");
    }

    // Graph checks need a fully resolved graph (same rule as FlowBuilder).
    if (!out.issues.empty() || doc.nodes.empty()) return out;

    // Implicit sequential flow: an action without a continue edge goes to the next node in the list (none after the last).
    const size_t n = doc.nodes.size();
    std::vector<std::vector<size_t>> succ(n);
    for (size_t i = 0; i < n; ++i) {
        if (desc[i]->type == BlockType::Decision) {
            if (yes_to[i] != SIZE_MAX) succ[i].push_back(yes_to[i]);
            if (no_to[i] != SIZE_MAX) succ[i].push_back(no_to[i]);
        } else if (exits[i].cont) {
            if (cont_to[i] != SIZE_MAX) succ[i].push_back(cont_to[i]);
        } else if (i + 1 < n) {
            succ[i].push_back(i + 1);
        }
    }

    enum : uint8_t { White, Grey, Black };
    std::vector<uint8_t> color(n, White);
    for (size_t root = 0; root < n && out.issues.empty(); ++root) {
        if (color[root] != White) continue;
        std::vector<std::pair<size_t, size_t>> stack{{root, 0}};         // (node, next successor index)
        color[root] = Grey;
        while (!stack.empty() && out.issues.empty()) {
            auto& top = stack.back();
            if (top.second >= succ[top.first].size()) { color[top.first] = Black; stack.pop_back(); continue; }
            const size_t nxt = succ[top.first][top.second++];
            if (color[nxt] == Grey) {
                std::string loop;                                          // nxt -> ... -> top.first -> nxt
                size_t at = 0;
                for (size_t k = 0; k < stack.size(); ++k) if (stack[k].first == nxt) at = k;
                for (size_t k = at; k < stack.size(); ++k) loop += doc.nodes[stack[k].first].id + " -> ";
                loop += doc.nodes[nxt].id;
                issue("Cycle", "/nodes/" + std::to_string(nxt), "the flow can loop: " + loop);
            } else if (color[nxt] == White) {
                color[nxt] = Grey;
                stack.push_back({nxt, 0});
            }
        }
    }
    if (!out.issues.empty()) return out;

    std::vector<bool> reach(n, false);
    std::vector<size_t> work{0};
    reach[0] = true;
    while (!work.empty()) {
        const size_t i = work.back();
        work.pop_back();
        for (size_t t : succ[i]) if (!reach[t]) { reach[t] = true; work.push_back(t); }
    }
    for (size_t i = 0; i < n; ++i)
        if (!reach[i]) issue("Unreachable", "/nodes/" + std::to_string(i), "node \"" + doc.nodes[i].id + "\" cannot be reached from the first node \"" + doc.nodes[0].id + "\"");
    return out;
}

CompileResult compile_flow(const FlowDocument& doc, const BlockRegistry& reg) {
    CompileResult r;
    FlowValidation v = validate_flow(doc, reg);
    if (!v.ok()) { r.issues = std::move(v.issues); return r; }

    FlowBuilder b(doc.name);
    for (const auto& n : doc.nodes) {
        const BlockDescriptor* d = reg.find(std::string_view(n.block));
        if (!d) { r.issues.push_back({"Internal", "", "validator accepted unknown block \"" + n.block + "\""}); return r; }
        b.add(n.id, d->id);
    }
    for (const auto& e : doc.edges) {
        const std::string to = e.to ? *e.to : std::string();      // "" = end of flow
        if (e.port == "yes") b.on_yes(e.from, to);
        else if (e.port == "no") b.on_no(e.from, to);
        else b.on_continue(e.from, to);
    }
    FlowBuildResult built = b.build(reg);
    if (!built.ok()) {                                            // validator and builder must agree: this is OUR bug
        for (const auto& m : built.errors) r.issues.push_back({"Internal", "", "validator accepted a flow the builder rejected: " + m});
        return r;
    }
    r.flow = std::move(built.flow);
    return r;
}

LoadedFlow load_flow_json(std::string_view text, const BlockRegistry& reg, const FlowMigrations* migrations) {
    LoadedFlow out;
    FlowJsonResult parsed = parse_flow_json(text, migrations);
    out.migrated_from = parsed.migrated_from;
    if (!parsed.ok()) {
        for (const auto& e : parsed.errors) out.issues.push_back({flow_json_error_name(e.code), e.path, e.message});
        return out;
    }
    out.doc = std::move(parsed.doc);
    CompileResult c = compile_flow(out.doc, reg);
    out.issues = std::move(c.issues);
    if (out.issues.empty()) out.flow = std::move(c.flow);
    return out;
}

}  // namespace pf
