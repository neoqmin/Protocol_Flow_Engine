#include "pf/flow.h"

#include "pf/packet_buffer.h"

#include <unordered_map>

namespace pf {

FlowBuilder& FlowBuilder::add(std::string label, BlockId block) {
    nodes_.push_back({std::move(label), block, std::nullopt, std::nullopt, std::nullopt});
    return *this;
}

FlowBuilder::Pending* FlowBuilder::find_label(const std::string& label) {
    for (auto& n : nodes_)
        if (n.label == label) return &n;
    return nullptr;
}

FlowBuilder& FlowBuilder::on_continue(const std::string& from, const std::string& to) {
    if (Pending* n = find_label(from)) n->cont = to;
    else pending_errors_.push_back("on_continue: unknown label '" + from + "'");
    return *this;
}
FlowBuilder& FlowBuilder::on_yes(const std::string& from, const std::string& to) {
    if (Pending* n = find_label(from)) n->yes = to;
    else pending_errors_.push_back("on_yes: unknown label '" + from + "'");
    return *this;
}
FlowBuilder& FlowBuilder::on_no(const std::string& from, const std::string& to) {
    if (Pending* n = find_label(from)) n->no = to;
    else pending_errors_.push_back("on_no: unknown label '" + from + "'");
    return *this;
}

FlowBuildResult FlowBuilder::build(const BlockRegistry& registry) const {
    FlowBuildResult out;
    out.errors = pending_errors_;
    auto err = [&](std::string m) { out.errors.push_back("flow '" + name_ + "': " + std::move(m)); };

    if (nodes_.empty()) { err("empty flow"); return out; }

    // Pass 1: resolve blocks and labels.
    std::unordered_map<std::string, size_t> index;
    std::vector<FlowNode> nodes(nodes_.size());
    for (size_t i = 0; i < nodes_.size(); ++i) {
        const Pending& p = nodes_[i];
        if (!index.emplace(p.label, i).second) err("duplicate label '" + p.label + "'");
        nodes[i].label = p.label;
        nodes[i].block = p.block;
        const BlockDescriptor* d = registry.find(p.block);
        if (!d) { err("node '" + p.label + "': unknown block id " + std::to_string(p.block)); continue; }
        nodes[i].type = d->type;
        nodes[i].execute = d->execute;
    }

    // Pass 2: resolve edges.
    auto resolve = [&](const Pending& p, const std::optional<std::string>& target,
                       const char* what, bool allow_end) -> size_t {
        if (!target) return kNoNode;
        if (target->empty()) {
            if (!allow_end) err("node '" + p.label + "': " + what + " edge needs a target");
            return kNoNode;
        }
        auto it = index.find(*target);
        if (it == index.end()) {
            err("node '" + p.label + "': " + what + " edge to unknown label '" + *target + "'");
            return kNoNode;
        }
        return it->second;
    };
    for (size_t i = 0; i < nodes_.size(); ++i) {
        const Pending& p = nodes_[i];
        FlowNode& n = nodes[i];
        if (n.execute == nullptr) continue;   // already reported
        if (n.type == BlockType::Action) {
            if (p.yes || p.no) err("node '" + p.label + "': YES/NO edge on a block that is not a decision");
            n.on_continue = p.cont ? resolve(p, p.cont, "continue", true)
                                   : (i + 1 < nodes_.size() ? i + 1 : kNoNode);
        } else {
            if (p.cont) err("node '" + p.label + "': decision has no continue edge");
            if (!p.yes) err("node '" + p.label + "': missing YES edge");
            if (!p.no) err("node '" + p.label + "': missing NO edge");
            n.on_yes = resolve(p, p.yes, "YES", false);
            n.on_no = resolve(p, p.no, "NO", false);
        }
    }

    // Graph checks only make sense on a fully resolved graph.
    if (!out.errors.empty()) return out;

    // Cycle detection (plan section 22: loop violation): iterative DFS, 3 colors.
    enum : uint8_t { White, Grey, Black };
    std::vector<uint8_t> color(nodes.size(), White);
    auto successors = [&](size_t i) {
        std::vector<size_t> s;
        for (size_t t : {nodes[i].on_continue, nodes[i].on_yes, nodes[i].on_no})
            if (t != kNoNode) s.push_back(t);
        return s;
    };
    for (size_t root = 0; root < nodes.size(); ++root) {
        if (color[root] != White) continue;
        std::vector<std::pair<size_t, std::vector<size_t>>> stack;
        color[root] = Grey; stack.push_back({root, successors(root)});
        while (!stack.empty()) {
            auto& top = stack.back();
            if (top.second.empty()) { color[top.first] = Black; stack.pop_back(); continue; }
            size_t nxt = top.second.back(); top.second.pop_back();
            if (color[nxt] == Grey) { err("cycle through node '" + nodes[nxt].label + "'"); return out; }
            if (color[nxt] == White) { color[nxt] = Grey; stack.push_back({nxt, successors(nxt)}); }
        }
    }

    // Reachability from the entry node (node 0).
    std::vector<bool> seen(nodes.size(), false);
    std::vector<size_t> work{0};
    seen[0] = true;
    while (!work.empty()) {
        size_t i = work.back(); work.pop_back();
        for (size_t t : successors(i))
            if (!seen[t]) { seen[t] = true; work.push_back(t); }
    }
    for (size_t i = 0; i < nodes.size(); ++i)
        if (!seen[i]) err("unreachable node '" + nodes[i].label + "'");

    if (out.errors.empty()) {
        out.flow.name_ = name_;
        out.flow.nodes_ = std::move(nodes);
    }
    return out;
}

namespace {

FlowResult finish(FlowStats* stats, FlowContext& ctx, FlowOutcome o, Error e, size_t steps, size_t last) {
    ctx.error = e;
    if (stats) {
        switch (o) {
            case FlowOutcome::Completed: ++stats->completed; break;
            case FlowOutcome::Dropped: ++stats->dropped; break;
            case FlowOutcome::Errored: ++stats->errored; break;
        }
        if (e != Error::None && static_cast<size_t>(e) < kErrorCount) ++stats->by_error[static_cast<size_t>(e)];
    }
    return FlowResult{o, e, steps, last};
}

bool allowed(BlockType t, BlockResult r) {
    switch (r) {
        case BlockResult::Continue: return t == BlockType::Action;
        case BlockResult::Yes:
        case BlockResult::No: return t == BlockType::Decision;
        case BlockResult::Drop:
        case BlockResult::Error: return true;
    }
    return false;
}

void trace_end(TraceSink* trace, const Flow& flow, const FlowResult& r) {
    TraceRecord t;
    t.kind = TraceKind::FlowEnd;
    t.t_ms = trace->now_ms;
    t.scope = flow.name();
    if (r.last_node != kNoNode) t.name = flow.node(r.last_node).label;
    t.result = static_cast<uint8_t>(r.outcome);
    t.error = r.error;
    t.value = static_cast<uint32_t>(r.steps);
    trace->record(t);
}

void trace_node(TraceSink* trace, const Flow& flow, const FlowNode& n, BlockResult r, const FlowContext& ctx) {
    TraceRecord t;
    t.kind = TraceKind::Node;
    t.t_ms = trace->now_ms;
    t.scope = flow.name();
    t.name = n.label;
    t.block = n.block;
    t.result = static_cast<uint8_t>(r);
    t.error = ctx.error;
    t.value = ctx.packet ? static_cast<uint32_t>(ctx.packet->size()) : 0;     // a length, never the bytes
    trace->record(t);
}

// Two instantiations so the untraced path (the data plane's) has no trace test at all.
template <bool kTraced>
FlowResult execute(const Flow& flow, FlowContext& ctx, FlowStats* stats, size_t max_steps, TraceSink* trace) {
    ctx.error = Error::None;
    if (flow.node_count() == 0)
        return finish(stats, ctx, FlowOutcome::Errored, Error::FlowInvalid, 0, kNoNode);

    size_t i = 0, steps = 0;
    while (true) {
        if (steps >= max_steps) return finish(stats, ctx, FlowOutcome::Errored, Error::StepLimit, steps, i);
        const FlowNode& n = flow.node(i);
        ++steps;
        const BlockResult r = n.execute(ctx);
        if constexpr (kTraced) trace_node(trace, flow, n, r, ctx);
        if (!allowed(n.type, r))
            return finish(stats, ctx, FlowOutcome::Errored, Error::Internal, steps, i);

        size_t next = kNoNode;
        switch (r) {
            case BlockResult::Continue: next = n.on_continue; break;
            case BlockResult::Yes: next = n.on_yes; break;
            case BlockResult::No: next = n.on_no; break;
            case BlockResult::Drop:
                if (ctx.error == Error::None)   // contract: Drop must carry a reason
                    return finish(stats, ctx, FlowOutcome::Errored, Error::Internal, steps, i);
                return finish(stats, ctx, FlowOutcome::Dropped, ctx.error, steps, i);
            case BlockResult::Error:
                return finish(stats, ctx, FlowOutcome::Errored,
                              ctx.error == Error::None ? Error::Internal : ctx.error, steps, i);
        }
        if (next == kNoNode) return finish(stats, ctx, FlowOutcome::Completed, Error::None, steps, i);
        i = next;
    }
}

}  // namespace

FlowResult run_flow(const Flow& flow, FlowContext& ctx, FlowStats* stats, size_t max_steps, TraceSink* trace) {
    if (!trace) return execute<false>(flow, ctx, stats, max_steps, nullptr);
    const FlowResult r = execute<true>(flow, ctx, stats, max_steps, trace);
    trace_end(trace, flow, r);
    return r;
}

}  // namespace pf
