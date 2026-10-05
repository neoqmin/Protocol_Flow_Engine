#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pf/block.h"

namespace pf {

inline constexpr size_t kNoNode = static_cast<size_t>(-1);  // "end of flow"

// One resolved step of a Flow. Block handler/type are copied from the registry
// at build time so the runner dispatches directly (no lookups per packet).
struct FlowNode {
    std::string label;
    BlockId block = 0;
    BlockType type = BlockType::Action;
    BlockHandler execute = nullptr;
    size_t on_continue = kNoNode;   // Action: next node (default: next added) or end
    size_t on_yes = kNoNode;        // Decision only
    size_t on_no = kNoNode;         // Decision only
};

// Immutable, validated block graph. Entry is node 0. Obtain via FlowBuilder.
class Flow {
public:
    Flow() = default;
    const std::string& name() const { return name_; }
    size_t node_count() const { return nodes_.size(); }
    const FlowNode& node(size_t i) const { return nodes_[i]; }

private:
    friend class FlowBuilder;
    std::string name_;
    std::vector<FlowNode> nodes_;
};

struct FlowBuildResult {
    Flow flow;
    std::vector<std::string> errors;
    bool ok() const { return errors.empty(); }
};

// Static flow definition (plan section 6.1). Nodes run in the order added;
// Action nodes continue to the next added node unless on_continue overrides it
// (target "" = end the flow). Decision nodes need both on_yes and on_no.
// build() validates everything and reports ALL problems: unknown block/label,
// duplicate label, missing/extra edges, cycles, unreachable nodes.
class FlowBuilder {
public:
    explicit FlowBuilder(std::string name) : name_(std::move(name)) {}

    FlowBuilder& add(std::string label, BlockId block);
    FlowBuilder& on_continue(const std::string& from, const std::string& to);
    FlowBuilder& on_yes(const std::string& from, const std::string& to);
    FlowBuilder& on_no(const std::string& from, const std::string& to);

    FlowBuildResult build(const BlockRegistry& registry) const;

private:
    struct Pending {
        std::string label;
        BlockId block;
        std::optional<std::string> cont, yes, no;
    };
    Pending* find_label(const std::string& label);

    std::string name_;
    std::vector<Pending> nodes_;
    std::vector<std::string> pending_errors_;
};

enum class FlowOutcome { Completed, Dropped, Errored };

struct FlowResult {
    FlowOutcome outcome = FlowOutcome::Errored;
    Error error = Error::None;      // reason for Dropped/Errored
    size_t steps = 0;               // blocks executed
    size_t last_node = kNoNode;     // node that ended the flow
};

struct FlowStats {
    uint64_t completed = 0;
    uint64_t dropped = 0;
    uint64_t errored = 0;
    std::array<uint64_t, kErrorCount> by_error{};   // drop/error reasons
};

inline constexpr size_t kDefaultMaxSteps = 1024;

// Runs one packet through the flow. Resets ctx.error first. Never throws.
// Enforces the BlockResult contract and the step budget (runtime loop guard).
FlowResult run_flow(const Flow& flow, FlowContext& ctx, FlowStats* stats = nullptr,
                    size_t max_steps = kDefaultMaxSteps);

}  // namespace pf
