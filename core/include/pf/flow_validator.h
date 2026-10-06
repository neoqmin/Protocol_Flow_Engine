#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "pf/block.h"
#include "pf/flow.h"
#include "pf/flow_json.h"

namespace pf {

// Semantic validation of a loaded Flow document against a BlockRegistry, BEFORE anything runs ("reject bad flows
// early"). The loader (flow_json.h) already guarantees shapes, names and unique ids; this checks that the Flow means
// something executable. Every issue has a code, a JSON Pointer into the file and a message an editor can show.
//
//   UnknownBlock       node.block is not registered (message suggests the closest registered name)
//   UnknownParam       block does not declare this parameter
//   MissingParam       a required parameter is absent
//   ParamType          parameter value has the wrong type for the block
//   EdgeUnknownSource  edge.from is not a node id
//   EdgeUnknownTarget  edge.to is not a node id
//   PortMismatch       Action node with a yes/no edge, or Decision node with a continue edge
//   DuplicateEdge      two edges leave the same node through the same port
//   MissingEdge        Decision node without both its yes and no edge
//   RuntimeUnsupported "user" is not among flow.runtime (the only runtime this build executes)
//   Cycle              the flow can loop (flows are acyclic: bounded work per packet)
//   Unreachable        a node cannot be reached from the first node
//   Internal           compile step disagreed with the validator (a bug, never a user error)
struct FlowIssue {
    std::string code;
    std::string path;
    std::string message;
};

struct FlowValidation {
    bool ok() const { return issues.empty(); }
    std::vector<FlowIssue> issues;
};

FlowValidation validate_flow(const FlowDocument& doc, const BlockRegistry& registry);

struct CompileResult {
    bool ok() const { return issues.empty(); }
    Flow flow;
    std::vector<FlowIssue> issues;
};

// Validates, then builds the executable Flow (node labels are the document's ids). Flows only come from valid documents.
CompileResult compile_flow(const FlowDocument& doc, const BlockRegistry& registry);

struct LoadedFlow {
    bool ok() const { return issues.empty(); }
    Flow flow;
    FlowDocument doc;
    int64_t migrated_from = 0;
    std::vector<FlowIssue> issues;      // syntax errors (loader) or semantic issues (validator), same shape
};

// The one call tools and the runtime use: text -> parse (+ migrate) -> validate -> executable Flow.
LoadedFlow load_flow_json(std::string_view text, const BlockRegistry& registry, const FlowMigrations* migrations = nullptr);

}  // namespace pf
