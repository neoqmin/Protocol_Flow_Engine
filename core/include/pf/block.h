#pragma once
#include <cstdint>
#include <string_view>
#include <vector>

#include "pf/flow_context.h"

namespace pf {

// What a block tells the runner. Contract (docs/Block_API.md):
//   Action blocks   may return Continue | Drop | Error
//   Decision blocks may return Yes | No | Drop | Error
//   Drop  = discard THIS packet because of bad/unwanted input; MUST set ctx.error != None
//   Error = internal failure; sets ctx.error (Internal if left None)
// Anything else is a contract violation and ends the flow as Errored/Internal.
enum class BlockResult : uint8_t { Continue, Yes, No, Drop, Error };
enum class BlockType : uint8_t { Action, Decision };

using BlockId = uint32_t;  // 0 is invalid
using BlockHandler = BlockResult (*)(FlowContext&);  // plain function: no heap, kernel-friendly

struct BlockDescriptor {
    BlockId id;
    const char* name;
    BlockType type;
    BlockHandler execute;
};

class BlockRegistry {
public:
    enum class AddStatus { Ok, DuplicateId, DuplicateName, InvalidDescriptor };

    AddStatus add(const BlockDescriptor& d);
    const BlockDescriptor* find(BlockId id) const;
    const BlockDescriptor* find(std::string_view name) const;
    size_t size() const { return blocks_.size(); }

private:
    std::vector<BlockDescriptor> blocks_;
};

}  // namespace pf
