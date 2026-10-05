#include "pf/block.h"

namespace pf {

BlockRegistry::AddStatus BlockRegistry::add(const BlockDescriptor& d) {
    if (d.id == 0 || d.name == nullptr || d.name[0] == '\0' || d.execute == nullptr)
        return AddStatus::InvalidDescriptor;
    if (find(d.id) != nullptr) return AddStatus::DuplicateId;
    if (find(std::string_view(d.name)) != nullptr) return AddStatus::DuplicateName;
    blocks_.push_back(d);
    return AddStatus::Ok;
}

const BlockDescriptor* BlockRegistry::find(BlockId id) const {
    for (const auto& b : blocks_)
        if (b.id == id) return &b;
    return nullptr;
}

const BlockDescriptor* BlockRegistry::find(std::string_view name) const {
    for (const auto& b : blocks_)
        if (name == b.name) return &b;
    return nullptr;
}

}  // namespace pf
