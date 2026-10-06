#include "pf/block.h"

namespace pf {

bool is_valid_fact(std::string_view s) {                 // segments of [a-z][a-z0-9_]* separated by '.'
    if (s.empty() || s.size() > 64) return false;
    bool start = true;
    for (const char c : s) {
        if (start) { if (!(c >= 'a' && c <= 'z')) return false; start = false; continue; }
        if (c == '.') { start = true; continue; }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return !start;
}

std::vector<std::string_view> split_facts(const char* list) {
    std::vector<std::string_view> out;
    if (!list || !*list) return out;
    std::string_view s(list);
    while (true) {
        const size_t c = s.find(',');
        const std::string_view f = s.substr(0, c);
        out.push_back(is_valid_fact(f) ? f : std::string_view());
        if (c == std::string_view::npos) break;
        s.remove_prefix(c + 1);
    }
    return out;
}

namespace {
bool valid_fact_list(const char* list) {
    const auto facts = split_facts(list);
    if (facts.size() > 16) return false;
    for (const auto f : facts) if (f.empty()) return false;
    return true;
}
}  // namespace

BlockRegistry::AddStatus BlockRegistry::add(const BlockDescriptor& d) {
    if (d.id == 0 || d.name == nullptr || d.name[0] == '\0' || d.execute == nullptr)
        return AddStatus::InvalidDescriptor;
    if (!valid_fact_list(d.consumes) || !valid_fact_list(d.produces)) return AddStatus::InvalidDescriptor;
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
