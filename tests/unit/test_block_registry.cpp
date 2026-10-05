#include "pf/block.h"
#include "pf_test.h"

using namespace pf;

static BlockResult noop(FlowContext&) { return BlockResult::Continue; }
static BlockResult yes(FlowContext&) { return BlockResult::Yes; }

PF_TEST(registry_add_and_find_by_id_and_name) {
    BlockRegistry r;
    PF_CHECK(r.add({1, "noop", BlockType::Action, noop}) == BlockRegistry::AddStatus::Ok);
    PF_CHECK(r.add({2, "yes", BlockType::Decision, yes}) == BlockRegistry::AddStatus::Ok);
    PF_CHECK_EQ(r.size(), size_t(2));
    const BlockDescriptor* d = r.find(BlockId{2});
    PF_REQUIRE(d != nullptr);
    PF_CHECK(d->execute == yes);
    PF_CHECK(r.find(std::string_view("noop")) != nullptr);
    PF_CHECK(r.find(BlockId{99}) == nullptr);
    PF_CHECK(r.find(std::string_view("nope")) == nullptr);
}

PF_TEST(registry_rejects_duplicate_id_and_name) {
    BlockRegistry r;
    r.add({1, "a", BlockType::Action, noop});
    PF_CHECK(r.add({1, "b", BlockType::Action, noop}) == BlockRegistry::AddStatus::DuplicateId);
    PF_CHECK(r.add({2, "a", BlockType::Action, noop}) == BlockRegistry::AddStatus::DuplicateName);
    PF_CHECK_EQ(r.size(), size_t(1));
}

PF_TEST(registry_rejects_invalid_descriptors) {
    BlockRegistry r;
    PF_CHECK(r.add({0, "zero_id", BlockType::Action, noop}) == BlockRegistry::AddStatus::InvalidDescriptor);
    PF_CHECK(r.add({1, nullptr, BlockType::Action, noop}) == BlockRegistry::AddStatus::InvalidDescriptor);
    PF_CHECK(r.add({1, "", BlockType::Action, noop}) == BlockRegistry::AddStatus::InvalidDescriptor);
    PF_CHECK(r.add({1, "nohandler", BlockType::Action, nullptr}) == BlockRegistry::AddStatus::InvalidDescriptor);
    PF_CHECK_EQ(r.size(), size_t(0));
}
