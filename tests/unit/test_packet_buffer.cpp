#include <cstring>
#include "pf/packet_buffer.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(new_buffer_is_empty_with_requested_room) {
    PacketBuffer b(/*headroom=*/16, /*capacity=*/100, /*tailroom=*/8);
    PF_CHECK_EQ(b.size(), size_t(0));
    PF_CHECK_EQ(b.headroom(), size_t(16));
    PF_CHECK_EQ(b.tailroom(), size_t(108));  // everything after the data start
}

PF_TEST(from_bytes_copies_data_and_keeps_default_room) {
    const uint8_t src[] = {1, 2, 3, 4};
    PacketBuffer b = PacketBuffer::from_bytes(src, sizeof src);
    PF_CHECK_EQ(b.size(), sizeof src);
    PF_CHECK(std::memcmp(b.data(), src, sizeof src) == 0);
    PF_CHECK_EQ(b.headroom(), kDefaultHeadroom);
    PF_CHECK(b.data() != src);
}

PF_TEST(pull_front_strips_header_without_copy) {
    const uint8_t src[] = {0xAA, 0xBB, 1, 2, 3};
    PacketBuffer b = PacketBuffer::from_bytes(src, sizeof src);
    const uint8_t* before = b.data();
    PF_CHECK(b.pull_front(2));
    PF_CHECK_EQ(b.size(), size_t(3));
    PF_CHECK(b.data() == before + 2);           // same storage, pointer moved
    PF_CHECK_EQ(b.data()[0], 1);
    PF_CHECK_EQ(b.headroom(), kDefaultHeadroom + 2);
}

PF_TEST(pull_front_more_than_size_fails_and_changes_nothing) {
    const uint8_t src[] = {1, 2};
    PacketBuffer b = PacketBuffer::from_bytes(src, sizeof src);
    PF_CHECK(!b.pull_front(3));
    PF_CHECK_EQ(b.size(), size_t(2));
}

PF_TEST(push_front_uses_headroom_for_encapsulation) {
    const uint8_t src[] = {9, 9};
    PacketBuffer b = PacketBuffer::from_bytes(src, sizeof src);
    const uint8_t* before = b.data();
    uint8_t* hdr = b.push_front(4);
    PF_REQUIRE(hdr != nullptr);
    PF_CHECK(hdr == before - 4);
    hdr[0] = 0x48;
    PF_CHECK_EQ(b.size(), size_t(6));
    PF_CHECK_EQ(b.data()[0], 0x48);
    PF_CHECK_EQ(b.data()[4], 9);
}

PF_TEST(push_front_beyond_headroom_fails) {
    PacketBuffer b(/*headroom=*/2, /*capacity=*/10, 0);
    PF_CHECK(b.push_front(3) == nullptr);
    PF_CHECK_EQ(b.size(), size_t(0));
    PF_CHECK(b.push_front(2) != nullptr);
}

PF_TEST(put_extends_tail_within_capacity_only) {
    PacketBuffer b(0, /*capacity=*/4, 0);
    uint8_t* p = b.put(3);
    PF_REQUIRE(p != nullptr);
    p[0] = 1; p[1] = 2; p[2] = 3;
    PF_CHECK_EQ(b.size(), size_t(3));
    PF_CHECK(b.put(2) == nullptr);       // only 1 byte left
    PF_CHECK_EQ(b.size(), size_t(3));
    PF_CHECK(b.put(1) != nullptr);
}

PF_TEST(trim_back_removes_trailer_such_as_tag) {
    const uint8_t src[] = {1, 2, 3, 4, 5};
    PacketBuffer b = PacketBuffer::from_bytes(src, sizeof src);
    PF_CHECK(b.trim_back(2));
    PF_CHECK_EQ(b.size(), size_t(3));
    PF_CHECK(!b.trim_back(4));
    PF_CHECK_EQ(b.size(), size_t(3));
}

PF_TEST(zero_length_operations_are_noops) {
    PacketBuffer b(4, 8, 0);
    PF_CHECK(b.pull_front(0));
    PF_CHECK(b.trim_back(0));
    PF_CHECK(b.put(0) != nullptr);
    PF_CHECK(b.push_front(0) != nullptr);
    PF_CHECK_EQ(b.size(), size_t(0));
}

PF_TEST(wipe_zeroes_storage_and_resets) {
    const uint8_t src[] = {0xDE, 0xAD, 0xBE, 0xEF};
    PacketBuffer b = PacketBuffer::from_bytes(src, sizeof src);
    const uint8_t* p = b.data();
    b.wipe();
    PF_CHECK_EQ(b.size(), size_t(0));
    PF_CHECK_EQ(p[0], 0); PF_CHECK_EQ(p[1], 0); PF_CHECK_EQ(p[2], 0); PF_CHECK_EQ(p[3], 0);
}

PF_TEST(move_transfers_ownership_and_empties_source) {
    const uint8_t src[] = {1, 2, 3};
    PacketBuffer a = PacketBuffer::from_bytes(src, sizeof src);
    const uint8_t* p = a.data();
    PacketBuffer b(std::move(a));
    PF_CHECK(b.data() == p);
    PF_CHECK_EQ(b.size(), size_t(3));
    PF_CHECK_EQ(a.size(), size_t(0));
}

PF_TEST(from_bytes_with_null_and_zero_length_is_valid_empty) {
    PacketBuffer b = PacketBuffer::from_bytes(nullptr, 0);
    PF_CHECK_EQ(b.size(), size_t(0));
}
