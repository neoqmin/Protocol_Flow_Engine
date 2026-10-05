#include "pf/reliable.h"
#include "pf_test.h"

using namespace pf;

static std::vector<uint8_t> bytes(uint8_t v) { return {v}; }
static const uint8_t HR = static_cast<uint8_t>(OvpnOpcode::ControlHardResetClientV2);
static const uint8_t CV = static_cast<uint8_t>(OvpnOpcode::ControlV1);

// ---- receiver -------------------------------------------------------------------------------

PF_TEST(receiver_delivers_in_order_messages_immediately) {
    ReliableReceiver r;
    std::vector<ReliableReceiver::Delivered> out;
    PF_CHECK(r.on_message(0, bytes(10), out) == ReliableReceiver::Result::Delivered);
    PF_REQUIRE(out.size() == 1); PF_CHECK_EQ(out[0].id, 0u); PF_CHECK_EQ(out[0].payload[0], 10);
    out.clear();
    PF_CHECK(r.on_message(1, bytes(11), out) == ReliableReceiver::Result::Delivered);
    PF_CHECK_EQ(out.size(), size_t(1));
    PF_CHECK_EQ(r.next_expected(), 2u);
}

PF_TEST(receiver_buffers_out_of_order_and_releases_when_gap_fills) {
    ReliableReceiver r;
    std::vector<ReliableReceiver::Delivered> out;
    PF_CHECK(r.on_message(2, bytes(12), out) == ReliableReceiver::Result::Buffered);
    PF_CHECK(r.on_message(1, bytes(11), out) == ReliableReceiver::Result::Buffered);
    PF_CHECK(out.empty());
    PF_CHECK(r.on_message(0, bytes(10), out) == ReliableReceiver::Result::Delivered);
    PF_REQUIRE(out.size() == 3);                       // 0,1,2 released together, in order
    PF_CHECK_EQ(out[0].id, 0u); PF_CHECK_EQ(out[1].id, 1u); PF_CHECK_EQ(out[2].id, 2u);
    PF_CHECK_EQ(r.next_expected(), 3u);
}

PF_TEST(receiver_reports_duplicates_and_does_not_redeliver) {
    ReliableReceiver r;
    std::vector<ReliableReceiver::Delivered> out;
    r.on_message(0, bytes(1), out); out.clear();
    PF_CHECK(r.on_message(0, bytes(1), out) == ReliableReceiver::Result::Duplicate);
    PF_CHECK(out.empty());
    r.on_message(2, bytes(3), out);
    PF_CHECK(r.on_message(2, bytes(3), out) == ReliableReceiver::Result::Duplicate);   // duplicate of a buffered one
}

PF_TEST(receiver_ignores_messages_beyond_its_window_and_does_not_ack_them) {
    ReliableReceiver r(ReliableConfig{4, 2000, 16000, 6, /*recv_window=*/4});
    std::vector<ReliableReceiver::Delivered> out;
    PF_CHECK(r.on_message(4, bytes(1), out) == ReliableReceiver::Result::OutOfWindow);   // next=0, window 0..3
    PF_CHECK(!r.has_pending_acks());
    PF_CHECK(r.on_message(3, bytes(1), out) == ReliableReceiver::Result::Buffered);
}

PF_TEST(receiver_acks_every_accepted_or_duplicate_message_newest_first) {
    ReliableReceiver r;
    std::vector<ReliableReceiver::Delivered> out;
    r.on_message(0, bytes(1), out); r.on_message(1, bytes(1), out); r.on_message(2, bytes(1), out);
    PF_CHECK(r.has_pending_acks());
    auto acks = r.take_acks(8);
    PF_CHECK(acks == (std::vector<uint32_t>{2, 1, 0}));      // as OpenVPN lists them
    PF_CHECK(!r.has_pending_acks());
    r.on_message(1, bytes(1), out);                           // duplicate: peer missed our ack, ack again
    PF_CHECK(r.take_acks(8) == (std::vector<uint32_t>{1}));
}

PF_TEST(receiver_take_acks_respects_the_per_packet_limit) {
    ReliableReceiver r;
    std::vector<ReliableReceiver::Delivered> out;
    for (uint32_t i = 0; i < 6; ++i) r.on_message(i, bytes(1), out);
    auto first = r.take_acks(4);
    PF_CHECK_EQ(first.size(), size_t(4));
    PF_CHECK(r.has_pending_acks());
    PF_CHECK_EQ(r.take_acks(4).size(), size_t(2));
}

// ---- sender ---------------------------------------------------------------------------------

PF_TEST(sender_assigns_sequential_ids_from_zero) {
    ReliableSender s;
    uint32_t id = 99;
    PF_REQUIRE(s.enqueue(HR, {}, id)); PF_CHECK_EQ(id, 0u);
    PF_REQUIRE(s.enqueue(CV, bytes(1), id)); PF_CHECK_EQ(id, 1u);
}

PF_TEST(sender_respects_the_send_window) {
    ReliableSender s(ReliableConfig{2, 2000, 16000, 6, 8});
    uint32_t id;
    PF_CHECK(s.enqueue(CV, bytes(1), id));
    PF_CHECK(s.enqueue(CV, bytes(2), id));
    PF_CHECK(!s.can_send());
    PF_CHECK(!s.enqueue(CV, bytes(3), id));
    uint32_t acked = 0; s.on_ack(&acked, 1);
    PF_CHECK(s.can_send());
    PF_CHECK(s.enqueue(CV, bytes(3), id));
    PF_CHECK_EQ(id, 2u);                                     // ids keep counting up
}

PF_TEST(sender_sends_new_messages_once_then_waits_for_the_timeout) {
    ReliableSender s;
    uint32_t id; s.enqueue(CV, bytes(7), id);
    auto first = s.due(1000);
    PF_REQUIRE(first.size() == 1);
    PF_CHECK_EQ(first[0].id, 0u); PF_CHECK_EQ(first[0].attempt, 1u);
    PF_CHECK_EQ(first[0].opcode, CV); PF_CHECK(first[0].payload == bytes(7));
    PF_CHECK(s.due(1000 + 1999).empty());                    // rto = 2000 ms not reached
    auto again = s.due(1000 + 2000);
    PF_REQUIRE(again.size() == 1);
    PF_CHECK_EQ(again[0].attempt, 2u);
}

PF_TEST(sender_backs_off_exponentially_up_to_the_cap) {
    ReliableSender s(ReliableConfig{4, 1000, 4000, 10, 8});
    uint32_t id; s.enqueue(CV, bytes(1), id);
    uint64_t t = 0;
    PF_CHECK_EQ(s.due(t).size(), size_t(1));                 // attempt 1 at t=0
    t += 1000; PF_CHECK_EQ(s.due(t).size(), size_t(1));      // attempt 2 after 1000
    t += 1999; PF_CHECK(s.due(t).empty());                   // next wait is 2000
    t += 1;    PF_CHECK_EQ(s.due(t).size(), size_t(1));      // attempt 3
    t += 3999; PF_CHECK(s.due(t).empty());                   // next wait is 4000 (cap)
    t += 1;    PF_CHECK_EQ(s.due(t).size(), size_t(1));      // attempt 4
    t += 3999; PF_CHECK(s.due(t).empty());                   // stays at the 4000 cap
    t += 1;    PF_CHECK_EQ(s.due(t).size(), size_t(1));
}

PF_TEST(sender_stops_retransmitting_after_ack) {
    ReliableSender s;
    uint32_t id; s.enqueue(CV, bytes(1), id);
    s.due(0);
    s.on_ack(&id, 1);
    PF_CHECK(s.due(100000).empty());
    PF_CHECK_EQ(s.outstanding(), size_t(0));
}

PF_TEST(sender_ignores_acks_for_unknown_or_old_ids) {
    ReliableSender s;
    uint32_t id; s.enqueue(CV, bytes(1), id);
    const uint32_t junk[] = {5, 77, 0xFFFFFFFFu};
    s.on_ack(junk, 3);
    PF_CHECK_EQ(s.outstanding(), size_t(1));
}

PF_TEST(sender_acks_can_arrive_in_any_order_and_duplicated) {
    ReliableSender s;
    uint32_t a, b, c;
    s.enqueue(CV, bytes(1), a); s.enqueue(CV, bytes(2), b); s.enqueue(CV, bytes(3), c);
    const uint32_t acks[] = {2, 0, 2, 0};
    s.on_ack(acks, 4);
    PF_CHECK_EQ(s.outstanding(), size_t(1));
    auto due = s.due(0);
    PF_REQUIRE(due.size() == 1); PF_CHECK_EQ(due[0].id, 1u);
}

PF_TEST(sender_declares_failure_after_max_attempts) {
    ReliableSender s(ReliableConfig{4, 100, 100, /*max_attempts=*/3, 8});
    uint32_t id; s.enqueue(CV, bytes(1), id);
    s.due(0); s.due(100); s.due(200);
    PF_CHECK(!s.failed());
    s.due(300);                                              // would be attempt 4
    PF_CHECK(s.failed());
    PF_CHECK(s.due(1000).empty());                           // a dead session stops sending
}

PF_TEST(sender_reports_next_deadline) {
    ReliableSender s;
    PF_CHECK(!s.next_deadline_ms().has_value());             // nothing outstanding
    uint32_t id; s.enqueue(CV, bytes(1), id);
    PF_CHECK_EQ(s.next_deadline_ms().value(), uint64_t(0));  // never sent: due right away
    s.due(500);
    PF_CHECK_EQ(s.next_deadline_ms().value(), uint64_t(2500));
}

PF_TEST(sender_message_id_space_is_never_reused) {
    ReliableSender s;
    s.set_next_id_for_test(0xFFFFFFFFu);
    uint32_t id;
    PF_CHECK(s.enqueue(CV, bytes(1), id));
    PF_CHECK_EQ(id, 0xFFFFFFFFu);
    s.on_ack(&id, 1);
    PF_CHECK(!s.enqueue(CV, bytes(1), id));                  // exhausted: new session required
}
