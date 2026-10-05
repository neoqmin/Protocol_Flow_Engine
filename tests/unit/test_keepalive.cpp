#include "pf/keepalive.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(keepalive_ping_payload_is_openvpns_fixed_16_bytes) {
    PF_CHECK_EQ(kPingPayloadLen, size_t(16));
    PF_CHECK_EQ(kPingPayload[0], 0x2a);
    PF_CHECK_EQ(kPingPayload[15], 0x48);
    PF_CHECK(is_ping_payload(kPingPayload, kPingPayloadLen));
    uint8_t other[16]; for (auto& b : other) b = 0;
    PF_CHECK(!is_ping_payload(other, 16));
    PF_CHECK(!is_ping_payload(kPingPayload, 15));
    PF_CHECK(!is_ping_payload(nullptr, 0));
    uint8_t one_off[16]; for (size_t i = 0; i < 16; ++i) one_off[i] = kPingPayload[i];
    one_off[7] ^= 1;
    PF_CHECK(!is_ping_payload(one_off, 16));
}

PF_TEST(keepalive_stays_quiet_before_the_ping_interval) {
    KeepaliveTimer t(2, 8, /*now_ms=*/1000);
    PF_CHECK(t.poll(1000) == KeepaliveTimer::Action::None);
    PF_CHECK(t.poll(2999) == KeepaliveTimer::Action::None);
}

PF_TEST(keepalive_asks_for_a_ping_after_an_idle_send_interval) {
    KeepaliveTimer t(2, 8, 1000);
    PF_CHECK(t.poll(3000) == KeepaliveTimer::Action::SendPing);
}

PF_TEST(keepalive_does_not_repeat_the_ping_request_within_one_interval) {
    KeepaliveTimer t(2, 8, 1000);
    PF_CHECK(t.poll(3000) == KeepaliveTimer::Action::SendPing);       // poll assumes the caller sends it
    PF_CHECK(t.poll(3500) == KeepaliveTimer::Action::None);
    PF_CHECK(t.poll(4999) == KeepaliveTimer::Action::None);
    PF_CHECK(t.poll(5000) == KeepaliveTimer::Action::SendPing);
}

PF_TEST(keepalive_real_traffic_suppresses_pings) {
    KeepaliveTimer t(2, 8, 0);
    t.on_sent(1500);
    PF_CHECK(t.poll(3000) == KeepaliveTimer::Action::None);           // 1500 ms since the last send
    PF_CHECK(t.poll(3500) == KeepaliveTimer::Action::SendPing);
}

PF_TEST(keepalive_times_out_when_nothing_is_received_for_ping_restart) {
    KeepaliveTimer t(2, 8, 0);
    t.on_received(1000);
    PF_CHECK(t.poll(8999) != KeepaliveTimer::Action::Timeout);
    PF_CHECK(t.poll(9000) == KeepaliveTimer::Action::Timeout);
}

PF_TEST(keepalive_timeout_wins_over_a_due_ping_and_is_sticky) {
    KeepaliveTimer t(2, 8, 0);
    PF_CHECK(t.poll(8000) == KeepaliveTimer::Action::Timeout);
    t.on_received(8100);                                              // too late: the session was declared dead
    PF_CHECK(t.poll(8200) == KeepaliveTimer::Action::Timeout);
}

PF_TEST(keepalive_received_packets_keep_the_session_alive) {
    KeepaliveTimer t(2, 8, 0);
    for (uint64_t now = 1000; now < 60000; now += 1000) {
        t.on_received(now);
        PF_REQUIRE(t.poll(now) != KeepaliveTimer::Action::Timeout);
    }
}

PF_TEST(keepalive_zero_disables_each_timer_independently) {
    KeepaliveTimer no_ping(0, 8, 0);
    PF_CHECK(no_ping.poll(7000) == KeepaliveTimer::Action::None);
    PF_CHECK(no_ping.poll(8000) == KeepaliveTimer::Action::Timeout);
    KeepaliveTimer no_restart(2, 0, 0);
    PF_CHECK(no_restart.poll(1000000) == KeepaliveTimer::Action::SendPing);
    KeepaliveTimer off(0, 0, 0);
    PF_CHECK(off.poll(1000000) == KeepaliveTimer::Action::None);
    PF_CHECK(!off.next_deadline_ms().has_value());
}

PF_TEST(keepalive_next_deadline_is_the_earlier_of_ping_and_timeout) {
    KeepaliveTimer t(2, 8, 1000);
    PF_CHECK_EQ(t.next_deadline_ms().value(), uint64_t(3000));
    t.on_sent(2500);
    PF_CHECK_EQ(t.next_deadline_ms().value(), uint64_t(4500));
    t.on_received(2600);
    PF_CHECK_EQ(t.next_deadline_ms().value(), uint64_t(4500));        // ping still earlier than 2600 + 8000
    KeepaliveTimer slow(100, 8, 0);
    PF_CHECK_EQ(slow.next_deadline_ms().value(), uint64_t(8000));
}

PF_TEST(keepalive_tolerates_a_clock_that_goes_backwards) {
    KeepaliveTimer t(2, 8, 5000);
    PF_CHECK(t.poll(1000) == KeepaliveTimer::Action::None);           // now < last activity: no unsigned wrap-around
    t.on_sent(100);
    t.on_received(100);
    PF_CHECK(t.poll(50) == KeepaliveTimer::Action::None);
}
