// Transport contract exercised on the in-memory loopback (the fake used by B3 fallback tests).
#include <cstring>
#include <memory>
#include <vector>

#include "pf/loopback_transport.h"
#include "pf_test.h"

using namespace pf;

namespace {
struct Rig {
    std::shared_ptr<LoopbackLink> link = std::make_shared<LoopbackLink>();
    std::unique_ptr<LoopbackTransport> a, b;
    explicit Rig(TransportKind k = TransportKind::Udp, size_t max_packet = 1500) {
        auto p = LoopbackTransport::make_pair(link, k, max_packet);
        a = std::move(p.first);
        b = std::move(p.second);
    }
};
}  // namespace

PF_TEST(transport_loopback_delivers_whole_packets_in_order_both_ways) {
    Rig r;
    const uint8_t p1[] = {1, 2, 3}, p2[] = {9}, p3[] = {7, 7};
    PF_CHECK(r.a->send(p1, 3) == TransportStatus::Ok);
    PF_CHECK(r.a->send(p2, 1) == TransportStatus::Ok);
    PF_CHECK(r.b->send(p3, 2) == TransportStatus::Ok);
    uint8_t buf[16];
    auto x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 3);
    PF_CHECK(std::memcmp(buf, p1, 3) == 0);
    x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 1);
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
    x = r.a->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 2);
}

PF_TEST(transport_loopback_zero_length_packet_is_a_packet) {
    Rig r;
    PF_CHECK(r.a->send(nullptr, 0) == TransportStatus::Ok);
    uint8_t buf[4];
    auto x = r.b->recv(buf, sizeof buf);
    PF_CHECK(x.status == TransportStatus::Ok);
    PF_CHECK_EQ(x.len, 0u);
}

PF_TEST(transport_loopback_oversized_packets_are_rejected_or_discarded) {
    Rig r(TransportKind::Udp, 8);
    std::vector<uint8_t> big(9, 1), ok(8, 2);
    PF_CHECK(r.a->send(big.data(), big.size()) == TransportStatus::TooLarge);
    PF_CHECK(r.a->send(ok.data(), ok.size()) == TransportStatus::Ok);
    uint8_t small[4];
    PF_CHECK(r.b->recv(small, sizeof small).status == TransportStatus::TooLarge);    // does not fit the caller's buffer
    PF_CHECK(r.b->recv(small, sizeof small).status == TransportStatus::WouldBlock);  // and was discarded, not retried
}

PF_TEST(transport_loopback_block_loses_packets_silently_and_unblock_recovers) {
    Rig r;
    const uint8_t d[] = {5};
    uint8_t buf[4];
    r.link->block(true);
    PF_CHECK(r.a->send(d, 1) == TransportStatus::Ok);            // the sender cannot tell (a blocked UDP path)
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
    PF_CHECK_EQ(r.link->dropped(), 1u);
    r.link->block(false);
    PF_CHECK(r.a->send(d, 1) == TransportStatus::Ok);
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::Ok);
}

PF_TEST(transport_loopback_drop_next_and_capacity) {
    Rig r;
    const uint8_t d[] = {1};
    uint8_t buf[4];
    r.link->drop_next(2);
    for (int i = 0; i < 3; ++i) PF_CHECK(r.a->send(d, 1) == TransportStatus::Ok);
    PF_CHECK_EQ(r.link->delivered(), 1u);
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::Ok);
    r.link->set_capacity(2);
    PF_CHECK(r.a->send(d, 1) == TransportStatus::Ok);
    PF_CHECK(r.a->send(d, 1) == TransportStatus::Ok);
    PF_CHECK(r.a->send(d, 1) == TransportStatus::WouldBlock);    // full buffer: retry later, nothing lost
}

PF_TEST(transport_loopback_close_is_reported_to_both_ends) {
    Rig r;
    const uint8_t d[] = {1};
    uint8_t buf[4];
    r.a->close();
    PF_CHECK(!r.a->is_open());
    PF_CHECK(r.a->send(d, 1) == TransportStatus::Closed);
    PF_CHECK(r.a->recv(buf, sizeof buf).status == TransportStatus::Closed);
    Rig q;
    q.link->close_link();
    PF_CHECK(q.a->send(d, 1) == TransportStatus::Closed);
    PF_CHECK(q.b->recv(buf, sizeof buf).status == TransportStatus::Closed);
    PF_CHECK(!q.b->is_open());
}

PF_TEST(transport_kind_is_reported) {
    Rig t(TransportKind::Tcp);
    PF_CHECK(t.a->kind() == TransportKind::Tcp);
    PF_CHECK_EQ(t.a->poll_fd(), -1);
}
