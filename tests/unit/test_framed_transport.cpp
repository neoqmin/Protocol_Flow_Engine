// TCP framing (2-byte big-endian length prefix) over a fake byte stream with forced partial reads/writes.
#include <cstring>
#include <memory>
#include <vector>

#include "fake_stream.h"
#include "pf/framed_transport.h"
#include "pf_test.h"

using namespace pf;
using namespace pf::test;

namespace {
struct Rig {
    std::shared_ptr<StreamPipe> pipe = std::make_shared<StreamPipe>();
    std::unique_ptr<FramedTransport> a, b;
    explicit Rig(size_t max_queued = 256 * 1024) {
        auto s = make_stream_pair(pipe);
        a = std::make_unique<FramedTransport>(std::move(s.first), TransportKind::Tcp, max_queued);
        b = std::make_unique<FramedTransport>(std::move(s.second), TransportKind::Tcp, max_queued);
    }
    // Raw bytes as if the peer's TCP stack had delivered them (to end b).
    void inject_to_b(const std::vector<uint8_t>& bytes) { pipe->to[1].insert(pipe->to[1].end(), bytes.begin(), bytes.end()); }
};
std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(seed + i * 31);
    return v;
}
}  // namespace

PF_TEST(framed_send_writes_big_endian_length_then_payload) {
    Rig r;
    const uint8_t pkt[] = {0xAA, 0xBB, 0xCC};
    PF_CHECK(r.a->send(pkt, 3) == TransportStatus::Ok);
    PF_REQUIRE(r.pipe->to[1].size() == 5);
    const std::vector<uint8_t> wire(r.pipe->to[1].begin(), r.pipe->to[1].end());
    PF_CHECK((wire == std::vector<uint8_t>{0x00, 0x03, 0xAA, 0xBB, 0xCC}));
    const auto big = pattern(0x1234, 1);
    Rig q;
    PF_CHECK(q.a->send(big.data(), big.size()) == TransportStatus::Ok);
    PF_CHECK_EQ(q.pipe->to[1][0], 0x12);
    PF_CHECK_EQ(q.pipe->to[1][1], 0x34);
}

PF_TEST(framed_round_trip_with_every_read_and_write_chunk_size) {
    // Same packets, different TCP segmentation: results must be identical, boundaries preserved.
    const std::vector<std::vector<uint8_t>> pkts = {pattern(1, 1), pattern(200, 2), pattern(0, 3), pattern(1500, 4), pattern(7, 5)};
    for (const size_t chunk : {1u, 2u, 3u, 5u, 64u, 1000u, 100000u}) {
        Rig r;
        r.pipe->read_chunk = chunk;
        r.pipe->write_chunk = chunk;
        std::vector<std::vector<uint8_t>> got;
        size_t next = 0;
        uint8_t buf[4096];
        for (int spins = 0; spins < 200000 && got.size() < pkts.size(); ++spins) {
            if (next < pkts.size() && r.a->send(pkts[next].data(), pkts[next].size()) == TransportStatus::Ok) ++next;
            r.a->flush();
            const RecvResult x = r.b->recv(buf, sizeof buf);
            if (x.status == TransportStatus::Ok) got.emplace_back(buf, buf + x.len);
        }
        PF_CHECK_EQ(got.size(), pkts.size());
        for (size_t i = 0; i < got.size() && i < pkts.size(); ++i) PF_CHECK(got[i] == pkts[i]);
    }
}

PF_TEST(framed_recv_returns_wouldblock_until_the_whole_frame_arrived) {
    Rig r;
    uint8_t buf[64];
    r.inject_to_b({0x00});                                   // half of the length prefix
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
    r.inject_to_b({0x04, 1, 2});                              // length 4, only 2 payload bytes yet
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
    PF_CHECK(!r.b->has_pending_input());
    r.inject_to_b({3, 4});
    const RecvResult x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 4);
    PF_CHECK(buf[3] == 4);
}

PF_TEST(framed_two_frames_in_one_read_second_is_reported_as_pending_input) {
    Rig r;
    r.inject_to_b({0, 1, 0x11, 0, 2, 0x22, 0x33});
    uint8_t buf[16];
    RecvResult x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 1);
    PF_CHECK(r.b->has_pending_input());                      // the event loop must not sleep: no new bytes will wake it
    x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 2);
    PF_CHECK(!r.b->has_pending_input());
}

PF_TEST(framed_oversized_frame_is_discarded_and_framing_stays_aligned) {
    Rig r;
    r.inject_to_b({0, 6, 1, 2, 3, 4, 5, 6, 0, 1, 0x7F});
    uint8_t small[4];
    PF_CHECK(r.b->recv(small, sizeof small).status == TransportStatus::TooLarge);
    const RecvResult x = r.b->recv(small, sizeof small);       // the next frame is intact
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 1);
    PF_CHECK_EQ(small[0], 0x7F);
}

PF_TEST(framed_zero_length_frame_is_a_packet_and_max_frame_works) {
    Rig r;
    PF_CHECK(r.a->send(nullptr, 0) == TransportStatus::Ok);
    uint8_t buf[70000];
    RecvResult x = r.b->recv(buf, sizeof buf);
    PF_CHECK(x.status == TransportStatus::Ok);
    PF_CHECK_EQ(x.len, 0u);
    const auto max = pattern(0xFFFF, 9);
    PF_CHECK(r.a->send(max.data(), max.size()) == TransportStatus::Ok);
    x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 0xFFFF);
    PF_CHECK(std::memcmp(buf, max.data(), max.size()) == 0);
    const std::vector<uint8_t> too_big(0x10000, 1);
    PF_CHECK(r.a->send(too_big.data(), too_big.size()) == TransportStatus::TooLarge);   // cannot be framed in 16 bits
}

PF_TEST(framed_send_queues_when_the_socket_is_full_and_flush_drains_in_order) {
    Rig r;
    r.pipe->capacity = 10;                                    // tiny socket buffer
    const auto p1 = pattern(20, 1), p2 = pattern(20, 2);
    PF_CHECK(r.a->send(p1.data(), p1.size()) == TransportStatus::Ok);      // accepted, partly queued
    PF_CHECK(r.a->wants_write());
    PF_CHECK(r.a->send(p2.data(), p2.size()) == TransportStatus::Ok);
    std::vector<std::vector<uint8_t>> got;
    uint8_t buf[64];
    for (int i = 0; i < 100 && got.size() < 2; ++i) {
        r.a->flush();
        const RecvResult x = r.b->recv(buf, sizeof buf);
        if (x.status == TransportStatus::Ok) got.emplace_back(buf, buf + x.len);
    }
    PF_REQUIRE(got.size() == 2);
    PF_CHECK(got[0] == p1);
    PF_CHECK(got[1] == p2);
    PF_CHECK(!r.a->wants_write());
}

PF_TEST(framed_send_reports_wouldblock_beyond_the_queue_limit_without_corrupting_the_stream) {
    Rig r(100);
    r.pipe->capacity = 0;                                     // nothing can go out
    const auto p = pattern(40, 7);
    PF_CHECK(r.a->send(p.data(), p.size()) == TransportStatus::Ok);        // 42 queued
    PF_CHECK(r.a->send(p.data(), p.size()) == TransportStatus::Ok);        // 84 queued
    PF_CHECK(r.a->send(p.data(), p.size()) == TransportStatus::WouldBlock);   // would exceed 100
    r.pipe->capacity = SIZE_MAX;
    r.a->flush();
    uint8_t buf[64];
    for (int i = 0; i < 2; ++i) {
        const RecvResult x = r.b->recv(buf, sizeof buf);
        PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 40);
    }
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::WouldBlock);   // the rejected packet left no partial frame
}

PF_TEST(framed_eof_mid_frame_is_closed_and_stays_closed) {
    Rig r;
    r.inject_to_b({0, 5, 1, 2});                              // frame cut short
    r.pipe->eof[0] = true;                                    // peer closed
    uint8_t buf[16];
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::Closed);
    PF_CHECK(!r.b->is_open());
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::Closed);
    PF_CHECK(r.b->send(buf, 1) == TransportStatus::Closed);
}

PF_TEST(framed_complete_frame_before_eof_is_still_delivered) {
    Rig r;
    r.inject_to_b({0, 2, 8, 9});
    r.pipe->eof[0] = true;
    uint8_t buf[16];
    const RecvResult x = r.b->recv(buf, sizeof buf);
    PF_REQUIRE(x.status == TransportStatus::Ok && x.len == 2);
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::Closed);
}

PF_TEST(framed_stream_error_is_reported_as_error) {
    Rig r;
    r.pipe->fail = true;
    uint8_t buf[8];
    PF_CHECK(r.b->recv(buf, sizeof buf).status == TransportStatus::Error);
    PF_CHECK(!r.b->is_open());
    PF_CHECK(r.a->send(buf, 1) != TransportStatus::Ok);
}

PF_TEST(framed_kind_and_limits) {
    Rig r;
    PF_CHECK(r.a->kind() == TransportKind::Tcp);
    PF_CHECK_EQ(r.a->max_packet(), 0xFFFFu);
    PF_CHECK(r.a->is_open());
}
