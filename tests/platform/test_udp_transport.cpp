// UdpTransport over real 127.0.0.1 sockets (no root, no network namespace needed).
#include <arpa/inet.h>
#include <poll.h>

#include <cstring>
#include <string>
#include <vector>

#include "pf_test.h"
#include "udp_transport.h"

using namespace pf;
using pf::pal::UdpTransport;

namespace {
sockaddr_in loopback(uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

// Two connected endpoints: `a` bound to a free port first, `b` connects to it, `a` is then re-opened toward b.
struct Pair {
    UdpTransport a, b;
    Pair() {
        std::string err;
        const sockaddr_in any = loopback(0);
        // Bind both to ephemeral ports, then connect each to the other's port.
        UdpTransport tmp_a, tmp_b;
        PF_REQUIRE(tmp_a.open(loopback(9), &any, err));       // peer port is irrelevant, only the bound port is reused
        PF_REQUIRE(tmp_b.open(loopback(9), &any, err));
        const uint16_t pa = tmp_a.local_port(), pb = tmp_b.local_port();
        tmp_a.close();
        tmp_b.close();
        const sockaddr_in la = loopback(pa), lb = loopback(pb);
        PF_REQUIRE(a.open(lb, &la, err));
        PF_REQUIRE(b.open(la, &lb, err));
    }
    static bool wait_readable(UdpTransport& t) {
        pollfd p{t.poll_fd(), POLLIN, 0};
        return poll(&p, 1, 1000) > 0;
    }
};
}  // namespace

PF_TEST(udp_transport_round_trips_datagrams_and_preserves_boundaries) {
    Pair p;
    const uint8_t m1[] = {1, 2, 3}, m2[] = {4, 5};
    PF_CHECK(p.a.send(m1, 3) == TransportStatus::Ok);
    PF_CHECK(p.a.send(m2, 2) == TransportStatus::Ok);
    PF_REQUIRE(Pair::wait_readable(p.b));
    uint8_t buf[64];
    auto r = p.b.recv(buf, sizeof buf);
    PF_REQUIRE(r.status == TransportStatus::Ok && r.len == 3);
    PF_CHECK(std::memcmp(buf, m1, 3) == 0);
    r = p.b.recv(buf, sizeof buf);
    PF_REQUIRE(r.status == TransportStatus::Ok && r.len == 2);        // not merged with the previous datagram
    PF_CHECK(p.b.recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
}

PF_TEST(udp_transport_oversized_datagram_is_reported_not_clipped) {
    Pair p;
    std::vector<uint8_t> big(500, 0xEE);
    PF_CHECK(p.a.send(big.data(), big.size()) == TransportStatus::Ok);
    PF_REQUIRE(Pair::wait_readable(p.b));
    uint8_t small[100];
    PF_CHECK(p.b.recv(small, sizeof small).status == TransportStatus::TooLarge);
    PF_CHECK(p.b.recv(small, sizeof small).status == TransportStatus::WouldBlock);   // discarded
}

PF_TEST(udp_transport_rejects_packets_over_the_udp_limit_and_reports_closed) {
    Pair p;
    std::vector<uint8_t> huge(p.a.max_packet() + 1, 0);
    PF_CHECK(p.a.send(huge.data(), huge.size()) == TransportStatus::TooLarge);
    p.a.close();
    PF_CHECK(!p.a.is_open());
    uint8_t buf[4];
    PF_CHECK(p.a.send(buf, 1) == TransportStatus::Closed);
    PF_CHECK(p.a.recv(buf, sizeof buf).status == TransportStatus::Closed);
    PF_CHECK(p.a.poll_fd() == -1);
}

PF_TEST(udp_transport_packets_from_other_sources_are_not_delivered) {
    Pair p;
    UdpTransport stranger;
    std::string err;
    const sockaddr_in any = loopback(0);
    PF_REQUIRE(stranger.open(loopback(p.b.local_port()), &any, err));   // not the peer b is connected to
    const uint8_t m[] = {9};
    PF_CHECK(stranger.send(m, 1) == TransportStatus::Ok);
    uint8_t buf[8];
    pollfd pf_{p.b.poll_fd(), POLLIN, 0};
    (void)poll(&pf_, 1, 200);
    PF_CHECK(p.b.recv(buf, sizeof buf).status == TransportStatus::WouldBlock);   // connected socket filters by source
}

PF_TEST(udp_transport_kind_and_fd) {
    Pair p;
    PF_CHECK(p.a.kind() == TransportKind::Udp);
    PF_CHECK(p.a.poll_fd() >= 0);
    PF_CHECK(p.a.is_open());
}
