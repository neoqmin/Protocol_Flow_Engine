// TcpStream + FramedTransport over a real 127.0.0.1 TCP connection (no root needed).
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <vector>

#include "pf_test.h"
#include "tcp_stream.h"

using namespace pf;

namespace {
struct Listener {
    int fd = -1;
    sockaddr_in addr{};
    Listener() {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        PF_REQUIRE(bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);
        PF_REQUIRE(listen(fd, 4) == 0);
        socklen_t n = sizeof addr;
        getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &n);
    }
    ~Listener() { if (fd >= 0) ::close(fd); }
    int accept_one() { return ::accept(fd, nullptr, nullptr); }
};
bool wait_readable(int fd, int ms = 2000) { pollfd p{fd, POLLIN, 0}; return poll(&p, 1, ms) > 0; }
}  // namespace

PF_TEST(tcp_transport_exchanges_framed_packets_with_a_raw_peer) {
    Listener l;
    std::string err;
    auto t = pal::open_tcp_transport(l.addr, 2000, err);
    PF_REQUIRE(t != nullptr);
    const int peer = l.accept_one();
    PF_REQUIRE(peer >= 0);
    const uint8_t pkt[] = {0xDE, 0xAD, 0xBE, 0xEF};
    PF_CHECK(t->send(pkt, 4) == TransportStatus::Ok);
    uint8_t raw[16];
    PF_REQUIRE(wait_readable(peer));
    const ssize_t n = ::recv(peer, raw, sizeof raw, 0);
    PF_REQUIRE(n == 6);
    PF_CHECK(raw[0] == 0 && raw[1] == 4 && std::memcmp(raw + 2, pkt, 4) == 0);          // 2-byte BE length + payload

    // Peer replies with a frame split across two TCP segments.
    const uint8_t reply[] = {0, 3, 7, 8, 9};
    PF_CHECK(::send(peer, reply, 3, 0) == 3);
    PF_REQUIRE(wait_readable(t->poll_fd()));
    uint8_t buf[16];
    PF_CHECK(t->recv(buf, sizeof buf).status == TransportStatus::WouldBlock);           // header + 1 byte only
    PF_CHECK(::send(peer, reply + 3, 2, 0) == 2);
    RecvResult r;
    for (int i = 0; i < 100 && r.status != TransportStatus::Ok; ++i) {
        wait_readable(t->poll_fd(), 50);
        r = t->recv(buf, sizeof buf);
    }
    PF_REQUIRE(r.status == TransportStatus::Ok && r.len == 3);
    PF_CHECK(buf[0] == 7 && buf[2] == 9);

    ::close(peer);                                                                      // orderly FIN
    for (int i = 0; i < 100 && t->is_open(); ++i) { wait_readable(t->poll_fd(), 50); (void)t->recv(buf, sizeof buf); }
    PF_CHECK(!t->is_open());
    PF_CHECK(t->send(pkt, 4) == TransportStatus::Closed);
}

PF_TEST(tcp_transport_large_burst_does_not_lose_or_reorder_packets) {
    Listener l;
    std::string err;
    auto t = pal::open_tcp_transport(l.addr, 2000, err);
    PF_REQUIRE(t != nullptr);
    const int peer = l.accept_one();
    PF_REQUIRE(peer >= 0);
    // 2000 packets of 1200 bytes (2.4 MB) overflow the socket buffers: exercises queueing/partial writes.
    const int kPackets = 2000;
    std::vector<uint8_t> echo_buf;
    int sent = 0, got = 0;
    bool ok = true;
    std::vector<uint8_t> acc;
    uint8_t buf[2048];
    for (int spin = 0; spin < 200000 && got < kPackets; ++spin) {
        while (sent < kPackets) {
            std::vector<uint8_t> p(1200, static_cast<uint8_t>(sent));
            p[0] = static_cast<uint8_t>(sent >> 8);
            p[1] = static_cast<uint8_t>(sent);
            if (t->send(p.data(), p.size()) != TransportStatus::Ok) break;           // WouldBlock: retry after draining
            ++sent;
        }
        t->flush();
        // The raw peer drains the socket and parses frames itself.
        uint8_t tmp[16384];
        const ssize_t n = ::recv(peer, tmp, sizeof tmp, MSG_DONTWAIT);
        if (n > 0) acc.insert(acc.end(), tmp, tmp + n);
        while (acc.size() >= 2) {
            const size_t len = (static_cast<size_t>(acc[0]) << 8) | acc[1];
            if (acc.size() < 2 + len) break;
            if (len != 1200 || ((acc[2] << 8) | acc[3]) != got) ok = false;
            acc.erase(acc.begin(), acc.begin() + 2 + static_cast<std::ptrdiff_t>(len));
            ++got;
        }
        (void)buf;
    }
    PF_CHECK_EQ(got, kPackets);
    PF_CHECK(ok);                                                                       // in order, whole, correct length
    ::close(peer);
}

PF_TEST(tcp_connect_to_a_closed_port_fails_fast_with_a_reason) {
    Listener l;
    const sockaddr_in dead = l.addr;
    ::close(l.fd);
    l.fd = -1;
    std::string err;
    auto t = pal::open_tcp_transport(dead, 2000, err);
    PF_CHECK(t == nullptr);
    PF_CHECK(!err.empty());                                                             // refusal is reported (fallback input)
}
