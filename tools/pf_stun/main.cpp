// pf_stun: STUN client diagnostic (PM-2b N3). Runs one Binding transaction, or RFC 5780 NAT behaviour discovery,
// against a STUN server over a real UDP socket and prints what it found.
//
//   pf_stun --server 198.51.100.1:3478 [--discover] [--bind ip:port] [--rto MS] [--probe-rto MS] [--probe-rm N]
//
// Output (one "key: value" per line): status, mapped, other, behind_nat, mapping (EIM|ADM|APDM), filtering
// (EIF|ADF|APDF), detail. --bind also tells discovery our own address (so "no NAT" can be detected).
// Exit codes: 0 found what was asked, 1 the server did not answer / discovery incomplete, 4 usage error.
#include <arpa/inet.h>
#include <poll.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "pf/crypto/os_random.h"
#include "pf/stun_client.h"
#include "udp_socket.h"

namespace {

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool parse_endpoint(const std::string& s, sockaddr_in& out) {
    const size_t colon = s.rfind(':');
    if (colon == std::string::npos) return false;
    const int port = std::atoi(s.c_str() + colon + 1);
    out = sockaddr_in{};
    out.sin_family = AF_INET;
    out.sin_port = htons(static_cast<uint16_t>(port));
    return port > 0 && port <= 65535 && inet_pton(AF_INET, s.substr(0, colon).c_str(), &out.sin_addr) == 1;
}

pf::stun::Address to_stun(const sockaddr_in& a) {
    pf::stun::Address x;
    x.family = pf::stun::Address::Family::V4;
    std::memcpy(x.ip.data(), &a.sin_addr, 4);
    x.port = ntohs(a.sin_port);
    return x;
}
sockaddr_in to_sock(const pf::stun::Address& a) {
    sockaddr_in s{};
    s.sin_family = AF_INET;
    std::memcpy(&s.sin_addr, a.ip.data(), 4);
    s.sin_port = htons(a.port);
    return s;
}

// Drives any client (BindingClient or NatDiscovery) over the socket until it is done.
template <typename C, typename Deliver>
void drive(C& c, pf::pal::UdpSocket& sock, Deliver deliver) {
    auto send_all = [&](const std::vector<pf::stun::Outgoing>& out) {
        for (const auto& o : out) sock.send_to(to_sock(o.to), o.bytes.data(), o.bytes.size());
    };
    send_all(c.start(now_ms()));
    uint8_t buf[2048];
    while (!c.done()) {
        const auto deadline = c.next_deadline_ms();
        const uint64_t now = now_ms();
        int wait = deadline ? static_cast<int>(*deadline > now ? *deadline - now : 0) : 1000;
        pollfd p{sock.fd(), POLLIN, 0};
        if (poll(&p, 1, wait) > 0) {
            size_t len = 0;
            sockaddr_in from{};
            while (sock.recv_from(buf, sizeof buf, len, from) == pf::pal::UdpSocket::Status::Ok)
                send_all(deliver(buf, len, to_stun(from)));
        }
        send_all(c.poll(now_ms()));
    }
}

}  // namespace

int main(int argc, char** argv) {
    using namespace pf::stun;
    std::string server, bind;
    bool discover = false;
    uint32_t rto = 500, probe_rto = 500, probe_rm = 16;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--server") server = val();
        else if (a == "--bind") bind = val();
        else if (a == "--discover") discover = true;
        else if (a == "--rto") rto = static_cast<uint32_t>(std::atoi(val().c_str()));
        else if (a == "--probe-rto") probe_rto = static_cast<uint32_t>(std::atoi(val().c_str()));
        else if (a == "--probe-rm") probe_rm = static_cast<uint32_t>(std::atoi(val().c_str()));
        else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 4; }
    }
    sockaddr_in srv{}, local{};
    if (!parse_endpoint(server, srv)) { std::fprintf(stderr, "bad or missing --server ip:port\n"); return 4; }
    if (!bind.empty() && !parse_endpoint(bind, local)) { std::fprintf(stderr, "bad --bind ip:port\n"); return 4; }
    if (rto == 0 || probe_rto == 0) { std::fprintf(stderr, "--rto/--probe-rto must be positive\n"); return 4; }
    pf::pal::UdpSocket sock;
    std::string err;
    if (!sock.open(bind.empty() ? nullptr : &local, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 4; }
    auto random = pf::make_os_random();

    if (!discover) {
        BindingConfig cfg;
        cfg.server = to_stun(srv);
        cfg.rto_ms = rto;
        cfg.software = "pf_stun";
        auto c = BindingClient::create(cfg, *random, &err);
        if (!c) { std::fprintf(stderr, "%s\n", err.c_str()); return 4; }
        drive(*c, sock, [&](const uint8_t* d, size_t n, const Address& from) {
            c->on_datagram(d, n, from, now_ms());
            return std::vector<Outgoing>{};
        });
        const BindingResult& r = c->result();
        const bool ok = r.status == BindingStatus::Succeeded;
        std::printf("status: %s\n", ok ? "Succeeded" : binding_failure_name(r.failure));
        if (ok) std::printf("mapped: %s\n", r.mapped.to_string().c_str());
        if (r.other_address) std::printf("other: %s\n", r.other_address->to_string().c_str());
        std::printf("requests: %d\nrtt_ms: %llu\n", r.requests_sent, static_cast<unsigned long long>(r.rtt_ms));
        return ok ? 0 : 1;
    }

    DiscoveryConfig cfg;
    cfg.server = to_stun(srv);
    if (!bind.empty()) cfg.local = to_stun(local);
    cfg.rto_ms = rto;
    cfg.probe_rto_ms = probe_rto;
    cfg.probe_rm = probe_rm;
    cfg.software = "pf_stun";
    auto d = NatDiscovery::create(cfg, *random, &err);
    if (!d) { std::fprintf(stderr, "%s\n", err.c_str()); return 4; }
    drive(*d, sock, [&](const uint8_t* b, size_t n, const Address& from) {
        std::vector<Outgoing> out;
        d->on_datagram(b, n, from, now_ms(), out);
        return out;
    });
    const DiscoveryResult& r = d->result();
    std::printf("status: %s\n", discovery_status_name(r.status));
    if (r.status != DiscoveryStatus::NoResponse) std::printf("mapped: %s\n", r.mapped.to_string().c_str());
    if (r.other_address) std::printf("other: %s\n", r.other_address->to_string().c_str());
    if (cfg.local) std::printf("behind_nat: %s\n", r.behind_nat ? "yes" : "no");
    if (r.mapping) std::printf("mapping: %s\n", pf::nat_mapping_name(*r.mapping));
    if (r.filtering) std::printf("filtering: %s\n", pf::nat_filtering_name(*r.filtering));
    if (!r.detail.empty()) std::printf("detail: %s\n", r.detail.c_str());
    return r.status == DiscoveryStatus::Done && r.mapping && r.filtering ? 0 : 1;
}
