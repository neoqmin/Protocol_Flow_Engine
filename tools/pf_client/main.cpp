// pf_client: the A4 Linux client. UDP socket + TUN device + ControlClient/TunnelSession against an unmodified
// OpenVPN 2.6 server (UDP, TLS 1.3, tls-crypt, AES-256-GCM). Needs root/CAP_NET_ADMIN (TUN) and OpenSSL.
//
//   pf_client --server 10.99.0.1:11940 --tls-crypt tc.key --ca ca.crt --cert c.crt --key c.key
//             [--tun-name pf0] [--mtu 1400] [--duration SECONDS] [--stats-interval SECONDS] [--reneg-seconds N]
//
// The TUN device is created and configured (address, MTU, pushed routes) once the server's PUSH_REPLY arrives, and
// disappears when the process exits. Runs until SIGINT/SIGTERM, --duration, or the session dies.
//
// Policy: when the session dies (control failure or ping-restart timeout) the client EXITS with code 2; reconnecting
// is the supervisor's job (systemd Restart=, a wrapper loop). Exit codes: 0 clean stop, 2 session lost/failed,
// 4 usage/config/device error.
#include <poll.h>
#include <signal.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "linux_net.h"
#include "pf/control_client.h"
#include "pf/tunnel_session.h"

using namespace pf;

namespace {

volatile sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

std::string ip_str(uint32_t ip) {
    char b[16];
    std::snprintf(b, sizeof b, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return b;
}

void print_stats(const char* tag, const TunnelSession& s, const ControlClient& c, const std::vector<int>& key_ids) {
    const auto& t = s.stats();
    const auto& st = c.stats();
    std::printf("%s: tx_packets=%llu tx_bytes=%llu tx_pings=%llu tx_failed=%llu rx_packets=%llu rx_bytes=%llu rx_pings=%llu rx_dropped=%llu rx_not_ip=%llu "
                "renegotiations=%u reneg_failures=%u unknown_key_id=%u key_ids=",
                tag, static_cast<unsigned long long>(t.tx_packets), static_cast<unsigned long long>(t.tx_bytes), static_cast<unsigned long long>(t.tx_pings),
                static_cast<unsigned long long>(t.tx_failed), static_cast<unsigned long long>(t.rx_packets), static_cast<unsigned long long>(t.rx_bytes),
                static_cast<unsigned long long>(t.rx_pings), static_cast<unsigned long long>(t.rx_dropped), static_cast<unsigned long long>(t.rx_not_ip),
                st.renegotiations, st.reneg_failures, st.unknown_key_id);
    for (size_t i = 0; i < key_ids.size(); ++i) std::printf("%s%d", i ? "," : "", key_ids[i]);
    std::printf("\n");
    std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
    std::string server = "10.99.0.1:11940", tc, ca, cert, key, tun_name;
    unsigned mtu_cap = 1400;
    int duration_s = 0, stats_s = 60, reneg_s = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& dst) { if (i + 1 < argc) dst = argv[++i]; };
        auto next_int = [&](int& dst) { if (i + 1 < argc) dst = std::atoi(argv[++i]); };
        if (a == "--server") next(server);
        else if (a == "--tls-crypt") next(tc);
        else if (a == "--ca") next(ca);
        else if (a == "--cert") next(cert);
        else if (a == "--key") next(key);
        else if (a == "--tun-name") next(tun_name);
        else if (a == "--mtu") { int m = 0; next_int(m); mtu_cap = static_cast<unsigned>(std::max(576, m)); }
        else if (a == "--duration") next_int(duration_s);
        else if (a == "--stats-interval") next_int(stats_s);
        else if (a == "--reneg-seconds") next_int(reneg_s);
        else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 4; }
    }
    if (tc.empty() || ca.empty() || cert.empty() || key.empty()) { std::fprintf(stderr, "missing --tls-crypt/--ca/--cert/--key\n"); return 4; }

    ControlClientConfig cfg;
    std::string tc_text;
    if (!read_file(tc, tc_text) || !parse_static_key_file(tc_text, cfg.tls_crypt_key)) { std::fprintf(stderr, "bad tls-crypt key file\n"); return 4; }
    cfg.tls.role = TlsRole::Client;
    if (!read_file(ca, cfg.tls.ca_pem) || !read_file(cert, cfg.tls.cert_pem) || !read_file(key, cfg.tls.key_pem)) {
        std::fprintf(stderr, "cannot read ca/cert/key\n");
        return 4;
    }
    KeyStore keys;
    cfg.keys = &keys;
    if (reneg_s > 0) cfg.reneg_interval_ms = static_cast<uint32_t>(reneg_s) * 1000u;
    std::string err;
    auto client = ControlClient::create(std::move(cfg), err);
    if (!client) { std::fprintf(stderr, "config error: %s\n", err.c_str()); return 4; }
    auto session = TunnelSession::create(*client, keys, err);
    if (!session) { std::fprintf(stderr, "session error: %s\n", err.c_str()); return 4; }

    pal::UdpSocket udp;
    if (!udp.open_connected(server, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 4; }
    pal::TunDevice tun;
    bool tun_up = false;

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    const uint64_t t0 = now_ms();
    uint64_t next_stats = t0 + static_cast<uint64_t>(std::max(1, stats_s)) * 1000;
    uint64_t connect_deadline = t0 + 30000;
    std::vector<int> key_ids;
    int rc = 0;
    auto unix_now = [] { return static_cast<uint32_t>(std::time(nullptr)); };
    client->start(t0, unix_now());
    std::vector<uint8_t> buf(65536), wire;

    while (!g_stop) {
        const uint64_t now = now_ms();
        for (const auto& d : session->poll(now, unix_now())) udp.send(d.data(), d.size());

        if (client->state() == ControlClient::State::Failed) { std::printf("control channel failed: %s\n", client->failure_reason().c_str()); rc = 2; break; }
        if (session->timed_out()) { std::printf("ping-restart: no packet from the server\n"); rc = 2; break; }
        if (!tun_up && now > connect_deadline) { std::printf("timeout waiting for the control channel\n"); rc = 2; break; }

        if (!tun_up && client->state() == ControlClient::State::Established) {
            const PushReply& p = client->push();
            if (!p.has_ifconfig) { std::fprintf(stderr, "server pushed no ifconfig\n"); rc = 4; break; }
            if (!tun.open(tun_name, err)) { std::fprintf(stderr, "%s\n", err.c_str()); rc = 4; break; }
            const unsigned mtu = p.tun_mtu ? std::min(p.tun_mtu, mtu_cap) : mtu_cap;
            if (!tun.configure(p.ifconfig_ip, p.ifconfig_netmask, mtu, err)) { std::fprintf(stderr, "%s\n", err.c_str()); rc = 4; break; }
            for (const auto& r : p.routes) {
                const bool gw = r.has_gateway || p.route_gateway != 0;
                if (!tun.add_route({r.network, r.netmask, r.has_gateway ? r.gateway : p.route_gateway, gw}, err)) std::fprintf(stderr, "warning: %s\n", err.c_str());
            }
            tun_up = true;
            key_ids.push_back(client->tx_key_id());
            std::printf("[%6llu ms] tunnel UP dev=%s addr=%s/%s mtu=%u peer_id=%u routes=%zu\n", static_cast<unsigned long long>(now - t0), tun.name().c_str(),
                        ip_str(p.ifconfig_ip).c_str(), ip_str(p.ifconfig_netmask).c_str(), mtu, p.peer_id, p.routes.size());
            std::fflush(stdout);
            if (duration_s > 0) connect_deadline = UINT64_MAX;
        }
        if (tun_up && client->tx_key_id() != key_ids.back()) key_ids.push_back(client->tx_key_id());
        if (duration_s > 0 && tun_up && now >= t0 + static_cast<uint64_t>(duration_s) * 1000) break;
        if (tun_up && now >= next_stats) { print_stats("stats", *session, *client, key_ids); next_stats = now + static_cast<uint64_t>(std::max(1, stats_s)) * 1000; }

        uint64_t wait = 1000;
        if (auto w = session->next_wakeup_ms()) wait = std::min<uint64_t>(wait, *w > now ? *w - now : 0);
        pollfd fds[2] = {{udp.fd(), POLLIN, 0}, {tun_up ? tun.fd() : -1, POLLIN, 0}};
        if (poll(fds, 2, static_cast<int>(wait)) <= 0) continue;

        if (fds[0].revents & POLLIN) {
            for (int i = 0; i < 64; ++i) {
                const long n = udp.recv(buf.data(), buf.size());
                if (n < 0) { std::fprintf(stderr, "udp receive failed\n"); rc = 2; g_stop = 1; break; }
                if (n == 0) break;
                PacketBuffer ip;
                if (session->on_datagram(buf.data(), static_cast<size_t>(n), now_ms(), unix_now(), ip) == TunnelSession::RxKind::Packet && tun_up)
                    tun.write(ip.data(), ip.size());
            }
        }
        if (tun_up && (fds[1].revents & POLLIN)) {
            for (int i = 0; i < 64; ++i) {
                const long n = tun.read(buf.data(), buf.size());
                if (n < 0) { std::fprintf(stderr, "tun read failed\n"); rc = 2; g_stop = 1; break; }
                if (n == 0) break;
                if (session->encapsulate(buf.data(), static_cast<size_t>(n), now_ms(), wire)) udp.send(wire.data(), wire.size());
            }
        }
    }

    if (tun_up) print_stats("final", *session, *client, key_ids);
    return rc;
}
