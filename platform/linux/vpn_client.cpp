#include "vpn_client.h"

#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <ctime>

#include "linux_net.h"
#include "pf/tunnel_session.h"
#include "tcp_stream.h"
#include "udp_transport.h"

namespace pf::pal {

namespace {

uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}
uint32_t unix_now() { return static_cast<uint32_t>(std::time(nullptr)); }

std::string ip_str(uint32_t ip) {
    char b[16];
    std::snprintf(b, sizeof b, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return b;
}

const char* kind_name(TransportKind k) { return k == TransportKind::Udp ? "udp" : k == TransportKind::Tcp ? "tcp" : "other"; }

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

constexpr size_t kBuf = 65536;

}  // namespace

VpnExit VpnClient::run(VpnOptions opts, const std::atomic<bool>& stop) {
    error_.clear();
    attempts_.clear();
    KeyStore keys;
    std::string err;

    // --- phase 1: control channel over the first transport that works (UDP -> TCP ...) --------------------------
    FallbackConnector::TransportFactory make_transport = opts.transport_factory;
    if (!make_transport) {
        const sockaddr_in udp_peer = opts.server, tcp_peer = opts.tcp_server;
        const uint32_t connect_ms = opts.policy.connect_timeout_ms();
        make_transport = [udp_peer, tcp_peer, connect_ms](TransportKind kind, std::string& e) -> std::unique_ptr<Transport> {
            if (kind == TransportKind::Udp) {
                auto udp = std::make_unique<UdpTransport>();
                if (!udp->open(udp_peer, nullptr, e)) return nullptr;
                return udp;
            }
            if (kind == TransportKind::Tcp) return open_tcp_transport(tcp_peer, connect_ms, e);
            e = "transport not implemented yet";
            return nullptr;
        };
    }
    const ControlClientConfig base_control = opts.control;
    auto make_client = [&](TransportKind kind, std::string& e) -> std::unique_ptr<ControlClient> {
        ControlClientConfig c = base_control;                         // fresh client (and session ids) per attempt
        c.keys = &keys;
        if (kind == TransportKind::Tcp) {                             // the options string names the carrier (only a server warning if wrong)
            const std::string from = "proto UDPv4";
            const size_t at = c.options_string.find(from);
            if (at != std::string::npos) c.options_string.replace(at, from.size(), "proto TCPv4_CLIENT");
        }
        return ControlClient::create(std::move(c), e);
    };
    FallbackConnector connector(opts.policy, make_transport, make_client);
    const uint64_t t0 = now_ms();
    connector.start(t0, unix_now());
    while (!connector.done()) {
        const uint64_t now = now_ms();
        if (stop.load()) return VpnExit::Ok;
        connector.step(now, unix_now());
        if (connector.done()) break;
        Transport* t = connector.transport();
        int wait = 100;
        if (auto w = connector.next_wakeup_ms(now)) wait = static_cast<int>(std::min<uint64_t>(100, *w > now ? *w - now : 0));
        if (t && t->has_pending_input()) wait = 0;
        pollfd p{t ? t->poll_fd() : -1, static_cast<short>(POLLIN | (t && t->wants_write() ? POLLOUT : 0)), 0};
        if (p.fd < 0) { if (wait > 0) usleep(static_cast<useconds_t>(wait) * 1000); }
        else (void)poll(&p, 1, wait);
    }
    attempts_ = connector.history();
    for (const auto& a : attempts_) {
        if (a.ok) std::printf("attempt: %s ok\n", kind_name(a.kind));
        else std::printf("attempt: %s failed: %s\n", kind_name(a.kind), a.outcome.c_str());
    }
    if (connector.state() == FallbackConnector::State::Failed) {
        error_ = connector.failure_reason();
        return VpnExit::SessionLost;
    }
    std::unique_ptr<Transport> transport = connector.take_transport();
    std::unique_ptr<ControlClient> client = connector.take_client();
    kind_ = transport->kind();
    const int net_fd = transport->poll_fd();
    if (net_fd < 0) { error_ = "transport has no pollable descriptor"; return VpnExit::ConfigError; }
    const PushReply& pr = client->push();
    if (!pr.has_ifconfig) { error_ = "server pushed no ifconfig"; return VpnExit::ConfigError; }
    auto session = TunnelSession::create(*client, keys, err);
    if (!session) { error_ = "session: " + err; return VpnExit::ConfigError; }
    session->set_trace(opts.trace);
    std::printf("control channel ESTABLISHED in %llu ms over %s\n", static_cast<unsigned long long>(now_ms() - t0), kind_name(kind_));

    // --- phase 2: TUN, only now that the server pushed an address ------------------------------------------------
    TunDevice tun;
    const unsigned mtu = pr.tun_mtu ? std::min(pr.tun_mtu, opts.mtu_cap) : opts.mtu_cap;
    if (!tun.open(opts.tun_name, err) || !tun.configure(pr.ifconfig_ip, pr.ifconfig_netmask, mtu, err)) { error_ = "tun: " + err; return VpnExit::ConfigError; }
    size_t routes = 0;
    if (opts.install_routes) {
        for (const auto& r : pr.routes) {
            const bool gw = r.has_gateway || pr.route_gateway != 0;
            if (tun.add_route({r.network, r.netmask, r.has_gateway ? r.gateway : pr.route_gateway, gw}, err)) ++routes;
            else std::fprintf(stderr, "warning: route not installed: %s\n", err.c_str());
        }
    }
    const uint64_t up_at = now_ms();
    std::printf("[%6llu ms] tunnel UP dev=%s addr=%s/%s mtu=%u peer_id=%u routes=%zu ping=%u ping_restart=%u\n", static_cast<unsigned long long>(up_at - t0),
                tun.name().c_str(), ip_str(pr.ifconfig_ip).c_str(), ip_str(pr.ifconfig_netmask).c_str(), mtu, pr.peer_id, routes, pr.ping_seconds, pr.ping_restart_seconds);
    std::fflush(stdout);

    // --- phase 3: data plane -------------------------------------------------------------------------------------
    const uint64_t end = opts.duration_s > 0 ? up_at + static_cast<uint64_t>(opts.duration_s) * 1000 : UINT64_MAX;
    const uint64_t stats_ms = static_cast<uint64_t>(std::max(1, opts.stats_interval_s)) * 1000;
    uint64_t next_stats = up_at + stats_ms;
    std::vector<int> key_ids{client->tx_key_id()};
    VpnExit result = VpnExit::Ok;
    std::vector<uint8_t> buf(kBuf), wire;

    while (!stop.load()) {
        const uint64_t now = now_ms();
        if (now >= end) break;
        for (const auto& d : session->poll(now, unix_now())) (void)transport->send(d.data(), d.size());
        transport->flush();
        if (client->state() == ControlClient::State::Failed) { error_ = "control channel failed: " + client->failure_reason(); result = VpnExit::SessionLost; break; }
        if (session->timed_out()) { error_ = "ping-restart: no packet from the server"; result = VpnExit::SessionLost; break; }
        if (client->tx_key_id() != key_ids.back()) key_ids.push_back(client->tx_key_id());
        if (now >= next_stats) { print_stats("stats", *session, *client, key_ids); next_stats = now + stats_ms; }

        uint64_t wait = 1000;
        if (auto w = session->next_wakeup_ms()) wait = std::min<uint64_t>(wait, *w > now ? *w - now : 0);
        wait = std::min<uint64_t>(wait, end > now ? end - now : 0);
        if (transport->has_pending_input()) wait = 0;
        pollfd fds[2] = {{net_fd, static_cast<short>(POLLIN | (transport->wants_write() ? POLLOUT : 0)), 0}, {tun.fd(), POLLIN, 0}};
        const int ready = poll(fds, 2, static_cast<int>(wait));
        if (ready < 0 && errno != EINTR) { error_ = "poll failed"; result = VpnExit::SessionLost; break; }
        if (ready <= 0) fds[0].revents = fds[1].revents = 0;

        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) || transport->has_pending_input()) {
            for (int i = 0; i < 64; ++i) {                                   // bounded drain so timers still run
                const RecvResult rr = transport->recv(buf.data(), buf.size());
                if (rr.status == TransportStatus::TooLarge) continue;
                if (rr.status == TransportStatus::Closed || rr.status == TransportStatus::Error) { error_ = "transport closed"; result = VpnExit::SessionLost; break; }
                if (rr.status != TransportStatus::Ok) break;
                PacketBuffer ip;
                if (session->on_datagram(buf.data(), rr.len, now_ms(), unix_now(), ip) == TunnelSession::RxKind::Packet) tun.write(ip.data(), ip.size());
            }
            if (result != VpnExit::Ok) break;
        }
        if (fds[1].revents & POLLIN) {
            for (int i = 0; i < 64; ++i) {
                const long n = tun.read(buf.data(), buf.size());
                if (n < 0) { error_ = "tun read failed"; result = VpnExit::SessionLost; break; }
                if (n == 0) break;
                if (session->encapsulate(buf.data(), static_cast<size_t>(n), now_ms(), wire)) (void)transport->send(wire.data(), wire.size());
            }
            if (result != VpnExit::Ok) break;
        }
    }
    print_stats("final", *session, *client, key_ids);
    return result;
}

}  // namespace pf::pal
