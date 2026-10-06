#include "vpn_client.h"

#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <memory>

#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/data_path.h"
#include "pf/keepalive.h"
#include "tun_device.h"
#include "udp_transport.h"

namespace pf::pal {

namespace {

uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint32_t unix_now() { return static_cast<uint32_t>(std::time(nullptr)); }

constexpr size_t kMaxDatagram = 2048;

}  // namespace

VpnExit VpnClient::run(VpnOptions opts, const std::atomic<bool>& stop) {
    stats_ = {};
    control_stats_ = {};
    KeyStore keys;
    opts.control.keys = &keys;
    std::string err;
    auto client = ControlClient::create(std::move(opts.control), err);
    if (!client) { error_ = "config: " + err; return VpnExit::ConfigError; }
    auto aead = make_openssl_aes256gcm();
    DataPath dp;
    if (!dp.init(&keys, aead.get())) { error_ = "data path init failed"; return VpnExit::ConfigError; }

    std::unique_ptr<Transport> transport = std::move(opts.transport);
    if (!transport) {
        auto udp = std::make_unique<UdpTransport>();
        if (!udp->open(opts.server, nullptr, err)) { error_ = "udp: " + err; return VpnExit::ConfigError; }
        transport = std::move(udp);
    }
    const int fd = transport->poll_fd();
    if (fd < 0) { error_ = "transport has no pollable descriptor"; return VpnExit::ConfigError; }
    auto send_all = [&](const std::vector<std::vector<uint8_t>>& dgrams) {
        for (const auto& d : dgrams) (void)transport->send(d.data(), d.size());
    };

    // --- phase 1: control channel ------------------------------------------------------------------------------
    const uint64_t t0 = now_ms();
    client->start(t0, unix_now());
    while (client->state() != ControlClient::State::Established) {
        const uint64_t now = now_ms();
        if (stop.load()) return VpnExit::Ok;
        send_all(client->poll(now, unix_now()));
        if (client->state() == ControlClient::State::Failed) {
            error_ = "control channel failed: " + client->failure_reason();
            control_stats_ = client->stats();
            return VpnExit::ControlFailed;
        }
        if (client->state() == ControlClient::State::Established) break;
        if (now > t0 + static_cast<uint64_t>(opts.connect_timeout_s) * 1000) { error_ = "control channel timeout"; return VpnExit::ControlFailed; }
        int wait = 100;
        if (auto w = client->next_wakeup_ms()) wait = static_cast<int>(std::min<uint64_t>(100, *w > now ? *w - now : 0));
        pollfd p{fd, POLLIN, 0};
        if (poll(&p, 1, wait) > 0 && (p.revents & POLLIN)) {
            uint8_t buf[kMaxDatagram];
            const RecvResult rr = transport->recv(buf, sizeof buf);
            if (rr.status == TransportStatus::Ok) (void)client->on_datagram(buf, rr.len, now_ms(), unix_now());
            else if (rr.status == TransportStatus::Closed || rr.status == TransportStatus::Error) { error_ = "transport closed"; return VpnExit::ControlFailed; }
        }
    }
    const PushReply pr = client->push();
    if (!pr.has_ifconfig) { error_ = "server pushed no ifconfig"; return VpnExit::ControlFailed; }
    std::printf("control channel ESTABLISHED in %llu ms\n", static_cast<unsigned long long>(now_ms() - t0));

    // --- phase 2: TUN ------------------------------------------------------------------------------------------
    TunDevice tun;
    if (!tun.open(opts.dev_name, err) || !tun.configure(pr.ifconfig_ip, pr.ifconfig_netmask, opts.mtu, err)) {
        error_ = "tun: " + err;
        return VpnExit::DeviceError;
    }
    if (opts.install_routes) {
        for (const auto& r : pr.routes) {
            const uint32_t gw = r.has_gateway ? r.gateway : pr.route_gateway;
            if (!tun.add_route(r.network, r.netmask, gw, err)) std::printf("warning: route not installed: %s\n", err.c_str());
        }
    }
    std::printf("tunnel UP dev=%s ip=%u.%u.%u.%u/%u.%u.%u.%u mtu=%d peer_id=%u ping=%u ping_restart=%u\n", tun.name().c_str(),
                pr.ifconfig_ip >> 24, (pr.ifconfig_ip >> 16) & 255, (pr.ifconfig_ip >> 8) & 255, pr.ifconfig_ip & 255,
                pr.ifconfig_netmask >> 24, (pr.ifconfig_netmask >> 16) & 255, (pr.ifconfig_netmask >> 8) & 255, pr.ifconfig_netmask & 255,
                opts.mtu, pr.peer_id, pr.ping_seconds, pr.ping_restart_seconds);
    std::fflush(stdout);

    // --- phase 3: data plane -----------------------------------------------------------------------------------
    const uint64_t start = now_ms();
    const uint64_t end = opts.duration_s > 0 ? start + static_cast<uint64_t>(opts.duration_s) * 1000 : UINT64_MAX;
    uint64_t next_stats = opts.stats_interval_s > 0 ? start + static_cast<uint64_t>(opts.stats_interval_s) * 1000 : UINT64_MAX;
    KeepaliveTimer ka(pr.ping_seconds, pr.ping_restart_seconds, start);
    VpnExit result = VpnExit::Ok;
    unsigned drop_logs = 0;

    auto print_stats = [&](const char* tag) {
        const auto& cs = client->stats();
        std::printf("%s: up=%llus tun_to_net=%llu/%lluB net_to_tun=%llu/%lluB pings_sent=%llu pings_received=%llu rx_dropped=%llu rx_other=%llu "
                    "tx_failed=%llu renegotiations=%u reneg_failures=%u key_id=%u\n",
                    tag, static_cast<unsigned long long>((now_ms() - start) / 1000),
                    static_cast<unsigned long long>(stats_.tun_to_net_packets), static_cast<unsigned long long>(stats_.tun_to_net_bytes),
                    static_cast<unsigned long long>(stats_.net_to_tun_packets), static_cast<unsigned long long>(stats_.net_to_tun_bytes),
                    static_cast<unsigned long long>(stats_.pings_sent), static_cast<unsigned long long>(stats_.pings_received),
                    static_cast<unsigned long long>(stats_.rx_dropped), static_cast<unsigned long long>(stats_.rx_other),
                    static_cast<unsigned long long>(stats_.tx_failed), cs.renegotiations, cs.reneg_failures, client->tx_key_id());
        std::fflush(stdout);
    };

    auto transmit = [&](PacketBuffer& pkt) -> bool {
        const Error e = dp.seal(pkt, client->tx_key_id(), pr.peer_id);
        if (e != Error::None) { ++stats_.tx_failed; return false; }
        if (transport->send(pkt.data(), pkt.size()) != TransportStatus::Ok) { ++stats_.tx_failed; return false; }
        ka.on_sent(now_ms());
        return true;
    };

    while (!stop.load()) {
        const uint64_t now = now_ms();
        if (now >= end) break;
        send_all(client->poll(now, unix_now()));
        if (client->state() == ControlClient::State::Failed) {
            error_ = "control channel failed: " + client->failure_reason();
            result = VpnExit::ControlFailed;
            break;
        }
        const KeepaliveTimer::Action act = ka.poll(now);
        if (act == KeepaliveTimer::Action::Timeout) { error_ = "ping-restart: no packet from the server"; result = VpnExit::PingRestart; break; }
        if (act == KeepaliveTimer::Action::SendPing) {
            PacketBuffer pkt = PacketBuffer::from_bytes(kPingPayload, kPingPayloadLen);
            if (transmit(pkt)) ++stats_.pings_sent;
        }
        if (now >= next_stats) {
            print_stats("stats");
            next_stats += static_cast<uint64_t>(opts.stats_interval_s) * 1000;
        }

        uint64_t wait = 500;
        if (auto w = client->next_wakeup_ms()) wait = std::min<uint64_t>(wait, *w > now ? *w - now : 0);
        if (auto d = ka.next_deadline_ms()) wait = std::min<uint64_t>(wait, *d > now ? *d - now : 0);
        wait = std::min<uint64_t>(wait, end > now ? end - now : 0);
        pollfd fds[2] = {{fd, POLLIN, 0}, {tun.fd(), POLLIN, 0}};
        if (poll(fds, 2, static_cast<int>(wait)) <= 0) continue;

        if (fds[0].revents & POLLIN) {
            for (int i = 0; i < 64; ++i) {                              // drain, bounded so timers still run
                uint8_t buf[kMaxDatagram];
                const RecvResult rr = transport->recv(buf, sizeof buf);
                if (rr.status == TransportStatus::TooLarge) { ++stats_.rx_dropped; continue; }
                if (rr.status == TransportStatus::Closed || rr.status == TransportStatus::Error) {
                    error_ = "transport closed";
                    result = VpnExit::ControlFailed;
                    break;
                }
                if (rr.status != TransportStatus::Ok) break;
                const uint64_t t = now_ms();
                if (client->on_datagram(buf, rr.len, t, unix_now())) { ka.on_received(t); continue; }
                PacketBuffer pkt = PacketBuffer::from_bytes(buf, rr.len);
                const DataPath::Opened o = dp.open(pkt);
                if (o.error != Error::None) {
                    ++stats_.rx_dropped;
                    if (drop_logs++ < 5) std::printf("data packet dropped: %s\n", error_name(o.error));
                    continue;
                }
                ka.on_received(t);
                if (o.kind == PayloadKind::Ping) { ++stats_.pings_received; continue; }
                if (o.kind == PayloadKind::Other) { ++stats_.rx_other; continue; }
                if (tun.write_packet(pkt.data(), pkt.size())) { ++stats_.net_to_tun_packets; stats_.net_to_tun_bytes += pkt.size(); }
                pkt.wipe();
            }
        }
        if (result != VpnExit::Ok) break;
        if (fds[1].revents & POLLIN) {
            for (int i = 0; i < 64; ++i) {
                PacketBuffer pkt = DataPath::make_tx_buffer(kMaxDatagram);
                uint8_t* room = pkt.put(kMaxDatagram);
                const long n = room ? tun.read_packet(room, kMaxDatagram) : 0;
                if (n <= 0) {
                    if (n < 0) { error_ = "tun read failed"; result = VpnExit::DeviceError; }
                    break;
                }
                pkt.trim_back(kMaxDatagram - static_cast<size_t>(n));
                const size_t plain = pkt.size();
                if (transmit(pkt)) { ++stats_.tun_to_net_packets; stats_.tun_to_net_bytes += plain; }
            }
            if (result != VpnExit::Ok) break;
        }
    }
    print_stats("final");
    control_stats_ = client->stats();
    return result;
}

}  // namespace pf::pal
