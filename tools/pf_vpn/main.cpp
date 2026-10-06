// pf_vpn: Linux VPN client (UDP + TUN) for the OpenVPN 2.6 MVP profile. Needs root / CAP_NET_ADMIN and OpenSSL.
//
//   pf_vpn --server 203.0.113.1:1194 --tls-crypt tc.key --ca ca.crt --cert c.crt --key c.key
//          [--dev pfvpn0] [--mtu 1400] [--timeout 30] [--duration SECONDS] [--stats-interval SECONDS]
//          [--reneg-seconds N] [--no-routes] [--proto udp|tcp|auto] [--tcp-port P] [--connect-timeout S]
//
// Runs until SIGINT/SIGTERM or --duration. Exit codes: 0 ok, 2 control channel failed, 4 usage/config,
// 5 ping-restart (server silent), 6 TUN device error.
#include <arpa/inet.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "tcp_stream.h"
#include "vpn_client.h"

namespace {
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}
}  // namespace

int main(int argc, char** argv) {
    using namespace pf;
    pal::VpnOptions opt;
    std::string server, tc, ca, cert, key, proto = "udp";
    int tcp_port = 0, connect_timeout_s = 10;
    int reneg_s = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&](std::string& dst) { if (i + 1 < argc) dst = argv[++i]; };
        auto num = [&](int& dst) { if (i + 1 < argc) dst = std::atoi(argv[++i]); };
        if (a == "--server") val(server);
        else if (a == "--tls-crypt") val(tc);
        else if (a == "--ca") val(ca);
        else if (a == "--cert") val(cert);
        else if (a == "--key") val(key);
        else if (a == "--dev") val(opt.dev_name);
        else if (a == "--proto") val(proto);
        else if (a == "--mtu") num(opt.mtu);
        else if (a == "--timeout" || a == "--connect-timeout") num(connect_timeout_s);
        else if (a == "--tcp-port") num(tcp_port);
        else if (a == "--duration") num(opt.duration_s);
        else if (a == "--stats-interval") num(opt.stats_interval_s);
        else if (a == "--reneg-seconds") num(reneg_s);
        else if (a == "--no-routes") opt.install_routes = false;
        else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 4; }
    }
    if (server.empty() || tc.empty() || ca.empty() || cert.empty() || key.empty()) {
        std::fprintf(stderr, "usage: pf_vpn --server HOST:PORT --tls-crypt F --ca F --cert F --key F [options]\n");
        return 4;
    }
    const size_t colon = server.rfind(':');
    opt.server.sin_family = AF_INET;
    if (colon == std::string::npos || inet_pton(AF_INET, server.substr(0, colon).c_str(), &opt.server.sin_addr) != 1) {
        std::fprintf(stderr, "bad --server (IPv4 address:port)\n");
        return 4;
    }
    opt.server.sin_port = htons(static_cast<uint16_t>(std::atoi(server.substr(colon + 1).c_str())));
    if (proto != "udp" && proto != "tcp" && proto != "auto") { std::fprintf(stderr, "--proto must be udp, tcp or auto\n"); return 4; }
    if (opt.mtu < 576 || opt.mtu > 1500) { std::fprintf(stderr, "--mtu must be 576..1500\n"); return 4; }

    std::string tc_text;
    if (!read_file(tc, tc_text) || !parse_static_key_file(tc_text, opt.control.tls_crypt_key)) { std::fprintf(stderr, "bad tls-crypt key file\n"); return 4; }
    opt.control.tls.role = TlsRole::Client;
    if (!read_file(ca, opt.control.tls.ca_pem) || !read_file(cert, opt.control.tls.cert_pem) || !read_file(key, opt.control.tls.key_pem)) {
        std::fprintf(stderr, "cannot read ca/cert/key\n");
        return 4;
    }
    if (reneg_s > 0) opt.control.reneg_interval_ms = static_cast<uint32_t>(reneg_s) * 1000u;

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    opt.tcp_server = opt.server;
    if (tcp_port > 0) opt.tcp_server.sin_port = htons(static_cast<uint16_t>(tcp_port));
    opt.policy = proto == "udp" ? FallbackPolicy({TransportKind::Udp})
               : proto == "tcp" ? FallbackPolicy({TransportKind::Tcp})
                                : FallbackPolicy({TransportKind::Udp, TransportKind::Tcp});      // auto: UDP first, TCP when UDP is blocked
    opt.policy.set_connect_timeout_ms(static_cast<uint32_t>(connect_timeout_s) * 1000u);

    pal::VpnClient vpn;
    const pal::VpnExit rc = vpn.run(std::move(opt), g_stop);
    if (rc != pal::VpnExit::Ok) std::fprintf(stderr, "pf_vpn: %s\n", vpn.error().c_str());
    return static_cast<int>(rc);
}
