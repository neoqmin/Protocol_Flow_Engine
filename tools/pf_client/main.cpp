// pf_client: the Linux client. Transport (UDP, falling back to TCP) + control channel + data plane + TUN device
// against an unmodified OpenVPN 2.6 server (TLS 1.3, tls-crypt, AES-256-GCM). Needs root/CAP_NET_ADMIN (TUN) and OpenSSL.
//
//   pf_client --server 10.99.0.1:11940 --tls-crypt tc.key --ca ca.crt --cert c.crt --key c.key
//             [--proto udp|tcp|auto] [--tcp-port P] [--connect-timeout S]
//             [--tun-name pf0] [--mtu 1400] [--duration S] [--stats-interval S] [--reneg-seconds N] [--no-routes]
//             [--trace FILE] [--trace-records N]
//
// --trace keeps the last N (default 4096) data-plane trace records in memory (every block of the DATA_V2 RX/TX Flows,
// how each packet ended; names, result codes and lengths only - never packet bytes or keys, pf/trace.h) and writes
// them to FILE as JSON Lines when the client exits.
// --proto auto tries UDP first and falls back to TCP when UDP is blocked (docs/Linux_Client_Notes.md).
// The TUN device is created and configured (address, MTU, pushed routes) once the server's PUSH_REPLY arrives, and
// disappears when the process exits. Runs until SIGINT/SIGTERM, --duration, or the session dies.
//
// Policy (D-029): when the session dies (control failure, ping-restart, no transport works) the client EXITS with
// code 2; reconnecting is the supervisor's job. Exit codes: 0 clean stop, 2 session lost/failed, 4 usage/config/device.
#include <arpa/inet.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include "pf/trace.h"
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
    std::string server = "10.99.0.1:11940", tc, ca, cert, key, proto = "udp";
    std::string trace_file;
    int tcp_port = 0, connect_timeout_s = 10, reneg_s = 0, mtu = 1400, trace_records = 4096;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&](std::string& dst) { if (i + 1 < argc) dst = argv[++i]; };
        auto num = [&](int& dst) { if (i + 1 < argc) dst = std::atoi(argv[++i]); };
        if (a == "--server") val(server);
        else if (a == "--tls-crypt") val(tc);
        else if (a == "--ca") val(ca);
        else if (a == "--cert") val(cert);
        else if (a == "--key") val(key);
        else if (a == "--proto") val(proto);
        else if (a == "--tun-name") val(opt.tun_name);
        else if (a == "--mtu") num(mtu);
        else if (a == "--tcp-port") num(tcp_port);
        else if (a == "--connect-timeout" || a == "--timeout") num(connect_timeout_s);
        else if (a == "--duration") num(opt.duration_s);
        else if (a == "--stats-interval") num(opt.stats_interval_s);
        else if (a == "--reneg-seconds") num(reneg_s);
        else if (a == "--no-routes") opt.install_routes = false;
        else if (a == "--trace") val(trace_file);
        else if (a == "--trace-records") num(trace_records);
        else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 4; }
    }
    if (tc.empty() || ca.empty() || cert.empty() || key.empty()) { std::fprintf(stderr, "missing --tls-crypt/--ca/--cert/--key\n"); return 4; }
    if (proto != "udp" && proto != "tcp" && proto != "auto") { std::fprintf(stderr, "--proto must be udp, tcp or auto\n"); return 4; }
    opt.mtu_cap = static_cast<unsigned>(std::max(576, mtu));

    const size_t colon = server.rfind(':');
    opt.server.sin_family = AF_INET;
    const int port = colon == std::string::npos ? 0 : std::atoi(server.c_str() + colon + 1);
    if (port <= 0 || port > 65535 || inet_pton(AF_INET, server.substr(0, colon).c_str(), &opt.server.sin_addr) != 1) {
        std::fprintf(stderr, "bad --server (want a.b.c.d:port)\n");
        return 4;
    }
    opt.server.sin_port = htons(static_cast<uint16_t>(port));
    opt.tcp_server = opt.server;
    if (tcp_port > 0) opt.tcp_server.sin_port = htons(static_cast<uint16_t>(tcp_port));
    opt.policy = proto == "udp" ? FallbackPolicy({TransportKind::Udp})
               : proto == "tcp" ? FallbackPolicy({TransportKind::Tcp})
                                : FallbackPolicy({TransportKind::Udp, TransportKind::Tcp});       // auto: UDP first, TCP when UDP is blocked
    opt.policy.set_connect_timeout_ms(static_cast<uint32_t>(std::max(1, connect_timeout_s)) * 1000u);

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

    std::unique_ptr<TraceRing> trace;
    if (!trace_file.empty()) {
        if (trace_records < 1 || trace_records > 1000000) { std::fprintf(stderr, "--trace-records must be 1..1000000\n"); return 4; }
        trace = std::make_unique<TraceRing>(static_cast<size_t>(trace_records));
        opt.trace = trace.get();
    }

    pal::VpnClient client;
    const pal::VpnExit rc = client.run(std::move(opt), g_stop);
    if (rc != pal::VpnExit::Ok) std::printf("pf_client: %s\n", client.error().c_str());
    if (trace) {
        std::ofstream f(trace_file, std::ios::binary | std::ios::trunc);
        f << write_trace_jsonl(*trace);
        if (!f) std::fprintf(stderr, "pf_client: cannot write trace file %s\n", trace_file.c_str());
        else std::printf("trace: %zu records (%llu overwritten) -> %s\n", trace->size(),
                         static_cast<unsigned long long>(trace->overwritten()), trace_file.c_str());
    }
    return static_cast<int>(rc);
}
