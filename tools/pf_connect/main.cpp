// pf_connect: drives ControlClient over a UDP socket against a REAL (unmodified) OpenVPN 2.6 server.
// Interop/diagnostic tool, not the product client. POSIX only. Needs OpenSSL.
//
//   pf_connect --server 10.99.0.1:11940 --tls-crypt tc.key --ca ca.crt --cert c.crt --key c.key
//              [--timeout 30] [--probe-keys] [--keepalive-seconds N]
//
// --keepalive-seconds N: after the control channel is up, exchange OpenVPN keepalive pings over the DATA channel
//   (our DATA_V2 TX/RX blocks) for N seconds. Proves both key directions against the real server.
//
// Exit codes: 0 ok, 2 control channel failed, 3 probe/keepalive found nothing, 4 usage/config error.
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "pf/blocks/data_plane_blocks.h"
#include "pf/control_client.h"
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/data_v2.h"
#include "pf/flow.h"

using namespace pf;

namespace {

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

const char* state_name(ControlClient::State s) {
    switch (s) {
        case ControlClient::State::Idle: return "Idle";
        case ControlClient::State::ResetSent: return "ResetSent";
        case ControlClient::State::TlsHandshake: return "TlsHandshake";
        case ControlClient::State::KeyExchange: return "KeyExchange";
        case ControlClient::State::WaitPush: return "WaitPush";
        case ControlClient::State::Established: return "Established";
        case ControlClient::State::Failed: return "Failed";
    }
    return "?";
}

// Tries every (cipher key offset, nonce-tail offset) over the exported material against server->client
// DATA_V2 packets. A match means the GCM tag verified, which is unambiguous evidence for the layout.
int probe_layout(const ControlClient& c, const std::vector<std::vector<uint8_t>>& packets) {
    auto aead = make_openssl_aes256gcm();
    int found = 0;
    for (const bool empty_ctx : {false, true}) {
        std::vector<uint8_t> km(256);
        if (!c.export_ekm_for_probe(empty_ctx, km.data(), km.size())) continue;
        for (size_t k = 0; k + 32 <= km.size(); ++k) {
            for (size_t t = 0; t + 8 <= km.size(); ++t) {
                size_t ok = 0;
                for (const auto& pkt : packets) {
                    DataV2Packet d{};
                    if (parse_data_v2(pkt.data(), pkt.size(), d) != ParseStatus::Ok) continue;
                    uint8_t nonce[12];
                    std::memcpy(nonce, pkt.data() + 4, 4);
                    std::memcpy(nonce + 4, km.data() + t, 8);
                    std::vector<uint8_t> buf(pkt.begin() + kDataV2Overhead, pkt.end());
                    if (aead->decrypt(km.data() + k, nonce, pkt.data(), kDataV2AadLen, buf.data(), buf.size(), d.tag.data())) ++ok;
                }
                if (ok > 0) {
                    std::printf("LAYOUT_RX context=%s cipher_off=%zu tail_off=%zu verified=%zu/%zu\n",
                                empty_ctx ? "empty" : "none", k, t, ok, packets.size());
                    ++found;
                }
            }
        }
        for (auto& b : km) b = 0;
    }
    return found;
}

// OpenVPN's fixed 16-byte keepalive payload (observed in decrypted server pings, see tools/interop/verify_aead.py).
const uint8_t kPing[16] = {0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48};

struct DataPlane {
    BlockRegistry reg;
    Flow rx, tx;
    bool init() {
        if (!register_data_plane_blocks(reg)) return false;
        FlowBuilder r("rx");
        r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
         .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
        auto rr = r.build(reg);
        FlowBuilder t("tx");
        t.add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
        auto tt = t.build(reg);
        if (!rr.ok() || !tt.ok()) return false;
        rx = std::move(rr.flow);
        tx = std::move(tt.flow);
        return true;
    }
};

}  // namespace

int main(int argc, char** argv) {
    std::string server = "10.99.0.1:11940", tc, ca, cert, key;
    int timeout_s = 30, keepalive_s = 0;
    bool probe = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& dst) { if (i + 1 < argc) dst = argv[++i]; };
        if (a == "--server") next(server);
        else if (a == "--tls-crypt") next(tc);
        else if (a == "--ca") next(ca);
        else if (a == "--cert") next(cert);
        else if (a == "--key") next(key);
        else if (a == "--timeout" && i + 1 < argc) timeout_s = std::atoi(argv[++i]);
        else if (a == "--probe-keys") probe = true;
        else if (a == "--keepalive-seconds" && i + 1 < argc) keepalive_s = std::atoi(argv[++i]);
        else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 4; }
    }
    if (tc.empty() || ca.empty() || cert.empty() || key.empty()) { std::fprintf(stderr, "missing --tls-crypt/--ca/--cert/--key\n"); return 4; }

    ControlClientConfig cfg;
    std::string tc_text;
    if (!read_file(tc, tc_text) || !parse_static_key_file(tc_text, cfg.tls_crypt_key)) { std::fprintf(stderr, "bad tls-crypt key file\n"); return 4; }
    cfg.tls.role = TlsRole::Client;
    if (!read_file(ca, cfg.tls.ca_pem) || !read_file(cert, cfg.tls.cert_pem) || !read_file(key, cfg.tls.key_pem)) {
        std::fprintf(stderr, "cannot read ca/cert/key\n"); return 4;
    }
    KeyStore keys;
    cfg.keys = &keys;
    std::string err;
    auto client = ControlClient::create(std::move(cfg), err);
    if (!client) { std::fprintf(stderr, "config error: %s\n", err.c_str()); return 4; }

    const size_t colon = server.rfind(':');
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(std::atoi(server.substr(colon + 1).c_str())));
    if (colon == std::string::npos || inet_pton(AF_INET, server.substr(0, colon).c_str(), &addr.sin_addr) != 1) { std::fprintf(stderr, "bad --server\n"); return 4; }
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) { std::perror("socket/connect"); return 4; }

    const uint64_t t0 = now_ms();
    const uint64_t deadline = t0 + static_cast<uint64_t>(timeout_s) * 1000;
    ControlClient::State last = ControlClient::State::Idle;
    std::vector<std::vector<uint8_t>> data_packets;
    uint64_t established_at = 0;
    client->start(now_ms(), static_cast<uint32_t>(std::time(nullptr)));

    for (;;) {
        const uint64_t now = now_ms();
        const uint32_t unix_s = static_cast<uint32_t>(std::time(nullptr));
        for (const auto& d : client->poll(now, unix_s)) (void)send(fd, d.data(), d.size(), 0);

        if (client->state() != last) {
            last = client->state();
            std::printf("[%6llu ms] state=%s%s%s\n", static_cast<unsigned long long>(now - t0), state_name(last),
                        last == ControlClient::State::Failed ? " reason=" : "",
                        last == ControlClient::State::Failed ? client->failure_reason().c_str() : "");
            std::fflush(stdout);
            if (last == ControlClient::State::Established) established_at = now;
        }
        if (last == ControlClient::State::Failed) {
            const auto& st = client->stats();
            std::printf("stats: out=%u retx=%u auth_failed=%u replays=%u malformed=%u wrong_session=%u\n", st.datagrams_out, st.retransmits,
                        st.auth_failed, st.replays, st.malformed, st.wrong_session);
            return 2;
        }
        if (last == ControlClient::State::Established) {
            if (!probe && keepalive_s == 0) break;
            if (keepalive_s > 0 && !probe) break;                      // keepalive phase runs after the loop
            if (!probe) break;
            if (data_packets.size() >= 3 || now > established_at + 6000) break;
        }
        if (now > deadline) { std::printf("timeout (state=%s)\n", state_name(last)); return 2; }

        int wait_ms = 200;
        if (auto w = client->next_wakeup_ms()) wait_ms = static_cast<int>(std::min<uint64_t>(200, *w > now ? *w - now : 0));
        pollfd p{fd, POLLIN, 0};
        if (poll(&p, 1, wait_ms) > 0 && (p.revents & POLLIN)) {
            uint8_t buf[2048];
            const ssize_t n = recv(fd, buf, sizeof buf, 0);
            if (n > 0 && !client->on_datagram(buf, static_cast<size_t>(n), now_ms(), unix_s))
                data_packets.emplace_back(buf, buf + n);
        }
    }

    const PushReply& pr = client->push();
    std::printf("server_options: %s\n", client->server_options().c_str());
    for (const auto& w : client->warnings()) std::printf("warning: %s\n", w.c_str());
    std::printf("ignored_control_messages=%u\n", client->stats().ignored_control_messages);
    std::printf("push: ifconfig=%u.%u.%u.%u/%u.%u.%u.%u peer_id=%u cipher=%s ping=%u ping_restart=%u flags=", pr.ifconfig_ip >> 24, (pr.ifconfig_ip >> 16) & 255,
                (pr.ifconfig_ip >> 8) & 255, pr.ifconfig_ip & 255, pr.ifconfig_netmask >> 24, (pr.ifconfig_netmask >> 16) & 255, (pr.ifconfig_netmask >> 8) & 255,
                pr.ifconfig_netmask & 255, pr.peer_id, pr.cipher.c_str(), pr.ping_seconds, pr.ping_restart_seconds);
    for (const auto& f : pr.protocol_flags) std::printf("%s ", f.c_str());
    std::printf("\ncontrol channel ESTABLISHED\n");
    std::fflush(stdout);

    if (keepalive_s > 0) {
        DataPlane dp;
        auto aead = make_openssl_aes256gcm();
        if (!dp.init()) { std::fprintf(stderr, "data plane init failed\n"); return 4; }
        unsigned sent = 0, ok = 0, other = 0, bad = 0, tx_failed = 0;
        const uint64_t start = now_ms(), end = start + static_cast<uint64_t>(keepalive_s) * 1000;
        const uint64_t every = (pr.ping_seconds ? pr.ping_seconds : 2) * 1000ull;
        uint64_t next_ping = start;
        // Keep the control channel serviced (acks/retransmits) while the data channel runs.
        while (now_ms() < end) {
            const uint64_t t = now_ms();
            const uint32_t unix_s = static_cast<uint32_t>(std::time(nullptr));
            for (const auto& d : client->poll(t, unix_s)) (void)send(fd, d.data(), d.size(), 0);
            if (t >= next_ping) {
                PacketBuffer pkt = PacketBuffer::from_bytes(kPing, sizeof kPing);
                FlowContext ctx;
                ctx.packet = &pkt; ctx.keys = &keys; ctx.aead = aead.get();
                ctx.header = OvpnHeader{OvpnOpcode::DataV2, 0, pr.peer_id};
                ctx.header_valid = true;
                if (run_flow(dp.tx, ctx).outcome == FlowOutcome::Completed) {
                    (void)send(fd, pkt.data(), pkt.size(), 0);
                    ++sent;
                } else {
                    ++tx_failed;
                }
                next_ping = t + every;
            }
            pollfd p{fd, POLLIN, 0};
            if (poll(&p, 1, 100) > 0 && (p.revents & POLLIN)) {
                uint8_t buf[2048];
                const ssize_t n = recv(fd, buf, sizeof buf, 0);
                if (n <= 0 || client->on_datagram(buf, static_cast<size_t>(n), now_ms(), unix_s)) continue;
                PacketBuffer pkt = PacketBuffer::from_bytes(buf, static_cast<size_t>(n));
                FlowContext ctx;
                ctx.packet = &pkt; ctx.keys = &keys; ctx.aead = aead.get();
                const FlowResult r = run_flow(dp.rx, ctx);
                if (r.outcome != FlowOutcome::Completed) {
                    ++bad;                                              // failed authentication / replay / unknown key: a real problem
                    std::printf("data packet not accepted: %s\n", error_name(r.error));
                } else if (pkt.size() == sizeof kPing && std::memcmp(pkt.data(), kPing, sizeof kPing) == 0) {
                    ++ok;
                } else {
                    // Authenticated, but not a keepalive: some other data-channel message from the server (e.g. an OCC
                    // exchange). Not an error; recorded so it can be identified. Lab traffic only: print length and head.
                    ++other;
                    std::printf("data packet: authenticated non-ping payload len=%zu head=", pkt.size());
                    for (size_t i = 0; i < pkt.size() && i < 8; ++i) std::printf("%02x", pkt.data()[i]);
                    std::printf("\n");
                }
            }
            if (client->state() == ControlClient::State::Failed) { std::printf("control channel failed: %s\n", client->failure_reason().c_str()); return 2; }
        }
        std::printf("keepalive: sent=%u tx_failed=%u received_ok=%u received_other=%u received_bad=%u\n", sent, tx_failed, ok, other, bad);
        return (sent > 0 && ok > 0 && bad == 0 && tx_failed == 0) ? 0 : 3;
    }
    if (!probe) return 0;

    std::printf("data packets from server: %zu\n", data_packets.size());
    for (const auto& d : data_packets) std::printf("  len=%zu key_id=%u\n", d.size(), d[0] & 7);
    if (data_packets.empty()) { std::printf("NO_DATA_PACKETS\n"); return 3; }
    const int found = probe_layout(*client, data_packets);
    if (found == 0) { std::printf("NO_MATCH\n"); return 3; }
    return 0;
}
