// libFuzzer: the server receive path (PM-11 V2, D-049). The input is a script of datagrams from a few addresses:
// raw bytes, control packets sealed with the real tls-crypt key around fuzzer-chosen plaintext, and packets that echo
// the last cookie the server sent to that address - so the fuzzer reaches session adoption and the per-session
// ControlServer, not just the HMAC check. Invariants: limits hold, and nothing crashes or leaks (ASan/UBSan).
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "pf/crypto/control_wire.h"
#include "pf/server_core.h"
#include "test_pki.h"

namespace {

std::array<uint8_t, pf::kTlsCryptStaticKeyLen> static_key() {
    std::array<uint8_t, pf::kTlsCryptStaticKeyLen> k{};
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(i * 13 + 7);
    return k;
}

const pf_test::TestPki& pki() { static pf_test::TestPki p = pf_test::make_test_pki(); return p; }

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pf::DeterministicRandom rnd(size);
    pf::ServerCoreConfig cfg;
    cfg.session.tls_crypt_key = static_key();
    cfg.session.tls.role = pf::TlsRole::Server;
    cfg.session.tls.ca_pem = pki().ca_pem;
    cfg.session.tls.cert_pem = pki().server_cert_pem;
    cfg.session.tls.key_pem = pki().server_key_pem;
    cfg.session.hand_window_ms = 5000;
    cfg.max_clients = 3;
    cfg.max_sessions_per_ip = 2;
    cfg.new_session_burst = 4;
    cfg.random = &rnd;
    cfg.prepare_push = [](uint32_t pid, pf::ServerPush& p) {
        p.ifconfig_ip = 0x0A080002 + pid; p.ifconfig_netmask = 0xFFFFFF00; p.route_gateway = 0x0A080001;
        return true;
    };
    std::string err;
    auto core = pf::ServerCore::create(cfg, err);
    if (!core) __builtin_trap();
    pf::TlsCryptChannel as_client(pf::derive_tls_crypt_keys(static_key(), pf::TlsCryptRole::Client));
    const pf::TlsCryptKeys client_keys = pf::derive_tls_crypt_keys(static_key(), pf::TlsCryptRole::Client);   // reads replies
    std::map<uint8_t, std::array<uint8_t, 8>> last_cookie, last_client_sid;

    uint64_t now = 1000;
    uint32_t unix_s = 1790000000;
    size_t pos = 0;
    while (pos + 3 <= size) {
        const uint8_t host = data[pos] & 3, mode = data[pos + 1] % 4;
        const size_t len = std::min<size_t>(data[pos + 2], size - pos - 3);
        const uint8_t* body = data + pos + 3;
        pos += 3 + len;
        const pf::NetAddress from = pf::NetAddress::v4(0xC6336400u + (host >> 1), static_cast<uint16_t>(1000 + (host & 1)));
        std::vector<uint8_t> dg;
        if (mode == 0) {
            dg.assign(body, body + len);
        } else if (mode == 3) {
            now += 50u * (len + 1);
            if (len & 1) ++unix_s;
            for (auto& o : core->poll(now, unix_s)) (void)o;
            continue;
        } else {
            pf::ControlPacket p;
            if (len < 1) continue;
            p.opcode = static_cast<uint8_t>(3 + body[0] % 3 + (body[0] & 0x80 ? 4 : 0));   // 3,4,5 or 7,8,9
            p.key_id = static_cast<uint8_t>((body[0] >> 3) & 7);
            std::array<uint8_t, 8> sid{};
            for (size_t i = 0; i < 8 && 1 + i < len; ++i) sid[i] = body[1 + i];
            if (mode == 2 && last_client_sid.count(host)) sid = last_client_sid[host];
            p.session_id = sid;
            last_client_sid[host] = sid;
            if (mode == 2 && last_cookie.count(host)) { p.acks = {0}; p.remote_session_id = last_cookie[host]; }
            if (p.opcode != 5 && len > 9) { p.has_message = true; p.message_id = body[9] % 4; }
            if (len > 10 && p.has_message) p.payload.assign(body + 10, body + len);
            if (!pf::seal_control_packet(as_client, p, unix_s, dg)) continue;
        }
        std::vector<pf::ServerCore::Outgoing> out;
        (void)core->on_datagram(dg.data(), dg.size(), from, now, unix_s, out);
        for (const auto& o : out) {                            // remember cookies sent to each address
            pf::TlsCryptPlain plain;
            pf::ControlPacket r;
            if (pf::tls_crypt_open(client_keys.rx, o.bytes.data(), o.bytes.size(), plain) == pf::TlsCryptStatus::Ok &&
                pf::parse_control(plain.op_keyid, plain.session_id, plain.payload.data(), plain.payload.size(), r) == pf::ControlParseStatus::Ok &&
                r.opcode == static_cast<uint8_t>(pf::OvpnOpcode::ControlHardResetServerV2))
                for (uint8_t h = 0; h < 4; ++h)
                    if (pf::NetAddress::v4(0xC6336400u + (h >> 1), static_cast<uint16_t>(1000 + (h & 1))) == o.to) last_cookie[h] = r.session_id;
        }
        if (core->session_count() > cfg.max_clients) __builtin_trap();
        for (auto& a : core->take_auth_requests()) core->resolve_auth(a.session, a.request.username.empty());
        (void)core->take_events();
    }
    return 0;
}
