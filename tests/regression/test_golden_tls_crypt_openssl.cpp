// Replays tls-crypt golden vectors captured from unmodified OpenVPN 2.6.19. Requires OpenSSL.
#include <fstream>
#include <memory>
#include <sstream>
#include "pf/crypto/tls_crypt.h"
#include "pf_test.h"

using namespace pf;

static std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t\r");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
namespace { struct TlsVec { bool c2s; std::array<uint8_t, kTlsCryptStaticKeyLen> key; std::vector<uint8_t> wire, plain; int line; }; }  // namespace (avoid ODR clash with other test files)

static std::vector<TlsVec> load() {
    std::vector<TlsVec> out;
    std::ifstream f(std::string(GOLDEN_DIR) + "/tls_crypt.golden");
    PF_REQUIRE(f.good());
    std::string line; int n = 0;
    while (std::getline(f, line)) {
        ++n;
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c; std::stringstream ss(line); std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(trim(cell));
        PF_REQUIRE(c.size() == 4);
        TlsVec v; v.c2s = (c[0] == "c2s"); v.line = n;
        auto k = unhex(c[1]); PF_REQUIRE(k.size() == kTlsCryptStaticKeyLen);
        std::copy(k.begin(), k.end(), v.key.begin());
        v.wire = unhex(c[2]); v.plain = unhex(c[3]);
        out.push_back(std::move(v));
    }
    return out;
}

PF_TEST(golden_tls_crypt_open_with_role_derived_keys) {
    auto vecs = load();
    PF_CHECK(vecs.size() >= 10);
    for (auto& v : vecs) {
        // The receiver of a c2s packet is the server and vice versa.
        TlsCryptKeys rx = derive_tls_crypt_keys(v.key, v.c2s ? TlsCryptRole::Server : TlsCryptRole::Client);
        TlsCryptPlain out;
        auto st = tls_crypt_open(rx.rx, v.wire.data(), v.wire.size(), out);
        if (st != TlsCryptStatus::Ok) pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": open failed");
        else if (out.payload != v.plain) pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": plaintext mismatch");
    }
}

PF_TEST(golden_tls_crypt_reseal_reproduces_wire_bytes) {
    // seal() is deterministic for fixed (keys, header, packet_id, time, plaintext): it must match OpenVPN's exact bytes.
    auto vecs = load();
    for (auto& v : vecs) {
        TlsCryptKeys tx = derive_tls_crypt_keys(v.key, v.c2s ? TlsCryptRole::Client : TlsCryptRole::Server);
        TlsCryptPlain p;
        TlsCryptKeys rx = derive_tls_crypt_keys(v.key, v.c2s ? TlsCryptRole::Server : TlsCryptRole::Client);
        PF_REQUIRE(tls_crypt_open(rx.rx, v.wire.data(), v.wire.size(), p) == TlsCryptStatus::Ok);
        std::vector<uint8_t> again;
        PF_REQUIRE(tls_crypt_seal(tx.tx, p.op_keyid, p.session_id, p.packet_id, p.net_time, p.payload.data(), p.payload.size(), again));
        if (again != v.wire) pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": re-sealed bytes differ");
    }
}

PF_TEST(golden_tls_crypt_wrong_direction_keys_fail) {
    auto vecs = load();
    PF_REQUIRE(!vecs.empty());
    auto& v = vecs[0];
    TlsCryptKeys same = derive_tls_crypt_keys(v.key, v.c2s ? TlsCryptRole::Client : TlsCryptRole::Server);   // sender's own role
    TlsCryptPlain out;
    PF_CHECK(tls_crypt_open(same.rx, v.wire.data(), v.wire.size(), out) == TlsCryptStatus::AuthFailed);
}

PF_TEST(golden_tls_crypt_stateful_channel_accepts_capture_order_and_rejects_replays) {
    auto vecs = load();
    // One channel per direction receiver, fed in capture order (increasing packet-ids per sender).
    std::unique_ptr<TlsCryptChannel> srv, cli;
    for (auto& v : vecs) {
        auto& ch = v.c2s ? srv : cli;
        if (!ch) ch = std::make_unique<TlsCryptChannel>(derive_tls_crypt_keys(v.key, v.c2s ? TlsCryptRole::Server : TlsCryptRole::Client));
        TlsCryptPlain out;
        if (ch->unwrap(v.wire.data(), v.wire.size(), out) != TlsCryptStatus::Ok)
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": channel rejected a genuine packet");
        if (ch->unwrap(v.wire.data(), v.wire.size(), out) != TlsCryptStatus::Replay)
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": replay not detected");
    }
}
