// Shared harness for ControlClient tests: PKI, keys, configs, an in-memory network between the sans-I/O client and the
// deterministic fake server (with drop/duplicate/reverse hooks), and a Rig bundling client + server + KeyStore.
#pragma once
#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "fake_ovpn_server.h"
#include "pf/control_client.h"
#include "pf_test.h"
#include "test_pki.h"

namespace pf_test {

using namespace pf;


inline const TestPki& pki() { static TestPki p = make_test_pki(); return p; }

inline std::array<uint8_t, kTlsCryptStaticKeyLen> key(uint8_t seed) {
    std::array<uint8_t, kTlsCryptStaticKeyLen> k{};
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed * 7 + i * 13 + (i >> 3));
    return k;
}

inline ControlClientConfig client_cfg(KeyStore* ks, uint8_t seed = 1) {
    ControlClientConfig c;
    c.tls_crypt_key = key(seed);
    c.tls.role = TlsRole::Client;
    c.tls.ca_pem = pki().ca_pem; c.tls.cert_pem = pki().client_cert_pem; c.tls.key_pem = pki().client_key_pem;
    c.keys = ks;
    uint8_t ctr = 0;
    c.random = [ctr](uint8_t* p, size_t n) mutable { for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(++ctr * 29 + 3); };
    return c;
}

inline FakeServerConfig server_cfg(uint8_t seed = 1) {
    FakeServerConfig s;
    s.static_key = key(seed);
    s.tls.role = TlsRole::Server;
    s.tls.ca_pem = pki().ca_pem; s.tls.cert_pem = pki().server_cert_pem; s.tls.key_pem = pki().server_key_pem;
    return s;
}

// Connects the two sans-I/O peers with an in-memory "network" that can drop/duplicate/reorder datagrams.
struct Net {
    ControlClient& c;
    FakeServer& s;
    uint64_t now = 1000;
    uint32_t unix_s = 1790000000;
    std::function<int(bool to_server, size_t index)> fate = [](bool, size_t) { return 1; };   // copies delivered: 0 drop, 2 duplicate
    size_t to_server_idx = 0, to_client_idx = 0;
    size_t sent_by_client = 0, sent_by_server = 0;
    bool reverse_server_flights = false;

    void deliver_to_server(const std::vector<std::vector<uint8_t>>& dgs) {
        for (auto& d : dgs) {
            ++sent_by_client;
            const int copies = fate(true, to_server_idx++);
            for (int i = 0; i < copies; ++i) {
                auto back = s.on_datagram(d.data(), d.size(), now, unix_s);
                deliver_to_client(back);
            }
        }
    }
    void deliver_to_client(std::vector<std::vector<uint8_t>> dgs) {
        if (reverse_server_flights) std::reverse(dgs.begin(), dgs.end());
        for (auto& d : dgs) {
            ++sent_by_server;
            const int copies = fate(false, to_client_idx++);
            for (int i = 0; i < copies; ++i) c.on_datagram(d.data(), d.size(), now, unix_s);
        }
    }
    void run(uint64_t duration_ms, uint64_t step_ms = 100) {
        const uint64_t end = now + duration_ms;
        while (now < end) {
            deliver_to_server(c.poll(now, unix_s));
            deliver_to_client(s.poll(now, unix_s));
            now += step_ms;
        }
    }
};

struct Rig {
    KeyStore keys;
    std::unique_ptr<ControlClient> client;
    std::unique_ptr<FakeServer> server;
    Rig(ControlClientConfig cc, FakeServerConfig sc) {
        cc.keys = &keys;
        std::string err;
        client = ControlClient::create(std::move(cc), err);
        PF_REQUIRE(client != nullptr);
        server = std::make_unique<FakeServer>(std::move(sc));
    }
    Rig() : Rig(client_cfg(nullptr), server_cfg()) {}
};


}  // namespace pf_test
