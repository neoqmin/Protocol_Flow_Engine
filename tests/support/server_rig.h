// ControlClient <-> ControlServer in memory (PM-11 V1): both sans-I/O peers, an in-memory network with
// drop/duplicate/reorder hooks, separate KeyStores, and a data check that encrypts with one side's installed keys
// and decrypts with the other's real RX Flow. Needs OpenSSL.
#pragma once
#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "control_rig.h"
#include "pf/blocks/data_plane_blocks.h"
#include "pf/control_server.h"
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/flow.h"

namespace pf_test {

inline ControlServerConfig control_server_cfg(uint8_t seed = 1) {
    ControlServerConfig s;
    s.tls_crypt_key = key(seed);
    s.tls.role = TlsRole::Server;
    s.tls.ca_pem = pki().ca_pem; s.tls.cert_pem = pki().server_cert_pem; s.tls.key_pem = pki().server_key_pem;
    s.push.ifconfig_ip = 0x0A080002; s.push.ifconfig_netmask = 0xFFFFFF00; s.push.route_gateway = 0x0A080001;
    s.push.peer_id = 5; s.push.ping_seconds = 10; s.push.ping_restart_seconds = 60;
    return s;
}

struct ServerNet {
    ServerNet(ControlClient& client, ControlServer& server) : c(client), s(server) {}
    ControlClient& c;
    ControlServer& s;
    uint64_t now = 1000;
    uint32_t unix_s = 1790000000;
    std::function<int(bool to_server, size_t index)> fate = [](bool, size_t) { return 1; };   // copies: 0 drop, 2 duplicate
    bool reverse_flights = false;
    size_t to_server_idx = 0, to_client_idx = 0;
    std::vector<std::vector<uint8_t>> client_sent;     // every datagram the client produced (for replay tests)

    void to_server(std::vector<std::vector<uint8_t>> dgs) {
        if (reverse_flights) std::reverse(dgs.begin(), dgs.end());
        for (auto& d : dgs) {
            client_sent.push_back(d);
            const int copies = fate(true, to_server_idx++);
            for (int i = 0; i < copies; ++i) s.on_datagram(d.data(), d.size(), now, unix_s);
        }
    }
    void to_client(std::vector<std::vector<uint8_t>> dgs) {
        if (reverse_flights) std::reverse(dgs.begin(), dgs.end());
        for (auto& d : dgs) {
            const int copies = fate(false, to_client_idx++);
            for (int i = 0; i < copies; ++i) c.on_datagram(d.data(), d.size(), now, unix_s);
        }
    }
    void step() {
        to_server(c.poll(now, unix_s));
        to_client(s.poll(now, unix_s));
    }
    void run(uint64_t duration_ms, uint64_t step_ms = 100) {
        const uint64_t end = now + duration_ms;
        while (now < end) { step(); now += step_ms; }
    }
    template <typename Pred> bool run_until(Pred pred, uint64_t budget_ms, uint64_t step_ms = 100) {
        for (uint64_t t = 0; t < budget_ms; t += step_ms) {
            if (pred()) return true;
            run(step_ms, step_ms);
        }
        return pred();
    }
};

struct ServerRig {
    KeyStore client_keys, server_keys;      // declared first: they outlive the peers that hold KeyRefs into them
    DeterministicRandom random{42};
    std::unique_ptr<ControlClient> client;
    std::unique_ptr<ControlServer> server;
    ServerRig(ControlClientConfig cc, ControlServerConfig sc) {
        cc.keys = &client_keys;
        sc.keys = &server_keys;
        if (sc.random == nullptr) sc.random = &random;
        std::string err;
        client = ControlClient::create(std::move(cc), err);
        PF_REQUIRE(client != nullptr);
        server = ControlServer::create(std::move(sc), err);
        PF_REQUIRE(server != nullptr);
    }
    ServerRig() : ServerRig(client_cfg(nullptr), control_server_cfg()) {}
};

// Encrypts with `from`'s TX key for key_id and opens it with `to`'s RX key through the real data-plane Flows.
struct DataPathCheck {
    BlockRegistry reg;
    Flow rx, tx;
    std::unique_ptr<AeadProvider> aead = make_openssl_aes256gcm();
    DataPathCheck() {
        PF_REQUIRE(register_data_plane_blocks(reg));
        FlowBuilder r("rx");
        r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
         .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
        auto rr = r.build(reg); PF_REQUIRE(rr.ok()); rx = std::move(rr.flow);
        FlowBuilder t("tx");
        t.input(kFactOvpnHeader).add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
        auto tt = t.build(reg); PF_REQUIRE(tt.ok()); tx = std::move(tt.flow);
    }
    bool carries(KeyStore& from, KeyStore& to, uint8_t key_id, uint32_t peer_id, const std::vector<uint8_t>& payload) {
        PacketBuffer pkt = PacketBuffer::from_bytes(payload.data(), payload.size());
        FlowContext a; a.packet = &pkt; a.keys = &from; a.aead = aead.get();
        set_ovpn_header(a, OvpnHeader{OvpnOpcode::DataV2, key_id, peer_id});
        if (run_flow(tx, a).outcome != FlowOutcome::Completed) return false;
        FlowContext b; b.packet = &pkt; b.keys = &to; b.aead = aead.get();
        if (run_flow(rx, b).outcome != FlowOutcome::Completed) return false;
        return std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size()) == payload;
    }
};

}  // namespace pf_test
