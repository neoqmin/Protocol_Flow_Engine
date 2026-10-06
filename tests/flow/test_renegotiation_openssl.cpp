// Renegotiation (SOFT_RESET, key_id rotation) of ControlClient against the deterministic fake server. Needs OpenSSL.
#include <set>
#include "control_rig.h"
#include "pf/blocks/data_plane_blocks.h"
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/flow.h"

using namespace pf;
using namespace pf_test;

namespace {

ControlClientConfig reneg_client(uint32_t grace_ms = 5000) {
    ControlClientConfig c = client_cfg(nullptr);
    c.old_key_grace_ms = grace_ms;
    return c;
}

FakeServerConfig reneg_server(uint64_t after_ms) {
    FakeServerConfig s = server_cfg();
    s.reneg_after_ms = after_ms;
    return s;
}

void establish(Rig& r, Net& n) {
    r.client->start(n.now, n.unix_s);
    n.run(3000);
    PF_REQUIRE(r.client->state() == ControlClient::State::Established);
}

// Runs in small steps until `pred` or the budget is spent.
template <typename Pred> bool run_until(Net& n, Pred pred, uint64_t budget_ms, uint64_t step_ms = 100) {
    for (uint64_t t = 0; t < budget_ms; t += step_ms) {
        if (pred()) return true;
        n.run(step_ms, step_ms);
    }
    return pred();
}

// Encrypts `payload` the way the SERVER would with the given key_id, and lets the client's RX flow open it.
struct DataCheck {
    BlockRegistry reg;
    Flow rx, tx;
    std::unique_ptr<AeadProvider> aead = make_openssl_aes256gcm();
    DataCheck() {
        PF_REQUIRE(register_data_plane_blocks(reg));
        FlowBuilder r("rx");
        r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
         .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
        auto rr = r.build(reg); PF_REQUIRE(rr.ok()); rx = std::move(rr.flow);
        FlowBuilder t("tx");
        t.input(kFactOvpnHeader).add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
        auto tt = t.build(reg); PF_REQUIRE(tt.ok()); tx = std::move(tt.flow);
    }
    // server -> client
    bool server_sends_client_receives(FakeServer& srv, uint8_t key_id, KeyStore& client_keys, std::vector<uint8_t> payload) {
        auto it = srv.keys_by_id.find(key_id);
        if (it == srv.keys_by_id.end()) return false;
        KeyStore server_keys;
        const KeyRef tx_ref = server_keys.add(it->second.tx);
        server_keys.bind_tx(key_id, tx_ref);
        PacketBuffer pkt = PacketBuffer::from_bytes(payload.data(), payload.size());
        FlowContext sc; sc.packet = &pkt; sc.keys = &server_keys; sc.aead = aead.get();
        set_ovpn_header(sc, OvpnHeader{OvpnOpcode::DataV2, key_id, 7});
        if (run_flow(tx, sc).outcome != FlowOutcome::Completed) return false;
        FlowContext cc; cc.packet = &pkt; cc.keys = &client_keys; cc.aead = aead.get();
        if (run_flow(rx, cc).outcome != FlowOutcome::Completed) return false;
        return std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size()) == payload;
    }
    // client -> server: the client encrypts with its tx key for `key_id`; the server opens it with its rx key.
    bool client_sends_server_receives(FakeServer& srv, uint8_t key_id, KeyStore& client_keys, std::vector<uint8_t> payload) {
        auto it = srv.keys_by_id.find(key_id);
        if (it == srv.keys_by_id.end()) return false;
        PacketBuffer pkt = PacketBuffer::from_bytes(payload.data(), payload.size());
        FlowContext cc; cc.packet = &pkt; cc.keys = &client_keys; cc.aead = aead.get();
        set_ovpn_header(cc, OvpnHeader{OvpnOpcode::DataV2, key_id, 7});
        if (run_flow(tx, cc).outcome != FlowOutcome::Completed) return false;
        KeyStore server_keys;
        const KeyRef rx_ref = server_keys.add(it->second.rx);
        server_keys.bind_rx(key_id, rx_ref);
        FlowContext sc; sc.packet = &pkt; sc.keys = &server_keys; sc.aead = aead.get();
        if (run_flow(rx, sc).outcome != FlowOutcome::Completed) return false;
        return std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size()) == payload;
    }
};

}  // namespace

PF_TEST(reneg_server_initiated_installs_a_new_key_and_switches_tx) {
    Rig r(reneg_client(), reneg_server(10000)); Net n{*r.client, *r.server};
    establish(r, n);
    PF_CHECK_EQ(r.client->tx_key_id(), 0);
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().renegotiations == 1; }, 20000));
    PF_CHECK_EQ(r.client->tx_key_id(), 1);
    PF_CHECK_EQ(r.server->renegotiations_completed, 1u);
    PF_REQUIRE(r.keys.rx_for_key_id(1).valid());
    PF_REQUIRE(r.keys.tx_for_key_id(1).valid());
    const DataKey* tx = r.keys.get(r.keys.tx_for_key_id(1));
    const DataKey* rx = r.keys.get(r.keys.rx_for_key_id(1));
    PF_REQUIRE(tx != nullptr); PF_REQUIRE(rx != nullptr);
    const auto& sk = r.server->keys_by_id.at(1);
    PF_CHECK(tx->key == sk.rx.key && tx->nonce_tail == sk.rx.nonce_tail);    // client tx == server rx
    PF_CHECK(rx->key == sk.tx.key && rx->nonce_tail == sk.tx.nonce_tail);
    PF_CHECK(tx->key != r.keys.get(r.keys.tx_for_key_id(0))->key);          // a genuinely new key, not a reuse
}

PF_TEST(reneg_keeps_the_old_key_for_receiving_until_the_grace_period_ends) {
    Rig r(reneg_client(/*grace=*/5000), reneg_server(10000)); Net n{*r.client, *r.server};
    establish(r, n);
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().renegotiations == 1; }, 20000));
    n.run(1000);                                                            // several poll cycles after the switch
    PF_CHECK(r.keys.rx_for_key_id(0).valid());                              // still bound: peer packets in flight
    PF_CHECK(r.keys.rx_for_key_id(1).valid());
    DataCheck dc;
    PF_CHECK(dc.server_sends_client_receives(*r.server, 0, r.keys, {1, 2, 3}));         // old key still opens
    PF_CHECK(dc.server_sends_client_receives(*r.server, 1, r.keys, {4, 5, 6}));         // new key opens too
    n.run(6000);
    PF_CHECK(!r.keys.rx_for_key_id(0).valid());                             // retired and wiped
    PF_CHECK(!r.keys.tx_for_key_id(0).valid());
    PF_CHECK(r.keys.rx_for_key_id(1).valid());
    PF_CHECK(!dc.server_sends_client_receives(*r.server, 0, r.keys, {7}));              // old key no longer accepted
}

PF_TEST(reneg_keeps_at_most_one_old_key_even_when_the_grace_period_is_long) {
    Rig r(reneg_client(/*grace=*/60000), reneg_server(5000)); Net n{*r.client, *r.server};
    establish(r, n);
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().renegotiations >= 5; }, 120000, 500));
    PF_CHECK(r.keys.size() <= 4u);                                          // current + one retiring key (tx and rx each), never more
    PF_CHECK(r.keys.rx_for_key_id(r.client->tx_key_id()).valid());
}

PF_TEST(reneg_client_transmits_with_the_new_key_after_switching) {
    Rig r(reneg_client(), reneg_server(10000)); Net n{*r.client, *r.server};
    establish(r, n);
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().renegotiations == 1; }, 20000));
    DataCheck dc;
    PF_CHECK(dc.client_sends_server_receives(*r.server, r.client->tx_key_id(), r.keys, {9, 9, 9}));
}

PF_TEST(reneg_rotates_key_ids_through_the_wrap_from_7_back_to_1) {
    Rig r(reneg_client(/*grace=*/1000), reneg_server(5000)); Net n{*r.client, *r.server};
    establish(r, n);
    std::vector<int> seen{0};
    for (int i = 0; i < 1200 && r.client->stats().renegotiations < 10; ++i) {   // up to 120 s of simulated time
        n.run(100);
        if (r.client->tx_key_id() != seen.back()) seen.push_back(r.client->tx_key_id());
    }
    PF_REQUIRE(r.client->stats().renegotiations >= 10);
    PF_CHECK(seen.size() >= 10);
    for (size_t i = 1; i < seen.size(); ++i) PF_CHECK_EQ(seen[i], FakeServer::next_key_id(static_cast<uint8_t>(seen[i - 1])));
    PF_CHECK(std::find(seen.begin(), seen.end(), 7) != seen.end());
    PF_CHECK(std::count(seen.begin(), seen.end(), 1) >= 2);                  // 1 appears again after 7
    PF_CHECK_EQ(r.client->tx_key_id(), r.server->current_key_id());
    PF_CHECK(r.keys.size() <= 4u);                                           // no key leak: current + at most one retiring (tx+rx each)
    PF_CHECK_EQ(r.client->stats().auth_failed, 0u);
    PF_CHECK_EQ(r.client->stats().malformed, 0u);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
}

PF_TEST(reneg_client_initiated_when_the_server_does_not_start_one) {
    ControlClientConfig cc = reneg_client();
    cc.reneg_interval_ms = 8000;
    Rig r(cc, reneg_server(0)); Net n{*r.client, *r.server};
    establish(r, n);
    PF_CHECK(r.client->next_wakeup_ms().has_value());
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().renegotiations == 1; }, 20000));
    PF_CHECK_EQ(r.client->tx_key_id(), 1);
    PF_CHECK_EQ(r.server->renegotiations_completed, 1u);
    DataCheck dc;
    PF_CHECK(dc.client_sends_server_receives(*r.server, 1, r.keys, {1, 2}));
    PF_CHECK(dc.server_sends_client_receives(*r.server, 1, r.keys, {3, 4}));
}

PF_TEST(reneg_completes_despite_lost_datagrams) {
    Rig r(reneg_client(), reneg_server(6000)); Net n{*r.client, *r.server};
    establish(r, n);
    const size_t base_s = n.to_server_idx, base_c = n.to_client_idx;
    n.fate = [&](bool to_server, size_t i) { return (i - (to_server ? base_s : base_c)) < 3 ? 0 : 1; };   // lose the first 3 each way
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().renegotiations == 1; }, 60000));
    PF_CHECK_EQ(r.client->tx_key_id(), 1);
}

PF_TEST(reneg_abandoned_when_the_server_goes_silent_and_the_old_key_keeps_working) {
    ControlClientConfig cc = reneg_client();
    cc.reneg_timeout_ms = 10000;
    FakeServerConfig sc = reneg_server(5000);
    sc.reneg_silent = true;
    Rig r(cc, sc); Net n{*r.client, *r.server};
    establish(r, n);
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().reneg_failures >= 1; }, 60000));
    PF_CHECK(r.client->state() == ControlClient::State::Established);        // the tunnel survives a failed rekey
    PF_CHECK_EQ(r.client->tx_key_id(), 0);
    PF_CHECK(r.keys.rx_for_key_id(0).valid());
    PF_CHECK(!r.keys.rx_for_key_id(1).valid());
    PF_CHECK_EQ(r.client->stats().renegotiations, 0u);
    DataCheck dc;
    PF_CHECK(dc.client_sends_server_receives(*r.server, 0, r.keys, {1}));
}

PF_TEST(reneg_with_a_bad_key_method_reply_fails_without_switching_keys) {
    FakeServerConfig sc = reneg_server(5000);
    sc.reneg_corrupt_km = true;
    Rig r(reneg_client(), sc); Net n{*r.client, *r.server};
    establish(r, n);
    PF_REQUIRE(run_until(n, [&] { return r.client->stats().reneg_failures >= 1; }, 60000));
    PF_CHECK(r.client->state() == ControlClient::State::Established);
    PF_CHECK_EQ(r.client->tx_key_id(), 0);
    PF_CHECK(!r.keys.tx_for_key_id(1).valid());                              // nothing half-installed
    PF_CHECK(!r.keys.rx_for_key_id(1).valid());
}

PF_TEST(reneg_ignores_a_soft_reset_for_an_unexpected_key_id) {
    Rig r(reneg_client(), reneg_server(0)); Net n{*r.client, *r.server};
    establish(r, n);
    TlsCryptChannel peer(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    peer.set_next_packet_id_for_test(500);
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlSoftResetV1);
    p.key_id = 5;                                                            // next key_id would be 1
    p.session_id = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
    p.has_message = true; p.message_id = 0;
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(peer, p, n.unix_s, dg));
    PF_CHECK(r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
    PF_CHECK(r.client->stats().unknown_key_id > 0);
    PF_CHECK_EQ(r.client->stats().renegotiations, 0u);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
    n.run(3000);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
    PF_CHECK_EQ(r.client->tx_key_id(), 0);
}

PF_TEST(reneg_does_not_start_before_the_session_is_established) {
    Rig r(reneg_client(), reneg_server(0)); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(10);                                                               // handshake not finished yet
    PF_REQUIRE(r.client->state() != ControlClient::State::Established);
    TlsCryptChannel peer(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    peer.set_next_packet_id_for_test(12);                                    // inside the replay window: must not lock out the real server
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlSoftResetV1);
    p.key_id = 1; p.session_id = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
    p.has_message = true; p.message_id = 0;
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(peer, p, n.unix_s, dg));
    r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s);
    PF_CHECK_EQ(r.client->stats().renegotiations, 0u);
    n.run(3000);
    PF_CHECK(r.client->state() == ControlClient::State::Established);        // the real handshake still completes
    PF_CHECK_EQ(r.client->tx_key_id(), 0);
}
