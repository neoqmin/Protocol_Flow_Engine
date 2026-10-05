// ControlClient against a deterministic fake server (hermetic). Needs OpenSSL.
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "pf/control_client.h"
#include "pf_test.h"
#include "fake_ovpn_server.h"
#include "test_pki.h"

using namespace pf;

namespace {

const pf_test::TestPki& pki() { static pf_test::TestPki p = pf_test::make_test_pki(); return p; }

std::array<uint8_t, kTlsCryptStaticKeyLen> key(uint8_t seed) {
    std::array<uint8_t, kTlsCryptStaticKeyLen> k{};
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed * 7 + i * 13 + (i >> 3));
    return k;
}

ControlClientConfig client_cfg(KeyStore* ks, uint8_t seed = 1) {
    ControlClientConfig c;
    c.tls_crypt_key = key(seed);
    c.tls.role = TlsRole::Client;
    c.tls.ca_pem = pki().ca_pem; c.tls.cert_pem = pki().client_cert_pem; c.tls.key_pem = pki().client_key_pem;
    c.keys = ks;
    uint8_t ctr = 0;
    c.random = [ctr](uint8_t* p, size_t n) mutable { for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(++ctr * 29 + 3); };
    return c;
}

pf_test::FakeServerConfig server_cfg(uint8_t seed = 1) {
    pf_test::FakeServerConfig s;
    s.static_key = key(seed);
    s.tls.role = TlsRole::Server;
    s.tls.ca_pem = pki().ca_pem; s.tls.cert_pem = pki().server_cert_pem; s.tls.key_pem = pki().server_key_pem;
    return s;
}

// Connects the two sans-I/O peers with an in-memory "network" that can drop/duplicate/reorder datagrams.
struct Net {
    ControlClient& c;
    pf_test::FakeServer& s;
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
    std::unique_ptr<pf_test::FakeServer> server;
    Rig(ControlClientConfig cc, pf_test::FakeServerConfig sc) {
        cc.keys = &keys;
        std::string err;
        client = ControlClient::create(std::move(cc), err);
        PF_REQUIRE(client != nullptr);
        server = std::make_unique<pf_test::FakeServer>(std::move(sc));
    }
    Rig() : Rig(client_cfg(nullptr), server_cfg()) {}
};

}  // namespace

PF_TEST(client_completes_handshake_and_installs_matching_data_keys) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(5000);
    PF_REQUIRE(r.client->state() == ControlClient::State::Established);
    PF_CHECK(r.client->push().supported_by_mvp());
    PF_CHECK_EQ(r.client->push().peer_id, 7u);
    PF_REQUIRE(r.server->keys_derived);
    // Keys landed in the KeyStore, bound to key_id 0 for both directions, and mirror the server's.
    const DataKey* tx = r.keys.get(r.keys.tx_for_key_id(0));
    const DataKey* rx = r.keys.get(r.keys.rx_for_key_id(0));
    PF_REQUIRE(tx != nullptr); PF_REQUIRE(rx != nullptr);
    PF_CHECK(tx->key == r.server->rx_key.key && tx->nonce_tail == r.server->rx_key.nonce_tail);
    PF_CHECK(rx->key == r.server->tx_key.key && rx->nonce_tail == r.server->tx_key.nonce_tail);
    PF_CHECK(tx->key != rx->key);
    PF_CHECK_EQ(r.client->stats().ignored_control_messages, 0u);     // the key-method reply was consumed exactly
}

PF_TEST(client_sends_documented_key_method_2_with_mvp_profile_values) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(5000);
    PF_REQUIRE(r.server->got_key_method);
    PF_CHECK(r.server->client_options ==
             "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client");
    PF_CHECK(r.server->client_peer_info.find("IV_PROTO=14\n") != std::string::npos);      // DATA_V2|REQUEST_PUSH|TLS_KEY_EXPORT
    PF_CHECK(r.server->client_peer_info.find("IV_CIPHERS=AES-256-GCM\n") != std::string::npos);
    PF_CHECK(r.server->client_peer_info.find("IV_PROTO=990") == std::string::npos);       // never claims dyn-tls-crypt/cc-exit
    PF_CHECK(!r.server->got_push_request);                                                // server pushes by itself
}

PF_TEST(client_recovers_from_lost_datagrams_by_retransmitting) {
    Rig r; Net n{*r.client, *r.server};
    n.fate = [](bool to_server, size_t i) { return (to_server && i < 2) ? 0 : (!to_server && i < 1) ? 0 : 1; };   // lose first two of ours, first of theirs
    r.client->start(n.now, n.unix_s);
    n.run(40000);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
    PF_CHECK(r.client->stats().retransmits > 0);
}

PF_TEST(client_ignores_duplicated_and_replayed_datagrams) {
    Rig r; Net n{*r.client, *r.server};
    n.fate = [](bool, size_t) { return 2; };                       // every datagram arrives twice
    r.client->start(n.now, n.unix_s);
    n.run(5000);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
    PF_CHECK(r.client->stats().replays > 0);
    PF_CHECK(r.server->replays > 0);
}

PF_TEST(client_reassembles_a_server_flight_delivered_in_reverse_order) {
    Rig r; Net n{*r.client, *r.server};
    n.reverse_server_flights = true;
    r.client->start(n.now, n.unix_s);
    n.run(20000);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
}

PF_TEST(client_splits_large_tls_flights_into_bounded_control_messages) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.max_payload = 120;                                          // force many small messages
    Rig r(cc, server_cfg()); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(30000);
    PF_REQUIRE(r.client->state() == ControlClient::State::Established);
    PF_REQUIRE(!r.server->control_payload_sizes.empty());
    size_t biggest = 0, count = 0;
    for (size_t s : r.server->control_payload_sizes) { biggest = std::max(biggest, s); ++count; }
    PF_CHECK(biggest <= 120);
    PF_CHECK(count > 5);
}

PF_TEST(client_with_wrong_tls_crypt_key_never_connects_and_gives_up) {
    Rig r(client_cfg(nullptr, /*seed=*/1), server_cfg(/*seed=*/2));
    Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(120000, 500);
    PF_CHECK(r.client->state() == ControlClient::State::Failed);
    PF_CHECK(r.client->failure_reason().find("timeout") != std::string::npos);
    PF_CHECK(r.server->auth_failed > 0);
    PF_CHECK(!r.keys.rx_for_key_id(0).valid());
}

PF_TEST(client_rejects_a_server_with_an_untrusted_certificate) {
    pf_test::FakeServerConfig sc = server_cfg();
    sc.tls.cert_pem = pki().other_server_cert_pem; sc.tls.key_pem = pki().other_server_key_pem;
    Rig r(client_cfg(nullptr), sc); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(10000);
    PF_CHECK(r.client->state() == ControlClient::State::Failed);
    PF_CHECK(r.client->failure_reason().find("TLS") != std::string::npos);
}

PF_TEST(client_fails_on_unsupported_push_and_installs_no_keys) {
    pf_test::FakeServerConfig sc = server_cfg();
    sc.push_reply = "PUSH_REPLY,ifconfig 10.77.0.2 255.255.255.0,peer-id 7,cipher AES-128-GCM,protocol-flags tls-ekm";
    Rig r(client_cfg(nullptr), sc); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(10000);
    PF_CHECK(r.client->state() == ControlClient::State::Failed);
    PF_CHECK(r.client->failure_reason().find("push") != std::string::npos);
    PF_CHECK(!r.keys.rx_for_key_id(0).valid());
    PF_CHECK(!r.keys.tx_for_key_id(0).valid());
}

PF_TEST(client_fails_on_auth_failed_message) {
    pf_test::FakeServerConfig sc = server_cfg();
    sc.send_instead_of_push = "AUTH_FAILED,denied";
    Rig r(client_cfg(nullptr), sc); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(10000);
    PF_CHECK(r.client->state() == ControlClient::State::Failed);
    PF_CHECK(r.client->failure_reason().find("AUTH_FAILED") != std::string::npos);
}

PF_TEST(client_asks_for_the_push_when_the_server_does_not_volunteer_it) {
    pf_test::FakeServerConfig sc = server_cfg();
    sc.push_without_request = false;                               // server waits for PUSH_REQUEST
    Rig r(client_cfg(nullptr), sc); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(1500);
    PF_CHECK(r.client->state() == ControlClient::State::WaitPush);  // still waiting before the delay passes
    PF_CHECK(!r.server->got_push_request);
    n.run(10000);
    PF_CHECK(r.server->got_push_request);
    PF_CHECK(r.client->state() == ControlClient::State::Established);
}

PF_TEST(client_without_any_push_reply_times_out_in_wait_push) {
    pf_test::FakeServerConfig sc = server_cfg();
    sc.send_push = false;
    ControlClientConfig cc = client_cfg(nullptr); cc.push_timeout_ms = 8000;
    Rig r(cc, sc); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(20000);
    PF_CHECK(r.client->state() == ControlClient::State::Failed);
    PF_CHECK(r.client->failure_reason().find("PUSH_REPLY") != std::string::npos);
}

PF_TEST(client_ignores_datagrams_with_a_wrong_remote_session_id) {
    Rig r; Net n{*r.client, *r.server};
    // A peer that holds the tls-crypt key but answers some OTHER session: its reset names a session that is not ours.
    r.client->start(n.now, n.unix_s);
    (void)r.client->poll(n.now, n.unix_s);                          // our reset goes nowhere: no real server answers
    TlsCryptChannel stranger(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlHardResetServerV2);
    p.session_id = {9, 9, 9, 9, 9, 9, 9, 9}; p.acks = {0}; p.remote_session_id = {1, 2, 3, 4, 5, 6, 7, 8};   // does not ack OUR session
    p.has_message = true; p.message_id = 0;
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(stranger, p, n.unix_s, dg));
    PF_CHECK(r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
    PF_CHECK(r.client->stats().wrong_session > 0);
    PF_CHECK(r.client->state() == ControlClient::State::ResetSent);
}

PF_TEST(client_accepts_a_reset_retransmission_that_carries_no_ack) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    (void)r.client->poll(n.now, n.unix_s);
    // Build the server's reset by hand, without acks, the way a retransmission looks after its ack was already used.
    TlsCryptChannel srv(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlHardResetServerV2);
    p.session_id = {5, 5, 5, 5, 5, 5, 5, 5}; p.has_message = true; p.message_id = 0;
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(srv, p, n.unix_s, dg));
    PF_CHECK(r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
    PF_CHECK(r.client->stats().wrong_session == 0);
    PF_CHECK(r.client->state() == ControlClient::State::TlsHandshake);
}

PF_TEST(client_rejects_a_first_packet_that_is_not_a_reset_message_zero) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    (void)r.client->poll(n.now, n.unix_s);
    TlsCryptChannel srv(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlV1);               // data before any reset
    p.session_id = {5, 5, 5, 5, 5, 5, 5, 5}; p.has_message = true; p.message_id = 0; p.payload = {1, 2, 3};
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(srv, p, n.unix_s, dg));
    PF_CHECK(r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
    PF_CHECK(r.client->stats().wrong_session > 0);
    PF_CHECK(r.client->state() == ControlClient::State::ResetSent);
    ControlPacket q = p; q.opcode = static_cast<uint8_t>(OvpnOpcode::ControlHardResetServerV2); q.message_id = 3;   // reset with a later id
    PF_REQUIRE(seal_control_packet(srv, q, n.unix_s, dg));
    r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s);
    PF_CHECK(r.client->state() == ControlClient::State::ResetSent);
}

PF_TEST(client_ignores_control_packets_from_another_session_after_binding_to_the_server) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(100);                                                     // client is now bound to the real server's session
    PF_REQUIRE(r.client->state() != ControlClient::State::ResetSent);
    const auto before = r.client->state();
    TlsCryptChannel stranger(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    stranger.set_next_packet_id_for_test(20);                       // inside the replay window, so only the session check can stop it
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlV1);
    p.session_id = {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};
    p.has_message = true; p.message_id = 99; p.payload = {0x16, 0x03, 0x03, 0x00, 0x01, 0x00};
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(stranger, p, n.unix_s, dg));
    PF_CHECK(r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
    PF_CHECK(r.client->stats().wrong_session > 0);
    PF_CHECK(r.client->state() == before);
    PF_CHECK(r.client->state() != ControlClient::State::Failed);
}

PF_TEST(client_ignores_acks_that_name_a_different_client_session) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(100);
    const auto before = r.client->state();
    TlsCryptChannel peer(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    peer.set_next_packet_id_for_test(30);
    ControlPacket p; p.opcode = static_cast<uint8_t>(OvpnOpcode::AckV1);
    p.session_id = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};        // the real server's session (as the fake uses)
    p.acks = {1, 2, 3}; p.remote_session_id = {1, 2, 3, 4, 5, 6, 7, 8};      // ...but the acks are for some other client session
    std::vector<uint8_t> dg;
    PF_REQUIRE(seal_control_packet(peer, p, n.unix_s, dg));
    PF_CHECK(r.client->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
    PF_CHECK(r.client->stats().wrong_session > 0);
    PF_CHECK(r.client->state() == before);
}

PF_TEST(client_fails_when_the_server_sends_an_invalid_key_method_message) {
    pf_test::FakeServerConfig sc = server_cfg();
    sc.corrupt_key_method = true;
    Rig r(client_cfg(nullptr), sc); Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    n.run(10000);
    PF_CHECK(r.client->state() == ControlClient::State::Failed);
    PF_CHECK(r.client->failure_reason().find("key-method") != std::string::npos);
    PF_CHECK(!r.keys.rx_for_key_id(0).valid());
}

PF_TEST(client_leaves_data_packets_to_the_caller) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    const uint8_t data[] = {0x48, 0, 0, 0, 0, 0, 0, 1, 9, 9, 9, 9};
    PF_CHECK(!r.client->on_datagram(data, sizeof data, n.now, n.unix_s));      // not a control packet
    PF_CHECK(r.client->state() == ControlClient::State::ResetSent);
}

PF_TEST(client_survives_garbage_datagrams) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    for (int len = 0; len < 120; ++len) {
        std::vector<uint8_t> junk(static_cast<size_t>(len), static_cast<uint8_t>(0x20 + len));   // looks like CONTROL_V1
        (void)r.client->on_datagram(junk.data(), junk.size(), n.now, n.unix_s);
    }
    PF_CHECK(r.client->stats().auth_failed > 0);
    n.run(5000);
    PF_CHECK(r.client->state() == ControlClient::State::Established);          // junk did not break the real exchange
}

PF_TEST(client_first_packet_is_hard_reset_client_v2_with_empty_payload) {
    Rig r; Net n{*r.client, *r.server};
    r.client->start(n.now, n.unix_s);
    auto out = r.client->poll(n.now, n.unix_s);
    PF_REQUIRE(out.size() == 1);
    PF_CHECK_EQ(out[0][0], 0x38);                                              // opcode 7 << 3 | key_id 0
    PF_CHECK_EQ(out[0].size(), kTlsCryptOverhead + 5);                         // ack_len 0 + message id 0
    PF_CHECK(r.client->state() == ControlClient::State::ResetSent);
    PF_CHECK(r.client->poll(n.now + 1, n.unix_s).empty());                     // not retransmitted before the timeout
    PF_CHECK(r.client->next_wakeup_ms().has_value());
}
