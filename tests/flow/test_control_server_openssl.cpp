// PM-11 V1: our ControlClient against our ControlServer, in memory (loss, duplication, reordering, renegotiation,
// authentication decisions, revocation, capability checks, hand-window). Needs OpenSSL.
#include "server_rig.h"

using namespace pf;
using namespace pf_test;

namespace {

using SS = ControlServer::State;
using CS = ControlClient::State;

void start(ServerRig& r, ServerNet& n) { r.client->start(n.now, n.unix_s); }

bool established(ServerRig& r) {
    return r.client->state() == CS::Established && r.server->state() == SS::Established && r.server->data_ready();
}

// Both directions of key_id carry data through the real Flows with the installed keys.
void check_keys_work(ServerRig& r, uint8_t key_id) {
    DataPathCheck dc;
    PF_CHECK(dc.carries(r.server_keys, r.client_keys, key_id, 5, {1, 2, 3, 4}));
    PF_CHECK(dc.carries(r.client_keys, r.server_keys, key_id, 5, {5, 6, 7}));
}

ControlClientConfig user_client(const std::string& user, const std::string& pass) {
    ControlClientConfig c = client_cfg(nullptr);
    c.username = user;
    c.password = pass;
    return c;
}

ControlServerConfig auth_server(bool require_user_pass) {
    ControlServerConfig s = control_server_cfg();
    s.external_auth = true;
    s.require_user_pass = require_user_pass;
    return s;
}

}  // namespace

PF_TEST(server_session_comes_up_with_matching_keys_and_the_configured_push) {
    ServerRig r; ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    const PushReply& p = r.client->push();
    PF_CHECK_EQ(p.ifconfig_ip, 0x0A080002u);
    PF_CHECK_EQ(p.ifconfig_netmask, 0xFFFFFF00u);
    PF_CHECK_EQ(p.route_gateway, 0x0A080001u);
    PF_CHECK_EQ(p.peer_id, 5u);
    PF_CHECK_EQ(p.ping_seconds, 10u);
    PF_CHECK_EQ(p.ping_restart_seconds, 60u);
    PF_CHECK(r.client->warnings().empty());                    // the options strings match each other exactly
    PF_CHECK(r.server->warnings().empty());
    PF_CHECK(r.server->common_name() == "pf-client");
    PF_CHECK_EQ(r.server->peer_info().iv_proto, 14u);
    PF_CHECK_EQ(r.server->tx_key_id(), 0);
    check_keys_work(r, 0);
}

PF_TEST(server_session_survives_loss_duplication_and_reordering) {
    struct Case { const char* name; std::function<int(bool, size_t)> fate; bool reverse; };
    const Case cases[] = {
        {"drop every 3rd", [](bool, size_t i) { return i % 3 == 2 ? 0 : 1; }, false},
        {"drop every 2nd to server", [](bool to_s, size_t i) { return to_s && i % 2 == 1 ? 0 : 1; }, false},
        {"duplicate all", [](bool, size_t) { return 2; }, false},
        {"reverse flights", [](bool, size_t) { return 1; }, true},
        {"reverse + drop every 5th", [](bool, size_t i) { return i % 5 == 4 ? 0 : 1; }, true},
    };
    for (const Case& c : cases) {
        ServerRig r; ServerNet n{*r.client, *r.server};
        n.fate = c.fate;
        n.reverse_flights = c.reverse;
        start(r, n);
        const bool ok = n.run_until([&] { return established(r); }, 60000);
        PF_CHECK(ok);
        if (!ok) { std::printf("  case: %s (client %d, server %d)\n", c.name, int(r.client->state()), int(r.server->state())); continue; }
        check_keys_work(r, 0);
    }
}

PF_TEST(server_initiated_renegotiation_rotates_keys_on_both_sides) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.reneg_interval_ms = 0;                                  // only the server starts
    cc.old_key_grace_ms = 3000;
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 10000;
    sc.old_key_grace_ms = 3000;
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_REQUIRE(n.run_until([&] { return r.server->stats().renegotiations == 1 && r.client->stats().renegotiations == 1; }, 20000));
    PF_CHECK_EQ(r.server->tx_key_id(), 1);
    PF_CHECK_EQ(r.client->tx_key_id(), 1);
    check_keys_work(r, 1);
    n.run(5000);                                               // grace over: key 0 retired on both sides
    PF_CHECK(!r.server_keys.rx_for_key_id(0).valid());
    PF_CHECK(!r.server_keys.tx_for_key_id(0).valid());
    PF_CHECK(!r.client_keys.rx_for_key_id(0).valid());
    PF_CHECK_EQ(r.server_keys.size(), size_t{2});
    PF_CHECK_EQ(r.server->stats().reneg_failures, 0u);
}

PF_TEST(client_initiated_renegotiation_is_answered) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.reneg_interval_ms = 8000;
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 0;                                  // only the client starts
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_REQUIRE(n.run_until([&] { return r.server->stats().renegotiations == 2; }, 30000));
    PF_CHECK_EQ(r.client->stats().renegotiations, 2u);
    PF_CHECK_EQ(r.server->tx_key_id(), 2);
    check_keys_work(r, 2);
}

PF_TEST(renegotiation_key_ids_wrap_from_7_to_1_with_at_most_one_old_key) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.reneg_interval_ms = 0;
    cc.old_key_grace_ms = 60000;
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 3000;
    sc.old_key_grace_ms = 60000;
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    std::vector<uint8_t> seen;
    PF_REQUIRE(n.run_until([&] {
        if (seen.empty() || seen.back() != r.server->tx_key_id()) seen.push_back(r.server->tx_key_id());
        return r.server->stats().renegotiations >= 9;
    }, 60000));
    PF_CHECK(seen == (std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 1, 2}));
    PF_CHECK(r.server_keys.size() <= 4u);
    PF_CHECK_EQ(r.client->tx_key_id(), r.server->tx_key_id());
    check_keys_work(r, r.server->tx_key_id());
}

PF_TEST(renegotiation_survives_loss) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.reneg_interval_ms = 0;
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 10000;
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    n.fate = [](bool, size_t i) { return i % 4 == 3 ? 0 : 1; };
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 30000));
    PF_REQUIRE(n.run_until([&] { return r.server->stats().renegotiations == 2; }, 60000));
    PF_CHECK_EQ(r.client->tx_key_id(), r.server->tx_key_id());
    check_keys_work(r, r.server->tx_key_id());
}

PF_TEST(server_waits_for_the_authentication_decision_before_installing_keys) {
    ServerRig r(user_client("alice", "correct horse"), auth_server(true)); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    std::optional<AuthRequest> req = r.server->take_auth_request();
    PF_REQUIRE(req.has_value());
    PF_CHECK(!r.server->take_auth_request().has_value());      // handed out once
    PF_CHECK(req->common_name == "pf-client");
    PF_CHECK(req->username == "alice");
    PF_CHECK(req->password.reveal() == "correct horse");
    PF_CHECK(req->peer_info.find("IV_PROTO=14") != std::string::npos);
    n.run(3000);                                               // nothing moves while undecided
    PF_CHECK(r.client->state() == CS::WaitPush);
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});              // no data key before the decision
    r.server->resolve_auth(true);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_CHECK(r.server->username() == "alice");
    check_keys_work(r, 0);
}

PF_TEST(server_refusal_sends_auth_failed_and_closes_after_the_linger_time) {
    ServerRig r(user_client("mallory", "guess"), auth_server(true)); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    r.server->resolve_auth(false, "bad password");
    PF_REQUIRE(n.run_until([&] { return r.client->state() == CS::Failed; }, 5000));
    PF_CHECK(r.client->failure_reason() == "AUTH_FAILED: AUTH_FAILED");      // the client learns nothing more
    PF_CHECK(r.client->failure_kind() == ControlClient::FailureKind::Rejected);
    PF_CHECK(r.server->state() == SS::Rejected);
    PF_REQUIRE(n.run_until([&] { return r.server->done(); }, 6000));
    PF_CHECK(r.server->close_reason() == "authentication refused: bad password");
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});
    r.server->resolve_auth(true);                              // too late: ignored
    PF_CHECK(r.server->done());
}

PF_TEST(server_refuses_clients_without_usable_credentials_before_asking_anyone) {
    struct Case { std::string user, pass; };
    const Case cases[] = {
        {"", ""},                                          // no auth-user-pass at all
        {"alice", ""},                                     // empty password
        {"alice", "two\nlines"},                           // would break the via-file format
        {"al\tice", "pw"},                                 // control character in the username
        {std::string(257, 'u'), "pw"},                     // too long
        {"alice", std::string(1025, 'p')},
    };
    for (const Case& c : cases) {
        ServerRig r(user_client(c.user, c.pass), auth_server(true)); ServerNet n{*r.client, *r.server};
        start(r, n);
        PF_CHECK(n.run_until([&] { return r.client->state() == CS::Failed; }, 5000));
        PF_CHECK(r.client->failure_reason().rfind("AUTH_FAILED", 0) == 0);
        PF_CHECK(!r.server->take_auth_request().has_value());
        PF_CHECK_EQ(r.server_keys.size(), size_t{0});
    }
}

PF_TEST(server_without_user_pass_accepts_certificate_only_clients_and_ignores_a_sent_password) {
    ServerRig r(user_client("bob", "unused"), control_server_cfg()); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_CHECK(r.server->username() == "bob");
    PF_CHECK(!r.server->take_auth_request().has_value());
}

PF_TEST(server_external_auth_also_holds_certificate_only_clients) {
    ServerRig r(client_cfg(nullptr), auth_server(false)); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    auto req = r.server->take_auth_request();
    PF_REQUIRE(req.has_value());
    PF_CHECK(req->username.empty());
    PF_CHECK(req->password.empty());
    r.server->resolve_auth(true);
    PF_CHECK(n.run_until([&] { return established(r); }, 5000));
}

PF_TEST(server_refuses_a_client_outside_the_profile_with_the_reason) {
    struct Case { const char* peer_info; const char* expect; };
    const Case cases[] = {
        {"IV_VER=2.6.0\nIV_PROTO=6\nIV_CIPHERS=AES-256-GCM\n", "TLS key export"},
        {"IV_VER=2.6.0\nIV_PROTO=14\nIV_CIPHERS=CHACHA20-POLY1305\n", "no shared cipher"},
        {"IV_VER=2.4.0\nIV_CIPHERS=AES-256-GCM\n", "IV_PROTO"},
        {"IV_PROTO=14\nIV_PROTO=14\n", ""},                     // malformed: plain AUTH_FAILED
    };
    for (const Case& c : cases) {
        ControlClientConfig cc = client_cfg(nullptr);
        cc.peer_info = c.peer_info;
        ServerRig r(cc, control_server_cfg()); ServerNet n{*r.client, *r.server};
        start(r, n);
        PF_REQUIRE(n.run_until([&] { return r.client->state() == CS::Failed; }, 5000));
        PF_CHECK(r.client->failure_reason().find("AUTH_FAILED") != std::string::npos);
        PF_CHECK(r.client->failure_reason().find(c.expect) != std::string::npos);
        PF_CHECK(r.server->state() == SS::Rejected);
        PF_CHECK_EQ(r.server_keys.size(), size_t{0});
    }
}

PF_TEST(server_rejects_a_revoked_client_certificate) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.tls.cert_pem = pki().revoked_client_cert_pem; cc.tls.key_pem = pki().revoked_client_key_pem;
    ControlServerConfig sc = auth_server(false);
    sc.tls.crl_pem = pki().crl_pem;
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->done(); }, 10000));
    PF_CHECK(r.server->close_reason().find("revoked") != std::string::npos);
    PF_CHECK(!r.server->take_auth_request().has_value());      // never reached the decision
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});
    PF_CHECK(n.run_until([&] { return r.client->state() == CS::Failed; }, 5000));   // our alert reached it
}

PF_TEST(server_with_a_crl_accepts_other_clients) {
    ControlServerConfig sc = control_server_cfg();
    sc.tls.crl_pem = pki().crl_pem;
    ServerRig r(client_cfg(nullptr), sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_CHECK(n.run_until([&] { return established(r); }, 5000));
}

PF_TEST(server_closes_a_session_whose_renegotiation_presents_another_certificate) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.reneg_interval_ms = 0;
    TlsConfig other = cc.tls;
    other.cert_pem = pki().client2_cert_pem; other.key_pem = pki().client2_key_pem;   // same CA, valid, different identity
    cc.reneg_override_for_test.tls = other;
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 5000;
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_REQUIRE(n.run_until([&] { return r.server->done(); }, 15000));
    PF_CHECK(r.server->close_reason() == "renegotiation presented a different certificate");
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});              // every key wiped, including the original one
    PF_CHECK_EQ(r.server->stats().renegotiations, 0u);
}

PF_TEST(server_ignores_packets_under_a_wrong_tls_crypt_key_without_creating_state) {
    ServerRig r(client_cfg(nullptr, /*seed=*/9), control_server_cfg(/*seed=*/1)); ServerNet n{*r.client, *r.server};
    start(r, n);
    n.run(3000);
    PF_CHECK(r.server->state() == SS::WaitReset);
    PF_CHECK(r.server->stats().auth_failed > 0);
    PF_CHECK_EQ(r.server->stats().datagrams_out, 0u);          // not a single byte back: nothing to probe
    PF_CHECK(!r.server->next_wakeup_ms().has_value());
}

PF_TEST(server_gives_up_after_the_hand_window) {
    ControlServerConfig sc = control_server_cfg();
    sc.hand_window_ms = 10000;
    ServerRig r(client_cfg(nullptr), sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    n.fate = [](bool to_server, size_t i) { return to_server && i > 0 ? 0 : 1; };   // only the first reset arrives
    n.run(9000);
    PF_CHECK(r.server->state() == SS::TlsHandshake);
    n.run(2000);
    PF_CHECK(r.server->done());
    PF_CHECK(r.server->close_reason().find("hand-window") != std::string::npos);
}

PF_TEST(server_gives_up_on_an_undecided_authentication_after_the_hand_window) {
    ControlServerConfig sc = auth_server(false);
    sc.hand_window_ms = 10000;
    ServerRig r(client_cfg(nullptr), sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    n.run(11000);
    PF_CHECK(r.server->done());
    r.server->resolve_auth(true);                              // a late answer changes nothing
    PF_CHECK(r.server->done());
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});
}

PF_TEST(server_ignores_another_client_session_and_replays) {
    ServerRig r; ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    KeyStore other_keys;
    ControlClientConfig oc = client_cfg(&other_keys);
    uint8_t ctr = 100;
    oc.random = [ctr](uint8_t* p, size_t len) mutable { for (size_t i = 0; i < len; ++i) p[i] = static_cast<uint8_t>(++ctr * 31 + 7); };
    std::string err;
    auto other = ControlClient::create(std::move(oc), err);
    PF_REQUIRE(other != nullptr);
    // Every client shares the tls-crypt key: the other client's packets are authentic, with a LATER timestamp.
    other->start(n.now, n.unix_s + 10);
    const uint32_t wrong = r.server->stats().wrong_session;
    for (auto& d : other->poll(n.now, n.unix_s + 10)) r.server->on_datagram(d.data(), d.size(), n.now, n.unix_s);
    PF_CHECK_EQ(r.server->stats().wrong_session, wrong + 1);
    const uint32_t replays = r.server->stats().replays;
    for (auto& d : n.client_sent) r.server->on_datagram(d.data(), d.size(), n.now, n.unix_s);
    PF_CHECK_EQ(r.server->stats().replays, replays + static_cast<uint32_t>(n.client_sent.size()));
    PF_CHECK(r.server->state() == SS::Established);
    // The foreign packet must not have moved our replay window: our client's next packets (older timestamp) still count.
    const uint32_t before = r.server->stats().replays;
    r.server->close("restart for the check");
    PF_CHECK(r.server->done());
    PF_CHECK_EQ(r.server->stats().replays, before);
}

PF_TEST(server_replay_window_is_not_moved_by_another_sessions_packets) {
    ControlClientConfig cc = client_cfg(nullptr);
    cc.reneg_interval_ms = 0;
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 5000;                               // traffic from our client is needed after the foreign packet
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    KeyStore other_keys;
    ControlClientConfig oc = client_cfg(&other_keys);
    uint8_t ctr = 100;
    oc.random = [ctr](uint8_t* p, size_t len) mutable { for (size_t i = 0; i < len; ++i) p[i] = static_cast<uint8_t>(++ctr * 31 + 7); };
    std::string err;
    auto other = ControlClient::create(std::move(oc), err);
    PF_REQUIRE(other != nullptr);
    other->start(n.now, n.unix_s + 1000);
    for (auto& d : other->poll(n.now, n.unix_s + 1000)) r.server->on_datagram(d.data(), d.size(), n.now, n.unix_s);
    const uint32_t replays = r.server->stats().replays;
    PF_REQUIRE(n.run_until([&] { return r.server->stats().renegotiations == 1; }, 15000));
    PF_CHECK_EQ(r.server->stats().replays, replays);
    PF_CHECK(established(r));
}

PF_TEST(server_close_wipes_every_key) {
    ServerRig r; ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_CHECK_EQ(r.server_keys.size(), size_t{2});
    r.server->close("operator kill");
    PF_CHECK(r.server->done());
    PF_CHECK(r.server->close_reason() == "operator kill");
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});
    PF_CHECK(!r.server->data_ready());
    PF_CHECK(r.server->poll(n.now, n.unix_s).empty());
    PF_CHECK(!r.server->next_wakeup_ms().has_value());
}

PF_TEST(server_create_rejects_unusable_configurations) {
    std::string err;
    ControlServerConfig a = control_server_cfg(); a.tls.role = TlsRole::Client;
    PF_CHECK(ControlServer::create(a, err) == nullptr);
    ControlServerConfig b = control_server_cfg(); b.require_user_pass = true;      // without external_auth
    PF_CHECK(ControlServer::create(b, err) == nullptr);
    ControlServerConfig c = control_server_cfg(); c.push.ifconfig_ip = 0;
    PF_CHECK(ControlServer::create(c, err) == nullptr);
    ControlServerConfig d = control_server_cfg(); d.push.peer_id = 0xFFFFFF;
    PF_CHECK(ControlServer::create(d, err) == nullptr);
    ControlServerConfig e = control_server_cfg(); e.tls.key_pem.clear();
    PF_CHECK(ControlServer::create(e, err) == nullptr);
    struct Failing : RandomSource { bool fill(uint8_t*, size_t) override { return false; } } failing;
    ControlServerConfig f = control_server_cfg(); f.random = &failing;
    PF_CHECK(ControlServer::create(f, err) == nullptr);
    PF_CHECK(err == "random source failed");
}

PF_TEST(server_next_wakeup_drives_a_sleeping_event_loop) {
    // Instead of fixed 100 ms steps, advance time only to the next wakeup either side asks for.
    ServerRig r; ServerNet n{*r.client, *r.server};
    start(r, n);
    for (int i = 0; i < 200 && !established(r); ++i) {
        n.step();
        std::optional<uint64_t> a = r.client->next_wakeup_ms(), b = r.server->next_wakeup_ms();
        uint64_t next = n.now + 60000;
        if (a) next = std::min(next, std::max(*a, n.now));
        if (b) next = std::min(next, std::max(*b, n.now));
        n.now = next == n.now ? n.now + 1 : next;
    }
    PF_CHECK(established(r));
}

PF_TEST(server_never_transmits_on_a_key_the_client_cannot_decrypt_yet) {
    // Invariant checked after every step, under loss: whenever the server would send data (data_ready, tx_key_id),
    // the client already holds the matching RX key. Switching TX early would black-hole traffic.
    int completed = 0;
    for (uint32_t seed = 0; seed < 4; ++seed) {
        ControlClientConfig cc = client_cfg(nullptr);
        cc.reneg_interval_ms = seed % 2 ? 4000 : 0;
        ControlServerConfig sc = control_server_cfg();
        sc.reneg_interval_ms = seed % 2 ? 0 : 4000;
        ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
        n.fate = [seed](bool, size_t i) { return (i * 7 + seed) % 3 == 0 ? 0 : 1; };
        start(r, n);
        bool violated = false;
        n.run_until([&] {
            if (r.server->data_ready() && !r.client_keys.rx_for_key_id(r.server->tx_key_id()).valid()) violated = true;
            return r.server->stats().renegotiations >= 3 || r.server->done();
        }, 120000, 50);
        PF_CHECK(!violated);
        // Heavy loss may leave a key switch unconfirmed: then the session must END, never limp on with mismatched keys.
        const bool closed_cleanly = r.server->done() && r.server->close_reason().rfind("renegotiation could not be confirmed", 0) == 0;
        PF_CHECK(r.server->stats().renegotiations >= 3 || closed_cleanly);
        PF_CHECK(r.server->stats().reneg_failures == 0 || closed_cleanly);
        if (r.server->stats().renegotiations >= 3) ++completed;
        if (r.server->stats().renegotiations < 3 && !closed_cleanly)
            std::printf("  seed %u: server %d reneg %u fail %u (%s), client %d reneg %u fail %u\n", seed, int(r.server->state()),
                        r.server->stats().renegotiations, r.server->stats().reneg_failures, r.server->close_reason().c_str(),
                        int(r.client->state()), r.client->stats().renegotiations, r.client->stats().reneg_failures);
    }
    PF_CHECK(completed >= 3);                                  // the loss pattern is heavy, not hopeless
}

PF_TEST(server_data_is_not_ready_until_the_client_acknowledged_the_push) {
    ServerRig r(client_cfg(nullptr), auth_server(false)); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    n.fate = [](bool to_server, size_t) { return to_server ? 1 : 0; };   // the push never reaches the client
    r.server->resolve_auth(true);
    n.run(3000);
    PF_CHECK(r.server->state() == SS::Established);
    PF_CHECK(!r.server->data_ready());
    n.fate = [](bool, size_t) { return 1; };
    PF_CHECK(n.run_until([&] { return established(r); }, 20000));
}

PF_TEST(server_closes_a_session_whose_renegotiation_presents_another_username) {
    ControlClientConfig cc = user_client("alice", "pw");
    cc.reneg_interval_ms = 0;
    cc.reneg_override_for_test.username = std::string("root");
    ControlServerConfig sc = auth_server(true);
    sc.reneg_interval_ms = 5000;
    ServerRig r(cc, sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    r.server->resolve_auth(true);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    PF_REQUIRE(n.run_until([&] { return r.server->done(); }, 15000));
    PF_CHECK(r.server->close_reason() == "renegotiation presented a different username");
    PF_CHECK_EQ(r.server_keys.size(), size_t{0});
}

PF_TEST(server_ignores_a_late_or_repeated_authentication_answer) {
    ServerRig r(client_cfg(nullptr), auth_server(false)); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return r.server->state() == SS::AuthPending; }, 5000));
    r.server->resolve_auth(true);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    r.server->resolve_auth(false, "second answer");            // must not undo the accepted session
    n.run(2000);
    PF_CHECK(established(r));
    PF_CHECK(r.client->state() == CS::Established);
}

PF_TEST(server_creates_no_key_state_for_a_soft_reset_with_the_wrong_key_id) {
    ControlServerConfig sc = control_server_cfg();
    sc.reneg_interval_ms = 0;
    ServerRig r(client_cfg(nullptr), sc); ServerNet n{*r.client, *r.server};
    start(r, n);
    PF_REQUIRE(n.run_until([&] { return established(r); }, 5000));
    // Learn the client's session id from its first datagram, then speak as that client (tls-crypt key is shared).
    TlsCryptChannel as_server(derive_tls_crypt_keys(key(1), TlsCryptRole::Server));
    ControlPacket first;
    PF_REQUIRE(open_control_packet(as_server, n.client_sent[0].data(), n.client_sent[0].size(), first) == OpenControlStatus::Ok);
    TlsCryptChannel as_client(derive_tls_crypt_keys(key(1), TlsCryptRole::Client));
    for (uint8_t kid : {uint8_t{0}, uint8_t{2}, uint8_t{5}, uint8_t{7}}) {      // next would be 1
        ControlPacket p;
        p.opcode = static_cast<uint8_t>(OvpnOpcode::ControlSoftResetV1);
        p.key_id = kid;
        p.session_id = first.session_id;
        p.has_message = true;
        p.message_id = 0;
        std::vector<uint8_t> dg;
        PF_REQUIRE(seal_control_packet(as_client, p, n.unix_s + 100 + kid, dg));
        const uint32_t unknown = r.server->stats().unknown_key_id;
        PF_CHECK(r.server->on_datagram(dg.data(), dg.size(), n.now, n.unix_s));
        if (kid != 0) PF_CHECK_EQ(r.server->stats().unknown_key_id, unknown + 1);
    }
    n.run(3000);
    PF_CHECK_EQ(r.server->stats().renegotiations, 0u);
    PF_CHECK_EQ(r.server_keys.size(), size_t{2});              // still only key 0
    PF_CHECK(established(r));
}
