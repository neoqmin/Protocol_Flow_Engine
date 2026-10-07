// PM-11 V2: many ControlClients against one ServerCore (stateless cookie, peer-id, routing, limits, restarts,
// floats, authentication across sessions). Needs OpenSSL.
#include <set>

#include "server_core_rig.h"

using namespace pf;
using namespace pf_test;

namespace {

using Kind = ServerCore::Event::Kind;
using Drop = ServerCore::DropReason;

std::vector<uint8_t> data_v2(uint32_t peer_id, uint8_t key_id = 0) {
    return {static_cast<uint8_t>((9 << 3) | key_id), static_cast<uint8_t>(peer_id >> 16), static_cast<uint8_t>(peer_id >> 8),
            static_cast<uint8_t>(peer_id), 0, 0, 0, 1, 0xAA, 0xBB};
}

// The first datagram a fresh client sends: its HARD_RESET.
std::vector<uint8_t> first_reset(uint32_t seed) {
    std::string err;
    KeyStore ks;
    ControlClientConfig cc = distinct_client(seed);
    cc.keys = &ks;
    auto c = ControlClient::create(std::move(cc), err);
    c->start(0, 1790000000);
    return c->poll(0, 1790000000).at(0);
}

}  // namespace

PF_TEST(core_brings_up_several_clients_with_their_own_peer_ids_and_keys) {
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    for (uint32_t i = 0; i < 3; ++i) n.add(distinct_client(i + 1), addr(static_cast<uint8_t>(10 + i), 40000));
    PF_REQUIRE(n.run_until([&] { return n.all_established(); }, 10000));
    PF_CHECK_EQ(core->session_count(), size_t{3});
    std::set<uint32_t> pids;
    DataPathCheck dc;
    for (auto& c : n.clients) {
        const auto id = core->find_by_address(c.address);
        PF_REQUIRE(id.has_value());
        const uint32_t pid = core->peer_id_of(*id);
        pids.insert(pid);
        PF_CHECK_EQ(c.client->push().peer_id, pid);
        PF_CHECK_EQ(c.client->push().ifconfig_ip, 0x0A080002u + pid);
        PF_CHECK(dc.carries(*core->keys(*id), *c.keys, 0, pid, {1, 2, 3}));
        PF_CHECK(dc.carries(*c.keys, *core->keys(*id), 0, pid, {4, 5}));
    }
    PF_CHECK(pids == (std::set<uint32_t>{0, 1, 2}));
    // Keys are per session: client 0's key does not open client 1's traffic.
    const auto id1 = *core->find_by_address(n.clients[1].address);
    PF_CHECK(!dc.carries(*n.clients[0].keys, *core->keys(id1), 0, 1, {9}));
    int opened = 0, established = 0;
    for (const auto& e : core->take_events()) { opened += e.kind == Kind::Opened; established += e.kind == Kind::Established; }
    PF_CHECK_EQ(opened, 3);
    PF_CHECK_EQ(established, 3);
}

PF_TEST(core_answers_a_reset_without_storing_anything) {
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    std::vector<ServerCore::Outgoing> out;
    const auto reset = first_reset(1);
    for (int i = 0; i < 100; ++i) {                            // a flood of resets, e.g. from spoofed sources
        const auto r = core->on_datagram(reset.data(), reset.size(), addr(static_cast<uint8_t>(i), 1000), 1000, 1790000000, out);
        PF_CHECK(r.route == ServerCore::Route::Control);
    }
    PF_CHECK_EQ(core->session_count(), size_t{0});
    PF_CHECK_EQ(out.size(), size_t{100});                       // one answer each, to the claimed source, same size class
    PF_CHECK(out[0].bytes.size() <= reset.size() + 16);         // no amplification worth the name
    PF_CHECK_EQ(core->stats().cookies_sent, 100u);
    PF_CHECK(!core->next_wakeup_ms().has_value());
}

PF_TEST(core_ignores_strangers_without_the_tls_crypt_key) {
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(client_cfg(nullptr, /*seed=*/9), addr(1, 1000));    // wrong tls-crypt key
    n.run(3000);
    PF_CHECK_EQ(core->session_count(), size_t{0});
    PF_CHECK_EQ(core->stats().cookies_sent, 0u);
    PF_CHECK(core->stats().not_ours > 0);
}

PF_TEST(core_needs_a_valid_cookie_from_the_same_address) {
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    n.step();                                                  // reset out, cookie back
    PF_CHECK_EQ(core->stats().cookies_sent, 1u);
    n.clients[0].address = addr(2, 1000);                      // its next packet comes from elsewhere
    n.run(500);
    PF_CHECK_EQ(core->session_count(), size_t{0});
    PF_CHECK(core->stats().bad_cookies > 0);
}

PF_TEST(core_cookie_expires_after_two_windows) {
    ServerCoreConfig cfg = core_cfg();
    cfg.cookie_window_ms = 10000;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    n.step();                                                  // cookie for window 0 (now = 1000)
    n.clients[0].online = false;
    n.now = 25000;                                             // window 2: neither current nor previous
    n.clients[0].online = true;
    const uint32_t bad = core->stats().bad_cookies;
    for (auto& d : n.clients[0].client->poll(n.now, n.unix_s)) n.send_raw(d, n.clients[0].address);
    PF_CHECK(core->stats().bad_cookies > bad || core->session_count() == 0);
    PF_CHECK_EQ(core->session_count(), size_t{0});
}

PF_TEST(core_cookie_survives_a_window_boundary) {
    ServerCoreConfig cfg = core_cfg();
    cfg.cookie_window_ms = 10000;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    n.now = 9900;                                              // reset answered at the end of window 0
    n.add(distinct_client(1), addr(1, 1000));
    PF_CHECK(n.run_until([&] { return n.all_established(); }, 10000));
}

PF_TEST(core_routes_data_by_peer_id_and_reports_new_addresses) {
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    n.add(distinct_client(2), addr(2, 1000));
    PF_REQUIRE(n.run_until([&] { return n.all_established(); }, 10000));
    const auto id1 = *core->find_by_address(addr(2, 1000));
    std::vector<ServerCore::Outgoing> out;
    auto d = data_v2(core->peer_id_of(id1));
    auto r = core->on_datagram(d.data(), d.size(), addr(2, 1000), n.now, n.unix_s, out);
    PF_CHECK(r.route == ServerCore::Route::Data);
    PF_CHECK_EQ(r.session, id1);
    PF_CHECK(!r.new_address);
    r = core->on_datagram(d.data(), d.size(), addr(77, 5555), n.now, n.unix_s, out);
    PF_CHECK(r.route == ServerCore::Route::Data);               // the caller decides after decrypting (V3)
    PF_CHECK(r.new_address);
    PF_CHECK(core->find_by_address(addr(2, 1000)) == id1);      // nothing moves without confirm_float
    auto unknown = data_v2(4000);
    PF_CHECK(core->on_datagram(unknown.data(), unknown.size(), addr(2, 1000), n.now, n.unix_s, out).reason == Drop::UnknownPeerId);
    std::vector<uint8_t> v1 = {static_cast<uint8_t>(6 << 3), 1, 2, 3};
    PF_CHECK(core->on_datagram(v1.data(), v1.size(), addr(2, 1000), n.now, n.unix_s, out).reason == Drop::Unsupported);
    std::vector<uint8_t> shorty = {static_cast<uint8_t>(9 << 3), 0};
    PF_CHECK(core->on_datagram(shorty.data(), shorty.size(), addr(2, 1000), n.now, n.unix_s, out).reason == Drop::Malformed);
    PF_CHECK(out.empty());
}

PF_TEST(core_data_before_the_session_is_accepted_is_dropped) {
    ServerCoreConfig cfg = core_cfg();
    cfg.session.external_auth = true;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    PF_REQUIRE(n.run_until([&] { return !core->take_auth_requests().empty(); }, 5000));
    std::vector<ServerCore::Outgoing> out;
    auto d = data_v2(0);
    PF_CHECK(core->on_datagram(d.data(), d.size(), addr(1, 1000), n.now, n.unix_s, out).reason == Drop::NoDataKeys);
}

PF_TEST(core_float_moves_the_session_to_the_confirmed_address) {
    ControlClientConfig cc = distinct_client(1);
    cc.reneg_interval_ms = 5000;                               // control traffic after the move
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(cc, addr(1, 1000));
    n.add(distinct_client(2), addr(2, 1000));
    PF_REQUIRE(n.run_until([&] { return n.all_established(); }, 10000));
    const auto id = *core->find_by_address(addr(1, 1000));
    PF_CHECK(!core->confirm_float(id, addr(2, 1000)));        // occupied by another session
    PF_CHECK(core->confirm_float(id, addr(1, 2000)));          // NAT rebinding, proven by authenticated data (V3)
    n.clients[0].address = addr(1, 2000);
    PF_CHECK(core->address_of(id) == addr(1, 2000));
    PF_REQUIRE(n.run_until([&] { return n.clients[0].client->stats().renegotiations >= 1; }, 15000));
    PF_CHECK_EQ(core->stats().floats, 1u);
    PF_CHECK_EQ(core->session_count(), size_t{2});
}

PF_TEST(core_enforces_max_clients_and_admits_waiting_clients_when_a_slot_frees) {
    ServerCoreConfig cfg = core_cfg();
    cfg.max_clients = 2;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    for (uint32_t i = 0; i < 3; ++i) n.add(distinct_client(i + 1), addr(static_cast<uint8_t>(i + 1), 1000));
    n.run(5000);
    PF_CHECK_EQ(core->session_count(), size_t{2});
    PF_CHECK(core->stats().limit_clients > 0);
    PF_CHECK(n.clients[2].client->state() != ControlClient::State::Established);
    PF_REQUIRE(core->kill(*core->find_by_address(addr(1, 1000)), "operator kill"));
    PF_CHECK(n.run_until([&] { return n.clients[2].client->state() == ControlClient::State::Established; }, 20000));
    PF_CHECK_EQ(core->peer_id_of(*core->find_by_address(addr(3, 1000))), 0u);   // the freed peer-id is reused
}

PF_TEST(core_enforces_the_per_ip_limit) {
    ServerCoreConfig cfg = core_cfg();
    cfg.max_sessions_per_ip = 2;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    for (uint16_t i = 0; i < 3; ++i) n.add(distinct_client(i + 1u), addr(1, static_cast<uint16_t>(1000 + i)));   // one NAT
    n.add(distinct_client(9), addr(2, 1000));
    n.run(5000);
    PF_CHECK_EQ(core->session_count(), size_t{3});
    PF_CHECK(core->stats().limit_per_ip > 0);
    PF_CHECK(n.clients[3].client->state() == ControlClient::State::Established);   // other addresses unaffected
}

PF_TEST(core_rate_limits_session_creation_but_lets_everyone_in_eventually) {
    ServerCoreConfig cfg = core_cfg();
    cfg.new_sessions_per_second = 1;
    cfg.new_session_burst = 2;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    for (uint32_t i = 0; i < 5; ++i) n.add(distinct_client(i + 1), addr(static_cast<uint8_t>(i + 1), 1000));
    n.run(800);
    PF_CHECK_EQ(core->session_count(), size_t{2});              // the burst
    PF_CHECK(core->stats().limit_rate > 0);
    PF_CHECK(n.run_until([&] { return n.all_established(); }, 60000));
}

PF_TEST(core_replaces_the_session_of_a_client_that_restarted_at_the_same_address) {
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    PF_REQUIRE(n.run_until([&] { return n.all_established(); }, 5000));
    const auto old_id = *core->find_by_address(addr(1, 1000));
    (void)core->take_events();
    n.clients[0].online = false;                               // the old process is gone
    n.add(distinct_client(2), addr(1, 1000));                  // a new one at the same address
    PF_REQUIRE(n.run_until([&] { return n.clients[1].client->state() == ControlClient::State::Established; }, 10000));
    const auto new_id = *core->find_by_address(addr(1, 1000));
    PF_CHECK(new_id != old_id);
    PF_CHECK(core->session(old_id) == nullptr);
    PF_CHECK_EQ(core->session_count(), size_t{1});
    PF_CHECK_EQ(core->stats().sessions_replaced, 1u);
    bool closed = false;
    for (const auto& e : core->take_events())
        if (e.kind == Kind::Closed && e.session == old_id) closed = e.detail == "replaced by a new session from the same address";
    PF_CHECK(closed);
}

PF_TEST(core_a_resets_alone_does_not_disturb_an_existing_session) {
    // A new reset from the same address (spoofed or a restarting client) must not kill the session until the cookie
    // round-trip completes.
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    PF_REQUIRE(n.run_until([&] { return n.all_established(); }, 5000));
    for (int i = 0; i < 10; ++i) n.send_raw(first_reset(50 + static_cast<uint32_t>(i)), addr(1, 1000));
    n.run(2000);
    PF_CHECK_EQ(core->session_count(), size_t{1});
    PF_CHECK_EQ(core->stats().sessions_replaced, 0u);
    PF_CHECK(n.all_established());
}

PF_TEST(core_routes_authentication_decisions_to_the_right_session) {
    ServerCoreConfig cfg = core_cfg();
    cfg.session.external_auth = true;
    cfg.session.require_user_pass = true;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    ControlClientConfig a = distinct_client(1); a.username = "alice"; a.password = "pa";
    ControlClientConfig b = distinct_client(2); b.username = "bob"; b.password = "pb";
    n.add(a, addr(1, 1000));
    n.add(b, addr(2, 1000));
    std::vector<ServerCore::PendingAuth> pending;
    PF_REQUIRE(n.run_until([&] {
        for (auto& p : core->take_auth_requests()) pending.push_back(std::move(p));
        return pending.size() == 2;
    }, 5000));
    for (auto& p : pending) PF_CHECK(core->resolve_auth(p.session, p.request.username == "alice"));
    PF_CHECK(!core->resolve_auth(pending[0].session, true));    // already answered
    PF_CHECK(!core->resolve_auth(9999, true));                  // no such session
    PF_REQUIRE(n.run_until([&] { return n.clients[1].client->state() == ControlClient::State::Failed; }, 5000));
    PF_CHECK(n.run_until([&] { return n.clients[0].client->state() == ControlClient::State::Established; }, 5000));
    PF_CHECK(n.run_until([&] { return core->session_count() == 1; }, 10000));     // bob's session lingered, then went
}

PF_TEST(core_removes_dead_sessions_and_frees_their_peer_ids) {
    ServerCoreConfig cfg = core_cfg();
    cfg.session.hand_window_ms = 5000;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    PF_REQUIRE(n.run_until([&] { return core->session_count() == 1; }, 1000, 1));   // session created...
    n.clients[0].online = false;                               // ...and the client vanishes mid-handshake
    PF_REQUIRE(core->session(*core->find_by_peer_id(0))->state() != ControlServer::State::Established);
    n.run(6000);
    PF_CHECK_EQ(core->session_count(), size_t{0});
    PF_CHECK(!core->find_by_peer_id(0).has_value());
    bool closed = false;
    for (const auto& e : core->take_events()) closed = closed || (e.kind == Kind::Closed && e.detail.find("hand-window") != std::string::npos);
    PF_CHECK(closed);
}

PF_TEST(core_handles_many_clients_under_loss) {
    ServerCoreConfig cfg = core_cfg();
    cfg.new_session_burst = 64;
    DeterministicRandom rnd(7);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    // About 1/7 loss and 1/11 duplication, hashed so the pattern cannot alias with the steady per-step traffic and
    // starve one client (a plain modulo did: each step carries the same number of packets).
    n.fate = [](bool, size_t i) {
        uint64_t z = (i + 1) * 0x9E3779B97F4A7C15ull;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z ^= z >> 31;
        return z % 7 == 0 ? 0 : (z % 11 == 0 ? 2 : 1);
    };
    for (uint32_t i = 0; i < 40; ++i) n.add(distinct_client(i + 1), addr(static_cast<uint8_t>(i / 4 + 1), static_cast<uint16_t>(1000 + i)));
    PF_CHECK(n.run_until([&] { return n.all_established(); }, 60000));
    PF_CHECK_EQ(core->session_count(), size_t{40});
    std::set<uint32_t> pids;
    for (const auto& c : n.clients) pids.insert(c.client->push().peer_id);
    PF_CHECK_EQ(pids.size(), size_t{40});
}

PF_TEST(core_challenges_again_a_client_that_sends_each_ack_only_once) {
    // A client whose cookie echo was refused (here: the rate limit) retransmits without acks. The core repeats its
    // stateless reset; the client acks the copy, carrying the cookie again.
    ServerCoreConfig cfg = core_cfg();
    cfg.new_sessions_per_second = 1;
    cfg.new_session_burst = 1;
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    for (uint32_t i = 0; i < 3; ++i) {
        ControlClientConfig cc = distinct_client(i + 1);
        cc.repeat_recent_acks = false;
        n.add(cc, addr(static_cast<uint8_t>(i + 1), 1000));
    }
    PF_CHECK(n.run_until([&] { return n.all_established(); }, 30000));
    PF_CHECK(core->stats().limit_rate > 0);
    PF_CHECK(core->stats().cookies_sent > 3);                  // refused echoes were answered with a fresh challenge
}

PF_TEST(core_client_repeating_acks_proves_the_cookie_with_its_retransmission) {
    // The client's first answer to our reset is lost: its retransmitted ClientHello repeats the ack (and so the cookie
    // echo), and the session opens from it directly - no extra round trip.
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    size_t to_server = 0;
    n.fate = [&](bool ts, size_t) { return ts && to_server++ == 1 ? 0 : 1; };   // drop the client's second datagram
    PF_CHECK(n.run_until([&] { return n.all_established(); }, 10000));
    PF_CHECK_EQ(core->stats().bad_cookies, 0u);
    PF_CHECK_EQ(core->stats().cookies_sent, 1u);
}

PF_TEST(core_challenges_again_when_a_once_only_ack_is_lost) {
    // An older-style client (each ack sent once) loses the packet that echoed our cookie: its retransmissions carry no
    // ack, so only a repeated stateless reset lets it prove the cookie again.
    DeterministicRandom rnd(1);
    auto core = make_core(core_cfg(), rnd);
    CoreNet n(*core);
    ControlClientConfig cc = distinct_client(1);
    cc.repeat_recent_acks = false;
    n.add(cc, addr(1, 1000));
    size_t to_server = 0;
    n.fate = [&](bool ts, size_t) { return ts && to_server++ == 1 ? 0 : 1; };   // drop the client's second datagram
    PF_CHECK(n.run_until([&] { return n.all_established(); }, 20000));
    PF_CHECK(core->stats().bad_cookies > 0);
    PF_CHECK(core->stats().cookies_sent >= 2);
}

PF_TEST(core_create_rejects_unusable_configurations) {
    std::string err;
    ServerCoreConfig a = core_cfg(); a.prepare_push = nullptr;
    PF_CHECK(ServerCore::create(a, err) == nullptr);
    ServerCoreConfig b = core_cfg(); b.max_clients = 0;
    PF_CHECK(ServerCore::create(b, err) == nullptr);
    ServerCoreConfig c = core_cfg(); c.session.tls.key_pem.clear();
    PF_CHECK(ServerCore::create(c, err) == nullptr);
    ServerCoreConfig d = core_cfg(); d.new_sessions_per_second = 0;
    PF_CHECK(ServerCore::create(d, err) == nullptr);
}

PF_TEST(core_refuses_a_client_when_no_address_is_available) {
    ServerCoreConfig cfg = core_cfg();
    cfg.prepare_push = [](uint32_t, ServerPush&) { return false; };
    DeterministicRandom rnd(1);
    auto core = make_core(cfg, rnd);
    CoreNet n(*core);
    n.add(distinct_client(1), addr(1, 1000));
    n.run(2000);
    PF_CHECK_EQ(core->session_count(), size_t{0});
    bool setup_failed = false;
    for (const auto& r : n.received) setup_failed = setup_failed || r.reason == Drop::SetupFailed;
    PF_CHECK(setup_failed);
}
