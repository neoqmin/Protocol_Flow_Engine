// B3: transport fallback end to end in memory. A UDP-blocking "firewall" is a LoopbackLink that silently drops
// everything; the FallbackConnector must notice only through the missing answers (D-032), move to TCP, and still
// refuse to "fall back" from an answer the server really gave. Needs OpenSSL.
#include <map>
#include <memory>
#include <vector>

#include "control_rig.h"
#include "pf/fallback_connector.h"
#include "pf/loopback_transport.h"

using namespace pf;
using namespace pf_test;

namespace {

// Per transport kind: a link plus an unmodified-behavior fake server attached to its far end.
struct World {
    struct Side {
        std::shared_ptr<LoopbackLink> link = std::make_shared<LoopbackLink>();
        std::unique_ptr<LoopbackTransport> server_end;
        std::unique_ptr<FakeServer> server;
        unsigned opened = 0;
        bool refuse = false;              // factory fails (connect refused / unreachable)
    };
    std::map<TransportKind, Side> sides;
    KeyStore keys;
    std::vector<TransportKind> opened_order;
    FakeServerConfig scfg = server_cfg();
    std::function<void(ControlClientConfig&)> tweak_client;      // per-test client settings

    Side& side(TransportKind k) { return sides[k]; }

    FallbackConnector::TransportFactory transport_factory() {
        return [this](TransportKind k, std::string& err) -> std::unique_ptr<Transport> {
            Side& s = sides[k];
            opened_order.push_back(k);
            ++s.opened;
            if (s.refuse) { err = "connection refused"; return nullptr; }
            // A fresh link per attempt keeps the block/refuse settings but drops queued leftovers.
            const bool was_blocked = s.link->blocked_for_test();
            s.link = std::make_shared<LoopbackLink>();
            s.link->block(was_blocked);
            auto pair = LoopbackTransport::make_pair(s.link, k);
            s.server_end = std::move(pair.second);
            s.server = std::make_unique<FakeServer>(scfg);
            return std::move(pair.first);
        };
    }
    FallbackConnector::ClientFactory client_factory() {
        return [this](TransportKind, std::string&) {
            ControlClientConfig c = client_cfg(&keys);
            if (tweak_client) tweak_client(c);
            return ControlClient::create(std::move(c), err_);
        };
    }
    // Server side of every live link: deliver what arrived, send what the fake server answers.
    void pump(uint64_t now, uint32_t unix_s) {
        for (auto& kv : sides) {
            Side& s = kv.second;
            if (!s.server_end) continue;
            uint8_t buf[2048];
            for (;;) {
                const RecvResult r = s.server_end->recv(buf, sizeof buf);
                if (r.status != TransportStatus::Ok) break;
                for (auto& d : s.server->on_datagram(buf, r.len, now, unix_s)) s.server_end->send(d.data(), d.size());
            }
            for (auto& d : s.server->poll(now, unix_s)) s.server_end->send(d.data(), d.size());
        }
    }
    std::string err_;
};

// Drives connector + world with a simulated clock until done or `limit_ms`.
uint64_t run(FallbackConnector& c, World& w, uint64_t limit_ms, uint64_t step_ms = 50) {
    uint64_t now = 1000;
    const uint32_t unix_s = 1790000000;
    c.start(now, unix_s);
    const uint64_t t0 = now;
    while (!c.done() && now - t0 < limit_ms) {
        w.pump(now, unix_s);
        c.step(now, unix_s);
        w.pump(now, unix_s);
        now += step_ms;
    }
    return now - t0;
}
}  // namespace

PF_TEST(fallback_udp_works_first_try_and_tcp_is_never_opened) {
    World w;
    FallbackConnector c(FallbackPolicy::default_policy(), w.transport_factory(), w.client_factory());
    run(c, w, 30000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Connected);
    PF_CHECK(c.current_kind() == TransportKind::Udp);
    PF_CHECK_EQ(w.side(TransportKind::Tcp).opened, 0u);
    PF_REQUIRE(c.history().size() == 1);
    PF_CHECK(c.history()[0].ok);
    auto t = c.take_transport();
    auto cl = c.take_client();
    PF_CHECK(t != nullptr && t->kind() == TransportKind::Udp);
    PF_CHECK(cl != nullptr && cl->state() == ControlClient::State::Established);
}

PF_TEST(fallback_udp_blocked_silently_moves_to_tcp_after_the_deadline) {
    World w;
    w.side(TransportKind::Udp).link->block(true);                      // firewall drops UDP: no error, no answer
    FallbackPolicy pol = FallbackPolicy::default_policy();
    pol.set_connect_timeout_ms(3000);
    FallbackConnector c(pol, w.transport_factory(), w.client_factory());
    const uint64_t took = run(c, w, 60000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Connected);
    PF_CHECK(c.current_kind() == TransportKind::Tcp);
    PF_REQUIRE(c.history().size() == 2);
    PF_CHECK(c.history()[0].kind == TransportKind::Udp && !c.history()[0].ok);
    PF_CHECK(c.history()[0].outcome.find("timeout") != std::string::npos);
    PF_CHECK(c.history()[1].kind == TransportKind::Tcp && c.history()[1].ok);
    PF_CHECK(took >= 3000 && took < 3000 + 2000);                      // one deadline spent on UDP, TCP handshake is quick
    PF_CHECK(w.side(TransportKind::Udp).link->dropped() > 0);          // the client really did try UDP
    // Keys came from the TCP session and are usable.
    PF_CHECK(w.keys.get(w.keys.tx_for_key_id(0)) != nullptr);
}

PF_TEST(fallback_connect_refused_skips_to_next_transport_immediately) {
    World w;
    w.side(TransportKind::Udp).refuse = true;                          // e.g. network unreachable at socket level
    FallbackConnector c(FallbackPolicy::default_policy(), w.transport_factory(), w.client_factory());
    const uint64_t took = run(c, w, 30000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Connected);
    PF_CHECK(c.current_kind() == TransportKind::Tcp);
    PF_CHECK(took < 2000);                                             // no deadline waited
    PF_CHECK(c.history()[0].outcome.find("connect failed: connection refused") != std::string::npos);
}

PF_TEST(fallback_everything_blocked_ends_exhausted_with_every_reason) {
    World w;
    w.side(TransportKind::Udp).link->block(true);
    w.side(TransportKind::Tcp).link->block(true);
    FallbackPolicy pol({TransportKind::Udp, TransportKind::Tcp});
    pol.set_connect_timeout_ms(1500);
    FallbackConnector c(pol, w.transport_factory(), w.client_factory());
    const uint64_t took = run(c, w, 60000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Failed);
    PF_CHECK(took >= 3000 && took < 3600);                              // two deadlines, nothing more
    PF_CHECK(c.failure_reason().find("udp") != std::string::npos);
    PF_CHECK(c.failure_reason().find("tcp") != std::string::npos);
    PF_CHECK_EQ(c.history().size(), 2u);
    PF_CHECK(c.take_transport() == nullptr);
}

PF_TEST(fallback_control_client_giving_up_on_a_silent_path_counts_as_unreachable_not_rejected) {
    // The attempt deadline is far away; the ControlClient's own retransmission budget runs out first. That failure is
    // "nobody answered", so the next transport must still be tried (a Rejected failure would stop everything).
    World w;
    w.side(TransportKind::Udp).link->block(true);
    w.tweak_client = [](ControlClientConfig& c) { c.reliable.rto_ms = 200; c.reliable.max_rto_ms = 400; c.reliable.max_attempts = 3; };
    FallbackPolicy pol({TransportKind::Udp, TransportKind::Tcp});
    pol.set_connect_timeout_ms(600000);
    FallbackConnector c(pol, w.transport_factory(), w.client_factory());
    const uint64_t took = run(c, w, 120000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Connected);
    PF_CHECK(c.current_kind() == TransportKind::Tcp);
    PF_CHECK(took < 5000);                                              // far below the 600 s deadline
    PF_REQUIRE(!c.history().empty());
    PF_CHECK(c.history()[0].outcome.find("control channel failed") != std::string::npos);
}

PF_TEST(fallback_retries_the_same_transport_before_moving_on) {
    World w;
    w.side(TransportKind::Udp).link->block(true);
    FallbackPolicy pol({TransportKind::Udp, TransportKind::Tcp}, 2);   // two UDP attempts
    pol.set_connect_timeout_ms(1000);
    FallbackConnector c(pol, w.transport_factory(), w.client_factory());
    run(c, w, 60000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Connected);
    PF_CHECK_EQ(w.side(TransportKind::Udp).opened, 2u);
    PF_CHECK_EQ(w.side(TransportKind::Tcp).opened, 1u);
    PF_CHECK(c.current_kind() == TransportKind::Tcp);
}

PF_TEST(fallback_transport_closed_mid_handshake_fails_the_attempt_not_the_session) {
    World w;
    FallbackConnector c(FallbackPolicy::default_policy(), w.transport_factory(), w.client_factory());
    uint64_t now = 1000;
    c.start(now, 1790000000);
    w.pump(now, 1790000000);
    c.step(now, 1790000000);
    w.side(TransportKind::Udp).link->close_link();                     // the path dies (e.g. ICMP/RST equivalent)
    now += 50;
    c.step(now, 1790000000);                                           // notices Closed -> next transport
    PF_CHECK(c.history().size() == 1 && !c.history()[0].ok);
    PF_CHECK(c.current_kind() == TransportKind::Tcp);
    while (!c.done() && now < 30000) { now += 50; w.pump(now, 1790000000); c.step(now, 1790000000); w.pump(now, 1790000000); }
    PF_CHECK(c.state() == FallbackConnector::State::Connected);
}

PF_TEST(fallback_does_not_fall_back_from_an_answer_the_server_really_gave) {
    World w;
    w.scfg.send_instead_of_push = "AUTH_FAILED";                       // reachable server, rejects us
    FallbackConnector c(FallbackPolicy::default_policy(), w.transport_factory(), w.client_factory());
    run(c, w, 30000);
    PF_REQUIRE(c.state() == FallbackConnector::State::Failed);
    PF_CHECK(c.failure_reason().find("AUTH_FAILED") != std::string::npos);
    PF_CHECK_EQ(w.side(TransportKind::Tcp).opened, 0u);                // TCP would only get the same refusal
}

PF_TEST(fallback_wrong_tls_crypt_key_is_indistinguishable_from_a_blocked_path_so_it_falls_back_then_fails) {
    // A server that cannot authenticate our packets stays silent (tls-crypt drops them): looks like a block.
    World w;
    w.scfg = server_cfg(9);                                            // different static key
    FallbackPolicy pol = FallbackPolicy::default_policy();
    pol.set_connect_timeout_ms(1500);
    FallbackConnector c(pol, w.transport_factory(), w.client_factory());
    run(c, w, 60000);
    PF_CHECK(c.state() == FallbackConnector::State::Failed);
    PF_CHECK(w.side(TransportKind::Tcp).opened >= 1u);                 // it did try the next transport
}

PF_TEST(fallback_next_wakeup_reports_the_attempt_deadline) {
    World w;
    w.side(TransportKind::Udp).link->block(true);
    FallbackPolicy pol = FallbackPolicy::default_policy();
    pol.set_connect_timeout_ms(5000);
    FallbackConnector c(pol, w.transport_factory(), w.client_factory());
    c.start(1000, 1790000000);
    const auto wk = c.next_wakeup_ms(1000);
    PF_REQUIRE(wk.has_value());
    PF_CHECK(*wk <= 6000);
    c.step(1000, 1790000000);
    PF_CHECK(!c.done());
}
