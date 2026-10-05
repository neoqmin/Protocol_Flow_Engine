// TLS 1.3 over memory BIOs (the control channel carries the TLS records). Needs OpenSSL.
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include "pf/crypto/tls_session.h"
#include "pf_test.h"
#include "test_pki.h"

using namespace pf;

namespace {

const pf_test::TestPki& pki() { static pf_test::TestPki p = pf_test::make_test_pki(); return p; }

TlsConfig client_cfg() {
    TlsConfig c; c.role = TlsRole::Client;
    c.ca_pem = pki().ca_pem; c.cert_pem = pki().client_cert_pem; c.key_pem = pki().client_key_pem;
    return c;
}
TlsConfig server_cfg() {
    TlsConfig c; c.role = TlsRole::Server;
    c.ca_pem = pki().ca_pem; c.cert_pem = pki().server_cert_pem; c.key_pem = pki().server_key_pem;
    return c;
}

struct Pair {
    std::unique_ptr<TlsSession> cli, srv;
    Pair(const TlsConfig& c, const TlsConfig& s) {
        std::string err;
        cli = TlsSession::create(c, err); PF_REQUIRE(cli != nullptr);
        srv = TlsSession::create(s, err); PF_REQUIRE(srv != nullptr);
    }
    // Moves bytes between the sessions (like the control channel would) until nothing is left to do.
    void pump(size_t chunk = 0, int rounds = 20) {
        for (int i = 0; i < rounds; ++i) {
            cli->step(); srv->step();
            auto a = cli->take_output(), b = srv->take_output();
            if (a.empty() && b.empty()) break;
            feed(*srv, a, chunk); feed(*cli, b, chunk);
        }
        cli->step(); srv->step();
    }
    static void feed(TlsSession& to, const std::vector<uint8_t>& bytes, size_t chunk) {
        if (chunk == 0) { to.feed(bytes.data(), bytes.size()); return; }
        for (size_t i = 0; i < bytes.size(); i += chunk) {          // simulate small/fragmented deliveries
            to.feed(bytes.data() + i, std::min(chunk, bytes.size() - i));
            to.step();
        }
    }
};

}  // namespace

PF_TEST(tls_handshake_completes_over_memory_bios_with_tls13) {
    Pair p(client_cfg(), server_cfg());
    p.pump();
    PF_CHECK(p.cli->state() == TlsSession::State::Established);
    PF_CHECK(p.srv->state() == TlsSession::State::Established);
    PF_CHECK(p.cli->protocol_version() == "TLSv1.3");
}

PF_TEST(tls_client_hello_is_produced_before_any_input) {
    std::string err; auto cli = TlsSession::create(client_cfg(), err);
    PF_REQUIRE(cli != nullptr);
    PF_CHECK(cli->step() == TlsSession::State::Handshaking);
    auto out = cli->take_output();
    PF_REQUIRE(out.size() > 5);
    PF_CHECK_EQ(out[0], 0x16);                 // TLS record type: handshake
    PF_CHECK_EQ(out[1], 0x03);                 // record version major (what OpenVPN carries as TLS payload)
    PF_CHECK_EQ(out[5], 0x01);                 // handshake type: ClientHello
}

PF_TEST(tls_handshake_works_with_one_byte_deliveries) {
    Pair p(client_cfg(), server_cfg());
    p.pump(/*chunk=*/1, /*rounds=*/40);
    PF_CHECK(p.cli->state() == TlsSession::State::Established);
    PF_CHECK(p.srv->state() == TlsSession::State::Established);
}

PF_TEST(tls_application_data_flows_both_ways) {
    Pair p(client_cfg(), server_cfg());
    p.pump();
    const std::string hello = "PUSH_REQUEST", reply = "PUSH_REPLY,ping 2";
    PF_REQUIRE(p.cli->write(reinterpret_cast<const uint8_t*>(hello.data()), hello.size()));
    p.pump();
    auto got = p.srv->read();
    PF_CHECK(std::string(got.begin(), got.end()) == hello);
    PF_REQUIRE(p.srv->write(reinterpret_cast<const uint8_t*>(reply.data()), reply.size()));
    p.pump();
    auto back = p.cli->read();
    PF_CHECK(std::string(back.begin(), back.end()) == reply);
}

PF_TEST(tls_large_payload_survives_record_splitting) {
    Pair p(client_cfg(), server_cfg());
    p.pump();
    std::vector<uint8_t> big(100000);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 31 + 7);
    PF_REQUIRE(p.cli->write(big.data(), big.size()));
    p.pump(0, 50);
    PF_CHECK(p.srv->read() == big);
}

PF_TEST(tls_write_before_handshake_is_refused) {
    std::string err; auto cli = TlsSession::create(client_cfg(), err);
    const uint8_t b = 1;
    PF_CHECK(!cli->write(&b, 1));
    PF_CHECK(cli->read().empty());
}

PF_TEST(tls_client_rejects_server_from_untrusted_ca) {
    TlsConfig s = server_cfg(); s.cert_pem = pki().other_server_cert_pem; s.key_pem = pki().other_server_key_pem;
    Pair p(client_cfg(), s);
    p.pump();
    PF_CHECK(p.cli->state() == TlsSession::State::Failed);
    PF_CHECK(!p.cli->failure_reason().empty());
}

PF_TEST(tls_client_rejects_server_certificate_without_server_auth_eku) {
    TlsConfig s = server_cfg(); s.cert_pem = pki().wrong_eku_server_cert_pem; s.key_pem = pki().wrong_eku_server_key_pem;
    Pair p(client_cfg(), s);
    p.pump();
    PF_CHECK(p.cli->state() == TlsSession::State::Failed);
    // Same server is accepted when the EKU requirement is switched off: the check is what blocked it.
    TlsConfig c = client_cfg(); c.require_peer_eku = false;
    Pair q(c, s);
    q.pump();
    PF_CHECK(q.cli->state() == TlsSession::State::Established);
}

PF_TEST(tls_server_requires_a_client_certificate) {
    TlsConfig c = client_cfg(); c.cert_pem.clear(); c.key_pem.clear();
    Pair p(c, server_cfg());
    p.pump();
    PF_CHECK(p.srv->state() == TlsSession::State::Failed);
}

PF_TEST(tls_server_rejects_client_from_untrusted_ca) {
    TlsConfig s = server_cfg(); s.ca_pem = pki().other_ca_pem;       // server trusts a different CA
    Pair p(client_cfg(), s);
    p.pump();
    PF_CHECK(p.srv->state() == TlsSession::State::Failed);
}

PF_TEST(tls12_only_peer_is_refused_when_tls13_is_required) {
    TlsConfig s = server_cfg(); s.cap_at_tls12 = true;
    Pair p(client_cfg(), s);
    p.pump();
    PF_CHECK(p.cli->state() == TlsSession::State::Failed);
}

PF_TEST(tls_garbage_input_fails_cleanly) {
    std::string err; auto srv = TlsSession::create(server_cfg(), err);
    const uint8_t junk[64] = {0x41};
    srv->feed(junk, sizeof junk);
    PF_CHECK(srv->step() == TlsSession::State::Failed);
    PF_CHECK(srv->step() == TlsSession::State::Failed);              // stays failed
}

PF_TEST(tls_create_rejects_bad_identity_material) {
    std::string err;
    TlsConfig bad = client_cfg(); bad.key_pem = "not a key";
    PF_CHECK(TlsSession::create(bad, err) == nullptr);
    PF_CHECK(!err.empty());
    TlsConfig mismatch = server_cfg(); mismatch.key_pem = pki().client_key_pem;   // key does not match cert
    err.clear();
    PF_CHECK(TlsSession::create(mismatch, err) == nullptr);
    TlsConfig no_ca = client_cfg(); no_ca.ca_pem.clear();
    err.clear();
    PF_CHECK(TlsSession::create(no_ca, err) == nullptr);                          // refuse to run without trust anchors
}

PF_TEST(tls_exported_keying_material_matches_on_both_sides) {
    Pair p(client_cfg(), server_cfg());
    uint8_t a[64], b[64];
    PF_CHECK(!p.cli->export_keying_material("EXPORTER-OpenVPN-datakeys", nullptr, 0, a, sizeof a));   // too early
    p.pump();
    PF_REQUIRE(p.cli->export_keying_material("EXPORTER-OpenVPN-datakeys", nullptr, 0, a, sizeof a));
    PF_REQUIRE(p.srv->export_keying_material("EXPORTER-OpenVPN-datakeys", nullptr, 0, b, sizeof b));
    PF_CHECK(std::memcmp(a, b, sizeof a) == 0);
    uint8_t c[64];
    PF_REQUIRE(p.cli->export_keying_material("EXPORTER-OTHER", nullptr, 0, c, sizeof c));
    PF_CHECK(std::memcmp(a, c, sizeof a) != 0);                     // different label => different keys
    bool all_zero = true; for (auto x : a) all_zero = all_zero && x == 0;
    PF_CHECK(!all_zero);
}

PF_TEST(tls_exported_keying_material_differs_between_sessions) {
    Pair p(client_cfg(), server_cfg()), q(client_cfg(), server_cfg());
    p.pump(); q.pump();
    uint8_t a[32], b[32];
    PF_REQUIRE(p.cli->export_keying_material("L", nullptr, 0, a, sizeof a));
    PF_REQUIRE(q.cli->export_keying_material("L", nullptr, 0, b, sizeof b));
    PF_CHECK(std::memcmp(a, b, sizeof a) != 0);
}
