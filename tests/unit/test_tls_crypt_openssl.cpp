// Requires OpenSSL.
#include <cstring>
#include <string>
#include <vector>
#include "pf/crypto/tls_crypt.h"
#include "pf_test.h"

using namespace pf;

static std::string key_text(uint8_t seed) {
    std::string s = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n";
    for (int line = 0; line < 16; ++line) {
        for (int i = 0; i < 16; ++i) {
            char b[3]; std::snprintf(b, sizeof b, "%02x", static_cast<uint8_t>(seed + line * 16 + i));
            s += b;
        }
        s += "\n";
    }
    return s + "-----END OpenVPN Static key V1-----\n";
}

static std::array<uint8_t, kTlsCryptStaticKeyLen> test_key(uint8_t seed = 1) {
    std::array<uint8_t, kTlsCryptStaticKeyLen> k{};
    PF_REQUIRE(parse_static_key_file(key_text(seed), k));
    return k;
}

static const uint8_t SID[8] = {1, 2, 3, 4, 5, 6, 7, 8};

PF_TEST(static_key_file_is_parsed_to_256_bytes) {
    auto k = test_key(0);
    PF_CHECK_EQ(k[0], 0); PF_CHECK_EQ(k[1], 1); PF_CHECK_EQ(k[255], 255);
}

PF_TEST(static_key_file_rejects_bad_input) {
    std::array<uint8_t, kTlsCryptStaticKeyLen> k{};
    PF_CHECK(!parse_static_key_file("", k));
    PF_CHECK(!parse_static_key_file("-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----\n", k));   // too short
    std::string t = key_text(0); t.replace(t.find("-----END"), 8, "-----XXX");
    PF_CHECK(!parse_static_key_file(t, k));                                            // no END marker
    std::string u = key_text(0); u[u.find("\n0") + 1 + 3] = 'z';                       // non-hex digit
    PF_CHECK(!parse_static_key_file(u, k));
}

PF_TEST(client_and_server_role_keys_are_mirrored_and_use_documented_blocks) {
    auto k = test_key(0);
    TlsCryptKeys c = derive_tls_crypt_keys(k, TlsCryptRole::Client);
    TlsCryptKeys s = derive_tls_crypt_keys(k, TlsCryptRole::Server);
    PF_CHECK(c.tx.cipher == s.rx.cipher && c.tx.hmac == s.rx.hmac);
    PF_CHECK(c.rx.cipher == s.tx.cipher && c.rx.hmac == s.tx.hmac);
    PF_CHECK(c.tx.cipher != c.rx.cipher);
    // client tx = (K2, K3), rx = (K0, K1); each uses the first 32 bytes of its 64-byte block
    PF_CHECK_EQ(c.tx.cipher[0], 128); PF_CHECK_EQ(c.tx.hmac[0], 192);
    PF_CHECK_EQ(c.rx.cipher[0], 0);   PF_CHECK_EQ(c.rx.hmac[0], 64);
}

PF_TEST(seal_produces_documented_layout_and_open_round_trips) {
    TlsCryptKeys c = derive_tls_crypt_keys(test_key(), TlsCryptRole::Client);
    const std::vector<uint8_t> pt = {0, 0, 0, 0, 0};
    std::vector<uint8_t> wire;
    PF_REQUIRE(tls_crypt_seal(c.tx, 0x38, SID, 7, 0x11223344, pt.data(), pt.size(), wire));
    PF_CHECK_EQ(wire.size(), kTlsCryptOverhead + pt.size());
    PF_CHECK_EQ(wire[0], 0x38);
    PF_CHECK(std::memcmp(wire.data() + 1, SID, 8) == 0);
    PF_CHECK_EQ(wire[12], 7);                                         // packet_id big endian
    PF_CHECK_EQ(wire[13], 0x11); PF_CHECK_EQ(wire[16], 0x44);         // net_time
    TlsCryptKeys s = derive_tls_crypt_keys(test_key(), TlsCryptRole::Server);
    TlsCryptPlain out;
    PF_REQUIRE(tls_crypt_open(s.rx, wire.data(), wire.size(), out) == TlsCryptStatus::Ok);
    PF_CHECK(out.payload == pt);
    PF_CHECK_EQ(out.packet_id, 7u);
    PF_CHECK_EQ(out.net_time, 0x11223344u);
    PF_CHECK_EQ(out.op_keyid, 0x38);
    PF_CHECK(std::memcmp(out.session_id, SID, 8) == 0);
}

PF_TEST(seal_is_deterministic_and_hides_plaintext) {
    TlsCryptKeys c = derive_tls_crypt_keys(test_key(), TlsCryptRole::Client);
    std::vector<uint8_t> pt(32, 0x41), a, b;
    tls_crypt_seal(c.tx, 0x20, SID, 1, 5, pt.data(), pt.size(), a);
    tls_crypt_seal(c.tx, 0x20, SID, 1, 5, pt.data(), pt.size(), b);
    PF_CHECK(a == b);
    PF_CHECK(std::memcmp(a.data() + kTlsCryptOverhead, pt.data(), pt.size()) != 0);
    std::vector<uint8_t> c2;
    tls_crypt_seal(c.tx, 0x20, SID, 2, 5, pt.data(), pt.size(), c2);   // new packet-id => new tag and ciphertext
    PF_CHECK(std::memcmp(a.data() + 17, c2.data() + 17, 32) != 0);
}

PF_TEST(open_rejects_any_modified_byte) {
    TlsCryptKeys c = derive_tls_crypt_keys(test_key(), TlsCryptRole::Client);
    TlsCryptKeys s = derive_tls_crypt_keys(test_key(), TlsCryptRole::Server);
    std::vector<uint8_t> pt = {9, 8, 7, 6, 5, 4, 3}, wire;
    PF_REQUIRE(tls_crypt_seal(c.tx, 0x20, SID, 1, 5, pt.data(), pt.size(), wire));
    for (size_t i = 0; i < wire.size(); ++i) {
        auto w = wire; w[i] ^= 0x01;
        TlsCryptPlain out;
        PF_CHECK(tls_crypt_open(s.rx, w.data(), w.size(), out) == TlsCryptStatus::AuthFailed);
    }
}

PF_TEST(open_rejects_wrong_key_and_wrong_direction) {
    TlsCryptKeys c = derive_tls_crypt_keys(test_key(1), TlsCryptRole::Client);
    TlsCryptKeys other = derive_tls_crypt_keys(test_key(2), TlsCryptRole::Server);
    TlsCryptKeys s = derive_tls_crypt_keys(test_key(1), TlsCryptRole::Server);
    std::vector<uint8_t> wire; uint8_t pt = 1;
    tls_crypt_seal(c.tx, 0x20, SID, 1, 5, &pt, 1, wire);
    TlsCryptPlain out;
    PF_CHECK(tls_crypt_open(other.rx, wire.data(), wire.size(), out) == TlsCryptStatus::AuthFailed);
    PF_CHECK(tls_crypt_open(s.tx, wire.data(), wire.size(), out) == TlsCryptStatus::AuthFailed);   // server tx != client tx
}

PF_TEST(open_rejects_truncated_input) {
    TlsCryptKeys s = derive_tls_crypt_keys(test_key(), TlsCryptRole::Server);
    std::vector<uint8_t> w(kTlsCryptOverhead - 1, 0);
    TlsCryptPlain out;
    for (size_t n = 0; n < kTlsCryptOverhead; ++n)
        PF_CHECK(tls_crypt_open(s.rx, w.data(), n, out) == TlsCryptStatus::Truncated);
    PF_CHECK(tls_crypt_open(s.rx, nullptr, 0, out) == TlsCryptStatus::Truncated);
}

PF_TEST(empty_payload_is_supported) {
    TlsCryptKeys c = derive_tls_crypt_keys(test_key(), TlsCryptRole::Client);
    TlsCryptKeys s = derive_tls_crypt_keys(test_key(), TlsCryptRole::Server);
    std::vector<uint8_t> wire;
    PF_REQUIRE(tls_crypt_seal(c.tx, 0x28, SID, 1, 1, nullptr, 0, wire));
    PF_CHECK_EQ(wire.size(), kTlsCryptOverhead);
    TlsCryptPlain out;
    PF_CHECK(tls_crypt_open(s.rx, wire.data(), wire.size(), out) == TlsCryptStatus::Ok);
    PF_CHECK_EQ(out.payload.size(), size_t(0));
}

PF_TEST(channel_assigns_increasing_packet_ids_starting_at_one) {
    TlsCryptChannel tx(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    std::vector<uint8_t> a, b;
    PF_REQUIRE(tx.wrap(0x20, SID, nullptr, 0, 100, a));
    PF_REQUIRE(tx.wrap(0x20, SID, nullptr, 0, 100, b));
    PF_CHECK_EQ(a[12], 1); PF_CHECK_EQ(b[12], 2);
}

PF_TEST(channel_round_trip_between_client_and_server) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    TlsCryptChannel srv(derive_tls_crypt_keys(test_key(), TlsCryptRole::Server));
    const std::vector<uint8_t> m = {1, 2, 3};
    std::vector<uint8_t> w; TlsCryptPlain out;
    PF_REQUIRE(cli.wrap(0x20, SID, m.data(), m.size(), 50, w));
    PF_CHECK(srv.unwrap(w.data(), w.size(), out) == TlsCryptStatus::Ok);
    PF_CHECK(out.payload == m);
    PF_REQUIRE(srv.wrap(0x20, SID, m.data(), m.size(), 50, w));
    PF_CHECK(cli.unwrap(w.data(), w.size(), out) == TlsCryptStatus::Ok);
}

PF_TEST(channel_rejects_replayed_packets_but_accepts_reordering_in_window) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    TlsCryptChannel srv(derive_tls_crypt_keys(test_key(), TlsCryptRole::Server));
    std::vector<uint8_t> w1, w2, w3; TlsCryptPlain out;
    cli.wrap(0x20, SID, nullptr, 0, 50, w1); cli.wrap(0x20, SID, nullptr, 0, 50, w2); cli.wrap(0x20, SID, nullptr, 0, 50, w3);
    PF_CHECK(srv.unwrap(w3.data(), w3.size(), out) == TlsCryptStatus::Ok);   // arrives first
    PF_CHECK(srv.unwrap(w1.data(), w1.size(), out) == TlsCryptStatus::Ok);   // late but inside the window
    PF_CHECK(srv.unwrap(w3.data(), w3.size(), out) == TlsCryptStatus::Replay);
    PF_CHECK(srv.unwrap(w1.data(), w1.size(), out) == TlsCryptStatus::Replay);
    PF_CHECK(srv.unwrap(w2.data(), w2.size(), out) == TlsCryptStatus::Ok);
}

PF_TEST(channel_forged_packet_does_not_advance_replay_state) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    TlsCryptChannel srv(derive_tls_crypt_keys(test_key(), TlsCryptRole::Server));
    std::vector<uint8_t> good, forged; TlsCryptPlain out;
    cli.wrap(0x20, SID, nullptr, 0, 50, good);
    forged = good; forged[12] = 0xFF; forged[3] ^= 1;         // bogus packet-id, tag no longer valid
    PF_CHECK(srv.unwrap(forged.data(), forged.size(), out) == TlsCryptStatus::AuthFailed);
    PF_CHECK(srv.unwrap(good.data(), good.size(), out) == TlsCryptStatus::Ok);
}

PF_TEST(channel_rejects_older_net_time_after_newer_one_was_accepted) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    TlsCryptChannel srv(derive_tls_crypt_keys(test_key(), TlsCryptRole::Server));
    std::vector<uint8_t> a, b; TlsCryptPlain out;
    cli.wrap(0x20, SID, nullptr, 0, 100, a);
    cli.wrap(0x20, SID, nullptr, 0, 90, b);                  // sender clock went backwards
    PF_CHECK(srv.unwrap(a.data(), a.size(), out) == TlsCryptStatus::Ok);
    PF_CHECK(srv.unwrap(b.data(), b.size(), out) == TlsCryptStatus::Replay);
}

PF_TEST(channel_accepts_newer_net_time_and_restarts_window) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    TlsCryptChannel srv(derive_tls_crypt_keys(test_key(), TlsCryptRole::Server));
    std::vector<uint8_t> a, b; TlsCryptPlain out;
    cli.wrap(0x20, SID, nullptr, 0, 100, a);
    cli.wrap(0x20, SID, nullptr, 0, 101, b);
    PF_CHECK(srv.unwrap(a.data(), a.size(), out) == TlsCryptStatus::Ok);
    PF_CHECK(srv.unwrap(b.data(), b.size(), out) == TlsCryptStatus::Ok);
    PF_CHECK(srv.unwrap(a.data(), a.size(), out) == TlsCryptStatus::Replay);   // older time now rejected
}

PF_TEST(channel_refuses_to_wrap_when_packet_id_space_is_exhausted) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    cli.set_next_packet_id_for_test(0xFFFFFFFFu);
    std::vector<uint8_t> w;
    PF_CHECK(cli.wrap(0x20, SID, nullptr, 0, 1, w));
    PF_CHECK(!cli.wrap(0x20, SID, nullptr, 0, 1, w));          // never reuse (key, iv) material
}

PF_TEST(tls_crypt_open_checks_replay_without_changing_state_until_commit) {
    TlsCryptChannel cli(derive_tls_crypt_keys(test_key(), TlsCryptRole::Client));
    TlsCryptChannel srv(derive_tls_crypt_keys(test_key(), TlsCryptRole::Server));
    const uint8_t sid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t pl[3] = {9, 9, 9};
    std::vector<uint8_t> later, earlier;
    PF_REQUIRE(cli.wrap(0x38, sid, pl, sizeof pl, 2000, later));
    PF_REQUIRE(cli.wrap(0x38, sid, pl, sizeof pl, 1000, earlier));
    TlsCryptPlain p;
    PF_CHECK(srv.open(later.data(), later.size(), p) == TlsCryptStatus::Ok);       // not committed:
    PF_CHECK(srv.open(earlier.data(), earlier.size(), p) == TlsCryptStatus::Ok);   // the earlier time still passes
    PF_CHECK(srv.open(later.data(), later.size(), p) == TlsCryptStatus::Ok);       // and so does the same packet again
    srv.commit(p.net_time, p.packet_id);
    PF_CHECK(srv.open(later.data(), later.size(), p) == TlsCryptStatus::Replay);
    PF_CHECK(srv.open(earlier.data(), earlier.size(), p) == TlsCryptStatus::Replay);  // older window now
    srv.commit(1000, 2);                                                           // a stale commit changes nothing
    PF_CHECK(srv.open(later.data(), later.size(), p) == TlsCryptStatus::Replay);
}
