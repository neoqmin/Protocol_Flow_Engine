#include <cstring>
#include "pf/key_method2.h"
#include "pf_test.h"

using namespace pf;

static const char* kClientOptions = "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client";

static KeyMethod2Message sample() {
    KeyMethod2Message m;
    for (size_t i = 0; i < 48; ++i) m.pre_master[i] = static_cast<uint8_t>(0x10 + i);
    for (size_t i = 0; i < 32; ++i) { m.random1[i] = static_cast<uint8_t>(0x40 + i); m.random2[i] = static_cast<uint8_t>(0x80 + i); }
    m.options = kClientOptions;
    m.peer_info = "IV_VER=2.6.19\nIV_PLAT=linux\nIV_PROTO=14\nIV_CIPHERS=AES-256-GCM\n";
    return m;
}

PF_TEST(km2_client_message_layout_matches_documented_fields) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Client, w));
    PF_CHECK_EQ(w[0], 0); PF_CHECK_EQ(w[1], 0); PF_CHECK_EQ(w[2], 0); PF_CHECK_EQ(w[3], 0);   // literal 0 (4 bytes)
    PF_CHECK_EQ(w[4], 2);                                                                     // key method
    PF_CHECK(std::memcmp(&w[5], m.pre_master.data(), 48) == 0);                               // pre_master (client only)
    PF_CHECK(std::memcmp(&w[53], m.random1.data(), 32) == 0);
    PF_CHECK(std::memcmp(&w[85], m.random2.data(), 32) == 0);
    const size_t olen = m.options.size() + 1;                                                 // length includes the NUL
    PF_CHECK_EQ(w[117], olen >> 8); PF_CHECK_EQ(w[118], olen & 0xFF);
    PF_CHECK(std::memcmp(&w[119], m.options.data(), m.options.size()) == 0);
    PF_CHECK_EQ(w[119 + m.options.size()], 0);                                                // NUL terminator
    const size_t after = 119 + olen;
    PF_CHECK_EQ(w[after], 0); PF_CHECK_EQ(w[after + 1], 0);                                   // username: length 0
    PF_CHECK_EQ(w[after + 2], 0); PF_CHECK_EQ(w[after + 3], 0);                               // password: length 0
    const size_t plen = m.peer_info.size() + 1;
    PF_CHECK_EQ(w[after + 4], plen >> 8); PF_CHECK_EQ(w[after + 5], plen & 0xFF);             // peer info length incl NUL
    PF_CHECK_EQ(w.size(), after + 6 + plen);
    PF_CHECK_EQ(w.back(), 0);
}

PF_TEST(km2_server_message_has_no_pre_master) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Server, w));
    PF_CHECK(std::memcmp(&w[5], m.random1.data(), 32) == 0);          // key source starts directly with random1
    PF_CHECK(std::memcmp(&w[37], m.random2.data(), 32) == 0);
    std::vector<uint8_t> c;
    build_key_method2(m, KeyMethod2From::Client, c);
    PF_CHECK_EQ(c.size() - w.size(), size_t(48));
}

PF_TEST(km2_parse_round_trips_for_both_directions) {
    for (auto from : {KeyMethod2From::Client, KeyMethod2From::Server}) {
        KeyMethod2Message m = sample();
        std::vector<uint8_t> w;
        PF_REQUIRE(build_key_method2(m, from, w));
        KeyMethod2Message p; size_t used = 0;
        PF_REQUIRE(parse_key_method2(w.data(), w.size(), from, p, used) == KeyMethod2Status::Ok);
        PF_CHECK_EQ(used, w.size());
        PF_CHECK(p.options == m.options);
        PF_CHECK(p.peer_info == m.peer_info);
        PF_CHECK(p.random1 == m.random1 && p.random2 == m.random2);
        if (from == KeyMethod2From::Client) PF_CHECK(p.pre_master == m.pre_master);
        PF_CHECK(p.username.empty() && p.password.empty());
    }
}

PF_TEST(km2_parse_carries_username_and_password) {
    KeyMethod2Message m = sample(); m.username = "alice"; m.password = "s3cret";
    std::vector<uint8_t> w; KeyMethod2Message p; size_t used;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Client, w));
    PF_REQUIRE(parse_key_method2(w.data(), w.size(), KeyMethod2From::Client, p, used) == KeyMethod2Status::Ok);
    PF_CHECK(p.username == "alice"); PF_CHECK(p.password == "s3cret");
}

PF_TEST(km2_optional_trailing_fields_may_be_absent) {
    KeyMethod2Message m = sample(); m.peer_info.clear();
    std::vector<uint8_t> w;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Server, w));
    w.resize(w.size() - 6);                                            // drop username/password/peer-info length fields entirely
    KeyMethod2Message p; size_t used = 0;
    PF_REQUIRE(parse_key_method2(w.data(), w.size(), KeyMethod2From::Server, p, used) == KeyMethod2Status::Ok);
    PF_CHECK_EQ(used, w.size());
    PF_CHECK(p.peer_info.empty());
}

PF_TEST(km2_parse_reports_consumed_bytes_so_following_messages_can_be_read) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Server, w));
    const size_t n = w.size();
    const char* push = "PUSH_REPLY,ping 2";
    w.insert(w.end(), push, push + std::strlen(push) + 1);             // next control message on the same TLS stream
    KeyMethod2Message p; size_t used = 0;
    PF_REQUIRE(parse_key_method2(w.data(), w.size(), KeyMethod2From::Server, p, used) == KeyMethod2Status::Ok);
    PF_CHECK_EQ(used, n);
}

PF_TEST(km2_truncated_input_is_reported_not_misparsed) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Client, w));
    const size_t required = 5 + 112 + 2 + m.options.size() + 1;        // header + key source + options
    for (size_t n = 0; n < required; ++n) {
        KeyMethod2Message p; size_t used = 0;
        PF_CHECK(parse_key_method2(w.data(), n, KeyMethod2From::Client, p, used) == KeyMethod2Status::Truncated);
    }
    // A length field that promises more than is present is also truncation (never an out-of-bounds read).
    for (size_t n = required; n < w.size(); ++n) {
        KeyMethod2Message p; size_t used = 0;
        auto st = parse_key_method2(w.data(), n, KeyMethod2From::Client, p, used);
        PF_CHECK(st == KeyMethod2Status::Ok || st == KeyMethod2Status::Truncated);
    }
}

PF_TEST(km2_short_server_message_is_parsed_without_expecting_a_pre_master) {
    // A server message carries only 64 key-source bytes; with short options its whole length is below 5+112.
    KeyMethod2Message m = sample(); m.options = "V4"; m.peer_info.clear();
    std::vector<uint8_t> w; KeyMethod2Message p; size_t used = 0;
    PF_REQUIRE(build_key_method2(m, KeyMethod2From::Server, w));
    w.resize(5 + 64 + 2 + 3);                                         // header + random1/2 + options only
    PF_CHECK(w.size() < 5 + 112);
    PF_REQUIRE(parse_key_method2(w.data(), w.size(), KeyMethod2From::Server, p, used) == KeyMethod2Status::Ok);
    PF_CHECK(p.options == "V4");
    for (size_t n = 0; n < w.size(); ++n)
        PF_CHECK(parse_key_method2(w.data(), n, KeyMethod2From::Server, p, used) == KeyMethod2Status::Truncated);
}

PF_TEST(km2_rejects_bad_header_and_unsupported_method) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w; KeyMethod2Message p; size_t used;
    build_key_method2(m, KeyMethod2From::Client, w);
    auto bad = w; bad[2] = 1;
    PF_CHECK(parse_key_method2(bad.data(), bad.size(), KeyMethod2From::Client, p, used) == KeyMethod2Status::BadHeader);
    bad = w; bad[4] = 1;                                                // key method 1 is not supported
    PF_CHECK(parse_key_method2(bad.data(), bad.size(), KeyMethod2From::Client, p, used) == KeyMethod2Status::UnsupportedMethod);
}

PF_TEST(km2_rejects_unterminated_or_empty_options) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w; KeyMethod2Message p; size_t used;
    build_key_method2(m, KeyMethod2From::Server, w);
    auto bad = w; bad[71 + m.options.size()] = 'X';                     // overwrite the NUL (offset: 5 + 64 + 2 + n)
    PF_CHECK(parse_key_method2(bad.data(), bad.size(), KeyMethod2From::Server, p, used) == KeyMethod2Status::Malformed);
    bad = w; bad[69] = 0; bad[70] = 0;                                  // options length field (offset 5 + 64) = 0: must include the NUL
    PF_CHECK(parse_key_method2(bad.data(), bad.size(), KeyMethod2From::Server, p, used) == KeyMethod2Status::Malformed);
}

PF_TEST(km2_build_rejects_oversized_or_embedded_nul_strings) {
    KeyMethod2Message m = sample();
    std::vector<uint8_t> w;
    m.options.assign(70000, 'a');
    PF_CHECK(!build_key_method2(m, KeyMethod2From::Client, w));
    m = sample(); m.options = std::string("ab\0cd", 5);
    PF_CHECK(!build_key_method2(m, KeyMethod2From::Client, w));
    m = sample(); m.options.clear();
    PF_CHECK(!build_key_method2(m, KeyMethod2From::Client, w));        // empty options are not allowed
}

PF_TEST(km2_parse_sweep_never_reads_out_of_bounds) {  // meaningful under ASan
    for (int seed = 0; seed < 64; ++seed)
        for (size_t len = 0; len <= 200; ++len) {
            std::vector<uint8_t> w(len);
            for (size_t i = 0; i < len; ++i) w[i] = static_cast<uint8_t>((i * 37 + seed) & ((i < 5) ? 0x02 : 0xFF));
            KeyMethod2Message p; size_t used;
            (void)parse_key_method2(w.data(), w.size(), seed % 2 ? KeyMethod2From::Client : KeyMethod2From::Server, p, used);
        }
}
