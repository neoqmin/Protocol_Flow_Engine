// RFC 5769 test vectors through the STUN codec: structure, FINGERPRINT, addresses (no key needed; integrity is in
// test_golden_stun_openssl.cpp). GOLDEN_DIR is injected by CMake.
#include <string>

#include "pf/stun.h"
#include "pf_test.h"
#include "stun_vectors.h"

using namespace pf;
using namespace pf::stun;

namespace {
const pf_test::StunVector& vec(const std::vector<pf_test::StunVector>& vs, const char* name) {
    for (const auto& v : vs) if (v.name == name) return v;
    PF_REQUIRE(false);
    return vs[0];
}
std::string text(const Message& m, uint16_t type) {
    const Attribute* a = m.find(type);
    return a ? std::string(attribute_text(*a)) : std::string("<absent>");
}
}  // namespace

PF_TEST(golden_stun_request_2_1_parses_with_fingerprint) {
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    const auto& v = vec(vs, "request_2_1");
    Message m;
    PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
    PF_CHECK_EQ(m.method, kMethodBinding);
    PF_CHECK(m.cls == Class::Request);
    PF_CHECK_EQ(m.size, size_t{108});
    PF_CHECK_EQ(text(m, kAttrSoftware), std::string("STUN test client"));
    PF_CHECK_EQ(text(m, kAttrUsername), std::string("evtj:h6vY"));
    PF_CHECK(m.integrity.has_value());
    PF_CHECK(m.fingerprint.has_value());
    PF_CHECK_EQ(m.attributes.size(), size_t{6});            // SOFTWARE PRIORITY ICE-CONTROLLED USERNAME MI FINGERPRINT
    // PRIORITY (0x0024) is an ICE attribute this codec does not implement: comprehension-required, so reported
    PF_REQUIRE(m.unknown_required.size() == 1);
    PF_CHECK_EQ(m.unknown_required[0], uint16_t{0x0024});
    PF_CHECK(looks_like_stun(v.bytes.data(), v.bytes.size()));
}

PF_TEST(golden_stun_responses_2_2_and_2_3_carry_the_documented_mapped_address) {
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    struct Want { const char* name; const char* addr; };
    for (const Want w : {Want{"response_ipv4_2_2", "192.0.2.1:32853"}, Want{"response_ipv6_2_3", "[2001:db8:1234:5678:11:2233:4455:6677]:32853"}}) {
        const auto& v = vec(vs, w.name);
        Message m;
        PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
        PF_CHECK(m.cls == Class::Success);
        PF_CHECK_EQ(m.method, kMethodBinding);
        PF_CHECK_EQ(text(m, kAttrSoftware), std::string("test vector"));
        const Attribute* x = m.find(kAttrXorMappedAddress);
        PF_REQUIRE(x != nullptr);
        Address a;
        PF_REQUIRE(decode_xor_address(*x, m.tid, a));
        PF_CHECK_EQ(a.to_string(), std::string(w.addr));
        PF_CHECK(m.unknown_required.empty());
        PF_CHECK(m.fingerprint.has_value());
    }
}

PF_TEST(golden_stun_long_term_request_2_4_parses) {
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    const auto& v = vec(vs, "request_long_term_2_4");
    Message m;
    PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
    PF_CHECK_EQ(text(m, kAttrUsername), v.username);              // U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9
    PF_CHECK_EQ(text(m, kAttrRealm), std::string("example.org"));
    PF_CHECK_EQ(text(m, kAttrNonce), std::string("f//499k954d6OL34oL9FSTvy64sA"));
    PF_CHECK(m.integrity.has_value());
    PF_CHECK(!m.fingerprint.has_value());
}

PF_TEST(golden_stun_bit_flips_never_pass_a_fingerprint_check) {
    // For every single-bit corruption of a vector that carries a FINGERPRINT: either the parse fails, or the corrupted
    // message no longer HAS a fingerprint (a flipped length can swallow it into another attribute, or a flipped type
    // turn it into an ignored attribute; such messages then fail MESSAGE-INTEGRITY instead, see the OpenSSL test).
    // A corrupted message that still presents a FINGERPRINT is never accepted.
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    size_t checked = 0, rejected = 0, hidden = 0;
    for (const auto& v : vs) {
        Message m;
        PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
        if (!m.fingerprint) continue;
        for (size_t i = 0; i < v.bytes.size(); ++i)
            for (int bit = 0; bit < 8; ++bit) {
                auto c = v.bytes;
                c[i] ^= static_cast<uint8_t>(1u << bit);
                Message mm;
                const ParseStatus st = parse(c.data(), c.size(), mm);
                ++checked;
                if (st != ParseStatus::Ok) { ++rejected; continue; }
                PF_CHECK(!mm.fingerprint.has_value());
                ++hidden;
            }
    }
    PF_CHECK(checked > 2000);
    PF_CHECK(rejected > checked * 9 / 10);
    std::printf("bit flips: %zu checked, %zu rejected, %zu hid the fingerprint\n", checked, rejected, hidden);
}
