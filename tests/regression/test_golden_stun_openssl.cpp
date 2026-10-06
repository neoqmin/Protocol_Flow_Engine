// RFC 5769 test vectors: MESSAGE-INTEGRITY with the RFC's credentials (short-term and long-term), and the builder
// reproduces each vector BYTE FOR BYTE (attributes, padding, HMAC, CRC). Requires OpenSSL.
#include <string>

#include "pf/crypto/stun_hmac.h"
#include "pf/stun.h"
#include "pf_test.h"
#include "stun_vectors.h"

using namespace pf;
using namespace pf::stun;

namespace {
std::vector<uint8_t> key_for(const pf_test::StunVector& v) {
    if (!v.long_term) return std::vector<uint8_t>(v.password.begin(), v.password.end());
    std::array<uint8_t, 16> k{};
    PF_REQUIRE(stun_long_term_key_md5(v.username, v.realm, v.password, k));
    return std::vector<uint8_t>(k.begin(), k.end());
}
}  // namespace

PF_TEST(golden_stun_message_integrity_verifies_with_the_rfc_credentials) {
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    auto hmac = make_openssl_stun_hmac();
    for (const auto& v : vs) {
        Message m;
        PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
        const auto key = key_for(v);
        PF_CHECK(verify_integrity(v.bytes.data(), m, key.data(), key.size(), *hmac) == IntegrityStatus::Ok);
        auto wrong = key;
        wrong[0] ^= 1;
        PF_CHECK(verify_integrity(v.bytes.data(), m, wrong.data(), wrong.size(), *hmac) == IntegrityStatus::Mismatch);
        PF_CHECK(verify_integrity(v.bytes.data(), m, key.data(), key.size(), *hmac, true) == IntegrityStatus::Missing);
        // a change inside the integrity-covered region that keeps the structure valid must fail the HMAC
        auto t = v.bytes;
        t[9] ^= 0x01;                                               // transaction id
        Message mt;
        const ParseStatus st = parse(t.data(), t.size(), mt);
        if (st == ParseStatus::Ok)                                   // (vectors with FINGERPRINT already fail the CRC)
            PF_CHECK(verify_integrity(t.data(), mt, key.data(), key.size(), *hmac) == IntegrityStatus::Mismatch);
        else
            PF_CHECK(st == ParseStatus::BadFingerprint);
    }
}

PF_TEST(golden_stun_builder_reproduces_the_rfc_vectors_byte_for_byte) {
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    auto hmac = make_openssl_stun_hmac();
    for (const auto& v : vs) {
        Message m;
        PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
        const auto key = key_for(v);
        MessageBuilder b(m.method, m.cls, m.tid);
        for (const auto& a : m.attributes) {
            if (a.type == kAttrMessageIntegrity) { b.add_integrity(key.data(), key.size(), *hmac); continue; }
            if (a.type == kAttrFingerprint) { b.add_fingerprint(); continue; }
            // the RFC vectors' padding bytes: take them from the vector (0x20 or 0x00)
            const size_t pad_at = a.offset + 4 + a.length;
            const uint8_t pad = (a.length % 4) ? v.bytes[pad_at] : 0;
            b.add(a.type, a.value, a.length, pad);
        }
        PF_REQUIRE(b.ok());
        PF_CHECK(b.bytes() == v.bytes);
        if (b.bytes() != v.bytes) std::fprintf(stderr, "vector %s not reproduced\n", v.name.c_str());
    }
}

PF_TEST(golden_stun_long_term_key_is_md5_of_user_realm_password) {
    // RFC 8489 9.2.2: key = MD5(username ":" realm ":" OpaqueString(password)). Cross-check through the vector's MAC:
    // a key from a differently prepared password ("The\xC2\xADM\xC2\xAAtr\xE2\x85\xA8", NOT prepared) must fail.
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    auto hmac = make_openssl_stun_hmac();
    for (const auto& v : vs) {
        if (!v.long_term) continue;
        Message m;
        PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), m) == ParseStatus::Ok);
        std::array<uint8_t, 16> raw_key{};
        PF_REQUIRE(stun_long_term_key_md5(v.username, v.realm, "The\xC2\xADM\xC2\xAAtr\xE2\x85\xA8", raw_key));
        PF_CHECK(verify_integrity(v.bytes.data(), m, raw_key.data(), raw_key.size(), *hmac) == IntegrityStatus::Mismatch);
        std::array<uint8_t, 32> k256{};
        PF_CHECK(stun_long_term_key_sha256(v.username, v.realm, v.password, k256));
    }
}

PF_TEST(golden_stun_bit_flips_that_hide_the_fingerprint_fail_integrity) {
    // Completes the FINGERPRINT bit-flip test: flips in the bytes MESSAGE-INTEGRITY covers (everything up to the end of
    // the MI attribute) that still parse (because they hid the FINGERPRINT) must not verify. Bytes after MI (the
    // FINGERPRINT attribute) are outside the authenticated region: RFC 8489 ignores what follows MI except MI-SHA256 and
    // FINGERPRINT, so flipping them changes nothing that was authenticated.
    const auto vs = pf_test::load_stun_vectors(GOLDEN_DIR);
    auto hmac = make_openssl_stun_hmac();
    size_t parsed = 0;
    for (const auto& v : vs) {
        const auto key = key_for(v);
        Message orig;
        PF_REQUIRE(parse(v.bytes.data(), v.bytes.size(), orig) == ParseStatus::Ok);
        PF_REQUIRE(orig.integrity.has_value());
        const Attribute& mi = orig.attributes[*orig.integrity];
        const size_t authenticated_end = mi.offset + 4 + mi.length;
        for (size_t i = 0; i < authenticated_end; ++i)
            for (int bit = 0; bit < 8; ++bit) {
                auto c = v.bytes;
                c[i] ^= static_cast<uint8_t>(1u << bit);
                Message m;
                if (parse(c.data(), c.size(), m) != ParseStatus::Ok) continue;
                ++parsed;
                PF_CHECK(verify_integrity(c.data(), m, key.data(), key.size(), *hmac) != IntegrityStatus::Ok);
            }
    }
    PF_CHECK(parsed > 0);
}

