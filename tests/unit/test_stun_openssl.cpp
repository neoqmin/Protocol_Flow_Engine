// STUN MESSAGE-INTEGRITY(-SHA256) with the OpenSSL HMAC provider: build -> verify, truncated SHA-256, ordering.
#include "pf/crypto/stun_hmac.h"
#include "pf/stun.h"
#include "pf_test.h"

using namespace pf;
using namespace pf::stun;

PF_TEST(stun_integrity_sha1_and_sha256_round_trip) {
    auto hmac = make_openssl_stun_hmac();
    const TransactionId t{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const std::string key = "test-only-short-term-password";
    const auto* k = reinterpret_cast<const uint8_t*>(key.data());
    MessageBuilder b(kMethodBinding, Class::Request, t);
    b.add_text(kAttrUsername, "user:peer").add_integrity(k, key.size(), *hmac).add_integrity_sha256(k, key.size(), *hmac).add_fingerprint();
    PF_REQUIRE(b.ok());
    Message m;
    PF_REQUIRE(parse(b.bytes().data(), b.bytes().size(), m) == ParseStatus::Ok);
    PF_CHECK(verify_integrity(b.bytes().data(), m, k, key.size(), *hmac) == IntegrityStatus::Ok);
    PF_CHECK(verify_integrity(b.bytes().data(), m, k, key.size(), *hmac, true) == IntegrityStatus::Ok);
    PF_CHECK(verify_integrity(b.bytes().data(), m, k, key.size() - 1, *hmac, true) == IntegrityStatus::Mismatch);

    // MI-SHA256 alone (no MI), and truncated to 16 bytes (RFC 8489 14.6 allows 16..32, multiples of 4)
    MessageBuilder only(kMethodBinding, Class::Request, t);
    only.add_text(kAttrUsername, "u").add_integrity_sha256(k, key.size(), *hmac);
    PF_REQUIRE(only.ok());
    std::vector<uint8_t> v = only.bytes();
    PF_REQUIRE(parse(v.data(), v.size(), m) == ParseStatus::Ok);
    PF_CHECK(verify_integrity(v.data(), m, k, key.size(), *hmac) == IntegrityStatus::Missing);
    PF_CHECK(verify_integrity(v.data(), m, k, key.size(), *hmac, true) == IntegrityStatus::Ok);
    // truncate: the MAC is computed with the header length covering the TRUNCATED attribute, so rebuild properly
    const size_t at = m.attributes[*m.integrity_sha256].offset;
    std::vector<uint8_t> tr(v.begin(), v.begin() + static_cast<long>(at));
    tr[2] = 0; tr[3] = static_cast<uint8_t>(at + 4 + 16 - kHeaderLen);
    uint8_t mac[32];
    PF_REQUIRE(hmac->hmac_sha256(k, key.size(), tr.data(), tr.size(), mac));
    tr.insert(tr.end(), {0x00, 0x1C, 0x00, 0x10});
    tr.insert(tr.end(), mac, mac + 16);
    PF_REQUIRE(parse(tr.data(), tr.size(), m) == ParseStatus::Ok);
    PF_CHECK(verify_integrity(tr.data(), m, k, key.size(), *hmac, true) == IntegrityStatus::Ok);
    tr.back() ^= 1;
    PF_CHECK(verify_integrity(tr.data(), m, k, key.size(), *hmac, true) == IntegrityStatus::Mismatch);

    // builder ordering: MI after MI-SHA256, or twice, is misuse; ordinary attributes after integrity too
    MessageBuilder wrong(kMethodBinding, Class::Request, t);
    wrong.add_integrity_sha256(k, key.size(), *hmac).add_integrity(k, key.size(), *hmac);
    PF_CHECK(!wrong.ok());
    MessageBuilder twice(kMethodBinding, Class::Request, t);
    twice.add_integrity(k, key.size(), *hmac).add_integrity(k, key.size(), *hmac);
    PF_CHECK(!twice.ok());
    MessageBuilder late(kMethodBinding, Class::Request, t);
    late.add_integrity(k, key.size(), *hmac).add_text(kAttrSoftware, "x");
    PF_CHECK(!late.ok());
}

PF_TEST(stun_integrity_rejects_wrong_lengths) {
    auto hmac = make_openssl_stun_hmac();
    const TransactionId t{};
    std::vector<uint8_t> v;
    MessageBuilder b(kMethodBinding, Class::Request, t);
    PF_REQUIRE(b.ok());
    v = b.bytes();
    v.insert(v.end(), {0x00, 0x08, 0x00, 0x10});      // MESSAGE-INTEGRITY with 16 bytes (must be 20)
    v.resize(v.size() + 16, 0);
    v[3] = 20;
    Message m;
    PF_REQUIRE(parse(v.data(), v.size(), m) == ParseStatus::Ok);
    const uint8_t key[1] = {1};
    PF_CHECK(verify_integrity(v.data(), m, key, 1, *hmac) == IntegrityStatus::Mismatch);
}
