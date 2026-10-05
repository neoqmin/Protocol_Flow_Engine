// Requires OpenSSL (built only when PF_WITH_OPENSSL is enabled).
#include <cstring>
#include <string>
#include <vector>
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf_test.h"

using namespace pf;

static std::vector<uint8_t> hex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}

// NIST GCM spec Test Case 16 (AES-256, 96-bit IV, with AAD); also cross-checked with an independent implementation.
struct Tc16 {
    std::vector<uint8_t> key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    std::vector<uint8_t> iv = hex("cafebabefacedbaddecaf888");
    std::vector<uint8_t> pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    std::vector<uint8_t> aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    std::vector<uint8_t> ct = hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
    std::vector<uint8_t> tag = hex("76fc6ece0f4e1768cddf8853bb2d551b");
};

PF_TEST(aesgcm_encrypt_matches_nist_vector) {
    Tc16 t; auto aead = make_openssl_aes256gcm();
    std::vector<uint8_t> buf = t.pt; uint8_t tag[16];
    PF_REQUIRE(aead->encrypt(t.key.data(), t.iv.data(), t.aad.data(), t.aad.size(), buf.data(), buf.size(), tag));
    PF_CHECK(buf == t.ct);
    PF_CHECK(std::memcmp(tag, t.tag.data(), 16) == 0);
}

PF_TEST(aesgcm_decrypt_in_place_matches_nist_vector) {
    Tc16 t; auto aead = make_openssl_aes256gcm();
    std::vector<uint8_t> buf = t.ct;
    PF_REQUIRE(aead->decrypt(t.key.data(), t.iv.data(), t.aad.data(), t.aad.size(), buf.data(), buf.size(), t.tag.data()));
    PF_CHECK(buf == t.pt);
}

PF_TEST(aesgcm_rejects_modified_ciphertext_and_wipes_output) {
    Tc16 t; auto aead = make_openssl_aes256gcm();
    std::vector<uint8_t> buf = t.ct; buf[3] ^= 1;
    PF_CHECK(!aead->decrypt(t.key.data(), t.iv.data(), t.aad.data(), t.aad.size(), buf.data(), buf.size(), t.tag.data()));
    for (auto b : buf) PF_REQUIRE(b == 0);    // unauthenticated plaintext must not be released
}

PF_TEST(aesgcm_rejects_modified_tag_and_aad_and_key_and_nonce) {
    Tc16 t; auto aead = make_openssl_aes256gcm();
    { auto b = t.ct; auto tag = t.tag; tag[15] ^= 0x80;
      PF_CHECK(!aead->decrypt(t.key.data(), t.iv.data(), t.aad.data(), t.aad.size(), b.data(), b.size(), tag.data())); }
    { auto b = t.ct; auto a = t.aad; a[0] ^= 1;
      PF_CHECK(!aead->decrypt(t.key.data(), t.iv.data(), a.data(), a.size(), b.data(), b.size(), t.tag.data())); }
    { auto b = t.ct; auto k = t.key; k[31] ^= 1;
      PF_CHECK(!aead->decrypt(k.data(), t.iv.data(), t.aad.data(), t.aad.size(), b.data(), b.size(), t.tag.data())); }
    { auto b = t.ct; auto n = t.iv; n[11] ^= 1;
      PF_CHECK(!aead->decrypt(t.key.data(), n.data(), t.aad.data(), t.aad.size(), b.data(), b.size(), t.tag.data())); }
}

PF_TEST(aesgcm_supports_empty_plaintext_and_empty_aad) {
    Tc16 t; auto aead = make_openssl_aes256gcm();
    uint8_t tag[16];
    PF_REQUIRE(aead->encrypt(t.key.data(), t.iv.data(), nullptr, 0, nullptr, 0, tag));
    PF_CHECK(aead->decrypt(t.key.data(), t.iv.data(), nullptr, 0, nullptr, 0, tag));
    tag[0] ^= 1;
    PF_CHECK(!aead->decrypt(t.key.data(), t.iv.data(), nullptr, 0, nullptr, 0, tag));
}

PF_TEST(aesgcm_round_trip_all_small_lengths) {
    Tc16 t; auto aead = make_openssl_aes256gcm();
    for (size_t n = 0; n <= 70; ++n) {
        std::vector<uint8_t> pt(n); for (size_t i = 0; i < n; ++i) pt[i] = static_cast<uint8_t>(i * 7 + n);
        auto buf = pt; uint8_t tag[16];
        PF_REQUIRE(aead->encrypt(t.key.data(), t.iv.data(), t.aad.data(), 8, buf.data(), n, tag));
        PF_REQUIRE(aead->decrypt(t.key.data(), t.iv.data(), t.aad.data(), 8, buf.data(), n, tag));
        PF_REQUIRE(buf == pt);
    }
}
