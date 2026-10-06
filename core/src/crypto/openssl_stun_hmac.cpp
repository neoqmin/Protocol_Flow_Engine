#include "pf/crypto/stun_hmac.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <climits>
#include <string>

#include "pf/secure_mem.h"

namespace pf {
namespace {

bool hmac(const EVP_MD* md, const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t* out, unsigned want) {
    if (key_len > INT_MAX || (!key && key_len) || (!data && len)) return false;
    static const uint8_t empty = 0;
    unsigned out_len = 0;
    const bool ok = HMAC(md, key ? key : &empty, static_cast<int>(key_len), data ? data : &empty, len, out, &out_len) != nullptr;
    return ok && out_len == want;
}

class OpenSslStunHmac final : public stun::StunHmac {
public:
    bool hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[20]) const override {
        return hmac(EVP_sha1(), key, key_len, data, len, out, 20);
    }
    bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]) const override {
        return hmac(EVP_sha256(), key, key_len, data, len, out, 32);
    }
};

bool digest(const EVP_MD* md, std::string_view username, std::string_view realm, std::string_view password, uint8_t* out,
            unsigned want) {
    std::string s;
    s.reserve(username.size() + realm.size() + password.size() + 2);
    s.append(username).append(":").append(realm).append(":").append(password);
    unsigned n = 0;
    const bool ok = EVP_Digest(s.data(), s.size(), out, &n, md, nullptr) == 1 && n == want;
    secure_zero(s.data(), s.size());                   // holds the password
    return ok;
}

}  // namespace

std::unique_ptr<stun::StunHmac> make_openssl_stun_hmac() { return std::make_unique<OpenSslStunHmac>(); }

bool stun_long_term_key_md5(std::string_view username, std::string_view realm, std::string_view password,
                            std::array<uint8_t, 16>& out) {
    return digest(EVP_md5(), username, realm, password, out.data(), 16);
}

bool stun_long_term_key_sha256(std::string_view username, std::string_view realm, std::string_view password,
                               std::array<uint8_t, 32>& out) {
    return digest(EVP_sha256(), username, realm, password, out.data(), 32);
}

}  // namespace pf
