#include "pf/crypto/openssl_aes_gcm.h"

#include <openssl/evp.h>

#include <climits>

#include "pf/secure_mem.h"

namespace pf {
namespace {

constexpr size_t kTagLen = 16;
constexpr int kNonceLen = 12;

struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

class OpenSslAes256Gcm final : public AeadProvider {
public:
    bool decrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aad_len,
                 uint8_t* buf, size_t len, const uint8_t* tag) override {
        if (len > INT_MAX || aad_len > INT_MAX) return false;
        CtxPtr c(EVP_CIPHER_CTX_new());
        int outl = 0;
        bool ok = c &&
            EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_IVLEN, kNonceLen, nullptr) == 1 &&
            EVP_DecryptInit_ex(c.get(), nullptr, nullptr, key, nonce) == 1 &&
            (aad_len == 0 || EVP_DecryptUpdate(c.get(), nullptr, &outl, aad, static_cast<int>(aad_len)) == 1) &&
            (len == 0 || EVP_DecryptUpdate(c.get(), buf, &outl, buf, static_cast<int>(len)) == 1) &&
            EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_TAG, kTagLen, const_cast<uint8_t*>(tag)) == 1;
        if (ok) {
            uint8_t unused[16];
            ok = EVP_DecryptFinal_ex(c.get(), unused, &outl) == 1;
        }
        if (!ok && buf != nullptr) secure_zero(buf, len);   // never release unauthenticated plaintext
        return ok;
    }

    bool encrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aad_len,
                 uint8_t* buf, size_t len, uint8_t* tag_out) override {
        if (len > INT_MAX || aad_len > INT_MAX) return false;
        CtxPtr c(EVP_CIPHER_CTX_new());
        int outl = 0;
        bool ok = c &&
            EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_IVLEN, kNonceLen, nullptr) == 1 &&
            EVP_EncryptInit_ex(c.get(), nullptr, nullptr, key, nonce) == 1 &&
            (aad_len == 0 || EVP_EncryptUpdate(c.get(), nullptr, &outl, aad, static_cast<int>(aad_len)) == 1) &&
            (len == 0 || EVP_EncryptUpdate(c.get(), buf, &outl, buf, static_cast<int>(len)) == 1);
        if (ok) {
            uint8_t unused[16];
            ok = EVP_EncryptFinal_ex(c.get(), unused, &outl) == 1 &&
                 EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_GET_TAG, kTagLen, tag_out) == 1;
        }
        return ok;
    }
};

}  // namespace

std::unique_ptr<AeadProvider> make_openssl_aes256gcm() {
    return std::make_unique<OpenSslAes256Gcm>();
}

}  // namespace pf
