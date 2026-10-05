#pragma once
#include <cstddef>
#include <cstdint>

namespace pf {

// Crypto Provider interface for the data channel (plan section 11). Blocks only
// see this interface, so the implementation can be swapped per platform
// (OpenSSL, BoringSSL, hardware, kernel) without touching Flows.
// All buffers are operated on IN PLACE (buf is read and rewritten); nonce is 12
// bytes, key 32 bytes, tag 16 bytes.
class AeadProvider {
public:
    virtual ~AeadProvider() = default;

    // Verifies tag over (aad, ciphertext) and decrypts. On failure returns false
    // and leaves ZEROES in buf: unauthenticated plaintext must never be released.
    virtual bool decrypt(const uint8_t* key, const uint8_t* nonce,
                         const uint8_t* aad, size_t aad_len,
                         uint8_t* buf, size_t len, const uint8_t* tag) = 0;

    // Encrypts buf in place and writes the 16-byte tag.
    virtual bool encrypt(const uint8_t* key, const uint8_t* nonce,
                         const uint8_t* aad, size_t aad_len,
                         uint8_t* buf, size_t len, uint8_t* tag_out) = 0;
};

}  // namespace pf
