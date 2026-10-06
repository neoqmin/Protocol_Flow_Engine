#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string_view>

#include "pf/stun.h"

namespace pf {

// HMAC-SHA1 / HMAC-SHA256 for STUN MESSAGE-INTEGRITY(-SHA256) via OpenSSL 3.x (linked unmodified). Only built when
// PF_WITH_OPENSSL is enabled. Stateless: safe to share between threads.
std::unique_ptr<stun::StunHmac> make_openssl_stun_hmac();

// Long-term credential key (RFC 8489 section 9.2.2): MD5(username ":" realm ":" password), or SHA-256 of the same
// string when PASSWORD-ALGORITHM is SHA-256. `password` must already be OpaqueString-prepared (RFC 8265; SASLprep in
// RFC 5389): this codec does not implement Unicode preparation - plain ASCII passwords need none. The result is key
// material: callers keep it in the Key Manager and wipe it (secure_zero), never log or store it in a Flow.
bool stun_long_term_key_md5(std::string_view username, std::string_view realm, std::string_view password,
                            std::array<uint8_t, 16>& out);
bool stun_long_term_key_sha256(std::string_view username, std::string_view realm, std::string_view password,
                               std::array<uint8_t, 32>& out);

}  // namespace pf
