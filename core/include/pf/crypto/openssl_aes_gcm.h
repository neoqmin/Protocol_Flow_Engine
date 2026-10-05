#pragma once
#include <memory>

#include "pf/crypto/aead_provider.h"

namespace pf {

// AES-256-GCM via OpenSSL 3.x EVP (linked unmodified). Only built when
// PF_WITH_OPENSSL is enabled. Stateless: safe to share between threads.
std::unique_ptr<AeadProvider> make_openssl_aes256gcm();

}  // namespace pf
