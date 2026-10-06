#pragma once
#include <memory>

#include "pf/random.h"

namespace pf {

// The OS CSPRNG via OpenSSL RAND_bytes (linked unmodified). Only built with PF_WITH_OPENSSL.
std::unique_ptr<RandomSource> make_os_random();

}  // namespace pf
