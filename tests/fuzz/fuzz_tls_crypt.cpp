// libFuzzer: tls-crypt unwrap of attacker-controlled datagrams with a fixed key (needs OpenSSL).
// Random input must never authenticate; a sealed fuzz payload must open to the same bytes.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "pf/crypto/tls_crypt.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static pf::TlsCryptKeys keys = [] {
        std::array<uint8_t, pf::kTlsCryptStaticKeyLen> k{};
        for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(i * 7 + 3);
        return pf::derive_tls_crypt_keys(k, pf::TlsCryptRole::Client);
    }();
    pf::TlsCryptPlain out;
    (void)pf::tls_crypt_open(keys.rx, data, size, out);

    const uint8_t sid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint8_t> wire;
    if (!pf::tls_crypt_seal(keys.tx, 0x20, sid, 1, 2, data, size, wire)) return 0;
    pf::TlsCryptPlain back;
    if (pf::tls_crypt_open(keys.tx, wire.data(), wire.size(), back) != pf::TlsCryptStatus::Ok ||
        back.payload.size() != size || (size && std::memcmp(back.payload.data(), data, size) != 0))
        std::abort();
    return 0;
}
