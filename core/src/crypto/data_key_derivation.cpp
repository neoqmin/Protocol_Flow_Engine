#include "pf/crypto/data_key_derivation.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "pf/secure_mem.h"

namespace pf {

bool derive_data_keys_ekm(const TlsSession& tls, const EkmLayout& l, TlsRole role, DataKey& tx, DataKey& rx) {
    const size_t need = std::max(std::max(l.tx_cipher + 32, l.tx_tail + 8), std::max(l.rx_cipher + 32, l.rx_tail + 8));
    if (l.total == 0 || need > l.total) return false;

    std::vector<uint8_t> km(l.total);
    static const uint8_t kEmpty = 0;
    if (!tls.export_keying_material(kOpenVpnEkmLabel, l.use_empty_context ? &kEmpty : nullptr, 0, km.data(), km.size()))
        return false;

    const bool client = role == TlsRole::Client;
    const size_t t_c = client ? l.tx_cipher : l.rx_cipher, t_t = client ? l.tx_tail : l.rx_tail;
    const size_t r_c = client ? l.rx_cipher : l.tx_cipher, r_t = client ? l.rx_tail : l.tx_tail;
    DataKey t, r;
    std::memcpy(t.key.data(), km.data() + t_c, 32);
    std::memcpy(t.nonce_tail.data(), km.data() + t_t, 8);
    std::memcpy(r.key.data(), km.data() + r_c, 32);
    std::memcpy(r.nonce_tail.data(), km.data() + r_t, 8);
    secure_zero(km.data(), km.size());
    tx = t;
    rx = r;
    return true;
}

}  // namespace pf
