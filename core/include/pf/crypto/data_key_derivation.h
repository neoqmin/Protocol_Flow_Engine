#pragma once
#include <cstddef>

#include "pf/crypto/tls_session.h"
#include "pf/key_store.h"

namespace pf {

// Data-channel key derivation from the TLS keying material exporter (tls-ekm; RFC 5705 / 8446 7.5).
// Official docs fix the exporter LABEL (EXPORTER-OpenVPN-datakeys) and that it replaces the PRF; the amount of
// material and how it is split are NOT documented - the defaults below are a HYPOTHESIS that the interop test
// (tools / tests/protocol) confirms or corrects against real server packets (GCM tag verification).
//
// Layout is described from the CLIENT's point of view: the client encrypts with the "tx" slices and decrypts with
// the "rx" slices; a server uses them swapped.
struct EkmLayout {
    size_t total = 256;        // bytes exported (2 keys x (64 cipher + 64 hmac) slots)
    size_t tx_cipher = 0;      // 32-byte AES-256 key
    size_t tx_tail = 64;       // 8-byte implicit IV (GCM nonce tail)
    size_t rx_cipher = 128;
    size_t rx_tail = 192;
    bool use_empty_context = false;   // export with a zero-length context instead of none
};

inline constexpr const char* kOpenVpnEkmLabel = "EXPORTER-OpenVPN-datakeys";

// Fills tx/rx (key + nonce tail; replay/counters reset). false if the session is not established or the layout
// does not fit in `total`.
bool derive_data_keys_ekm(const TlsSession& tls, const EkmLayout& layout, TlsRole role, DataKey& tx, DataKey& rx);

}  // namespace pf
