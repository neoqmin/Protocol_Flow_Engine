#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <memory>

#include "pf/flow_context.h"
#include "pf/replay.h"
#include "pf/secure_mem.h"

namespace pf {

// Everything a data-channel key needs. Secret fields are wiped on destruction.
struct DataKey {
    std::array<uint8_t, 32> key{};          // AES-256-GCM key
    std::array<uint8_t, 8> nonce_tail{};    // per-direction implicit IV; nonce = packet_id(4) || tail(8)
    ReplayWindow replay;                    // RX direction state
    uint32_t tx_next = 1;                   // TX direction: next packet-id

    DataKey() = default;
    DataKey(const DataKey&) = default;
    DataKey& operator=(const DataKey&) = default;
    ~DataKey() { wipe(); }

    // Hands out the next TX packet-id. Returns false once 0xFFFFFFFF has been
    // used: the nonce would repeat, so the caller must switch to a new key.
    bool next_tx_id(uint32_t& out) {
        if (tx_next == 0) return false;
        out = tx_next;
        tx_next = (tx_next == 0xFFFFFFFFu) ? 0 : tx_next + 1;
        return true;
    }

    void wipe() {
        secure_zero(key.data(), key.size());
        secure_zero(nonce_tail.data(), nonce_tail.size());
        replay.reset();
        tx_next = 1;
    }
};

// Owns data-channel keys and hands out opaque KeyRefs. Blocks look keys up
// through the context; key bytes never travel in Flow definitions or logs.
// key_id (3 bits on the wire) is bound separately for RX and TX so a
// renegotiation can install key N+1 while key N is still draining.
class KeyStore {
public:
    KeyStore() = default;
    KeyStore(const KeyStore&) = delete;
    KeyStore& operator=(const KeyStore&) = delete;

    KeyRef add(const DataKey& k);
    DataKey* get(KeyRef r);
    const DataKey* get(KeyRef r) const;

    bool bind_rx(uint8_t key_id, KeyRef r);
    bool bind_tx(uint8_t key_id, KeyRef r);
    KeyRef rx_for_key_id(uint8_t key_id) const;
    KeyRef tx_for_key_id(uint8_t key_id) const;

    void remove(KeyRef r);   // wipes the key and drops its bindings
    size_t size() const { return keys_.size(); }

private:
    static constexpr size_t kKeyIds = 8;
    std::map<uint32_t, std::unique_ptr<DataKey>> keys_;   // stable addresses
    std::array<KeyRef, kKeyIds> rx_{};
    std::array<KeyRef, kKeyIds> tx_{};
    uint32_t next_id_ = 1;
};

}  // namespace pf
