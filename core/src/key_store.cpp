#include "pf/key_store.h"

namespace pf {

KeyRef KeyStore::add(const DataKey& k) {
    const uint32_t id = next_id_++;
    keys_.emplace(id, std::make_unique<DataKey>(k));
    return KeyRef{id};
}

DataKey* KeyStore::get(KeyRef r) {
    auto it = keys_.find(r.id);
    return it == keys_.end() ? nullptr : it->second.get();
}

const DataKey* KeyStore::get(KeyRef r) const {
    auto it = keys_.find(r.id);
    return it == keys_.end() ? nullptr : it->second.get();
}

bool KeyStore::bind_rx(uint8_t key_id, KeyRef r) {
    if (key_id >= kKeyIds || get(r) == nullptr) return false;
    rx_[key_id] = r;
    return true;
}

bool KeyStore::bind_tx(uint8_t key_id, KeyRef r) {
    if (key_id >= kKeyIds || get(r) == nullptr) return false;
    tx_[key_id] = r;
    return true;
}

KeyRef KeyStore::rx_for_key_id(uint8_t key_id) const {
    return key_id < kKeyIds ? rx_[key_id] : KeyRef{};
}

KeyRef KeyStore::tx_for_key_id(uint8_t key_id) const {
    return key_id < kKeyIds ? tx_[key_id] : KeyRef{};
}

void KeyStore::remove(KeyRef r) {
    auto it = keys_.find(r.id);
    if (it == keys_.end()) return;
    it->second->wipe();
    keys_.erase(it);
    for (auto& b : rx_) if (b.id == r.id) b = KeyRef{};
    for (auto& b : tx_) if (b.id == r.id) b = KeyRef{};
}

}  // namespace pf
