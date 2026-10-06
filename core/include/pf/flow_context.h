#pragma once
#include <cstdint>

#include "pf/error.h"
#include "pf/packet_buffer.h"
#include "pf/protocol_slot.h"

namespace pf {

class KeyStore;      // pf/key_store.h
class AeadProvider;  // pf/crypto/aead_provider.h

// Opaque handle to key material held by the Key Manager. Blocks never see key
// bytes through the context, only this reference (docs/Threat_Model... §4).
struct KeyRef {
    uint32_t id = 0;
    constexpr bool valid() const { return id != 0; }
};

// Per-packet execution context shared by all Blocks of a Flow.
// Blocks borrow `packet` (owned by the caller) and communicate through the
// fields below instead of holding their own state. Protocol-independent: what a
// protocol's blocks parse lives in `proto` (e.g. OvpnSlot, pf/ovpn_context.h).
struct FlowContext {
    PacketBuffer* packet = nullptr;
    ProtocolSlot proto;             // protocol-specific state (tag + fixed storage, no heap)
    KeyRef key_ref{};
    KeyStore* keys = nullptr;       // borrowed services (owned by the caller/session)
    AeadProvider* aead = nullptr;
    uint32_t flags = 0;
    Error error = Error::None;      // reason set by a block returning Drop/Error
    void* user_context = nullptr;
};

}  // namespace pf
