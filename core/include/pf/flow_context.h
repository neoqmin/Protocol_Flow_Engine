#pragma once
#include <cstdint>

#include "pf/error.h"
#include "pf/openvpn_header.h"
#include "pf/packet_buffer.h"

namespace pf {

// Opaque handle to key material held by the Key Manager. Blocks never see key
// bytes through the context, only this reference (docs/Threat_Model... §4).
struct KeyRef {
    uint32_t id = 0;
    constexpr bool valid() const { return id != 0; }
};

// Per-packet execution context shared by all Blocks of a Flow.
// Blocks borrow `packet` (owned by the caller) and communicate through the
// fields below instead of holding their own state.
struct FlowContext {
    PacketBuffer* packet = nullptr;
    OvpnHeader header{};            // valid only when header_valid
    bool header_valid = false;
    KeyRef key_ref{};
    uint32_t flags = 0;
    Error error = Error::None;      // reason set by a block returning Drop/Error
    void* user_context = nullptr;
};

}  // namespace pf
