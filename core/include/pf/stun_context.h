#pragma once
#include <cstdint>

#include "pf/flow_context.h"
#include "pf/protocol_slot.h"
#include "pf/stun.h"

namespace pf {

// STUN's per-packet state in the FlowContext protocol slot (F-2, D-043; PM-2b N1, D-045). The attributes stay in the
// packet buffer: the slot keeps the header and the offsets of the attributes later blocks/machines look at, so it is
// fixed-size plain data (offset 0 = attribute absent; a real attribute never starts before byte 20).
struct StunSlot {
    static constexpr ProtocolId kProtocolId = kProtocolStun;
    bool parsed = false;
    uint16_t method = 0;
    stun::Class cls = stun::Class::Request;
    stun::TransactionId tid{};
    uint16_t size = 0;                       // whole message
    uint8_t attribute_count = 0;
    uint8_t unknown_required_count = 0;      // comprehension-required attributes we do not understand
    uint16_t xor_mapped_address = 0;         // offsets of the FIRST occurrence (RFC 8489: later ones are not processed)
    uint16_t mapped_address = 0;
    uint16_t error_code = 0;
    uint16_t username = 0;
    uint16_t realm = 0;
    uint16_t nonce = 0;
    uint16_t message_integrity = 0;
    uint16_t message_integrity_sha256 = 0;
    uint16_t fingerprint = 0;
};

// Context fact (block.h): "stun.message" = the packet is a structurally valid STUN message (FINGERPRINT verified when
// present) and the StunSlot describes it.
inline constexpr const char* kFactStunMessage = "stun.message";

inline const StunSlot* stun_slot(const FlowContext& ctx) {
    const StunSlot* s = ctx.proto.get<StunSlot>();
    return s && s->parsed ? s : nullptr;
}

}  // namespace pf
