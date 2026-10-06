#pragma once
#include "pf/data_v2.h"
#include "pf/flow_context.h"
#include "pf/openvpn_header.h"
#include "pf/protocol_slot.h"

namespace pf {

// OpenVPN's per-packet state in the FlowContext protocol slot (F-2, D-043), and the context facts OpenVPN blocks declare.
struct OvpnSlot {
    static constexpr ProtocolId kProtocolId = kProtocolOpenVpn;
    OvpnHeader header{};            // valid only when header_valid
    bool header_valid = false;
    DataV2Packet data_v2{};         // fields parsed by parse_data_v2 (RX data plane), valid only when data_v2_valid
    bool data_v2_valid = false;
};

// Context facts (block.h): "ovpn.header" = slot.header is valid, "ovpn.data_v2" = slot.data_v2 was parsed,
// "key" = ctx.key_ref resolved for this packet.
inline constexpr const char* kFactOvpnHeader = "ovpn.header";
inline constexpr const char* kFactOvpnDataV2 = "ovpn.data_v2";
inline constexpr const char* kFactKey = "key";

inline OvpnSlot* ovpn_slot(FlowContext& ctx) { return ctx.proto.get<OvpnSlot>(); }
inline const OvpnSlot* ovpn_slot(const FlowContext& ctx) { return ctx.proto.get<OvpnSlot>(); }
// The parsed header, or nullptr when no valid OpenVPN header is in the context.
inline const OvpnHeader* ovpn_header(const FlowContext& ctx) {
    const OvpnSlot* s = ovpn_slot(ctx);
    return s && s->header_valid ? &s->header : nullptr;
}
// What a TX caller does before running lookup_tx_key/aead_encrypt (the TX flow's "ovpn.header" input).
inline void set_ovpn_header(FlowContext& ctx, const OvpnHeader& h) {
    OvpnSlot& s = ctx.proto.as<OvpnSlot>();
    s.header = h;
    s.header_valid = true;
}

}  // namespace pf
