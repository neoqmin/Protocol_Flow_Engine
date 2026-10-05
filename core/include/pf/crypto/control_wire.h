#pragma once
#include <cstdint>
#include <vector>

#include "pf/control_packet.h"
#include "pf/crypto/tls_crypt.h"

namespace pf {

// One UDP datagram <-> ControlPacket, with tls-crypt applied/removed. Shared by the client and test peers.

// Serializes `p` and protects it with the channel's tx key (assigns the next tls-crypt packet-id).
bool seal_control_packet(TlsCryptChannel& ch, const ControlPacket& p, uint32_t net_time, std::vector<uint8_t>& datagram);

enum class OpenControlStatus {
    Ok,
    NotControl,   // first byte is not a control opcode (e.g. DATA_V2): caller handles it elsewhere
    AuthFailed,   // wrong key, forged or damaged: drop silently
    Replay,       // authentic but already seen / too old: drop
    Malformed     // authentic but not a valid control packet
};

OpenControlStatus open_control_packet(TlsCryptChannel& ch, const uint8_t* datagram, size_t len, ControlPacket& out);

}  // namespace pf
