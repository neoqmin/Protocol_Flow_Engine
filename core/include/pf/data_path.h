#pragma once
#include <cstddef>
#include <cstdint>

#include "pf/blocks/data_plane_blocks.h"
#include "pf/error.h"
#include "pf/flow.h"
#include "pf/key_store.h"
#include "pf/keepalive.h"
#include "pf/packet_buffer.h"

namespace pf {

class AeadProvider;

// What a decrypted DATA_V2 payload is. MVP profile: no compression framing, so the payload is either a bare IP packet,
// the fixed keepalive ping, or something else authenticated (e.g. an exit notification) that must not reach the TUN.
enum class PayloadKind { Ip, Ping, Other };
PayloadKind classify_payload(const uint8_t* data, size_t len);

// Data-channel packet path: the TX/RX Flows of A2 behind a small, I/O-free API (SANS-I/O like ControlClient).
// Keys come from the KeyStore the ControlClient installs into; renegotiation therefore needs no change here.
class DataPath {
public:
    // false if the data-plane blocks cannot be registered or the Flows do not build (wiring bug).
    bool init(KeyStore* keys, AeadProvider* aead);

    // A buffer to read a plaintext packet into: headroom/tailroom for the DATA_V2 header and tag are already reserved.
    static PacketBuffer make_tx_buffer(size_t max_payload);

    // Encrypts `pkt` (plaintext) in place into a complete wire packet. Error::None on success.
    Error seal(PacketBuffer& pkt, uint8_t key_id, uint32_t peer_id);

    struct Opened {
        Error error = Error::None;         // None = authenticated; otherwise the Drop/Error reason (nothing was released)
        PayloadKind kind = PayloadKind::Other;
    };
    // Verifies and decrypts a wire packet. On success `pkt` holds only the plaintext.
    Opened open(PacketBuffer& pkt);

    // Optional trace of both Flows (pf/trace.h); the caller keeps trace->now_ms current. nullptr = off.
    void set_trace(TraceSink* trace) { trace_ = trace; }

private:
    BlockRegistry reg_;
    Flow rx_, tx_;
    KeyStore* keys_ = nullptr;
    AeadProvider* aead_ = nullptr;
    TraceSink* trace_ = nullptr;
};

}  // namespace pf
