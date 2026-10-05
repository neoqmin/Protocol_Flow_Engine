#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>

namespace pf {

// OpenVPN's fixed keepalive payload (the data-channel "ping"); observed in decrypted server pings
// (tools/interop/verify_aead.py) and accepted by the real server as ours (tests/protocol).
inline constexpr size_t kPingPayloadLen = 16;
inline constexpr uint8_t kPingPayload[kPingPayloadLen] = {0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
                                                          0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48};

bool is_ping_payload(const uint8_t* data, size_t len);

// Keepalive timers driven by the pushed `ping N` and `ping-restart M` (seconds; 0 disables each). Pure logic:
// the caller passes the clock. Semantics (OpenVPN): send a ping when nothing was SENT for N seconds; declare the
// peer dead when nothing was RECEIVED for M seconds (the session must then be restarted).
class KeepaliveTimer {
public:
    enum class Action { None, SendPing, Timeout };

    KeepaliveTimer(uint32_t ping_s, uint32_t restart_s, uint64_t now_ms)
        : ping_ms_(uint64_t{ping_s} * 1000), restart_ms_(uint64_t{restart_s} * 1000), last_sent_(now_ms), last_recv_(now_ms) {}

    void on_sent(uint64_t now_ms) { last_sent_ = now_ms; }          // any packet we transmitted
    void on_received(uint64_t now_ms) { if (!dead_) last_recv_ = now_ms; }   // any authenticated packet received

    // SendPing is returned at most once per interval (poll records it as sent). Timeout is final.
    Action poll(uint64_t now_ms);
    // Earliest time poll() could return something other than None.
    std::optional<uint64_t> next_deadline_ms() const;

private:
    uint64_t ping_ms_, restart_ms_;
    uint64_t last_sent_, last_recv_;
    bool dead_ = false;
};

}  // namespace pf
