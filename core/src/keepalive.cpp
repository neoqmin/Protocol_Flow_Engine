#include "pf/keepalive.h"

#include <algorithm>

#include "pf/secure_mem.h"

namespace pf {

bool is_ping_payload(const uint8_t* data, size_t len) {
    return data != nullptr && len == kPingPayloadLen && ct_equal(data, kPingPayload, kPingPayloadLen);
}

KeepaliveTimer::Action KeepaliveTimer::poll(uint64_t now_ms) {
    if (dead_) return Action::Timeout;
    if (restart_ms_ != 0 && now_ms >= last_recv_ && now_ms - last_recv_ >= restart_ms_) {
        dead_ = true;
        return Action::Timeout;
    }
    if (ping_ms_ != 0 && now_ms >= last_sent_ && now_ms - last_sent_ >= ping_ms_) {
        last_sent_ = now_ms;
        return Action::SendPing;
    }
    return Action::None;
}

std::optional<uint64_t> KeepaliveTimer::next_deadline_ms() const {
    std::optional<uint64_t> best;
    if (ping_ms_ != 0) best = last_sent_ + ping_ms_;
    if (restart_ms_ != 0 && !dead_) {
        const uint64_t t = last_recv_ + restart_ms_;
        if (!best || t < *best) best = t;
    }
    return best;
}

}  // namespace pf
