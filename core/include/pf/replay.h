#pragma once
#include <cstdint>

namespace pf {

enum class ReplayStatus { Ok, Replay, TooOld, InvalidId };

// Sliding anti-replay window over 32-bit packet-ids (64 ids wide).
// check() is read-only and commit() records an id: callers MUST commit only
// AFTER the packet authenticated, otherwise forged packets could advance the
// window and make genuine ones look too old. Ids never wrap; the sender must
// renegotiate before 0xFFFFFFFF (see DataKey::next_tx_id).
class ReplayWindow {
public:
    static constexpr uint32_t kWindow = 64;

    ReplayStatus check(uint32_t id) const;
    void commit(uint32_t id);
    uint32_t highest() const { return highest_; }
    void reset() { highest_ = 0; bitmap_ = 0; }

private:
    uint32_t highest_ = 0;
    uint64_t bitmap_ = 0;   // bit i set => id (highest_ - i) was seen
};

}  // namespace pf
