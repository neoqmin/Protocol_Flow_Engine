#include "pf/replay.h"

namespace pf {

ReplayStatus ReplayWindow::check(uint32_t id) const {
    if (id == 0) return ReplayStatus::InvalidId;
    if (id > highest_) return ReplayStatus::Ok;
    const uint32_t diff = highest_ - id;
    if (diff >= kWindow) return ReplayStatus::TooOld;
    return (bitmap_ >> diff) & 1u ? ReplayStatus::Replay : ReplayStatus::Ok;
}

void ReplayWindow::commit(uint32_t id) {
    if (id == 0) return;
    if (id > highest_) {
        const uint32_t shift = id - highest_;
        bitmap_ = shift >= kWindow ? 0 : bitmap_ << shift;
        bitmap_ |= 1u;
        highest_ = id;
        return;
    }
    const uint32_t diff = highest_ - id;
    if (diff < kWindow) bitmap_ |= (uint64_t{1} << diff);   // too-old ids are ignored
}

}  // namespace pf
