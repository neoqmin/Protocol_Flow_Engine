#include "pf/reliable.h"

#include <algorithm>

namespace pf {

void ReliableReceiver::queue_ack(uint32_t id) {
    if (std::find(pending_.begin(), pending_.end(), id) == pending_.end()) pending_.push_back(id);
}

ReliableReceiver::Result ReliableReceiver::on_message(uint32_t id, const std::vector<uint8_t>& payload,
                                                      std::vector<Delivered>& out) {
    if (id < next_ || buffered_.count(id) != 0) {   // peer may have missed our ack: acknowledge again
        queue_ack(id);
        return Result::Duplicate;
    }
    if (id - next_ >= cfg_.recv_window) return Result::OutOfWindow;   // not acknowledged: peer retransmits later

    queue_ack(id);
    if (id != next_) {
        buffered_.emplace(id, payload);
        return Result::Buffered;
    }
    out.push_back({id, payload});
    ++next_;
    for (auto it = buffered_.find(next_); it != buffered_.end(); it = buffered_.find(next_)) {
        out.push_back({it->first, std::move(it->second)});
        buffered_.erase(it);
        ++next_;
    }
    return Result::Delivered;
}

std::vector<uint32_t> ReliableReceiver::take_acks(size_t max) {
    std::vector<uint32_t> out;
    while (!pending_.empty() && out.size() < max) {
        out.push_back(pending_.back());
        pending_.pop_back();
    }
    return out;
}

bool ReliableSender::enqueue(uint8_t opcode, std::vector<uint8_t> payload, uint32_t& id_out) {
    if (!can_send()) return false;
    id_out = next_id_;
    Entry e;
    e.opcode = opcode;
    e.payload = std::move(payload);
    queue_.emplace(next_id_, std::move(e));
    if (next_id_ == 0xFFFFFFFFu) exhausted_ = true; else ++next_id_;
    return true;
}

void ReliableSender::on_ack(const uint32_t* ids, size_t n) {
    for (size_t i = 0; i < n; ++i) queue_.erase(ids[i]);
}

std::vector<ReliableSender::Outgoing> ReliableSender::due(uint64_t now_ms) {
    std::vector<Outgoing> out;
    if (failed_) return out;
    for (auto& [id, e] : queue_) {
        if (e.attempts == 0) {
            e.wait_ms = cfg_.rto_ms;
        } else if (now_ms >= e.last_sent_ms + e.wait_ms) {
            if (e.attempts >= cfg_.max_attempts) { failed_ = true; return {}; }
            e.wait_ms = std::min<uint32_t>(e.wait_ms * 2, cfg_.max_rto_ms);
        } else {
            continue;
        }
        ++e.attempts;
        e.last_sent_ms = now_ms;
        out.push_back({id, e.opcode, e.payload, e.attempts});
    }
    return out;
}

std::optional<uint64_t> ReliableSender::next_deadline_ms() const {
    std::optional<uint64_t> best;
    for (const auto& [id, e] : queue_) {
        const uint64_t t = e.attempts == 0 ? 0 : e.last_sent_ms + e.wait_ms;
        if (!best || t < *best) best = t;
    }
    return best;
}

}  // namespace pf
