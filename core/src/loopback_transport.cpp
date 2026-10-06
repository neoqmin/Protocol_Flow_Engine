#include "pf/loopback_transport.h"

#include <cstring>

namespace pf {

std::pair<std::unique_ptr<LoopbackTransport>, std::unique_ptr<LoopbackTransport>>
LoopbackTransport::make_pair(std::shared_ptr<LoopbackLink> link, TransportKind kind, size_t max_packet) {
    return {std::unique_ptr<LoopbackTransport>(new LoopbackTransport(link, 0, kind, max_packet)),
            std::unique_ptr<LoopbackTransport>(new LoopbackTransport(link, 1, kind, max_packet))};
}

TransportStatus LoopbackTransport::send(const uint8_t* data, size_t len) {
    if (!open_ || link_->closed_) return TransportStatus::Closed;
    if (len > max_packet_) return TransportStatus::TooLarge;
    auto& q = link_->queue_[1 - side_];
    if (q.size() >= link_->capacity_) return TransportStatus::WouldBlock;
    if (link_->blocked_ || link_->drop_ > 0) {
        if (link_->drop_ > 0) --link_->drop_;
        ++link_->dropped_;
        return TransportStatus::Ok;                    // lost on the way; the sender cannot tell
    }
    q.emplace_back(data, data + len);
    ++link_->delivered_;
    return TransportStatus::Ok;
}

RecvResult LoopbackTransport::recv(uint8_t* buf, size_t cap) {
    RecvResult r;
    if (!open_) { r.status = TransportStatus::Closed; return r; }
    auto& q = link_->queue_[side_];
    if (q.empty()) { r.status = link_->closed_ ? TransportStatus::Closed : TransportStatus::WouldBlock; return r; }
    std::vector<uint8_t> pkt = std::move(q.front());
    q.pop_front();
    if (pkt.size() > cap) { r.status = TransportStatus::TooLarge; return r; }     // discarded, like an oversized datagram
    if (!pkt.empty()) std::memcpy(buf, pkt.data(), pkt.size());
    r.status = TransportStatus::Ok;
    r.len = pkt.size();
    return r;
}

}  // namespace pf
