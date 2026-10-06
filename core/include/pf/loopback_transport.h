#pragma once
#include <deque>
#include <memory>
#include <utility>
#include <vector>

#include "pf/transport.h"

namespace pf {

// In-memory Transport pair for tests: whatever one end sends, the other receives. The shared link can be impaired
// to reproduce network behavior without sockets (B3 uses `block()` to simulate a UDP-blocking firewall).
// Not thread-safe; deterministic.
class LoopbackLink {
public:
    // Packets sent while blocked are silently lost (like a firewall that drops UDP) - the sender is NOT told.
    void block(bool on) { blocked_ = on; }
    // Drops the next `n` packets sent by either end.
    void drop_next(unsigned n) { drop_ = n; }
    // Max packets queued per direction; a send beyond it reports WouldBlock (a full socket buffer).
    void set_capacity(size_t n) { capacity_ = n; }
    // Either end sees Closed after this.
    void close_link() { closed_ = true; }

    uint64_t delivered() const { return delivered_; }
    uint64_t dropped() const { return dropped_; }

private:
    friend class LoopbackTransport;
    std::deque<std::vector<uint8_t>> queue_[2];    // queue_[i] = packets waiting to be received by end i
    bool blocked_ = false, closed_ = false;
    unsigned drop_ = 0;
    size_t capacity_ = 1024;
    uint64_t delivered_ = 0, dropped_ = 0;
};

class LoopbackTransport : public Transport {
public:
    // Both ends share `link` (kept alive by them). `kind` is what they report (e.g. Udp, Tcp).
    static std::pair<std::unique_ptr<LoopbackTransport>, std::unique_ptr<LoopbackTransport>>
    make_pair(std::shared_ptr<LoopbackLink> link, TransportKind kind = TransportKind::Udp, size_t max_packet = 1500);

    TransportKind kind() const override { return kind_; }
    TransportStatus send(const uint8_t* data, size_t len) override;
    RecvResult recv(uint8_t* buf, size_t cap) override;
    bool is_open() const override { return open_ && !link_->closed_; }
    void close() override { open_ = false; }
    size_t max_packet() const override { return max_packet_; }

private:
    LoopbackTransport(std::shared_ptr<LoopbackLink> l, int side, TransportKind k, size_t mp)
        : link_(std::move(l)), side_(side), kind_(k), max_packet_(mp) {}
    std::shared_ptr<LoopbackLink> link_;
    int side_;
    TransportKind kind_;
    size_t max_packet_;
    bool open_ = true;
};

}  // namespace pf
