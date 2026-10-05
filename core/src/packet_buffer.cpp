#include "pf/packet_buffer.h"

#include <cstring>

#include "pf/secure_mem.h"

namespace pf {

PacketBuffer::PacketBuffer(size_t headroom, size_t capacity, size_t tailroom)
    : total_(headroom + capacity + tailroom), start_(headroom) {
    base_.reset(new uint8_t[total_ ? total_ : 1]());
}

PacketBuffer PacketBuffer::from_bytes(const uint8_t* src, size_t n, size_t headroom, size_t tailroom) {
    PacketBuffer b(headroom, n, tailroom);
    if (n > 0) {
        std::memcpy(b.base_.get() + b.start_, src, n);
        b.len_ = n;
    }
    return b;
}

PacketBuffer::PacketBuffer(PacketBuffer&& o) noexcept
    : base_(std::move(o.base_)), total_(o.total_), start_(o.start_), len_(o.len_) {
    o.total_ = o.start_ = o.len_ = 0;
}

PacketBuffer& PacketBuffer::operator=(PacketBuffer&& o) noexcept {
    if (this != &o) {
        base_ = std::move(o.base_);
        total_ = o.total_; start_ = o.start_; len_ = o.len_;
        o.total_ = o.start_ = o.len_ = 0;
    }
    return *this;
}

uint8_t* PacketBuffer::push_front(size_t n) {
    if (n > start_) return nullptr;
    start_ -= n;
    len_ += n;
    return data();
}

bool PacketBuffer::pull_front(size_t n) {
    if (n > len_) return false;
    start_ += n;
    len_ -= n;
    return true;
}

uint8_t* PacketBuffer::put(size_t n) {
    if (n > tailroom()) return nullptr;
    uint8_t* p = data() + len_;
    len_ += n;
    return p;
}

bool PacketBuffer::trim_back(size_t n) {
    if (n > len_) return false;
    len_ -= n;
    return true;
}

void PacketBuffer::wipe() {
    secure_zero(base_.get(), total_);
    len_ = 0;
}

}  // namespace pf
