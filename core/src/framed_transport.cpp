#include "pf/framed_transport.h"

#include <algorithm>
#include <cstring>

namespace pf {

namespace {
constexpr size_t kReadChunk = 4096;
}

void FramedTransport::close() {
    if (stream_) stream_->close();
    open_ = false;
    failure_ = TransportStatus::Closed;
}

void FramedTransport::flush() {
    while (open_ && out_pos_ < out_.size()) {
        const StreamResult r = stream_->write(out_.data() + out_pos_, out_.size() - out_pos_);
        if (r.status == StreamStatus::Ok && r.n > 0) { out_pos_ += std::min(r.n, out_.size() - out_pos_); continue; }
        if (r.status == StreamStatus::WouldBlock) break;
        fail(r.status == StreamStatus::Closed ? TransportStatus::Closed : TransportStatus::Error);
        return;
    }
    if (out_pos_ >= out_.size()) { out_.clear(); out_pos_ = 0; }
    else if (out_pos_ > 64 * 1024) {                                    // reclaim the written prefix
        out_.erase(out_.begin(), out_.begin() + static_cast<std::ptrdiff_t>(out_pos_));
        out_pos_ = 0;
    }
}

TransportStatus FramedTransport::send(const uint8_t* data, size_t len) {
    if (!open_) return failure_;
    if (len > kMaxPacket) return TransportStatus::TooLarge;
    flush();                                                            // free queue space first
    if (!open_) return failure_;
    if (queued_output_bytes() + kLengthPrefix + len > max_queued_) return TransportStatus::WouldBlock;
    out_.push_back(static_cast<uint8_t>(len >> 8));
    out_.push_back(static_cast<uint8_t>(len & 0xFF));
    if (len) out_.insert(out_.end(), data, data + len);
    flush();                                                            // try to put it on the wire right away
    return open_ ? TransportStatus::Ok : failure_;
}

bool FramedTransport::frame_available() const {
    const size_t have = in_.size() - in_pos_;
    if (have < kLengthPrefix) return false;
    const size_t len = (static_cast<size_t>(in_[in_pos_]) << 8) | in_[in_pos_ + 1];
    return have >= kLengthPrefix + len;
}

bool FramedTransport::has_pending_input() const { return open_ && frame_available(); }

bool FramedTransport::fill() {
    // Compact so the buffer cannot grow without bound across many small frames.
    if (in_pos_ > 0 && in_pos_ == in_.size()) { in_.clear(); in_pos_ = 0; }
    else if (in_pos_ > 64 * 1024) { in_.erase(in_.begin(), in_.begin() + static_cast<std::ptrdiff_t>(in_pos_)); in_pos_ = 0; }
    uint8_t chunk[kReadChunk];
    const StreamResult r = stream_->read(chunk, sizeof chunk);
    if (r.status == StreamStatus::Ok && r.n > 0) { in_.insert(in_.end(), chunk, chunk + std::min(r.n, sizeof chunk)); return true; }
    if (r.status == StreamStatus::WouldBlock) return true;
    fail(r.status == StreamStatus::Closed ? TransportStatus::Closed : TransportStatus::Error);
    return false;
}

RecvResult FramedTransport::recv(uint8_t* buf, size_t cap) {
    RecvResult out;
    if (!open_) { out.status = failure_; return out; }
    for (;;) {
        if (frame_available()) {
            const size_t len = (static_cast<size_t>(in_[in_pos_]) << 8) | in_[in_pos_ + 1];
            const uint8_t* body = in_.data() + in_pos_ + kLengthPrefix;
            in_pos_ += kLengthPrefix + len;                               // consumed either way: framing must stay aligned
            if (len > cap) { out.status = TransportStatus::TooLarge; return out; }
            if (len) std::memcpy(buf, body, len);
            out.status = TransportStatus::Ok;
            out.len = len;
            return out;
        }
        const size_t before = in_.size();
        if (!fill()) { out.status = failure_; return out; }               // EOF/error, also when a frame is cut short
        if (in_.size() == before) { out.status = TransportStatus::WouldBlock; return out; }
    }
}

}  // namespace pf
