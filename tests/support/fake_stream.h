#pragma once
// In-memory ByteStream pair for tests: bytes written on one end are read on the other, with adjustable chunking so
// partial reads/writes (the normal TCP behavior) can be forced deterministically.
#include <algorithm>
#include <deque>
#include <memory>
#include <vector>

#include "pf/byte_stream.h"

namespace pf::test {

struct StreamPipe {
    std::deque<uint8_t> to[2];          // to[i] = bytes waiting to be read by end i
    size_t read_chunk = SIZE_MAX;       // max bytes one read() returns
    size_t write_chunk = SIZE_MAX;      // max bytes one write() accepts
    size_t capacity = SIZE_MAX;         // max bytes buffered per direction (full pipe = WouldBlock)
    bool eof[2] = {false, false};       // end i has closed: the other end reads Closed once drained
    bool fail = false;                  // next ops report Error
};

class FakeStream : public ByteStream {
public:
    FakeStream(std::shared_ptr<StreamPipe> p, int side) : p_(std::move(p)), side_(side) {}
    StreamResult read(uint8_t* buf, size_t cap) override {
        StreamResult r;
        if (p_->fail) { r.status = StreamStatus::Error; return r; }
        auto& q = p_->to[side_];
        if (q.empty()) { r.status = p_->eof[1 - side_] ? StreamStatus::Closed : StreamStatus::WouldBlock; return r; }
        const size_t n = std::min({cap, q.size(), p_->read_chunk});
        for (size_t i = 0; i < n; ++i) { buf[i] = q.front(); q.pop_front(); }
        r.status = StreamStatus::Ok;
        r.n = n;
        return r;
    }
    StreamResult write(const uint8_t* data, size_t len) override {
        StreamResult r;
        if (p_->fail) { r.status = StreamStatus::Error; return r; }
        if (p_->eof[side_] || p_->eof[1 - side_]) { r.status = StreamStatus::Closed; return r; }
        auto& q = p_->to[1 - side_];
        const size_t room = p_->capacity > q.size() ? p_->capacity - q.size() : 0;
        const size_t n = std::min({len, p_->write_chunk, room});
        if (n == 0) { r.status = StreamStatus::WouldBlock; return r; }
        q.insert(q.end(), data, data + n);
        r.status = StreamStatus::Ok;
        r.n = n;
        return r;
    }
    void close() override { p_->eof[side_] = true; }

private:
    std::shared_ptr<StreamPipe> p_;
    int side_;
};

inline std::pair<std::unique_ptr<FakeStream>, std::unique_ptr<FakeStream>> make_stream_pair(std::shared_ptr<StreamPipe> p) {
    return {std::make_unique<FakeStream>(p, 0), std::make_unique<FakeStream>(p, 1)};
}

}  // namespace pf::test
