// libFuzzer: TCP framing reassembly. Arbitrary byte streams delivered in arbitrary chunk sizes must never crash,
// every delivered packet must fit the caller's buffer, and total delivered bytes can never exceed what was fed.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <memory>

#include "pf/byte_stream.h"
#include "pf/framed_transport.h"

namespace {
struct Feed : pf::ByteStream {
    const uint8_t* d; size_t n, pos = 0, chunk;
    Feed(const uint8_t* data, size_t size, size_t c) : d(data), n(size), chunk(c) {}
    pf::StreamResult read(uint8_t* buf, size_t cap) override {
        pf::StreamResult r;
        if (pos >= n) { r.status = pf::StreamStatus::Closed; return r; }
        const size_t k = std::min({cap, n - pos, chunk});
        for (size_t i = 0; i < k; ++i) buf[i] = d[pos + i];
        pos += k;
        r.status = pf::StreamStatus::Ok; r.n = k;
        return r;
    }
    pf::StreamResult write(const uint8_t*, size_t len) override { pf::StreamResult r; r.status = pf::StreamStatus::Ok; r.n = len; return r; }
    void close() override {}
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const size_t chunk = 1 + data[0] % 97;
    const size_t cap = 1 + data[1] * 8;
    pf::FramedTransport t(std::make_unique<Feed>(data + 2, size - 2, chunk));
    std::unique_ptr<uint8_t[]> buf(new uint8_t[cap]);
    size_t total = 0;
    for (int i = 0; i < 100000; ++i) {
        const pf::RecvResult r = t.recv(buf.get(), cap);
        if (r.status == pf::TransportStatus::Ok) {
            if (r.len > cap) std::abort();
            total += r.len;
            if (total > size) std::abort();
        } else if (r.status != pf::TransportStatus::TooLarge) {
            break;
        }
    }
    return 0;
}
