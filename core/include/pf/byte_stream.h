#pragma once
#include <cstddef>
#include <cstdint>

namespace pf {

enum class StreamStatus { Ok, WouldBlock, Closed, Error };

struct StreamResult {
    StreamStatus status = StreamStatus::WouldBlock;
    size_t n = 0;          // bytes moved; for Ok, 1..cap/len (never 0)
};

// A non-blocking, ordered, unframed byte pipe (a TCP socket, later a TLS or proxy tunnel). Partial reads and writes
// are normal: read() returns whatever is available, write() accepts as much as fits.
class ByteStream {
public:
    virtual ~ByteStream() = default;
    // Ok = n bytes read; WouldBlock = nothing now; Closed = orderly end of stream (EOF); Error = failure.
    virtual StreamResult read(uint8_t* buf, size_t cap) = 0;
    // Ok = n bytes (maybe fewer than len) were taken; WouldBlock = none could be taken now.
    virtual StreamResult write(const uint8_t* data, size_t len) = 0;
    virtual void close() = 0;
    virtual int poll_fd() const { return -1; }
};

}  // namespace pf
