#pragma once
#include <cstdint>
#include <memory>
#include <vector>

#include "pf/byte_stream.h"
#include "pf/transport.h"

namespace pf {

// OpenVPN over a byte stream (TCP): every packet is preceded by a 2-byte big-endian length. This class turns the
// stream into the packet-oriented Transport contract: send() frames and queues, recv() reassembles from arbitrary
// chunks. No sockets and no clocks - it only talks to a ByteStream, so tests can feed it one byte at a time.
//
// Backpressure: send() queues until `max_queued_bytes`, beyond which it reports WouldBlock (nothing is dropped
// silently - the stream is reliable, so losing a frame would corrupt the framing). A stream that fails or ends
// mid-frame is reported as Error/Closed and the transport stays closed.
class FramedTransport : public Transport {
public:
    static constexpr size_t kLengthPrefix = 2;
    static constexpr size_t kMaxPacket = 0xFFFF;

    FramedTransport(std::unique_ptr<ByteStream> stream, TransportKind kind = TransportKind::Tcp,
                    size_t max_queued_bytes = 256 * 1024)
        : stream_(std::move(stream)), kind_(kind), max_queued_(max_queued_bytes) {}

    TransportKind kind() const override { return kind_; }
    TransportStatus send(const uint8_t* data, size_t len) override;
    RecvResult recv(uint8_t* buf, size_t cap) override;
    bool is_open() const override { return open_; }
    void close() override;
    size_t max_packet() const override { return kMaxPacket; }
    int poll_fd() const override { return stream_ ? stream_->poll_fd() : -1; }

    bool has_pending_input() const override;
    bool wants_write() const override { return open_ && out_pos_ < out_.size(); }
    void flush() override;

    size_t queued_output_bytes() const { return out_.size() - out_pos_; }

private:
    // Moves bytes from the stream into in_. Returns false when the stream failed/ended (state_ updated).
    bool fill();
    bool frame_available() const;
    void fail(TransportStatus s) { open_ = false; failure_ = s; }

    std::unique_ptr<ByteStream> stream_;
    TransportKind kind_;
    size_t max_queued_;
    bool open_ = true;
    TransportStatus failure_ = TransportStatus::Closed;

    std::vector<uint8_t> in_;       // received, not yet consumed
    size_t in_pos_ = 0;
    std::vector<uint8_t> out_;      // framed bytes not yet fully written
    size_t out_pos_ = 0;
};

}  // namespace pf
