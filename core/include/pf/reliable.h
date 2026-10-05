#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <vector>

#include "pf/control_packet.h"

namespace pf {

// Reliability layer of the control channel ("acknowledge and retransmit"): pure logic, no I/O and no
// clock - callers pass `now_ms`, so behavior is deterministic and testable. Timing/window values are OUR
// choices (the protocol only requires that we ACK what we receive and retransmit what is not ACKed);
// they are validated against the real server in the interop tests.
struct ReliableConfig {
    size_t send_window = 4;        // max unacknowledged messages in flight
    uint32_t rto_ms = 2000;        // first retransmission timeout
    uint32_t max_rto_ms = 16000;   // backoff cap (doubles each attempt)
    unsigned max_attempts = 6;     // total transmissions per message before the session is declared dead
    size_t recv_window = 8;        // how far ahead of the next expected id we buffer
};

// Receive side: reorders messages, drops duplicates, and remembers what to acknowledge.
class ReliableReceiver {
public:
    enum class Result { Delivered, Buffered, Duplicate, OutOfWindow };
    struct Delivered {
        uint32_t id;
        std::vector<uint8_t> payload;
    };

    explicit ReliableReceiver(ReliableConfig cfg = {}) : cfg_(cfg) {}

    // In-order messages (this one and any buffered successors) are appended to `out`.
    // Every accepted or duplicate message is queued for acknowledgement; OutOfWindow ones are not.
    Result on_message(uint32_t id, const std::vector<uint8_t>& payload, std::vector<Delivered>& out);

    bool has_pending_acks() const { return !pending_.empty(); }
    // Removes and returns up to `max` pending ids, newest first (as OpenVPN lists them).
    std::vector<uint32_t> take_acks(size_t max);
    uint32_t next_expected() const { return next_; }

private:
    void queue_ack(uint32_t id);

    ReliableConfig cfg_;
    uint32_t next_ = 0;
    std::map<uint32_t, std::vector<uint8_t>> buffered_;
    std::deque<uint32_t> pending_;   // oldest first
};

// Send side: assigns message ids (0,1,2,...), tracks unacknowledged messages and schedules retransmissions.
class ReliableSender {
public:
    struct Outgoing {
        uint32_t id;
        uint8_t opcode;
        std::vector<uint8_t> payload;
        unsigned attempt;            // 1 = first transmission
    };

    explicit ReliableSender(ReliableConfig cfg = {}) : cfg_(cfg) {}

    bool can_send() const { return !exhausted_ && queue_.size() < cfg_.send_window; }
    // false if the window is full or the 32-bit id space is used up (never reuse ids).
    bool enqueue(uint8_t opcode, std::vector<uint8_t> payload, uint32_t& id_out);
    void on_ack(const uint32_t* ids, size_t n);   // unknown/duplicate ids are ignored

    // Messages that must be (re)transmitted at `now_ms`. Marks them sent. Empty once failed().
    std::vector<Outgoing> due(uint64_t now_ms);
    bool failed() const { return failed_; }
    size_t outstanding() const { return queue_.size(); }
    // Earliest time something is due (0 = a message was never sent), or nullopt if nothing is outstanding.
    std::optional<uint64_t> next_deadline_ms() const;

    void set_next_id_for_test(uint32_t id) { next_id_ = id; }

private:
    struct Entry {
        uint8_t opcode;
        std::vector<uint8_t> payload;
        unsigned attempts = 0;
        uint64_t last_sent_ms = 0;
        uint32_t wait_ms = 0;
    };

    ReliableConfig cfg_;
    uint32_t next_id_ = 0;
    bool exhausted_ = false;
    bool failed_ = false;
    std::map<uint32_t, Entry> queue_;
};

}  // namespace pf
