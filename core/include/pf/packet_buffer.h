#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>

namespace pf {

// Room reserved in front/behind payload so encapsulation (DATA_V2 header 4 +
// packet-id 4) and AEAD tag (16) can be added in place without copying.
inline constexpr size_t kDefaultHeadroom = 32;
inline constexpr size_t kDefaultTailroom = 32;

// Owns one contiguous allocation: [ headroom | data | tailroom ].
//   pull_front / trim_back  strip a header / trailer (no copy)
//   push_front / put        add a header / append (fails if no room, never reallocates)
// Move-only: a packet has exactly one owner; Blocks borrow it via FlowContext.
// All operations are bounds-checked and leave the buffer unchanged on failure.
class PacketBuffer {
public:
    PacketBuffer() = default;
    // Empty buffer; usable room = headroom + capacity + tailroom.
    PacketBuffer(size_t headroom, size_t capacity, size_t tailroom = 0);
    static PacketBuffer from_bytes(const uint8_t* src, size_t n,
                                   size_t headroom = kDefaultHeadroom,
                                   size_t tailroom = kDefaultTailroom);

    PacketBuffer(const PacketBuffer&) = delete;
    PacketBuffer& operator=(const PacketBuffer&) = delete;
    PacketBuffer(PacketBuffer&& o) noexcept;
    PacketBuffer& operator=(PacketBuffer&& o) noexcept;

    uint8_t* data() { return base_.get() ? base_.get() + start_ : nullptr; }
    const uint8_t* data() const { return base_.get() ? base_.get() + start_ : nullptr; }
    size_t size() const { return len_; }
    size_t headroom() const { return start_; }
    size_t tailroom() const { return total_ - start_ - len_; }

    uint8_t* push_front(size_t n);   // nullptr if n > headroom()
    bool pull_front(size_t n);       // false if n > size()
    uint8_t* put(size_t n);          // nullptr if n > tailroom()
    bool trim_back(size_t n);        // false if n > size()

    // Zero the whole allocation (plaintext/keys must not linger) and empty it.
    void wipe();

private:
    std::unique_ptr<uint8_t[]> base_;
    size_t total_ = 0;
    size_t start_ = 0;
    size_t len_ = 0;
};

}  // namespace pf
