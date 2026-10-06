#pragma once
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>

namespace pf {

// Protocol-specific per-packet state (F-2, D-043). The FlowContext carries ONE protocol slot: a type tag plus fixed-size
// storage, so the context does not grow a field for every protocol (OpenVPN today, STUN/TURN next) and needs no heap -
// the same layout a kernel runtime (PM-8) could use. A slot type is a trivially copyable struct with a unique, never
// renumbered `static constexpr ProtocolId kProtocolId` (registry below), at most kProtocolSlotBytes large.
using ProtocolId = uint16_t;

// Protocol ids (stable, like block ids): 0 = none.
inline constexpr ProtocolId kProtocolNone = 0;
inline constexpr ProtocolId kProtocolOpenVpn = 1;
inline constexpr ProtocolId kProtocolStun = 2;     // STUN/TURN (PM-2b, D-045)

inline constexpr size_t kProtocolSlotBytes = 128;

class ProtocolSlot {
public:
    ProtocolId id() const { return id_; }

    // The slot as T if it currently holds T, else nullptr.
    template <typename T>
    T* get() {
        check<T>();
        return id_ == T::kProtocolId ? std::launder(reinterpret_cast<T*>(storage_)) : nullptr;
    }
    template <typename T>
    const T* get() const {
        check<T>();
        return id_ == T::kProtocolId ? std::launder(reinterpret_cast<const T*>(storage_)) : nullptr;
    }
    // Starts a fresh T (value-initialised), replacing whatever the slot held.
    template <typename T>
    T& emplace() {
        check<T>();
        T* p = ::new (static_cast<void*>(storage_)) T();
        id_ = T::kProtocolId;
        return *p;
    }
    // The slot as T, starting a fresh T if it held something else (or nothing).
    template <typename T>
    T& as() {
        if (T* p = get<T>()) return *p;
        return emplace<T>();
    }
    void reset() { id_ = kProtocolNone; }

private:
    template <typename T>
    static constexpr void check() {
        static_assert(std::is_trivially_copyable_v<T> && std::is_trivially_destructible_v<T>, "slot types must be plain data");
        static_assert(sizeof(T) <= kProtocolSlotBytes, "slot type too large for the protocol slot");
        static_assert(alignof(T) <= alignof(std::max_align_t), "slot type over-aligned");
        static_assert(T::kProtocolId != kProtocolNone, "slot types need a protocol id");
    }

    alignas(std::max_align_t) unsigned char storage_[kProtocolSlotBytes];   // uninitialised until emplace
    ProtocolId id_ = kProtocolNone;
};

}  // namespace pf
