#pragma once
#include <cstddef>
#include <cstdint>

namespace pf {

// Zeroizes memory in a way the optimizer may not drop (keys, plaintext).
inline void secure_zero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}

// Compares n bytes without early exit (timing does not depend on where they differ).
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

}  // namespace pf
