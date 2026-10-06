#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>

namespace pf {

// Randomness is injected like the clock (F-1 follow-up, D-047): protocol code asks a RandomSource, never the OS.
// Production uses the OS CSPRNG through OpenSSL (pf/crypto/os_random.h); tests and simulations use
// DeterministicRandom so every run is reproducible. Values that must be unpredictable (STUN transaction ids, ICE
// tie-breakers, TURN nonces) must only ever come from a cryptographic source in production.
class RandomSource {
public:
    virtual ~RandomSource() = default;
    // false = the source failed (callers must treat it as a hard error, never fall back to weak randomness).
    virtual bool fill(uint8_t* out, size_t len) = 0;
};

// Reproducible, NOT cryptographic (splitmix64). For tests and simulations only.
class DeterministicRandom final : public RandomSource {
public:
    explicit DeterministicRandom(uint64_t seed) : state_(seed) {}
    bool fill(uint8_t* out, size_t len) override {
        for (size_t i = 0; i < len; ++i) {
            if (i % 8 == 0) {
                uint64_t z = (state_ += 0x9E3779B97F4A7C15ull);
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
                word_ = z ^ (z >> 31);
            }
            out[i] = static_cast<uint8_t>(word_ >> (8 * (i % 8)));
        }
        return true;
    }

private:
    uint64_t state_, word_ = 0;
};

}  // namespace pf
