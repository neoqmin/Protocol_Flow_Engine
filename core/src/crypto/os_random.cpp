#include "pf/crypto/os_random.h"

#include <openssl/rand.h>

#include <climits>

namespace pf {
namespace {
class OsRandom final : public RandomSource {
public:
    bool fill(uint8_t* out, size_t len) override {
        while (len > 0) {
            const int n = len > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(len);
            if (RAND_bytes(out, n) != 1) return false;
            out += n;
            len -= static_cast<size_t>(n);
        }
        return true;
    }
};
}  // namespace

std::unique_ptr<RandomSource> make_os_random() { return std::make_unique<OsRandom>(); }

}  // namespace pf
