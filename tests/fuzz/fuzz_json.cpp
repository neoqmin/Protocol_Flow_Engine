// libFuzzer: strict JSON parser. Anything accepted must write back to text that parses to an equal value, and writing
// that value again must be byte-identical (stable canonical output).
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include "pf/json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto r = pf::parse_json(std::string_view(reinterpret_cast<const char*>(data), size));
    if (!r.ok) return 0;
    for (const bool pretty : {true, false}) {
        const std::string out = pf::write_json(r.value, pretty);
        const auto back = pf::parse_json(out);
        if (!back.ok || !(back.value == r.value)) std::abort();
        if (pf::write_json(back.value, pretty) != out) std::abort();
    }
    return 0;
}
