// libFuzzer: Flow JSON loader. Whatever loads must re-serialize to a canonical text that loads again to the same
// document and is itself a fixed point; no input may crash the loader, and no accepted document may contain a
// secret-looking parameter.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include "pf/flow_json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto r = pf::parse_flow_json(std::string_view(reinterpret_cast<const char*>(data), size));
    if (!r.ok()) return 0;
    const std::string out = pf::write_flow_json(r.doc);
    const auto back = pf::parse_flow_json(out);
    if (!back.ok()) std::abort();
    if (pf::write_flow_json(back.doc) != out) std::abort();
    for (const auto& n : r.doc.nodes)
        for (const auto& p : n.params)
            if (p.first == "key" || p.first == "secret" || p.first == "password") std::abort();
    return 0;
}
