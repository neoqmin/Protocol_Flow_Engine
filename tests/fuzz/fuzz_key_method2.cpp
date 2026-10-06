// libFuzzer: key-method 2 message parser (untrusted bytes from the TLS stream). Consumed length must stay in range.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include "pf/key_method2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const size_t optional_fields = data[0] & 3;
    for (const auto from : {pf::KeyMethod2From::Client, pf::KeyMethod2From::Server}) {
        pf::KeyMethod2Message m;
        size_t consumed = 0;
        if (pf::parse_key_method2(data + 1, size - 1, from, m, consumed, optional_fields) == pf::KeyMethod2Status::Ok && consumed > size - 1)
            std::abort();
    }
    return 0;
}
