// libFuzzer target: the DATA_V2 parser must never crash or read out of bounds.
#include <cstddef>
#include <cstdint>
#include "pf/data_v2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pf::DataV2Packet p{};
    (void)pf::parse_data_v2(data, size, p);
    return 0;
}
