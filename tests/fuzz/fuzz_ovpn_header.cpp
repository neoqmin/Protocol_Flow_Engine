// libFuzzer target: the header parser must never crash or read out of bounds.
#include <cstddef>
#include <cstdint>
#include "pf/openvpn_header.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pf::OvpnHeader h{};
    (void)pf::parse_ovpn_header(data, size, h);
    return 0;
}
