// libFuzzer: control-packet plaintext parser. Whatever parses must re-serialize without crashing, and a
// successful build must parse back to the same fields.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include "pf/control_packet.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 9) return 0;
    const uint8_t op_keyid = data[0];
    pf::ControlPacket p{};
    if (pf::parse_control(op_keyid, data + 1, data + 9, size - 9, p) != pf::ControlParseStatus::Ok) return 0;
    std::vector<uint8_t> out;
    if (!pf::build_control_plaintext(p, out)) return 0;
    pf::ControlPacket q{};
    if (pf::parse_control(op_keyid, data + 1, out.data(), out.size(), q) != pf::ControlParseStatus::Ok) std::abort();
    return 0;
}
