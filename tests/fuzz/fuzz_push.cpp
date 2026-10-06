// libFuzzer: PUSH_REPLY / control-message parsing (text from the server).
#include <cstddef>
#include <cstdint>
#include <string_view>
#include "pf/push.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view s(reinterpret_cast<const char*>(data), size);
    (void)pf::classify_control_message(s);
    pf::PushReply r;
    if (pf::parse_push_reply(s, r) == pf::PushStatus::Ok) (void)r.supported_by_mvp();
    uint32_t ip;
    (void)pf::parse_ipv4(s, ip);
    return 0;
}
