// libFuzzer: key-method 2 peer info parsing (text from the client, PM-11 server side) and the profile check.
#include <cstddef>
#include <cstdint>
#include <string_view>
#include "pf/peer_info.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view s(reinterpret_cast<const char*>(data), size);
    pf::PeerInfo p;
    if (pf::parse_peer_info(s, p) == pf::PeerInfoStatus::Ok) {
        if (p.values.size() > static_cast<size_t>(pf::kMaxPeerInfoEntries)) __builtin_trap();
        (void)pf::peer_info_unsupported_reason(p);
    }
    return 0;
}
