// libFuzzer: reliability receiver driven by arbitrary (id, payload) sequences. Invariants: next_expected never
// decreases and delivered ids are strictly consecutive.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include "pf/reliable.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pf::ReliableReceiver rx;
    uint32_t prev_next = 0;
    for (size_t i = 0; i + 2 <= size; i += 2) {
        const uint32_t id = data[i] % 24;
        std::vector<pf::ReliableReceiver::Delivered> out;
        (void)rx.on_message(id, std::vector<uint8_t>(1, data[i + 1]), out);
        uint32_t expect = prev_next;
        for (const auto& d : out) if (d.id != expect++) std::abort();
        if (rx.next_expected() < prev_next) std::abort();
        prev_next = rx.next_expected();
        (void)rx.take_acks(8);
    }
    return 0;
}
