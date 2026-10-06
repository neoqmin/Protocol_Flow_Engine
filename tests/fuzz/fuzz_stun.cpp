// libFuzzer: arbitrary bytes -> STUN parse (PM-2b N1). Invariants on every input that parses:
//   * every attribute lies inside the message, offsets strictly increase, size == input length;
//   * every decoder runs without fault on every attribute;
//   * rebuilding the ordinary attributes with the builder and parsing again yields the same types and values;
//   * verify_integrity never faults (dummy HMAC: the codec's bounds, not the MAC, are under test).
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "pf/stun.h"

namespace {
class DummyHmac final : public pf::stun::StunHmac {
public:
    bool hmac_sha1(const uint8_t*, size_t, const uint8_t* d, size_t n, uint8_t out[20]) const override {
        std::memset(out, n ? d[n - 1] : 0, 20);
        return true;
    }
    bool hmac_sha256(const uint8_t*, size_t, const uint8_t* d, size_t n, uint8_t out[32]) const override {
        std::memset(out, n ? d[0] : 0, 32);
        return true;
    }
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace pf::stun;
    (void)looks_like_stun(data, size);
    Message m;
    if (parse(data, size, m) != ParseStatus::Ok) return 0;
    if (m.size != size || size % 4 != 0) std::abort();
    size_t last = 0;
    MessageBuilder b(m.method, m.cls, m.tid);
    size_t ordinary = 0;
    for (const auto& a : m.attributes) {
        if (a.offset < kHeaderLen || a.offset <= last || a.offset + 4 + a.length > size) std::abort();
        if (a.value != data + a.offset + 4) std::abort();
        last = a.offset;
        Address addr;
        (void)decode_address(a, addr);
        (void)decode_xor_address(a, m.tid, addr);
        if (decode_address(a, addr)) (void)addr.to_string();
        ErrorCode e;
        (void)decode_error_code(a, e);
        std::vector<uint16_t> u;
        (void)decode_unknown_attributes(a, u);
        uint32_t fp = 0;
        (void)decode_fingerprint(a, fp);
        (void)attribute_text(a);
        if (a.type != kAttrMessageIntegrity && a.type != kAttrMessageIntegritySha256 && a.type != kAttrFingerprint) {
            b.add(a.type, a.value, a.length);
            ++ordinary;
        }
    }
    const DummyHmac h;
    const uint8_t key[4] = {1, 2, 3, 4};
    (void)verify_integrity(data, m, key, sizeof key, h);
    (void)verify_integrity(data, m, key, sizeof key, h, true);
    if (m.integrity || m.integrity_sha256) return 0;      // ordinary attributes before MI: rebuilt below would differ in order
    if (!b.ok()) std::abort();
    Message again;
    if (parse(b.bytes().data(), b.bytes().size(), again) != ParseStatus::Ok) std::abort();
    if (again.attributes.size() != ordinary || again.method != m.method || again.cls != m.cls || again.tid != m.tid) std::abort();
    for (size_t i = 0, k = 0; i < m.attributes.size(); ++i) {
        const auto& a = m.attributes[i];
        if (a.type == kAttrFingerprint) continue;
        const auto& r = again.attributes[k++];
        if (r.type != a.type || r.length != a.length || std::memcmp(r.value, a.value, a.length) != 0) std::abort();
    }
    return 0;
}
