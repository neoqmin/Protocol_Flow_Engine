// STUN codec (RFC 8489) without keys: exhaustive type packing, demux, every header/attribute rule, decoders, builder,
// and random build -> parse round trips. Integrity: test_stun_openssl.cpp; RFC 5769 vectors: regression/.
#include <random>
#include <string>

#include "pf/stun.h"
#include "pf_test.h"

using namespace pf;
using namespace pf::stun;

namespace {
TransactionId tid_of(uint8_t seed) {
    TransactionId t;
    for (size_t i = 0; i < t.size(); ++i) t[i] = static_cast<uint8_t>(seed + i * 17);
    return t;
}
std::vector<uint8_t> binding_with(std::initializer_list<std::pair<uint16_t, std::vector<uint8_t>>> attrs) {
    MessageBuilder b(kMethodBinding, Class::Request, tid_of(1));
    for (const auto& a : attrs) b.add(a.first, a.second.data(), a.second.size());
    PF_REQUIRE(b.ok());
    return b.bytes();
}
void put16(std::vector<uint8_t>& v, size_t at, uint16_t x) { v[at] = static_cast<uint8_t>(x >> 8); v[at + 1] = static_cast<uint8_t>(x); }
ParseStatus parse_vec(const std::vector<uint8_t>& v, Message& m) { return parse(v.data(), v.size(), m); }
}  // namespace

PF_TEST(stun_type_packing_is_exhaustively_reversible) {
    for (uint16_t method = 0; method <= 0x0FFF; ++method)
        for (uint8_t c = 0; c < 4; ++c) {
            const uint16_t t = make_type(method, static_cast<Class>(c));
            PF_REQUIRE((t & 0xC000) == 0);
            uint16_t m2 = 0;
            Class c2;
            split_type(t, m2, c2);
            PF_REQUIRE(m2 == method && static_cast<uint8_t>(c2) == c);
        }
    // RFC 8489 section 6 / 5769: Binding request 0x0001, success 0x0101, error 0x0111, indication 0x0011
    PF_CHECK_EQ(make_type(kMethodBinding, Class::Request), uint16_t{0x0001});
    PF_CHECK_EQ(make_type(kMethodBinding, Class::Success), uint16_t{0x0101});
    PF_CHECK_EQ(make_type(kMethodBinding, Class::Error), uint16_t{0x0111});
    PF_CHECK_EQ(make_type(kMethodBinding, Class::Indication), uint16_t{0x0011});
    PF_CHECK_EQ(make_type(kMethodAllocate, Class::Request), uint16_t{0x0003});
    PF_CHECK_EQ(make_type(kMethodData, Class::Indication), uint16_t{0x0017});
}

PF_TEST(stun_demux_by_first_byte_never_matches_openvpn) {
    std::vector<uint8_t> msg = binding_with({});
    PF_CHECK(looks_like_stun(msg.data(), msg.size()));
    for (int b = 0; b < 256; ++b) {
        msg[0] = static_cast<uint8_t>(b);
        PF_CHECK(looks_like_stun(msg.data(), msg.size()) == (b <= 3));
        // OpenVPN packets start with opcode << 3 | key_id, opcode 1..11: never 0..3
        if ((b >> 3) >= 1 && (b >> 3) <= 11) PF_CHECK(!looks_like_stun(msg.data(), msg.size()));
    }
    msg[0] = 0;
    msg[4] ^= 1;                                                  // wrong cookie
    PF_CHECK(!looks_like_stun(msg.data(), msg.size()));
    PF_CHECK(!looks_like_stun(msg.data(), kHeaderLen - 1));
    PF_CHECK(!looks_like_stun(nullptr, 100));
}

PF_TEST(stun_header_rules) {
    Message m;
    const std::vector<uint8_t> ok = binding_with({{kAttrSoftware, {'x'}}});
    PF_CHECK(parse_vec(ok, m) == ParseStatus::Ok);
    PF_CHECK_EQ(m.size, ok.size());
    PF_CHECK(m.tid == tid_of(1));
    for (size_t n = 0; n < kHeaderLen; ++n) PF_CHECK(parse(ok.data(), n, m) == ParseStatus::Truncated);
    PF_CHECK(parse(nullptr, 0, m) == ParseStatus::Truncated);
    auto top = ok; top[0] |= 0x40;
    PF_CHECK(parse_vec(top, m) == ParseStatus::NotStun);
    auto top2 = ok; top2[0] |= 0x80;
    PF_CHECK(parse_vec(top2, m) == ParseStatus::NotStun);
    auto cookie = ok; cookie[7] ^= 0xFF;
    PF_CHECK(parse_vec(cookie, m) == ParseStatus::NotStun);
    auto odd = ok; put16(odd, 2, 6);
    PF_CHECK(parse_vec(odd, m) == ParseStatus::BadLength);         // not a multiple of 4
    auto longer = ok; put16(longer, 2, 12);
    PF_CHECK(parse_vec(longer, m) == ParseStatus::Truncated);      // claims more than the buffer holds
    auto trailing = ok; trailing.push_back(0); trailing.push_back(0); trailing.push_back(0); trailing.push_back(0);
    PF_CHECK(parse_vec(trailing, m) == ParseStatus::BadLength);    // bytes after the message
    for (size_t cut = kHeaderLen; cut < ok.size(); ++cut) PF_CHECK(parse(ok.data(), cut, m) != ParseStatus::Ok);
    const std::vector<uint8_t> empty = binding_with({});
    PF_CHECK(parse_vec(empty, m) == ParseStatus::Ok);
    PF_CHECK(m.attributes.empty());
}

PF_TEST(stun_attribute_rules) {
    Message m;
    // attribute header cut short / value running past the end
    auto msg = binding_with({{kAttrSoftware, {1, 2, 3, 4}}});
    put16(msg, 22, 5);                                              // length 5 -> padded 8, only 4 bytes present
    PF_CHECK(parse_vec(msg, m) == ParseStatus::BadAttribute);
    // padding is not counted in length but must be present; padding VALUES are ignored
    auto pad = binding_with({{kAttrSoftware, {'a', 'b', 'c'}}});
    pad[27] = 0xEE;
    PF_CHECK(parse_vec(pad, m) == ParseStatus::Ok);
    PF_CHECK_EQ(std::string(attribute_text(*m.find(kAttrSoftware))), std::string("abc"));
    // zero-length attributes are fine
    PF_CHECK(parse_vec(binding_with({{kAttrSoftware, {}}}), m) == ParseStatus::Ok);
    PF_CHECK_EQ(m.attributes.size(), size_t{1});
    // too many attributes
    MessageBuilder many(kMethodBinding, Class::Request, tid_of(2));
    for (size_t i = 0; i <= kMaxAttributes; ++i) many.add(kAttrSoftware, nullptr, 0);
    PF_REQUIRE(many.ok());
    PF_CHECK(parse(many.bytes().data(), many.bytes().size(), m) == ParseStatus::TooManyAttributes);
    // duplicates: kept in order, find() returns the first
    auto dup = binding_with({{kAttrSoftware, {'1'}}, {kAttrSoftware, {'2'}}});
    PF_REQUIRE(parse_vec(dup, m) == ParseStatus::Ok);
    PF_CHECK_EQ(std::string(attribute_text(*m.find(kAttrSoftware))), std::string("1"));
    // unknown comprehension-required types are reported (distinct), optional ones are not
    auto unk = binding_with({{0x7F01, {}}, {0x7F01, {}}, {0x0024, {0, 0, 0, 1}}, {0xC001, {}}});
    PF_REQUIRE(parse_vec(unk, m) == ParseStatus::Ok);
    PF_CHECK(m.unknown_required == (std::vector<uint16_t>{0x7F01, 0x0024}));
    // TURN attributes count as understood
    PF_CHECK(parse_vec(binding_with({{0x000D, {0, 0, 0, 1}}, {0x0012, std::vector<uint8_t>(8, 0)}}), m) == ParseStatus::Ok);
    PF_CHECK(m.unknown_required.empty());
}

PF_TEST(stun_integrity_and_fingerprint_ordering) {
    // A fake 20-byte MI and 32-byte MI-SHA256 are fine structurally (their MACs are checked elsewhere).
    std::vector<uint8_t> mi(20, 0xAA), mi256(32, 0xBB);
    MessageBuilder raw(kMethodBinding, Class::Request, tid_of(3));
    raw.add(kAttrSoftware, reinterpret_cast<const uint8_t*>("s"), 1);
    std::vector<uint8_t> v = raw.bytes();
    auto append = [&](uint16_t type, const std::vector<uint8_t>& val) {
        const size_t at = v.size();
        v.resize(at + 4 + ((val.size() + 3) & ~size_t{3}), 0);
        put16(v, at, type);
        put16(v, at + 2, static_cast<uint16_t>(val.size()));
        std::copy(val.begin(), val.end(), v.begin() + static_cast<long>(at) + 4);
        put16(v, 2, static_cast<uint16_t>(v.size() - kHeaderLen));
    };
    append(kAttrMessageIntegrity, mi);
    append(kAttrRealm, {'r'});                    // after MI: ignored
    append(kAttrMessageIntegritySha256, mi256);   // allowed after MI
    append(kAttrNonce, {'n'});                    // after MI-SHA256: ignored
    Message m;
    PF_REQUIRE(parse_vec(v, m) == ParseStatus::Ok);
    PF_CHECK_EQ(m.ignored_after_integrity, size_t{2});
    PF_CHECK(m.find(kAttrRealm) == nullptr);
    PF_CHECK(m.integrity.has_value() && m.integrity_sha256.has_value());
    PF_CHECK_EQ(m.attributes.size(), size_t{3});
    // FINGERPRINT must be last
    auto fp = binding_with({{kAttrSoftware, {'x'}}});
    MessageBuilder withfp(kMethodBinding, Class::Request, tid_of(1));
    withfp.add(kAttrSoftware, reinterpret_cast<const uint8_t*>("x"), 1).add_fingerprint();
    std::vector<uint8_t> after = withfp.bytes();
    PF_REQUIRE(parse_vec(after, m) == ParseStatus::Ok);
    PF_CHECK(m.fingerprint.has_value());
    after.insert(after.end(), {0x80, 0x22, 0x00, 0x00});
    put16(after, 2, static_cast<uint16_t>(after.size() - kHeaderLen));
    PF_CHECK(parse_vec(after, m) == ParseStatus::AttributeAfterFingerprint);
    // wrong fingerprint value / length
    std::vector<uint8_t> badfp = withfp.bytes();
    badfp.back() ^= 1;
    PF_CHECK(parse_vec(badfp, m) == ParseStatus::BadFingerprint);
    PF_CHECK(parse_vec(binding_with({{kAttrSoftware, {}}}), m) == ParseStatus::Ok);
    std::vector<uint8_t> shortfp = binding_with({});
    shortfp.insert(shortfp.end(), {0x80, 0x28, 0x00, 0x00});
    put16(shortfp, 2, 4);
    PF_CHECK(parse_vec(shortfp, m) == ParseStatus::BadFingerprint);
}

PF_TEST(stun_addresses_round_trip_plain_and_xor) {
    std::mt19937 rng(8489);
    for (int i = 0; i < 2000; ++i) {
        Address a;
        a.family = (i & 1) ? Address::Family::V6 : Address::Family::V4;
        for (auto& b : a.ip) b = static_cast<uint8_t>(rng());
        if (a.family == Address::Family::V4) std::fill(a.ip.begin() + 4, a.ip.end(), 0);
        a.port = static_cast<uint16_t>(rng());
        const TransactionId t = tid_of(static_cast<uint8_t>(rng()));
        MessageBuilder b(kMethodBinding, Class::Success, t);
        b.add_xor_address(kAttrXorMappedAddress, a).add_address(kAttrMappedAddress, a);
        PF_REQUIRE(b.ok());
        Message m;
        PF_REQUIRE(parse(b.bytes().data(), b.bytes().size(), m) == ParseStatus::Ok);
        Address x, p;
        PF_REQUIRE(decode_xor_address(*m.find(kAttrXorMappedAddress), m.tid, x));
        PF_REQUIRE(decode_address(*m.find(kAttrMappedAddress), p));
        PF_CHECK(x == a);
        PF_CHECK(p == a);
        // the XOR form never carries the address in the clear (that is its purpose: NATs rewriting payloads)
        const Attribute* xa = m.find(kAttrXorMappedAddress);
        PF_CHECK(!std::equal(a.ip.begin(), a.ip.begin() + (a.family == Address::Family::V4 ? 4 : 16), xa->value + 4) ||
                 a.port == 0);
    }
    Attribute bad;
    uint8_t v[20] = {0, 0x01, 0, 0};
    bad.value = v;
    bad.length = 20;                                   // V4 family with a V6 length
    Address out;
    PF_CHECK(!decode_address(bad, out));
    v[1] = 0x02; bad.length = 8;
    PF_CHECK(!decode_address(bad, out));
    v[1] = 0x03; bad.length = 8;
    PF_CHECK(!decode_address(bad, out));
    v[1] = 0x01; bad.length = 7;
    PF_CHECK(!decode_address(bad, out));
}

PF_TEST(stun_address_text_forms) {
    Address a;
    a.family = Address::Family::V4;
    a.ip = {192, 0, 2, 1};
    a.port = 32853;
    PF_CHECK_EQ(a.to_string(), std::string("192.0.2.1:32853"));
    a.family = Address::Family::V6;
    a.ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    PF_CHECK_EQ(a.to_string(), std::string("[2001:db8::1]:32853"));
    a.ip = {};
    PF_CHECK_EQ(a.to_string(), std::string("[::]:32853"));
    a.ip[15] = 1;
    PF_CHECK_EQ(a.to_string(), std::string("[::1]:32853"));
    a.ip = {0x20, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    PF_CHECK_EQ(a.to_string(), std::string("[2001:0:0:1::]:32853"));   // the longer zero run is compressed
}

PF_TEST(stun_error_code_and_unknown_attributes) {
    MessageBuilder b(kMethodBinding, Class::Error, tid_of(4));
    b.add_error_code(420, "Unknown Attribute");
    const uint8_t list[] = {0x00, 0x24, 0x7F, 0x01};
    b.add(kAttrUnknownAttributes, list, sizeof list);
    PF_REQUIRE(b.ok());
    Message m;
    PF_REQUIRE(parse(b.bytes().data(), b.bytes().size(), m) == ParseStatus::Ok);
    ErrorCode e;
    PF_REQUIRE(decode_error_code(*m.find(kAttrErrorCode), e));
    PF_CHECK_EQ(e.code, 420);
    PF_CHECK_EQ(e.reason, std::string("Unknown Attribute"));
    std::vector<uint16_t> u;
    PF_REQUIRE(decode_unknown_attributes(*m.find(kAttrUnknownAttributes), u));
    PF_CHECK(u == (std::vector<uint16_t>{0x0024, 0x7F01}));
    for (int code : {300, 401, 438, 500, 699}) {
        MessageBuilder c(kMethodBinding, Class::Error, tid_of(5));
        c.add_error_code(code, "");
        PF_REQUIRE(c.ok());
        Message cm;
        PF_REQUIRE(parse(c.bytes().data(), c.bytes().size(), cm) == ParseStatus::Ok);
        ErrorCode ce;
        PF_REQUIRE(decode_error_code(*cm.find(kAttrErrorCode), ce));
        PF_CHECK_EQ(ce.code, code);
    }
    PF_CHECK(!MessageBuilder(kMethodBinding, Class::Error, tid_of(5)).add_error_code(299, "").ok());
    PF_CHECK(!MessageBuilder(kMethodBinding, Class::Error, tid_of(5)).add_error_code(700, "").ok());
    uint8_t raw[4] = {0, 0, 2, 0};                      // class 2 is not an error class
    Attribute a;
    a.value = raw;
    a.length = 4;
    PF_CHECK(!decode_error_code(a, e));
    raw[2] = 4; raw[3] = 100;                            // number > 99
    PF_CHECK(!decode_error_code(a, e));
    a.length = 3;
    PF_CHECK(!decode_error_code(a, e));
    const uint8_t oddlist[3] = {0, 1, 2};
    a.value = oddlist;
    a.length = 3;
    PF_CHECK(!decode_unknown_attributes(a, u));
}

PF_TEST(stun_crc32_and_builder_misuse) {
    const char* check = "123456789";
    PF_CHECK_EQ(crc32(reinterpret_cast<const uint8_t*>(check), 9), uint32_t{0xCBF43926});   // CRC-32/ISO-HDLC check value
    PF_CHECK_EQ(crc32(nullptr, 0), uint32_t{0});
    const TransactionId t = tid_of(6);
    PF_CHECK(!MessageBuilder(0x1000, Class::Request, t).ok());                       // method > 12 bits
    MessageBuilder fp(kMethodBinding, Class::Request, t);
    fp.add_fingerprint().add_text(kAttrSoftware, "late");
    PF_CHECK(!fp.ok());                                                               // nothing after FINGERPRINT
    MessageBuilder direct(kMethodBinding, Class::Request, t);
    direct.add(kAttrFingerprint, nullptr, 0);
    PF_CHECK(!direct.ok());                                                           // must use add_fingerprint()
    MessageBuilder big(kMethodBinding, Class::Request, t);
    std::vector<uint8_t> huge(70000, 0);
    big.add(kAttrSoftware, huge.data(), huge.size());
    PF_CHECK(!big.ok());
    MessageBuilder full(kMethodBinding, Class::Request, t);
    std::vector<uint8_t> chunk(30000, 0);
    full.add(kAttrSoftware, chunk.data(), chunk.size()).add(kAttrSoftware, chunk.data(), chunk.size()).add(kAttrSoftware, chunk.data(), chunk.size());
    PF_CHECK(!full.ok());                                                             // 16-bit message length exceeded
}

PF_TEST(stun_random_messages_round_trip) {
    std::mt19937 rng(5769);
    const uint16_t types[] = {kAttrUsername, kAttrRealm, kAttrNonce, kAttrSoftware, 0x0024, 0x8029, 0xC0DE, 0x000D};
    for (int i = 0; i < 3000; ++i) {
        const uint16_t method = static_cast<uint16_t>(rng() & 0xFFF);
        const Class cls = static_cast<Class>(rng() & 3);
        const TransactionId t = tid_of(static_cast<uint8_t>(rng()));
        MessageBuilder b(method, cls, t);
        std::vector<std::pair<uint16_t, std::vector<uint8_t>>> want;
        const size_t n = rng() % 10;
        for (size_t k = 0; k < n; ++k) {
            std::vector<uint8_t> v(rng() % 40);
            for (auto& x : v) x = static_cast<uint8_t>(rng());
            const uint16_t ty = types[rng() % 8];
            b.add(ty, v.data(), v.size(), static_cast<uint8_t>(rng()));
            want.emplace_back(ty, v);
        }
        const bool with_fp = rng() & 1;
        if (with_fp) b.add_fingerprint();
        PF_REQUIRE(b.ok());
        Message m;
        PF_REQUIRE(parse(b.bytes().data(), b.bytes().size(), m) == ParseStatus::Ok);
        PF_CHECK(m.method == method && m.cls == cls && m.tid == t);
        PF_REQUIRE(m.attributes.size() == want.size() + (with_fp ? 1 : 0));
        for (size_t k = 0; k < want.size(); ++k) {
            PF_CHECK_EQ(m.attributes[k].type, want[k].first);
            PF_CHECK(std::vector<uint8_t>(m.attributes[k].value, m.attributes[k].value + m.attributes[k].length) == want[k].second);
        }
        PF_CHECK(m.fingerprint.has_value() == with_fp);
        PF_CHECK(b.bytes().size() % 4 == 0);
    }
}
