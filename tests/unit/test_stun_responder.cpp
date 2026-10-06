// PM-2b N3: the RFC 8489 / RFC 5780 Binding responder - reply contents and which local address the reply leaves from.
#include "pf/stun_responder.h"
#include "pf_test.h"

using namespace pf::stun;

namespace {
Address addr(uint8_t d, uint16_t port) {
    Address x;
    x.family = Address::Family::V4;
    x.ip = {198, 51, 100, d};
    x.port = port;
    return x;
}
const Address P = addr(1, 3478), A = addr(2, 3479);
Address client() {
    Address c;
    c.ip = {203, 0, 113, 9};
    c.port = 40000;
    return c;
}
std::vector<uint8_t> request(uint32_t change = 0, uint16_t extra = 0) {
    TransactionId t{};
    t[0] = 0x42;
    MessageBuilder b(kMethodBinding, Class::Request, t);
    if (change) b.add_u32(kAttrChangeRequest, change);
    if (extra) b.add(extra, nullptr, 0);
    b.add_fingerprint();
    PF_REQUIRE(b.ok());
    return b.bytes();
}
Message reply_of(const ResponderReply& r) {
    Message m;
    PF_REQUIRE(parse(r.bytes.data(), r.bytes.size(), m) == ParseStatus::Ok);
    return m;
}
Address attr_addr(const Message& m, uint16_t type, bool xored = false) {
    Address a;
    const Attribute* x = m.find(type);
    PF_REQUIRE(x != nullptr);
    PF_REQUIRE(xored ? decode_xor_address(*x, m.tid, a) : decode_address(*x, a));
    return a;
}
}  // namespace

PF_TEST(responder_answers_binding_with_mapped_origin_and_other_address) {
    const ResponderAddresses addrs{P, A};
    const auto req = request();
    // the request may arrive on any of the four address/port combinations
    struct Case { Address local; Address other; };
    const Case cases[] = {{P, A}, {A, P}, {addr(1, 3479), addr(2, 3478)}, {addr(2, 3478), addr(1, 3479)}};
    for (const auto& c : cases) {
        const auto r = respond_to_binding(req.data(), req.size(), client(), c.local, addrs, "pf-test");
        PF_REQUIRE(r.has_value());
        PF_CHECK(r->to == client());
        PF_CHECK(r->from == c.local);                                // no CHANGE-REQUEST: answer from where it arrived
        const Message m = reply_of(*r);
        PF_CHECK(m.cls == Class::Success);
        PF_CHECK(m.tid[0] == 0x42);
        PF_CHECK(attr_addr(m, kAttrXorMappedAddress, true) == client());
        PF_CHECK(attr_addr(m, kAttrResponseOrigin) == c.local);
        PF_CHECK(attr_addr(m, kAttrOtherAddress) == c.other);
        PF_CHECK(m.fingerprint.has_value());
        PF_CHECK_EQ(std::string(attribute_text(*m.find(kAttrSoftware))), std::string("pf-test"));
    }
}

PF_TEST(responder_honours_change_request) {
    const ResponderAddresses addrs{P, A};
    struct Case { uint32_t change; Address from; };
    const Case cases[] = {{kChangeIp | kChangePort, addr(2, 3479)}, {kChangeIp, addr(2, 3478)}, {kChangePort, addr(1, 3479)}, {0, P}};
    for (const auto& c : cases) {
        const auto req = request(c.change);
        const auto r = respond_to_binding(req.data(), req.size(), client(), P, addrs);
        PF_REQUIRE(r.has_value());
        PF_CHECK(r->from == c.from);
        PF_CHECK(attr_addr(reply_of(*r), kAttrResponseOrigin) == c.from);
    }
}

PF_TEST(responder_420_for_what_it_does_not_understand) {
    // CHANGE-REQUEST without an alternate address: cannot be honoured -> 420 listing it
    const auto req = request(kChangePort);
    const auto r = respond_to_binding(req.data(), req.size(), client(), P, ResponderAddresses{P, std::nullopt});
    PF_REQUIRE(r.has_value());
    const Message m = reply_of(*r);
    PF_CHECK(m.cls == Class::Error);
    ErrorCode e;
    PF_REQUIRE(m.find(kAttrErrorCode) != nullptr && m.find(kAttrUnknownAttributes) != nullptr);
    PF_REQUIRE(decode_error_code(*m.find(kAttrErrorCode), e));
    PF_CHECK_EQ(e.code, 420);
    std::vector<uint16_t> u;
    PF_REQUIRE(decode_unknown_attributes(*m.find(kAttrUnknownAttributes), u));
    PF_CHECK(u == std::vector<uint16_t>{kAttrChangeRequest});
    // an unknown comprehension-required attribute
    const auto r2 = respond_to_binding(request(0, 0x7F42).data(), request(0, 0x7F42).size(), client(), P, ResponderAddresses{P, A});
    PF_REQUIRE(r2.has_value());
    const Message m2 = reply_of(*r2);
    PF_REQUIRE(m2.find(kAttrUnknownAttributes) != nullptr);
    PF_REQUIRE(decode_unknown_attributes(*m2.find(kAttrUnknownAttributes), u));
    PF_CHECK(u == std::vector<uint16_t>{0x7F42});
    // without an alternate, a plain request gets no OTHER-ADDRESS
    const auto r3 = respond_to_binding(request().data(), request().size(), client(), P, ResponderAddresses{P, std::nullopt});
    PF_REQUIRE(r3.has_value());
    PF_CHECK(reply_of(*r3).find(kAttrOtherAddress) == nullptr);
}

PF_TEST(responder_ignores_non_requests_and_garbage) {
    const ResponderAddresses addrs{P, A};
    TransactionId t{};
    MessageBuilder ind(kMethodBinding, Class::Indication, t);
    PF_CHECK(!respond_to_binding(ind.bytes().data(), ind.bytes().size(), client(), P, addrs).has_value());
    MessageBuilder resp(kMethodBinding, Class::Success, t);
    PF_CHECK(!respond_to_binding(resp.bytes().data(), resp.bytes().size(), client(), P, addrs).has_value());
    MessageBuilder alloc(kMethodAllocate, Class::Request, t);
    PF_CHECK(!respond_to_binding(alloc.bytes().data(), alloc.bytes().size(), client(), P, addrs).has_value());
    const uint8_t junk[5] = {0, 1, 0, 0, 9};
    PF_CHECK(!respond_to_binding(junk, sizeof junk, client(), P, addrs).has_value());
    MessageBuilder badcr(kMethodBinding, Class::Request, t);
    const uint8_t two[2] = {0, 6};
    badcr.add(kAttrChangeRequest, two, 2);
    PF_CHECK(!respond_to_binding(badcr.bytes().data(), badcr.bytes().size(), client(), P, addrs).has_value());
}
