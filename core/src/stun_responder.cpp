#include "pf/stun_responder.h"

namespace pf::stun {

namespace {
// `a` with b's IP (keeping a's port) / b's port (keeping a's IP).
Address with_ip(Address a, const Address& b) {
    a.family = b.family;
    a.ip = b.ip;
    return a;
}
Address with_port(Address a, const Address& b) {
    a.port = b.port;
    return a;
}
bool same_ip(const Address& a, const Address& b) { return a.family == b.family && a.ip == b.ip; }
}  // namespace

std::optional<ResponderReply> respond_to_binding(const uint8_t* req, size_t len, const Address& source, const Address& local,
                                                 const ResponderAddresses& addrs, std::string_view software) {
    Message m;
    if (parse(req, len, m) != ParseStatus::Ok || m.cls != Class::Request || m.method != kMethodBinding) return std::nullopt;

    std::vector<uint16_t> unknown = m.unknown_required;
    uint32_t change = 0;
    if (const Attribute* cr = m.find(kAttrChangeRequest)) {
        if (cr->length != 4) return std::nullopt;                       // malformed: no reply
        change = (uint32_t{cr->value[0]} << 24) | (uint32_t{cr->value[1]} << 16) | (uint32_t{cr->value[2]} << 8) | cr->value[3];
        if (!addrs.alternate) unknown.push_back(kAttrChangeRequest);   // we cannot honour it: we "do not understand" it
    }

    ResponderReply r;
    r.to = source;
    r.from = local;
    if (!unknown.empty()) {
        MessageBuilder e(kMethodBinding, Class::Error, m.tid);
        std::vector<uint8_t> list;
        for (uint16_t t : unknown) { list.push_back(static_cast<uint8_t>(t >> 8)); list.push_back(static_cast<uint8_t>(t)); }
        e.add_error_code(420, "Unknown Attribute").add(kAttrUnknownAttributes, list.data(), list.size());
        if (!software.empty()) e.add_text(kAttrSoftware, software);
        e.add_fingerprint();
        if (!e.ok()) return std::nullopt;
        r.bytes = e.bytes();
        return r;
    }

    std::optional<Address> other;
    if (addrs.alternate) {
        const Address& p = addrs.primary;
        const Address& a = *addrs.alternate;
        const Address& other_ip = same_ip(local, p) ? a : p;            // the IP we did not receive on
        const Address& other_port = local.port == p.port ? a : p;       // the port we did not receive on
        if (change & kChangeIp) r.from = with_ip(r.from, other_ip);
        if (change & kChangePort) r.from = with_port(r.from, other_port);
        other = with_port(with_ip(local, other_ip), other_port);
    }
    MessageBuilder b(kMethodBinding, Class::Success, m.tid);
    b.add_xor_address(kAttrXorMappedAddress, source).add_address(kAttrResponseOrigin, r.from);
    if (other) b.add_address(kAttrOtherAddress, *other);
    if (!software.empty()) b.add_text(kAttrSoftware, software);
    b.add_fingerprint();
    if (!b.ok()) return std::nullopt;
    r.bytes = b.bytes();
    return r;
}

}  // namespace pf::stun
