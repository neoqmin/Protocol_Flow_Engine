#include "pf/stun.h"

#include <algorithm>
#include <cstring>

#include "pf/secure_mem.h"

namespace pf::stun {

namespace {

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t be32(const uint8_t* p) {
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | uint32_t{p[3]};
}
void put16(uint8_t* p, uint16_t v) { p[0] = static_cast<uint8_t>(v >> 8); p[1] = static_cast<uint8_t>(v); }
void put32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}
size_t padded(size_t n) { return (n + 3) & ~size_t{3}; }

// Comprehension-required attributes this codec knows (RFC 8489 + the RFC 8656 TURN attributes N4/N5 will use).
bool known_required(uint16_t t) {
    switch (t) {
        case kAttrMappedAddress: case kAttrChangeRequest: case kAttrUsername: case kAttrMessageIntegrity: case kAttrErrorCode:
        case kAttrUnknownAttributes: case kAttrRealm: case kAttrNonce: case kAttrMessageIntegritySha256:
        case kAttrPasswordAlgorithm: case kAttrUserhash: case kAttrXorMappedAddress:
        case 0x000C: case 0x000D: case 0x0012: case 0x0013: case 0x0016:      // TURN: CHANNEL-NUMBER LIFETIME XOR-PEER-ADDRESS DATA XOR-RELAYED-ADDRESS
        case 0x0017: case 0x0018: case 0x0019: case 0x001A: case 0x0022:      // REQUESTED-ADDRESS-FAMILY EVEN-PORT REQUESTED-TRANSPORT DONT-FRAGMENT RESERVATION-TOKEN
            return true;
        default: return false;
    }
}

// The bytes an integrity/fingerprint attribute at `offset` covers: everything before it, with the header's length
// field rewritten to end just after that attribute (RFC 8489 sections 14.5, 14.6, 14.7).
std::vector<uint8_t> covered_prefix(const uint8_t* raw, size_t offset, size_t attr_value_len) {
    std::vector<uint8_t> v(raw, raw + offset);
    put16(v.data() + 2, static_cast<uint16_t>(offset + 4 + padded(attr_value_len) - kHeaderLen));
    return v;
}

std::array<uint32_t, 256> make_crc_table() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        t[i] = c;
    }
    return t;
}

}  // namespace

uint16_t make_type(uint16_t method, Class cls) {
    const uint16_t m = method & 0x0FFF;
    const uint16_t c = static_cast<uint16_t>(cls) & 0x3;
    return static_cast<uint16_t>((m & 0x000F) | ((m & 0x0070) << 1) | ((m & 0x0F80) << 2) | ((c & 1) << 4) | ((c & 2) << 7));
}

void split_type(uint16_t type, uint16_t& method, Class& cls) {
    method = static_cast<uint16_t>((type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));
    cls = static_cast<Class>(((type >> 4) & 1) | ((type >> 7) & 2));
}

const char* parse_status_name(ParseStatus s) {
    switch (s) {
        case ParseStatus::Ok: return "Ok";
        case ParseStatus::Truncated: return "Truncated";
        case ParseStatus::NotStun: return "NotStun";
        case ParseStatus::BadLength: return "BadLength";
        case ParseStatus::BadAttribute: return "BadAttribute";
        case ParseStatus::TooManyAttributes: return "TooManyAttributes";
        case ParseStatus::AttributeAfterFingerprint: return "AttributeAfterFingerprint";
        case ParseStatus::BadFingerprint: return "BadFingerprint";
    }
    return "Unknown";
}

const Attribute* Message::find(uint16_t type) const {
    for (const auto& a : attributes) if (a.type == type) return &a;
    return nullptr;
}

uint32_t crc32(const uint8_t* data, size_t len) {
    static const std::array<uint32_t, 256> table = make_crc_table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

bool looks_like_stun(const uint8_t* data, size_t len) {
    return data && len >= kHeaderLen && data[0] <= 3 && be32(data + 4) == kMagicCookie;
}

ParseStatus parse(const uint8_t* data, size_t len, Message& out) {
    out = Message{};
    if (!data || len < kHeaderLen) return ParseStatus::Truncated;
    if ((data[0] & 0xC0) != 0 || be32(data + 4) != kMagicCookie) return ParseStatus::NotStun;
    const size_t body = be16(data + 2);
    if (body % 4 != 0) return ParseStatus::BadLength;
    if (kHeaderLen + body > len) return ParseStatus::Truncated;
    if (kHeaderLen + body < len) return ParseStatus::BadLength;       // one message per buffer, nothing trailing
    split_type(be16(data), out.method, out.cls);
    std::memcpy(out.tid.data(), data + 8, out.tid.size());
    out.size = kHeaderLen + body;

    const size_t end = out.size;
    size_t pos = kHeaderLen, count = 0;
    bool seen_mi = false, seen_mi256 = false, seen_fp = false;
    while (pos < end) {
        if (pos + 4 > end) return ParseStatus::BadAttribute;
        Attribute a;
        a.type = be16(data + pos);
        a.length = be16(data + pos + 2);
        a.offset = pos;
        a.value = data + pos + 4;
        if (pos + 4 + padded(a.length) > end) return ParseStatus::BadAttribute;
        if (++count > kMaxAttributes) return ParseStatus::TooManyAttributes;
        if (seen_fp) return ParseStatus::AttributeAfterFingerprint;
        pos += 4 + padded(a.length);

        if (a.type == kAttrFingerprint) {
            seen_fp = true;
            uint32_t got = 0;
            if (!decode_fingerprint(a, got)) return ParseStatus::BadFingerprint;
            const std::vector<uint8_t> covered = covered_prefix(data, a.offset, a.length);
            if ((crc32(covered.data(), covered.size()) ^ kFingerprintXor) != got) return ParseStatus::BadFingerprint;
            out.fingerprint = out.attributes.size();
            out.attributes.push_back(a);
            continue;
        }
        if (seen_mi256 || (seen_mi && a.type != kAttrMessageIntegritySha256)) {   // RFC 8489 14.5/14.6: ignored
            ++out.ignored_after_integrity;
            continue;
        }
        if (a.type == kAttrMessageIntegrity) { seen_mi = true; out.integrity = out.attributes.size(); }
        else if (a.type == kAttrMessageIntegritySha256) { seen_mi256 = true; out.integrity_sha256 = out.attributes.size(); }
        else if (is_comprehension_required(a.type) && !known_required(a.type) &&
                 std::find(out.unknown_required.begin(), out.unknown_required.end(), a.type) == out.unknown_required.end())
            out.unknown_required.push_back(a.type);
        out.attributes.push_back(a);
    }
    return ParseStatus::Ok;
}

bool decode_address(const Attribute& a, Address& out) {
    if (a.length != 8 && a.length != 20) return false;
    const uint8_t fam = a.value[1];                    // a.value[0] is reserved: ignored on receipt
    if (fam == 0x01 && a.length == 8) out.family = Address::Family::V4;
    else if (fam == 0x02 && a.length == 20) out.family = Address::Family::V6;
    else return false;
    out.port = be16(a.value + 2);
    out.ip.fill(0);
    std::memcpy(out.ip.data(), a.value + 4, a.length - 4);
    return true;
}

bool decode_xor_address(const Attribute& a, const TransactionId& tid, Address& out) {
    if (!decode_address(a, out)) return false;
    uint8_t mask[16];
    put32(mask, kMagicCookie);
    std::memcpy(mask + 4, tid.data(), tid.size());
    out.port ^= static_cast<uint16_t>(kMagicCookie >> 16);
    const size_t n = out.family == Address::Family::V4 ? 4 : 16;
    for (size_t i = 0; i < n; ++i) out.ip[i] ^= mask[i];
    return true;
}

bool decode_error_code(const Attribute& a, ErrorCode& out) {
    if (a.length < 4 || a.length > 4 + 763) return false;
    const int cls = a.value[2] & 0x07, number = a.value[3];
    if (cls < 3 || cls > 6 || number > 99) return false;
    out.code = cls * 100 + number;
    out.reason.assign(reinterpret_cast<const char*>(a.value + 4), a.length - 4);
    return true;
}

bool decode_unknown_attributes(const Attribute& a, std::vector<uint16_t>& out) {
    if (a.length % 2 != 0) return false;
    out.clear();
    for (size_t i = 0; i < a.length; i += 2) out.push_back(be16(a.value + i));
    return true;
}

std::string_view attribute_text(const Attribute& a) { return std::string_view(reinterpret_cast<const char*>(a.value), a.length); }

bool decode_fingerprint(const Attribute& a, uint32_t& out) {
    if (a.length != 4) return false;
    out = be32(a.value);
    return true;
}

IntegrityStatus verify_integrity(const uint8_t* raw, const Message& m, const uint8_t* key, size_t key_len,
                                 const StunHmac& hmac, bool sha256) {
    const std::optional<size_t> idx = sha256 ? m.integrity_sha256 : m.integrity;
    if (!idx || *idx >= m.attributes.size()) return IntegrityStatus::Missing;
    const Attribute& a = m.attributes[*idx];
    if (sha256 ? (a.length < 16 || a.length > 32 || a.length % 4 != 0) : a.length != 20) return IntegrityStatus::Mismatch;
    const std::vector<uint8_t> covered = covered_prefix(raw, a.offset, a.length);
    uint8_t mac[32];
    const bool ok = sha256 ? hmac.hmac_sha256(key, key_len, covered.data(), covered.size(), mac)
                           : hmac.hmac_sha1(key, key_len, covered.data(), covered.size(), mac);
    if (!ok) return IntegrityStatus::Error;
    const bool match = ct_equal(mac, a.value, a.length);
    secure_zero(mac, sizeof mac);
    return match ? IntegrityStatus::Ok : IntegrityStatus::Mismatch;
}

// ---- builder ----------------------------------------------------------------------------------------------------------

MessageBuilder::MessageBuilder(uint16_t method, Class cls, const TransactionId& tid) : buf_(kHeaderLen, 0), tid_(tid) {
    put16(buf_.data(), make_type(method, cls));
    put32(buf_.data() + 4, kMagicCookie);
    std::memcpy(buf_.data() + 8, tid.data(), tid.size());
    if (method > 0x0FFF) ok_ = false;
}

void MessageBuilder::set_length(size_t body) { put16(buf_.data() + 2, static_cast<uint16_t>(body)); }

uint8_t* MessageBuilder::append_attr(uint16_t type, size_t len, uint8_t pad) {
    if (!ok_ || sealed_ || len > 0xFFFF || buf_.size() - kHeaderLen + 4 + padded(len) > 0xFFFC) { ok_ = false; return nullptr; }
    const size_t at = buf_.size();
    buf_.resize(at + 4 + padded(len), pad);
    put16(buf_.data() + at, type);
    put16(buf_.data() + at + 2, static_cast<uint16_t>(len));
    set_length(buf_.size() - kHeaderLen);
    return buf_.data() + at + 4;
}

MessageBuilder& MessageBuilder::add(uint16_t type, const uint8_t* value, size_t len, uint8_t pad) {
    if (type == kAttrMessageIntegrity || type == kAttrMessageIntegritySha256 || type == kAttrFingerprint || has_integrity_) {
        ok_ = false;                                   // use the dedicated calls; nothing ordinary after integrity
        return *this;
    }
    if (uint8_t* d = append_attr(type, len, pad)) if (len) std::memcpy(d, value, len);
    return *this;
}

MessageBuilder& MessageBuilder::add_text(uint16_t type, std::string_view text, uint8_t pad) {
    return add(type, reinterpret_cast<const uint8_t*>(text.data()), text.size(), pad);
}

MessageBuilder& MessageBuilder::add_u32(uint16_t type, uint32_t v) {
    uint8_t b[4];
    put32(b, v);
    return add(type, b, 4);
}

MessageBuilder& MessageBuilder::add_address(uint16_t type, const Address& a) {
    uint8_t v[20] = {0};
    const bool v4 = a.family == Address::Family::V4;
    v[1] = static_cast<uint8_t>(a.family);
    put16(v + 2, a.port);
    std::memcpy(v + 4, a.ip.data(), v4 ? 4 : 16);
    return add(type, v, v4 ? 8 : 20);
}

MessageBuilder& MessageBuilder::add_xor_address(uint16_t type, const Address& a) {
    Address x = a;
    uint8_t mask[16];
    put32(mask, kMagicCookie);
    std::memcpy(mask + 4, tid_.data(), tid_.size());
    x.port ^= static_cast<uint16_t>(kMagicCookie >> 16);
    const size_t n = a.family == Address::Family::V4 ? 4 : 16;
    for (size_t i = 0; i < n; ++i) x.ip[i] ^= mask[i];
    return add_address(type, x);
}

MessageBuilder& MessageBuilder::add_error_code(int code, std::string_view reason) {
    if (code < 300 || code > 699 || reason.size() > 763) { ok_ = false; return *this; }
    std::vector<uint8_t> v(4 + reason.size(), 0);
    v[2] = static_cast<uint8_t>(code / 100);
    v[3] = static_cast<uint8_t>(code % 100);
    std::memcpy(v.data() + 4, reason.data(), reason.size());
    return add(kAttrErrorCode, v.data(), v.size());
}

MessageBuilder& MessageBuilder::add_integrity(const uint8_t* key, size_t key_len, const StunHmac& hmac) {
    if (has_integrity_ || has_integrity_sha256_) { ok_ = false; return *this; }  // MESSAGE-INTEGRITY comes first
    set_length(buf_.size() - kHeaderLen + 24);
    uint8_t mac[20];
    if (!ok_ || !hmac.hmac_sha1(key, key_len, buf_.data(), buf_.size(), mac)) { ok_ = false; return *this; }
    if (uint8_t* d = append_attr(kAttrMessageIntegrity, 20, 0)) std::memcpy(d, mac, 20);
    secure_zero(mac, sizeof mac);
    has_integrity_ = true;
    return *this;
}

MessageBuilder& MessageBuilder::add_integrity_sha256(const uint8_t* key, size_t key_len, const StunHmac& hmac) {
    if (has_integrity_sha256_) { ok_ = false; return *this; }
    set_length(buf_.size() - kHeaderLen + 36);
    uint8_t mac[32];
    if (!ok_ || !hmac.hmac_sha256(key, key_len, buf_.data(), buf_.size(), mac)) { ok_ = false; return *this; }
    if (uint8_t* d = append_attr(kAttrMessageIntegritySha256, 32, 0)) std::memcpy(d, mac, 32);
    secure_zero(mac, sizeof mac);
    has_integrity_sha256_ = true;
    return *this;
}

MessageBuilder& MessageBuilder::add_fingerprint() {
    if (!ok_ || sealed_) { ok_ = false; return *this; }
    set_length(buf_.size() - kHeaderLen + 8);
    const uint32_t fp = crc32(buf_.data(), buf_.size()) ^ kFingerprintXor;
    if (uint8_t* d = append_attr(kAttrFingerprint, 4, 0)) put32(d, fp);
    sealed_ = true;
    return *this;
}

}  // namespace pf::stun
