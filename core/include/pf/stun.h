#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pf::stun {

// STUN message codec (RFC 8489), PM-2b N1, D-045. Clean-room from the RFC text; validated against the RFC 5769 test
// vectors (tests/regression/golden/stun_rfc5769.golden). OpenSSL-free: MESSAGE-INTEGRITY needs an HMAC provider
// (pf/crypto/stun_hmac.h), FINGERPRINT (CRC-32) is computed here.
//
// Wire format (all big-endian):
//   0                   1                   2                   3
//   |0 0|     STUN Message Type     |         Message Length        |   length = bytes after the 20-byte header,
//   |                         Magic Cookie 0x2112A442               |   always a multiple of 4
//   |                     Transaction ID (96 bits)                  |
//   attributes: Type(16) Length(16) Value(Length) + padding to a multiple of 4 (padding NOT counted in Length)

inline constexpr uint32_t kMagicCookie = 0x2112A442;
inline constexpr size_t kHeaderLen = 20;
inline constexpr size_t kMaxAttributes = 64;            // our bound: a real message has a handful
inline constexpr uint32_t kFingerprintXor = 0x5354554E; // "STUN"

enum class Class : uint8_t { Request = 0, Indication = 1, Success = 2, Error = 3 };

// Methods (12 bits). Binding is RFC 8489; the TURN methods (RFC 8656) are listed because N4/N5 build on this codec.
inline constexpr uint16_t kMethodBinding = 0x001;
inline constexpr uint16_t kMethodAllocate = 0x003;
inline constexpr uint16_t kMethodRefresh = 0x004;
inline constexpr uint16_t kMethodSend = 0x006;
inline constexpr uint16_t kMethodData = 0x007;
inline constexpr uint16_t kMethodCreatePermission = 0x008;
inline constexpr uint16_t kMethodChannelBind = 0x009;

// Attribute types. 0x0000-0x7FFF are comprehension-required, 0x8000-0xFFFF comprehension-optional.
inline constexpr uint16_t kAttrMappedAddress = 0x0001;
inline constexpr uint16_t kAttrChangeRequest = 0x0003;       // RFC 5780: value 4 bytes, flags below
inline constexpr uint16_t kAttrUsername = 0x0006;
inline constexpr uint16_t kAttrMessageIntegrity = 0x0008;
inline constexpr uint16_t kAttrErrorCode = 0x0009;
inline constexpr uint16_t kAttrUnknownAttributes = 0x000A;
inline constexpr uint16_t kAttrRealm = 0x0014;
inline constexpr uint16_t kAttrNonce = 0x0015;
inline constexpr uint16_t kAttrMessageIntegritySha256 = 0x001C;
inline constexpr uint16_t kAttrPasswordAlgorithm = 0x001D;
inline constexpr uint16_t kAttrUserhash = 0x001E;
inline constexpr uint16_t kAttrXorMappedAddress = 0x0020;
inline constexpr uint16_t kAttrPasswordAlgorithms = 0x8002;
inline constexpr uint16_t kAttrAlternateDomain = 0x8003;
inline constexpr uint16_t kAttrSoftware = 0x8022;
inline constexpr uint16_t kAttrAlternateServer = 0x8023;
inline constexpr uint16_t kAttrFingerprint = 0x8028;
inline constexpr uint16_t kAttrResponseOrigin = 0x802B;      // RFC 5780: address the response was sent from
inline constexpr uint16_t kAttrOtherAddress = 0x802C;        // RFC 5780: the server's alternate address and port

// CHANGE-REQUEST flags (RFC 5780 7.2).
inline constexpr uint32_t kChangeIp = 0x04;
inline constexpr uint32_t kChangePort = 0x02;

constexpr bool is_comprehension_required(uint16_t attr_type) { return attr_type < 0x8000; }

// Method/class are interleaved in the 14-bit type: M11..M7 C1 M6..M4 C0 M3..M0.
uint16_t make_type(uint16_t method, Class cls);           // method > 0xFFF or top bits: masked off
void split_type(uint16_t type, uint16_t& method, Class& cls);

using TransactionId = std::array<uint8_t, 12>;

// A transport address carried in (XOR-)MAPPED-ADDRESS and similar attributes.
struct Address {
    enum class Family : uint8_t { V4 = 0x01, V6 = 0x02 };
    Family family = Family::V4;
    std::array<uint8_t, 16> ip{};     // V4 uses the first 4 bytes
    uint16_t port = 0;
    bool operator==(const Address& o) const;
    bool operator!=(const Address& o) const { return !(*this == o); }
    std::string to_string() const;    // "192.0.2.1:32853", "[2001:db8::1]:32853"
};

// View of one attribute inside a parsed message (points into the caller's buffer).
struct Attribute {
    uint16_t type = 0;
    uint16_t length = 0;              // value length, without padding
    size_t offset = 0;                // offset of the attribute's TYPE field from the start of the message
    const uint8_t* value = nullptr;
};

enum class ParseStatus {
    Ok,
    Truncated,              // shorter than the header, or than the length field says
    NotStun,                // top two bits not 0, or wrong magic cookie
    BadLength,              // length field not a multiple of 4, or the buffer is longer than the message
    BadAttribute,           // an attribute runs past the end of the message
    TooManyAttributes,      // more than kMaxAttributes
    AttributeAfterFingerprint,
    BadFingerprint,         // FINGERPRINT present with a wrong length or value
};
const char* parse_status_name(ParseStatus s);

struct Message {
    uint16_t method = 0;
    Class cls = Class::Request;
    TransactionId tid{};
    size_t size = 0;                              // total bytes (header + attributes)
    std::vector<Attribute> attributes;            // in wire order; after MESSAGE-INTEGRITY only MI-SHA256/FINGERPRINT kept
    size_t ignored_after_integrity = 0;           // attributes after MESSAGE-INTEGRITY that RFC 8489 says to ignore
    std::vector<uint16_t> unknown_required;       // comprehension-required types this codec does not know (distinct)
    std::optional<size_t> integrity;              // index into attributes
    std::optional<size_t> integrity_sha256;
    std::optional<size_t> fingerprint;

    // First attribute of a type (RFC 8489: only the first occurrence is processed), or nullptr.
    const Attribute* find(uint16_t type) const;
};

// Parses exactly one message occupying the whole buffer (a UDP datagram, or one framed message). Checks the header,
// every attribute boundary and, when present, the FINGERPRINT. MESSAGE-INTEGRITY needs a key: verify_integrity().
ParseStatus parse(const uint8_t* data, size_t len, Message& out);

// Cheap demultiplexing test (RFC 7983 style) for a socket shared with OpenVPN: first byte 0..3, at least a header,
// and the magic cookie. OpenVPN packets start with opcode<<3 (>= 0x08), so they never match.
bool looks_like_stun(const uint8_t* data, size_t len);

// ---- attribute decoders (false = malformed value) -------------------------------------------------------------------
bool decode_address(const Attribute& a, Address& out);                                // MAPPED-ADDRESS style
bool decode_xor_address(const Attribute& a, const TransactionId& tid, Address& out);  // XOR-MAPPED-ADDRESS style
struct ErrorCode {
    int code = 0;                 // 300..699
    std::string reason;
};
bool decode_error_code(const Attribute& a, ErrorCode& out);
bool decode_unknown_attributes(const Attribute& a, std::vector<uint16_t>& out);
std::string_view attribute_text(const Attribute& a);                                    // USERNAME, REALM, NONCE, SOFTWARE
bool decode_fingerprint(const Attribute& a, uint32_t& out);

// ---- integrity / fingerprint ----------------------------------------------------------------------------------------
// HMAC provider (OpenSSL implementation: pf/crypto/stun_hmac.h). Outputs are 20 (SHA-1) / 32 (SHA-256) bytes.
class StunHmac {
public:
    virtual ~StunHmac() = default;
    virtual bool hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[20]) const = 0;
    virtual bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]) const = 0;
};

uint32_t crc32(const uint8_t* data, size_t len);                 // CRC-32 (ISO-HDLC), as FINGERPRINT uses

enum class IntegrityStatus { Ok, Missing, Mismatch, Error };
// Verifies MESSAGE-INTEGRITY (HMAC-SHA1) or MESSAGE-INTEGRITY-SHA256 (HMAC-SHA256, possibly truncated to 16..32
// bytes) of a message parsed from `raw`. Constant-time comparison. `key` is the short-term password or the long-term
// key (pf/crypto/stun_hmac.h) - callers obtain it from the Key Manager, never from a Flow.
IntegrityStatus verify_integrity(const uint8_t* raw, const Message& m, const uint8_t* key, size_t key_len,
                                 const StunHmac& hmac, bool sha256 = false);

// ---- builder ----------------------------------------------------------------------------------------------------------
// Appends attributes in order; integrity and fingerprint are computed over everything before them, as the RFC
// requires, so add them last (integrity, then integrity-sha256, then fingerprint). Padding bytes are `pad` (RFC 8489:
// any value, receivers ignore it; RFC 5769 vectors use 0x20 in places, which lets tests rebuild them byte for byte).
class MessageBuilder {
public:
    MessageBuilder(uint16_t method, Class cls, const TransactionId& tid);

    MessageBuilder& add(uint16_t type, const uint8_t* value, size_t len, uint8_t pad = 0);
    MessageBuilder& add_text(uint16_t type, std::string_view text, uint8_t pad = 0);
    MessageBuilder& add_u32(uint16_t type, uint32_t v);
    MessageBuilder& add_address(uint16_t type, const Address& a);
    MessageBuilder& add_xor_address(uint16_t type, const Address& a);
    MessageBuilder& add_error_code(int code, std::string_view reason);
    MessageBuilder& add_integrity(const uint8_t* key, size_t key_len, const StunHmac& hmac);          // SHA-1, 20 bytes
    MessageBuilder& add_integrity_sha256(const uint8_t* key, size_t key_len, const StunHmac& hmac);   // 32 bytes
    MessageBuilder& add_fingerprint();

    // false after misuse: value > 65535 bytes, message too large, attribute after FINGERPRINT, HMAC failure.
    bool ok() const { return ok_; }
    const std::vector<uint8_t>& bytes() const { return buf_; }

private:
    void set_length(size_t body);
    uint8_t* append_attr(uint16_t type, size_t len, uint8_t pad);
    std::vector<uint8_t> buf_;
    TransactionId tid_;
    bool ok_ = true, sealed_ = false, has_integrity_ = false, has_integrity_sha256_ = false;
};

}  // namespace pf::stun
