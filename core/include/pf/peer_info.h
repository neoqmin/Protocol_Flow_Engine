#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace pf {

// The peer info block a client sends in key-method 2 ("KEY=VALUE" lines, docs/OpenVPN_Interop_Profile.md).
// The server reads it to learn what the client can do. It is untrusted input: strict, bounded parsing.

// IV_PROTO bits [documented, OpenVPN ssl.h doxygen].
constexpr uint32_t kIvProtoDataV2 = 1u << 1;
constexpr uint32_t kIvProtoRequestPush = 1u << 2;
constexpr uint32_t kIvProtoTlsKeyExport = 1u << 3;
constexpr uint32_t kIvProtoCcExit = 1u << 7;
constexpr uint32_t kIvProtoDynTlsCrypt = 1u << 9;

constexpr int kMaxPeerInfoEntries = 64;

struct PeerInfo {
    std::map<std::string, std::string> values;   // every entry, verbatim
    bool has_proto = false;
    uint32_t iv_proto = 0;
    std::vector<std::string> ciphers;            // IV_CIPHERS, split on ':'
    std::string version, platform;               // IV_VER, IV_PLAT (informational only)
};

enum class PeerInfoStatus { Ok, Malformed };

// Lines are separated by '\n'; empty lines are skipped. Malformed: a line without '=' or with an empty key, a
// duplicate key, a control character, a bad IV_PROTO number, more than kMaxPeerInfoEntries entries.
PeerInfoStatus parse_peer_info(std::string_view text, PeerInfo& out);

// Why this client cannot use the server's profile (D-008/D-048: DATA_V2, TLS key export, AES-256-GCM);
// empty = supported. The text is safe to send back in AUTH_FAILED (it names no client data).
std::string peer_info_unsupported_reason(const PeerInfo& p);

}  // namespace pf
