#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "pf/replay.h"

namespace pf {

// OpenVPN 2.6 --tls-crypt control-channel protection (docs/OpenVPN_Control_Plane_Notes.md section 2).
// Verified against unmodified OpenVPN 2.6.19 by HMAC-tag verification on captured packets.
//
//   wire = op_keyid(1) | session_id(8) | packet_id(4,BE) | net_time(4,BE) | tag(32) | ciphertext
//   tag  = HMAC-SHA256(Ka, wire[0:17] || plaintext);  iv = tag[0:16];  ct = AES-256-CTR(Ke, iv, plaintext)
//
// Needs OpenSSL (built only with PF_WITH_OPENSSL).
inline constexpr size_t kTlsCryptStaticKeyLen = 256;   // 4 x 64 bytes
inline constexpr size_t kTlsCryptHeaderLen = 17;
inline constexpr size_t kTlsCryptTagLen = 32;
inline constexpr size_t kTlsCryptOverhead = kTlsCryptHeaderLen + kTlsCryptTagLen;

enum class TlsCryptRole { Client, Server };

// One direction's keys (AES-256 key + HMAC-SHA256 key). Wiped on destruction.
struct TlsCryptKey {
    std::array<uint8_t, 32> cipher{};
    std::array<uint8_t, 32> hmac{};
    TlsCryptKey() = default;
    TlsCryptKey(const TlsCryptKey&) = default;
    TlsCryptKey& operator=(const TlsCryptKey&) = default;
    ~TlsCryptKey();
};

struct TlsCryptKeys {
    TlsCryptKey tx;   // protects what we send
    TlsCryptKey rx;   // verifies what we receive
};

// Parses an "OpenVPN Static key V1" file (exactly 256 bytes of hex between the markers).
bool parse_static_key_file(std::string_view text, std::array<uint8_t, kTlsCryptStaticKeyLen>& out);

// Static key = K0|K1|K2|K3 (64 bytes each, first 32 bytes of each used).
// Client: tx=(K2 cipher, K3 hmac), rx=(K0, K1). Server: mirrored.
TlsCryptKeys derive_tls_crypt_keys(const std::array<uint8_t, kTlsCryptStaticKeyLen>& key, TlsCryptRole role);

enum class TlsCryptStatus { Ok, Truncated, AuthFailed, Replay };

struct TlsCryptPlain {
    uint8_t op_keyid = 0;
    uint8_t session_id[8] = {};
    uint32_t packet_id = 0;
    uint32_t net_time = 0;
    std::vector<uint8_t> payload;
};

// Stateless building blocks (deterministic: same inputs give the same bytes).
bool tls_crypt_seal(const TlsCryptKey& k, uint8_t op_keyid, const uint8_t session_id[8],
                    uint32_t packet_id, uint32_t net_time,
                    const uint8_t* plaintext, size_t len, std::vector<uint8_t>& wire_out);

// Verifies the tag, then decrypts. On AuthFailed no plaintext is returned.
// Does NOT check replay: use TlsCryptChannel for that.
TlsCryptStatus tls_crypt_open(const TlsCryptKey& k, const uint8_t* wire, size_t len, TlsCryptPlain& out);

// Stateful endpoint: TX packet-id counter and RX replay protection (packet_id within a net_time).
// Replay state is updated only for packets that authenticated.
class TlsCryptChannel {
public:
    explicit TlsCryptChannel(TlsCryptKeys keys) : keys_(std::move(keys)) {}

    // Assigns the next packet-id (starting at 1). false once the id space is used up: never reuse (key, iv).
    bool wrap(uint8_t op_keyid, const uint8_t session_id[8], const uint8_t* payload, size_t len,
              uint32_t net_time, std::vector<uint8_t>& wire_out);
    TlsCryptStatus unwrap(const uint8_t* wire, size_t len, TlsCryptPlain& out);
    // unwrap() in two steps, for a server (D-048): open() authenticates and applies the replay rules WITHOUT changing
    // any state; commit() records the packet once the caller has bound it to its session. Every client shares the
    // tls-crypt key, so a packet can be authentic yet belong to someone else: it must not move this session's window.
    TlsCryptStatus open(const uint8_t* wire, size_t len, TlsCryptPlain& out) const;
    void commit(uint32_t net_time, uint32_t packet_id);

    void set_next_packet_id_for_test(uint32_t id) { tx_next_ = id; }
    // Continue after packet-ids already used for this peer elsewhere (a stateless reply, D-049). Never goes back.
    void skip_packet_ids_to(uint32_t id) { if (tx_next_ != 0 && id > tx_next_) tx_next_ = id; }

private:
    TlsCryptKeys keys_;
    uint32_t tx_next_ = 1;
    uint32_t rx_time_ = 0;
    ReplayWindow rx_window_;
};

}  // namespace pf
