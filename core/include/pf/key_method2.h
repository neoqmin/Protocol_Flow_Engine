#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pf {

// Key method 2 message carried over the established TLS session (docs/OpenVPN_Control_Plane_Notes.md).
// Field order per the official protocol overview; observed field values come from OpenVPN 2.6.19 logs.
//
//   literal 0 (4) | key method = 2 (1) | key source | options length (2, incl NUL) | options (NUL-terminated)
//   | [username length (2) + username+NUL] | [password length (2) + password+NUL] | [peer info length (2) + text+NUL]
//
// key source: client -> server = pre_master(48) + random1(32) + random2(32); server -> client = random1 + random2.
// With TLS key export (tls-ekm) these random values are exchanged but not used for key derivation.
// A length of 0 means "empty". The trailing username/password/peer-info fields are optional on receive.
enum class KeyMethod2From { Client, Server };

struct KeyMethod2Message {
    std::array<uint8_t, 48> pre_master{};   // client only
    std::array<uint8_t, 32> random1{};
    std::array<uint8_t, 32> random2{};
    std::string options;                    // e.g. "V4,dev-type tun,...,key-method 2,tls-client"
    std::string username, password;
    std::string peer_info;                  // "IV_VER=2.6.19\nIV_PROTO=14\n..."
};

enum class KeyMethod2Status { Ok, Truncated, BadHeader, UnsupportedMethod, Malformed };

// false if a string is empty (options only), contains NUL, or does not fit a 16-bit length.
bool build_key_method2(const KeyMethod2Message& m, KeyMethod2From from, std::vector<uint8_t>& out);

// Parses one message from the front of a TLS byte stream. `consumed` = bytes it occupied, so the next control
// message (e.g. PUSH_REPLY) can be read from the same stream. Truncated = need more bytes.
// `optional_fields` = how many trailing length-prefixed strings may follow the options string, in the order
// username, password, peer info (default: all three). A stream that carries further control messages right after
// the key exchange needs the exact count the peer sends, or the next message would be misread as a length.
KeyMethod2Status parse_key_method2(const uint8_t* data, size_t len, KeyMethod2From from,
                                   KeyMethod2Message& out, size_t& consumed, size_t optional_fields = 3);

}  // namespace pf
