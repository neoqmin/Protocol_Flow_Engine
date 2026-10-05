#include "pf/key_method2.h"

#include <algorithm>
#include <cstring>

namespace pf {
namespace {

constexpr size_t kMaxString = 4096;   // generous for options/peer info; bounds what a peer can make us allocate

bool put_string(std::vector<uint8_t>& v, const std::string& s, bool allow_empty) {
    if (s.find('\0') != std::string::npos) return false;
    if (s.empty()) {
        if (!allow_empty) return false;
        v.push_back(0); v.push_back(0);
        return true;
    }
    const size_t n = s.size() + 1;
    if (n > 0xFFFF) return false;
    v.push_back(static_cast<uint8_t>(n >> 8));
    v.push_back(static_cast<uint8_t>(n));
    v.insert(v.end(), s.begin(), s.end());
    v.push_back(0);
    return true;
}

// Reads "len(2) + bytes". Returns Ok/Truncated/Malformed; empty string when len == 0.
KeyMethod2Status get_string(const uint8_t* d, size_t len, size_t& pos, std::string& out, bool allow_empty) {
    if (len - pos < 2) return KeyMethod2Status::Truncated;
    const size_t n = (size_t(d[pos]) << 8) | d[pos + 1];
    pos += 2;
    if (n == 0) {
        if (!allow_empty) return KeyMethod2Status::Malformed;
        out.clear();
        return KeyMethod2Status::Ok;
    }
    if (len - pos < n) return KeyMethod2Status::Truncated;
    if (n > kMaxString || d[pos + n - 1] != 0) return KeyMethod2Status::Malformed;   // must be NUL-terminated
    for (size_t i = 0; i + 1 < n; ++i)
        if (d[pos + i] == 0) return KeyMethod2Status::Malformed;                      // no embedded NUL
    out.assign(reinterpret_cast<const char*>(d + pos), n - 1);
    pos += n;
    return KeyMethod2Status::Ok;
}

}  // namespace

bool build_key_method2(const KeyMethod2Message& m, KeyMethod2From from, std::vector<uint8_t>& out) {
    std::vector<uint8_t> v = {0, 0, 0, 0, 2};
    if (from == KeyMethod2From::Client) v.insert(v.end(), m.pre_master.begin(), m.pre_master.end());
    v.insert(v.end(), m.random1.begin(), m.random1.end());
    v.insert(v.end(), m.random2.begin(), m.random2.end());
    if (!put_string(v, m.options, /*allow_empty=*/false)) return false;
    if (!put_string(v, m.username, true) || !put_string(v, m.password, true) || !put_string(v, m.peer_info, true)) return false;
    out = std::move(v);
    return true;
}

KeyMethod2Status parse_key_method2(const uint8_t* d, size_t len, KeyMethod2From from,
                                   KeyMethod2Message& out, size_t& consumed, size_t optional_fields) {
    consumed = 0;
    if (d == nullptr || len < 5) return KeyMethod2Status::Truncated;
    if (d[0] | d[1] | d[2] | d[3]) return KeyMethod2Status::BadHeader;
    if (d[4] != 2) return KeyMethod2Status::UnsupportedMethod;

    KeyMethod2Message m;
    size_t pos = 5;
    const size_t need = (from == KeyMethod2From::Client ? 48 : 0) + 64;
    if (len - pos < need) return KeyMethod2Status::Truncated;
    if (from == KeyMethod2From::Client) { std::memcpy(m.pre_master.data(), d + pos, 48); pos += 48; }
    std::memcpy(m.random1.data(), d + pos, 32); pos += 32;
    std::memcpy(m.random2.data(), d + pos, 32); pos += 32;

    KeyMethod2Status st = get_string(d, len, pos, m.options, /*allow_empty=*/false);
    if (st != KeyMethod2Status::Ok) return st;

    // Optional trailing fields: absent when the stream ends exactly at a field boundary.
    std::string* fields[] = {&m.username, &m.password, &m.peer_info};
    for (size_t i = 0; i < 3 && i < optional_fields; ++i) {
        std::string* f = fields[i];
        if (pos == len) break;
        st = get_string(d, len, pos, *f, true);
        if (st != KeyMethod2Status::Ok) return st;
    }
    out = std::move(m);
    consumed = pos;
    return KeyMethod2Status::Ok;
}

}  // namespace pf
