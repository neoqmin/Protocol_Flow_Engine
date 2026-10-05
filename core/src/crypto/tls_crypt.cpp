#include "pf/crypto/tls_crypt.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstring>
#include <memory>

#include "pf/secure_mem.h"

namespace pf {

TlsCryptKey::~TlsCryptKey() {
    secure_zero(cipher.data(), cipher.size());
    secure_zero(hmac.data(), hmac.size());
}

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

struct CtxDeleter { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };

// AES-256-CTR is symmetric: the same call encrypts and decrypts.
bool aes256_ctr(const uint8_t key[32], const uint8_t iv[16], const uint8_t* in, size_t len, uint8_t* out) {
    if (len == 0) return true;
    std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter> c(EVP_CIPHER_CTX_new());
    int outl = 0;
    return c && len <= 0x7FFFFFFF &&
           EVP_EncryptInit_ex(c.get(), EVP_aes_256_ctr(), nullptr, key, iv) == 1 &&
           EVP_EncryptUpdate(c.get(), out, &outl, in, static_cast<int>(len)) == 1;
}

bool hmac_sha256(const uint8_t key[32], const uint8_t* hdr, size_t hdr_len, const uint8_t* msg, size_t len,
                 uint8_t out[32]) {
    std::vector<uint8_t> buf(hdr, hdr + hdr_len);
    if (len) buf.insert(buf.end(), msg, msg + len);
    unsigned int outl = 0;
    bool ok = HMAC(EVP_sha256(), key, 32, buf.data(), buf.size(), out, &outl) != nullptr && outl == 32;
    secure_zero(buf.data(), buf.size());   // plaintext copy
    return ok;
}

void put_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24); p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);  p[3] = static_cast<uint8_t>(v);
}
uint32_t get_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

}  // namespace

bool parse_static_key_file(std::string_view text, std::array<uint8_t, kTlsCryptStaticKeyLen>& out) {
    constexpr std::string_view kBegin = "-----BEGIN OpenVPN Static key V1-----";
    constexpr std::string_view kEnd = "-----END OpenVPN Static key V1-----";
    const size_t b = text.find(kBegin);
    if (b == std::string_view::npos) return false;
    const size_t start = b + kBegin.size();
    const size_t e = text.find(kEnd, start);
    if (e == std::string_view::npos) return false;

    size_t nibbles = 0;
    std::array<uint8_t, kTlsCryptStaticKeyLen> tmp{};
    for (size_t i = start; i < e; ++i) {
        const char c = text[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        const int v = hex_value(c);
        if (v < 0 || nibbles >= 2 * kTlsCryptStaticKeyLen) { secure_zero(tmp.data(), tmp.size()); return false; }
        tmp[nibbles / 2] = static_cast<uint8_t>((nibbles % 2 == 0) ? (v << 4) : (tmp[nibbles / 2] | v));
        ++nibbles;
    }
    if (nibbles != 2 * kTlsCryptStaticKeyLen) { secure_zero(tmp.data(), tmp.size()); return false; }
    out = tmp;
    secure_zero(tmp.data(), tmp.size());
    return true;
}

TlsCryptKeys derive_tls_crypt_keys(const std::array<uint8_t, kTlsCryptStaticKeyLen>& key, TlsCryptRole role) {
    auto block = [&](size_t i, std::array<uint8_t, 32>& dst) { std::memcpy(dst.data(), key.data() + i * 64, 32); };
    TlsCryptKeys k;
    const bool client = role == TlsCryptRole::Client;
    block(client ? 2 : 0, k.tx.cipher); block(client ? 3 : 1, k.tx.hmac);
    block(client ? 0 : 2, k.rx.cipher); block(client ? 1 : 3, k.rx.hmac);
    return k;
}

bool tls_crypt_seal(const TlsCryptKey& k, uint8_t op_keyid, const uint8_t session_id[8],
                    uint32_t packet_id, uint32_t net_time,
                    const uint8_t* plaintext, size_t len, std::vector<uint8_t>& wire_out) {
    std::vector<uint8_t> w(kTlsCryptOverhead + len);
    w[0] = op_keyid;
    std::memcpy(&w[1], session_id, 8);
    put_be32(&w[9], packet_id);
    put_be32(&w[13], net_time);
    uint8_t* tag = &w[kTlsCryptHeaderLen];
    if (!hmac_sha256(k.hmac.data(), w.data(), kTlsCryptHeaderLen, plaintext, len, tag)) return false;
    if (!aes256_ctr(k.cipher.data(), tag, plaintext, len, &w[kTlsCryptOverhead])) return false;
    wire_out = std::move(w);
    return true;
}

TlsCryptStatus tls_crypt_open(const TlsCryptKey& k, const uint8_t* wire, size_t len, TlsCryptPlain& out) {
    if (wire == nullptr || len < kTlsCryptOverhead) return TlsCryptStatus::Truncated;
    const uint8_t* tag = wire + kTlsCryptHeaderLen;
    const size_t n = len - kTlsCryptOverhead;

    std::vector<uint8_t> pt(n);
    if (!aes256_ctr(k.cipher.data(), tag, wire + kTlsCryptOverhead, n, pt.data()))
        return TlsCryptStatus::AuthFailed;
    uint8_t expect[32];
    const bool ok = hmac_sha256(k.hmac.data(), wire, kTlsCryptHeaderLen, pt.data(), n, expect) &&
                    ct_equal(expect, tag, 32);
    if (!ok) {
        secure_zero(pt.data(), pt.size());   // unauthenticated plaintext must not escape
        return TlsCryptStatus::AuthFailed;
    }
    out.op_keyid = wire[0];
    std::memcpy(out.session_id, wire + 1, 8);
    out.packet_id = get_be32(wire + 9);
    out.net_time = get_be32(wire + 13);
    out.payload = std::move(pt);
    return TlsCryptStatus::Ok;
}

bool TlsCryptChannel::wrap(uint8_t op_keyid, const uint8_t session_id[8], const uint8_t* payload, size_t len,
                           uint32_t net_time, std::vector<uint8_t>& wire_out) {
    if (tx_next_ == 0) return false;
    if (!tls_crypt_seal(keys_.tx, op_keyid, session_id, tx_next_, net_time, payload, len, wire_out)) return false;
    tx_next_ = (tx_next_ == 0xFFFFFFFFu) ? 0 : tx_next_ + 1;
    return true;
}

TlsCryptStatus TlsCryptChannel::unwrap(const uint8_t* wire, size_t len, TlsCryptPlain& out) {
    TlsCryptPlain p;
    TlsCryptStatus st = tls_crypt_open(keys_.rx, wire, len, p);
    if (st != TlsCryptStatus::Ok) return st;

    // Authenticated: now apply replay rules. A newer net_time starts a fresh window.
    if (p.net_time < rx_time_) return TlsCryptStatus::Replay;
    if (p.net_time == rx_time_ && rx_window_.check(p.packet_id) != ReplayStatus::Ok) return TlsCryptStatus::Replay;
    if (p.net_time > rx_time_) {
        if (p.packet_id == 0) return TlsCryptStatus::Replay;
        rx_window_.reset();
        rx_time_ = p.net_time;
    }
    rx_window_.commit(p.packet_id);
    out = std::move(p);
    return TlsCryptStatus::Ok;
}

}  // namespace pf
