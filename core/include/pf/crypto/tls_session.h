#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace pf {

enum class TlsRole { Client, Server };

struct TlsConfig {
    TlsRole role = TlsRole::Client;
    std::string ca_pem;          // trust anchors for the PEER's chain (required: never run unauthenticated)
    std::string cert_pem;        // our certificate (+ optional chain). Required for servers; for clients if the peer asks
    std::string key_pem;         // matching private key (PEM)
    // Peer certificate must be usable for the peer's role (serverAuth / clientAuth EKU + key usage),
    // like OpenVPN's --remote-cert-tls. Turning it off accepts any purpose.
    bool require_peer_eku = true;
    // Certificate revocation list(s) for the PEER's chain (PEM, one or more). Empty = no revocation check.
    // Every CRL must be issued by one of the ca_pem anchors (a CRL that can never match is a configuration error).
    // Only the peer's leaf certificate is checked (like OpenVPN's crl-verify).
    std::string crl_pem;
    bool tls13_only = true;      // OpenVPN 2.6 profile (D-008): TLS 1.3 only
    bool cap_at_tls12 = false;   // TEST HOOK: behave like a TLS 1.2-only peer
};

// TLS endpoint driven entirely through memory buffers: the caller carries the bytes (the OpenVPN control
// channel transports TLS records inside CONTROL_V1 messages). No sockets, no clocks. OpenSSL-backed;
// built only with PF_WITH_OPENSSL.
//
//   network -> feed(bytes) -> step() -> take_output() -> network
//   app     -> write()/read()  (after the handshake)
class TlsSession {
public:
    enum class State { Handshaking, Established, Failed };

    // nullptr + `error` set if the configuration is unusable (bad PEM, key mismatch, no trust anchors...).
    static std::unique_ptr<TlsSession> create(const TlsConfig& cfg, std::string& error);
    ~TlsSession();
    TlsSession(const TlsSession&) = delete;
    TlsSession& operator=(const TlsSession&) = delete;

    void feed(const uint8_t* data, size_t len);     // bytes received from the peer
    std::vector<uint8_t> take_output();             // bytes to send to the peer (removes them)
    State step();                                   // advances the handshake; call after feed()/at start
    State state() const;

    bool write(const uint8_t* data, size_t len);    // false unless Established
    std::vector<uint8_t> read();                    // decrypted application bytes available now

    // RFC 5705 / RFC 8446 exporter. Only after Established. `context` may be null (no context).
    bool export_keying_material(std::string_view label, const uint8_t* context, size_t context_len,
                                uint8_t* out, size_t out_len) const;

    // The peer's verified leaf certificate (only after Established): its subject CN ("" if none) and the SHA-256 of
    // its DER encoding. A server pins the fingerprint across renegotiations (D-048).
    std::string peer_common_name() const;
    bool peer_certificate_sha256(std::array<uint8_t, 32>& out) const;

    std::string protocol_version() const;           // e.g. "TLSv1.3"
    std::string failure_reason() const;

private:
    TlsSession();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace pf
