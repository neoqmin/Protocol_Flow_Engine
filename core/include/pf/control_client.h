#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pf/control_packet.h"
#include "pf/crypto/control_wire.h"
#include "pf/crypto/data_key_derivation.h"
#include "pf/crypto/tls_crypt.h"
#include "pf/crypto/tls_session.h"
#include "pf/key_method2.h"
#include "pf/key_store.h"
#include "pf/push.h"
#include "pf/reliable.h"

namespace pf {

// MVP profile strings (docs/OpenVPN_Interop_Profile.md). The options string is compared by the server with its
// own (mismatches are only warnings there); peer info announces IV_PROTO = DATA_V2 | REQUEST_PUSH | TLS_KEY_EXPORT.
std::string default_client_options();
std::string default_peer_info();

struct ControlClientConfig {
    std::array<uint8_t, kTlsCryptStaticKeyLen> tls_crypt_key{};   // wiped from the config once keys are derived
    TlsConfig tls;                                                // role must be Client
    std::string options_string = default_client_options();
    std::string peer_info = default_peer_info();
    size_t server_km2_optional_fields = 3;      // username, password, peer info follow the server's options string (observed: 3)
    size_t max_payload = 1100;                  // TLS bytes per CONTROL_V1 message
    ReliableConfig reliable;
    uint32_t push_request_delay_ms = 2000;      // ask for the push if the server has not volunteered it
    uint32_t push_timeout_ms = 20000;           // give up waiting for PUSH_REPLY
    EkmLayout ekm;                              // how the exported keying material is split (hypothesis, see header)
    std::function<void(uint8_t*, size_t)> random;   // CSPRNG; defaults to OpenSSL RAND_bytes
    KeyStore* keys = nullptr;                   // receives the data keys (key_id 0, tx and rx) on success
};

// Control channel client for the OpenVPN 2.6 MVP profile (client role, tls-crypt, TLS 1.3, key-method 2, tls-ekm).
// SANS-I/O: no sockets and no clocks. The caller moves datagrams and passes the current time:
//
//   start(now); loop { for each received datagram: on_datagram(...); send everything poll(now) returns;
//                      sleep until next_wakeup_ms() or the next datagram }
//
// Datagrams that are not control packets (DATA_V2) are left to the caller (on_datagram returns false).
class ControlClient {
public:
    enum class State { Idle, ResetSent, TlsHandshake, KeyExchange, WaitPush, Established, Failed };
    struct Stats {
        uint32_t datagrams_out = 0, retransmits = 0;
        uint32_t auth_failed = 0, replays = 0, malformed = 0, wrong_session = 0, not_control = 0;
        uint32_t ignored_soft_resets = 0;
        uint32_t ignored_control_messages = 0;   // control strings we did not act on (incl. empty ones = stream misalignment)
    };

    // nullptr + `error` if the configuration is unusable.
    static std::unique_ptr<ControlClient> create(ControlClientConfig cfg, std::string& error);

    void start(uint64_t now_ms, uint32_t unix_s);
    // true if the datagram was a control packet (accepted or dropped); false if it is something else.
    bool on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t unix_s);
    // Datagrams to transmit now (new messages, retransmissions, acknowledgements).
    std::vector<std::vector<uint8_t>> poll(uint64_t now_ms, uint32_t unix_s);
    // Earliest time poll() has something to do (0 = right away); nullopt when idle/finished.
    std::optional<uint64_t> next_wakeup_ms() const;

    State state() const { return state_; }
    const std::string& failure_reason() const { return reason_; }
    const PushReply& push() const { return push_; }
    const Stats& stats() const { return stats_; }
    const std::string& server_options() const { return server_options_; }
    const std::vector<std::string>& warnings() const { return warnings_; }

    // DIAGNOSTIC (interop key-layout probe): the raw exporter output for the OpenVPN label. These bytes ARE key
    // material: never log or store them. Only valid once the TLS handshake finished.
    bool export_ekm_for_probe(bool empty_context, uint8_t* out, size_t n) const;

private:
    explicit ControlClient(ControlClientConfig cfg);

    void fail(const std::string& why);
    void handle_message(uint8_t opcode, const std::vector<uint8_t>& payload);
    void pump_tls();
    void flush_tls_output();
    void send_key_method();
    void send_control_string(const std::string& s);
    void process_app_stream();
    void handle_control_message(const std::string& msg);
    bool install_keys();
    ControlPacket base_packet() const;

    ControlClientConfig cfg_;
    TlsCryptChannel channel_;
    ReliableSender sender_;
    ReliableReceiver receiver_;
    std::unique_ptr<TlsSession> tls_;

    State state_ = State::Idle;
    std::string reason_;
    PushReply push_;
    Stats stats_;
    std::array<uint8_t, kSessionIdLen> my_sid_{}, server_sid_{};
    bool have_server_sid_ = false;
    std::map<uint32_t, uint8_t> opcodes_;                  // message id -> opcode, until delivered in order
    std::vector<std::vector<uint8_t>> tx_backlog_;         // TLS bytes waiting for send-window space
    std::vector<uint8_t> app_in_;                          // decrypted TLS stream not yet parsed
    bool km_sent_ = false, km_done_ = false, push_requested_ = false;
    std::string server_options_;
    std::vector<std::string> warnings_;
    uint64_t now_ms_ = 0;
    uint64_t push_request_at_ = 0, push_fail_at_ = 0;
};

}  // namespace pf
