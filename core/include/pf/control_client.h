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
    // auth-user-pass: sent in every key-method 2 message (initial key and renegotiations), like OpenVPN does.
    // Empty username = not sent. The password is a SECRET: never logged, wiped when the client is destroyed.
    std::string username, password;
    size_t server_km2_optional_fields = 3;      // username, password, peer info follow the server's options string (observed: 3)
    size_t max_payload = 1100;                  // TLS bytes per CONTROL_V1 message
    ReliableConfig reliable;
    uint32_t push_request_delay_ms = 2000;      // ask for the push if the server has not volunteered it
    uint32_t push_timeout_ms = 20000;           // give up waiting for PUSH_REPLY

    // Key renegotiation (SOFT_RESET, new key_id). The server normally starts it (its reneg-sec, default 3600 s);
    // we also start one ourselves after reneg_interval_ms of key age so a quiet server cannot leave a key in use forever.
    uint32_t reneg_interval_ms = 3600u * 1000u;   // 0 disables client-initiated renegotiation
    uint32_t reneg_timeout_ms = 60u * 1000u;      // abandon a renegotiation that has not produced keys by then (tunnel keeps the old key)
    uint32_t old_key_grace_ms = 60u * 1000u;      // the previous key stays valid for RECEIVING this long after the switch
    EkmLayout ekm;                              // how the exported keying material is split (hypothesis, see header)
    std::function<void(uint8_t*, size_t)> random;   // CSPRNG; defaults to OpenSSL RAND_bytes
    KeyStore* keys = nullptr;                   // receives the data keys (key_id 0, tx and rx) on success
    // TEST HOOK: present another identity in renegotiations (a server must refuse it).
    struct RenegOverride { std::optional<TlsConfig> tls; std::optional<std::string> username; };
    RenegOverride reneg_override_for_test;
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
        uint32_t unknown_key_id = 0;             // control packets for a key_id we have no state for and would not accept
        uint32_t renegotiations = 0;             // completed: new key installed and TX switched
        uint32_t reneg_failures = 0;             // abandoned (timeout, TLS error, bad key exchange); the old key stayed in use
        uint32_t ignored_control_messages = 0;   // control strings we did not act on (incl. empty ones = stream misalignment)
    };

    // nullptr + `error` if the configuration is unusable.
    static std::unique_ptr<ControlClient> create(ControlClientConfig cfg, std::string& error);
    ~ControlClient();
    ControlClient(const ControlClient&) = delete;
    ControlClient& operator=(const ControlClient&) = delete;

    void start(uint64_t now_ms, uint32_t unix_s);
    // true if the datagram was a control packet (accepted or dropped); false if it is something else.
    bool on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t unix_s);
    // Datagrams to transmit now (new messages, retransmissions, acknowledgements).
    std::vector<std::vector<uint8_t>> poll(uint64_t now_ms, uint32_t unix_s);
    // Earliest time poll() has something to do (0 = right away); nullopt when idle/finished.
    std::optional<uint64_t> next_wakeup_ms() const;

    // The key_id to put in outgoing DATA_V2 headers. Changes when a renegotiation completes (0, 1..7, then 1 again).
    uint8_t tx_key_id() const { return tx_key_id_; }
    static uint8_t next_key_id(uint8_t k) { return k >= 7 ? 1 : static_cast<uint8_t>(k + 1); }

    // Why a Failed client failed, for transport fallback: Unreachable = the path did not carry our packets / the server
    // never answered (another transport may work); Rejected = the server answered and said no, or its answer was
    // unacceptable (bad certificate, AUTH_FAILED, unsupported push): another transport would get the same answer.
    enum class FailureKind { None, Unreachable, Rejected };
    FailureKind failure_kind() const { return failure_kind_; }

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
    // One per key_id. Like OpenVPN, each key has its own reliable message-id sequence (restarting at 0) and its own TLS
    // session; the tls-crypt channel and both session ids are shared by all of them.
    struct KeyState {
        uint8_t key_id;
        bool initial;                                    // first key (HARD_RESET) vs a renegotiation (SOFT_RESET)
        ReliableSender sender;
        ReliableReceiver receiver;
        std::unique_ptr<TlsSession> tls;
        std::map<uint32_t, uint8_t> opcodes;             // message id -> opcode, until delivered in order
        std::vector<std::vector<uint8_t>> backlog;       // TLS bytes waiting for send-window space
        std::vector<uint8_t> app_in;                     // decrypted TLS stream not yet parsed
        bool tls_started = false, km_sent = false, km_done = false;
        uint64_t started_ms = 0;
        KeyRef tx_ref{}, rx_ref{};                       // installed data keys (so they can be wiped on retirement)
        KeyState(uint8_t id, bool init, const ReliableConfig& rc) : key_id(id), initial(init), sender(rc), receiver(rc) {}
    };

    explicit ControlClient(ControlClientConfig cfg);

    void fail(const std::string& why, FailureKind kind = FailureKind::Rejected);
    KeyState* find_state(uint8_t key_id);
    KeyState* add_state(uint8_t key_id, bool initial);
    void handle_message(KeyState& ks, uint8_t opcode, const std::vector<uint8_t>& payload);
    void pump_tls(KeyState& ks);
    void flush_tls_output(KeyState& ks);
    void send_key_method(KeyState& ks);
    void send_control_string(KeyState& ks, const std::string& s);
    void process_app_stream(KeyState& ks);
    void handle_control_message(KeyState& ks, const std::string& msg);
    bool install_keys(KeyState& ks);
    ControlPacket base_packet(const KeyState& ks) const;

    // Renegotiation.
    bool begin_reneg(uint8_t key_id);                    // creates the key state and queues our SOFT_RESET
    void finish_reneg(KeyState& ks);                     // key exchange done: install, switch TX, schedule old-key retirement
    void abandon_reneg(const std::string& why);          // keep the old key; drop the half-built state
    void retire_key(uint8_t key_id);                     // wipe keys and drop control state of a superseded key

    ControlClientConfig cfg_;
    TlsCryptChannel channel_;

    State state_ = State::Idle;
    std::string reason_;
    FailureKind failure_kind_ = FailureKind::None;
    PushReply push_;
    Stats stats_;
    std::array<uint8_t, kSessionIdLen> my_sid_{}, server_sid_{};
    bool have_server_sid_ = false;
    std::map<uint8_t, std::unique_ptr<KeyState>> states_;
    uint8_t tx_key_id_ = 0;
    std::optional<uint8_t> reneg_pending_;               // key_id of the renegotiation in flight
    struct Retiring { uint8_t key_id; uint64_t at_ms; };
    std::optional<Retiring> retiring_;
    uint64_t last_key_at_ms_ = 0;                        // when the current key was installed (client-initiated renegotiation timer)
    bool push_requested_ = false;
    std::string server_options_;
    std::vector<std::string> warnings_;
    uint64_t now_ms_ = 0;
    uint64_t push_request_at_ = 0, push_fail_at_ = 0;
};

}  // namespace pf
