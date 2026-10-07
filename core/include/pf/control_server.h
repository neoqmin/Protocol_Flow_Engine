#pragma once
#include <array>
#include <cstdint>
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
#include "pf/peer_info.h"
#include "pf/push.h"
#include "pf/random.h"
#include "pf/reliable.h"
#include "pf/secret.h"

namespace pf {

// The options string the server sends in key-method 2: the client's default with "tls-server" (observed from
// 2.6.19 to match exactly, docs/OpenVPN_Control_Plane_Notes.md).
std::string default_server_options();

// Who is asking to connect, handed to whoever decides (V6: the auth-user-pass-verify hook, management client-auth).
struct AuthRequest {
    std::string common_name;                 // of the verified client certificate
    std::array<uint8_t, 32> cert_sha256{};
    std::string username;                    // empty if the client sent none
    SecretString password;                   // SECRET (D-048 §5.3)
    std::string peer_info;                   // raw key-method 2 peer info text
};

struct ControlServerConfig {
    std::array<uint8_t, kTlsCryptStaticKeyLen> tls_crypt_key{};   // wiped from the config once keys are derived
    TlsConfig tls;                                                // role must be Server; crl_pem for revocation
    std::string options_string = default_server_options();
    ServerPush push;                         // this session's address, routes, peer-id, keepalive (V2/V3 allocate them)

    // Authentication (D-048 §5.1). external_auth: every client waits for resolve_auth() after its certificate and
    // capabilities passed. require_user_pass: a client without a username is refused before anyone is asked;
    // needs external_auth (someone has to check the password).
    bool external_auth = false;
    bool require_user_pass = false;

    size_t max_payload = 1100;               // TLS bytes per CONTROL_V1 message
    ReliableConfig reliable;
    uint32_t hand_window_ms = 60u * 1000u;   // the initial key exchange + authentication must finish in this time
    uint32_t reneg_interval_ms = 3600u * 1000u;   // server-initiated renegotiation (reneg-sec); 0 = never
    uint32_t reneg_timeout_ms = 60u * 1000u;
    uint32_t old_key_grace_ms = 60u * 1000u; // the previous key stays valid for RECEIVING this long after the switch
    uint32_t reject_linger_ms = 5u * 1000u;  // after AUTH_FAILED: keep retransmitting this long, then close
    EkmLayout ekm;                           // the client's layout; the server uses it with tx/rx reversed (D-026)
    RandomSource* random = nullptr;          // session id and key-method 2 randoms; nullptr = OS CSPRNG
    KeyStore* keys = nullptr;                // receives the data keys once the client is accepted
};

// Server side of the OpenVPN 2.6 MVP profile for ONE client (PM-11 V1, D-048). SANS-I/O like ControlClient: the
// caller feeds datagrams from this client and sends what poll() returns. Sequence:
//
//   HARD_RESET -> TLS (client certificate, CRL) -> key-method 2 -> capability check (IV_PROTO, IV_CIPHERS)
//   -> authentication (AuthRequest / resolve_auth when external_auth) -> data keys installed -> PUSH_REPLY
//
// Refusals (capability, authentication) send AUTH_FAILED after our key-method 2 reply, linger, then close.
// Renegotiations (either side starts) must present the same certificate and username; the password is not asked
// again. Datagrams that are not control packets are left to the caller (on_datagram returns false).
class ControlServer {
public:
    enum class State { WaitReset, TlsHandshake, KeyExchange, AuthPending, Established, Rejected, Closed };
    struct Stats {
        uint32_t datagrams_out = 0, retransmits = 0;
        uint32_t auth_failed = 0, replays = 0, malformed = 0, wrong_session = 0, not_control = 0, unknown_key_id = 0;
        uint32_t renegotiations = 0, reneg_failures = 0;
        uint32_t ignored_control_messages = 0;
    };

    static std::unique_ptr<ControlServer> create(ControlServerConfig cfg, std::string& error);

    // A session whose reset exchange already happened statelessly (ServerCore cookie, D-049): the client's HARD_RESET
    // (message 0) was acknowledged and our HARD_RESET_SERVER (message 0, session id `server_sid`, tls-crypt packet-ids
    // below `next_tls_crypt_packet_id`) was received - the client proved it by echoing `server_sid`. The session
    // starts in TlsHandshake, ready for the client's next packet.
    struct Adopted {
        std::array<uint8_t, kSessionIdLen> client_sid{}, server_sid{};
        uint32_t next_tls_crypt_packet_id = 2;
    };
    static std::unique_ptr<ControlServer> adopt(ControlServerConfig cfg, const Adopted& a, uint64_t now_ms, std::string& error);
    const std::array<uint8_t, kSessionIdLen>& client_session_id() const { return client_sid_; }
    ~ControlServer();
    ControlServer(const ControlServer&) = delete;
    ControlServer& operator=(const ControlServer&) = delete;

    bool on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t unix_s);
    std::vector<std::vector<uint8_t>> poll(uint64_t now_ms, uint32_t unix_s);
    std::optional<uint64_t> next_wakeup_ms() const;

    // The pending decision (once, in AuthPending). The request's password is the caller's to wipe (SecretString).
    std::optional<AuthRequest> take_auth_request();
    // Answer it. accept: keys are installed and PUSH_REPLY sent. Otherwise AUTH_FAILED (the client sees only
    // "AUTH_FAILED"; `reason` is kept for our records). Ignored outside AuthPending.
    void resolve_auth(bool accept, const std::string& reason = {});

    // Ends the session now (operator kill, ping-restart): wipes and unbinds every data key. Idempotent.
    void close(const std::string& why);

    State state() const { return state_; }
    bool done() const { return state_ == State::Closed; }
    const std::string& close_reason() const { return reason_; }
    // Our data TX may use tx_key_id() once the client has acknowledged the message that gave it the key (the push
    // for the first key, our key-method 2 for a renegotiation): it can decrypt what we send.
    bool data_ready() const { return data_ready_; }
    uint8_t tx_key_id() const { return tx_key_id_; }
    const std::string& common_name() const { return common_name_; }
    const std::string& username() const { return username_; }
    const PeerInfo& peer_info() const { return peer_info_; }
    const std::string& client_options() const { return client_options_; }
    const std::vector<std::string>& warnings() const { return warnings_; }
    const Stats& stats() const { return stats_; }
    static uint8_t next_key_id(uint8_t k) { return k >= 7 ? 1 : static_cast<uint8_t>(k + 1); }

private:
    struct KeyState {
        uint8_t key_id;
        bool initial;
        ReliableSender sender;
        ReliableReceiver receiver;
        std::unique_ptr<TlsSession> tls;
        std::map<uint32_t, uint8_t> opcodes;
        std::vector<std::vector<uint8_t>> backlog;
        std::vector<uint8_t> app_in;
        bool km_done = false;
        uint64_t started_ms = 0;
        KeyRef tx_ref{}, rx_ref{};
        DataKey tx, rx;                      // derived, held until installed (initial key waits for the decision)
        KeyState(uint8_t id, bool init, const ReliableConfig& rc) : key_id(id), initial(init), sender(rc), receiver(rc) {}
    };

    explicit ControlServer(ControlServerConfig cfg);

    KeyState* find_state(uint8_t key_id);
    KeyState* add_state(uint8_t key_id, bool initial);
    ControlPacket base_packet(const KeyState& ks) const;
    void handle_message(KeyState& ks, uint8_t opcode, const std::vector<uint8_t>& payload);
    void pump_tls(KeyState& ks);
    void flush_tls_output(KeyState& ks);
    void process_app_stream(KeyState& ks);
    bool send_key_method(KeyState& ks);
    void send_control_string(KeyState& ks, const std::string& s);
    void on_initial_key_method(KeyState& ks, KeyMethod2Message& m);
    void on_reneg_key_method(KeyState& ks, KeyMethod2Message& m);
    void accept_client();
    // Ends the handshake with a refusal: `client_message` (e.g. "AUTH_FAILED") is sent if not empty, then we only
    // retransmit until reject_linger_ms has passed.
    void reject(const std::string& why, const std::string& client_message);
    bool flushed(uint8_t key_id) const;      // everything sent on this key state has been acknowledged
    void maybe_push();
    bool install(KeyState& ks);
    bool begin_reneg(uint8_t key_id);
    void abandon_reneg(const std::string& why);
    void retire_key(uint8_t key_id);
    void wipe_keys(KeyState& ks);

    ControlServerConfig cfg_;
    std::unique_ptr<RandomSource> own_random_;
    RandomSource* random_ = nullptr;
    TlsCryptChannel channel_;
    State state_ = State::WaitReset;
    std::string reason_;
    Stats stats_;
    std::array<uint8_t, kSessionIdLen> my_sid_{}, client_sid_{};
    bool have_client_sid_ = false;
    std::map<uint8_t, std::unique_ptr<KeyState>> states_;
    uint64_t now_ms_ = 0, hand_deadline_ms_ = 0, linger_until_ms_ = 0, last_key_at_ms_ = 0;
    std::optional<AuthRequest> auth_request_;
    bool push_requested_ = false, push_sent_ = false, data_ready_ = false;
    uint8_t tx_key_id_ = 0;
    std::optional<uint8_t> reneg_pending_;
    std::optional<uint8_t> switch_pending_;  // renegotiated key waiting for the client's ack before TX moves to it
    struct Retiring { uint8_t key_id; uint64_t at_ms; };
    std::optional<Retiring> retiring_;
    std::array<uint8_t, 32> cert_sha256_{};
    std::string common_name_, username_, client_options_;
    PeerInfo peer_info_;
    std::vector<std::string> warnings_;
};

}  // namespace pf
