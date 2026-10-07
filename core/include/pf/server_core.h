#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pf/control_server.h"
#include "pf/key_store.h"
#include "pf/net_address.h"

namespace pf {

// PM-11 V2 (D-049): many clients on one UDP socket. SANS-I/O: the caller passes each datagram with its source
// address and sends what comes back to the address given. Single-threaded (D-048).
//
//   new client:  HARD_RESET_CLIENT -> stateless reply (our session id = HMAC cookie over the client's address and
//                session id, nothing stored) -> the client's next packet echoes the cookie -> limits -> session created
//   control:     routed by source address to its ControlServer (address changes are not followed on the control channel)
//   DATA_V2:     routed by peer-id; the caller decrypts with keys(session) (V3) and calls confirm_float() if the
//                authenticated packet came from a new address
//
// Nothing about a client is stored before it has shown it receives packets at its source address (no state from
// spoofed sources) and that it holds the tls-crypt key (no state from strangers). Rate and count limits apply when a
// session is about to be created.
struct ServerCoreConfig {
    ControlServerConfig session;             // template for every session (keys/push/random are set per session)
    // Fills this session's push (address, routes...); peer_id is already set. false = no address: refuse the client.
    std::function<bool(uint32_t peer_id, ServerPush& push)> prepare_push;
    size_t max_clients = 64;                 // sessions, unauthenticated ones included (max-clients)
    size_t max_sessions_per_ip = 8;          // one address behind NAT may carry several clients, not hundreds
    uint32_t new_sessions_per_second = 20;   // token bucket on session creation (connect-freq)
    uint32_t new_session_burst = 40;
    uint32_t cookie_window_ms = 30u * 1000u; // a cookie is valid in its window and the next one (30-60 s)
    RandomSource* random = nullptr;          // cookie secret, session ids; nullptr = OS CSPRNG
};

class ServerCore {
public:
    using SessionId = uint64_t;              // never reused (a late answer cannot reach a newer session)
    struct Outgoing { NetAddress to; std::vector<uint8_t> bytes; };
    enum class Route { Control, Data, Dropped };
    enum class DropReason { None, NotOurs, Malformed, BadCookie, LimitClients, LimitPerIp, LimitRate, UnknownPeerId,
                            NoDataKeys, Unsupported, SetupFailed };
    struct Received {
        Route route = Route::Dropped;
        DropReason reason = DropReason::None;
        SessionId session = 0;
        bool new_address = false;            // Data from an address other than the session's (float candidate)
    };
    struct Event {
        enum class Kind { Opened, Established, Closed } kind;
        SessionId session;
        NetAddress address;
        uint32_t peer_id;
        std::string detail;                  // Closed: the reason (never contains secrets)
    };
    struct Stats {
        uint32_t cookies_sent = 0, bad_cookies = 0, not_ours = 0, malformed = 0;
        uint32_t limit_clients = 0, limit_per_ip = 0, limit_rate = 0;
        uint32_t sessions_opened = 0, sessions_closed = 0, sessions_replaced = 0;
        uint32_t data_unknown_peer = 0, data_no_keys = 0, floats = 0;
    };
    struct PendingAuth { SessionId session; AuthRequest request; };

    static std::unique_ptr<ServerCore> create(ServerCoreConfig cfg, std::string& error);
    ~ServerCore();
    ServerCore(const ServerCore&) = delete;
    ServerCore& operator=(const ServerCore&) = delete;

    Received on_datagram(const uint8_t* data, size_t len, const NetAddress& from, uint64_t now_ms, uint32_t unix_s,
                         std::vector<Outgoing>& out);
    std::vector<Outgoing> poll(uint64_t now_ms, uint32_t unix_s);
    std::optional<uint64_t> next_wakeup_ms() const;

    std::vector<PendingAuth> take_auth_requests();
    bool resolve_auth(SessionId id, bool accept, const std::string& reason = {});
    bool kill(SessionId id, const std::string& why);
    // The caller authenticated a DATA packet of `id` from `from` (V3): the session now lives at that address.
    bool confirm_float(SessionId id, const NetAddress& from);

    std::vector<Event> take_events();
    size_t session_count() const { return sessions_.size(); }
    const ControlServer* session(SessionId id) const;
    KeyStore* keys(SessionId id);
    std::optional<SessionId> find_by_peer_id(uint32_t peer_id) const;
    std::optional<SessionId> find_by_address(const NetAddress& a) const;
    std::optional<NetAddress> address_of(SessionId id) const;
    uint32_t peer_id_of(SessionId id) const;
    const Stats& stats() const { return stats_; }

private:
    struct Entry {
        SessionId id;
        NetAddress address;
        uint32_t peer_id;
        std::unique_ptr<KeyStore> keys;      // before `server`: the server unbinds its keys when destroyed
        std::unique_ptr<ControlServer> server;
        bool announced_established = false;
    };
    explicit ServerCore(ServerCoreConfig cfg);

    std::array<uint8_t, kSessionIdLen> cookie(const NetAddress& a, const std::array<uint8_t, kSessionIdLen>& client_sid,
                                              uint64_t window) const;
    bool cookie_valid(const NetAddress& a, const std::array<uint8_t, kSessionIdLen>& client_sid,
                      const std::array<uint8_t, kSessionIdLen>& echoed, uint64_t now_ms) const;
    void answer_reset(const ControlPacket& p, const NetAddress& from, uint64_t window, uint32_t unix_s, std::vector<Outgoing>& out);
    Received open_session(const ControlPacket& p, const uint8_t* data, size_t len, const NetAddress& from, uint64_t now_ms,
                          uint32_t unix_s, std::vector<Outgoing>& out);
    std::optional<uint32_t> allocate_peer_id();
    bool take_token(uint64_t now_ms);
    void remove(SessionId id, const std::string& why);
    void collect(Entry& e, std::vector<std::vector<uint8_t>>&& dgs, std::vector<Outgoing>& out);
    size_t sessions_on_ip(const NetAddress& a) const;

    ServerCoreConfig cfg_;
    std::unique_ptr<RandomSource> own_random_;
    RandomSource* random_ = nullptr;
    TlsCryptKeys tls_crypt_;                 // for stateless opening and the stateless reply
    std::array<uint8_t, 32> cookie_secret_{};
    std::map<SessionId, Entry> sessions_;
    std::map<NetAddress, SessionId> by_address_;
    std::map<uint32_t, SessionId> by_peer_id_;
    SessionId next_id_ = 1;
    double tokens_ = 0;
    uint64_t tokens_at_ms_ = 0;
    uint32_t stateless_time_ = 0, stateless_next_ = 1;   // tls-crypt packet-ids of stateless replies (per second)
    std::vector<Event> events_;
    Stats stats_;
};

}  // namespace pf
