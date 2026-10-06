#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pf/control_client.h"
#include "pf/transport.h"
#include "pf/transport_fallback.h"

namespace pf {

// Brings up a control channel over the first transport that works, walking the FallbackPolicy (UDP -> TCP -> ...).
// SANS-I/O except for the two factories: the caller supplies how to open a transport of a given kind and how to build
// a fresh ControlClient, and calls step() with the clock. Deterministic and testable with LoopbackTransport.
//
// Falling back is decided ONLY by evidence that the path is bad (D-032: a blocked UDP path is silent, so that evidence
// is "no answer within the deadline"):
//   falls back  : factory failed (connect refused/unreachable), transport closed/errored, ControlClient Unreachable
//                 (nothing acknowledged / no PUSH_REPLY), or connect_timeout_ms() elapsed
//   does NOT    : ControlClient Rejected (certificate, AUTH_FAILED, unsupported profile): the server answered and the
//                 same answer would come over TCP, so the connector stops with that error
class FallbackConnector {
public:
    enum class State { Idle, Connecting, Connected, Failed };
    using TransportFactory = std::function<std::unique_ptr<Transport>(TransportKind kind, std::string& error)>;
    using ClientFactory = std::function<std::unique_ptr<ControlClient>(TransportKind kind, std::string& error)>;

    struct AttemptRecord {
        TransportKind kind;
        bool ok = false;
        std::string outcome;        // "established", "timeout after N ms", "connect failed: ...", ...
        uint64_t duration_ms = 0;
    };

    FallbackConnector(FallbackPolicy policy, TransportFactory make_transport, ClientFactory make_client)
        : policy_(std::move(policy)), make_transport_(std::move(make_transport)), make_client_(std::move(make_client)) {}

    void start(uint64_t now_ms, uint32_t unix_s);
    // Moves datagrams between the transport and the ControlClient, enforces the deadline, advances the policy.
    void step(uint64_t now_ms, uint32_t unix_s);

    State state() const { return state_; }
    bool done() const { return state_ == State::Connected || state_ == State::Failed; }
    const std::string& failure_reason() const { return reason_; }
    const std::vector<AttemptRecord>& history() const { return history_; }

    // While Connecting: the current attempt (for poll()-ing its descriptor).
    Transport* transport() { return transport_.get(); }
    ControlClient* client() { return client_.get(); }
    std::optional<TransportKind> current_kind() const { return kind_; }
    // Time until step() has something to do (deadline or client timer), nullopt when done.
    std::optional<uint64_t> next_wakeup_ms(uint64_t now_ms) const;

    // After Connected: ownership of the live transport and the established client.
    std::unique_ptr<Transport> take_transport() { return std::move(transport_); }
    std::unique_ptr<ControlClient> take_client() { return std::move(client_); }

private:
    void begin_attempt(uint64_t now_ms, uint32_t unix_s);
    void end_attempt_failed(const std::string& why, uint64_t now_ms, uint32_t unix_s, bool terminal);
    void finish_failed(const std::string& why);

    FallbackPolicy policy_;
    TransportFactory make_transport_;
    ClientFactory make_client_;
    State state_ = State::Idle;
    std::string reason_;
    std::vector<AttemptRecord> history_;
    std::unique_ptr<Transport> transport_;
    std::unique_ptr<ControlClient> client_;
    std::optional<TransportKind> kind_;
    uint64_t attempt_start_ = 0;
};

}  // namespace pf
