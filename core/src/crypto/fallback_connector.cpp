#include "pf/fallback_connector.h"

#include <algorithm>

namespace pf {

namespace {
const char* kind_name(TransportKind k) {
    switch (k) {
        case TransportKind::Udp: return "udp";
        case TransportKind::Tcp: return "tcp";
        case TransportKind::TcpViaProxy: return "tcp-proxy";
        case TransportKind::Relay: return "relay";
    }
    return "?";
}
}  // namespace

void FallbackConnector::start(uint64_t now_ms, uint32_t unix_s) {
    policy_.reset();
    history_.clear();
    reason_.clear();
    state_ = State::Connecting;
    begin_attempt(now_ms, unix_s);
}

void FallbackConnector::finish_failed(const std::string& why) {
    state_ = State::Failed;
    reason_ = why;
    transport_.reset();
    client_.reset();
    kind_.reset();
}

void FallbackConnector::begin_attempt(uint64_t now_ms, uint32_t unix_s) {
    // A factory failure is an attempt failure too; loop until an attempt is really running or the policy is spent.
    while (state_ == State::Connecting) {
        if (policy_.exhausted()) {
            std::string why = "all transports failed:";
            for (const auto& h : history_) why += std::string(" [") + kind_name(h.kind) + ": " + h.outcome + "]";
            finish_failed(why);
            return;
        }
        kind_ = policy_.current();
        attempt_start_ = now_ms;
        std::string err;
        transport_ = make_transport_(*kind_, err);
        if (transport_) client_ = make_client_(*kind_, err);
        if (transport_ && client_) {
            client_->start(now_ms, unix_s);
            return;
        }
        transport_.reset();
        client_.reset();
        history_.push_back({*kind_, false, "connect failed: " + err, 0});
        (void)policy_.on_failure();
    }
}

void FallbackConnector::end_attempt_failed(const std::string& why, uint64_t now_ms, uint32_t unix_s, bool terminal) {
    history_.push_back({*kind_, false, why, now_ms - attempt_start_});
    if (transport_) transport_->close();
    transport_.reset();
    client_.reset();
    if (terminal) {
        finish_failed(std::string(kind_name(*kind_)) + ": " + why);
        return;
    }
    (void)policy_.on_failure();
    begin_attempt(now_ms, unix_s);
}

std::optional<uint64_t> FallbackConnector::next_wakeup_ms(uint64_t now_ms) const {
    if (state_ != State::Connecting || !client_) return std::nullopt;
    uint64_t at = attempt_start_ + policy_.connect_timeout_ms();
    if (auto w = client_->next_wakeup_ms()) at = std::min(at, *w);
    return at > now_ms ? at : now_ms;
}

void FallbackConnector::step(uint64_t now_ms, uint32_t unix_s) {
    if (state_ != State::Connecting || !transport_ || !client_) return;

    // Receive everything available (bounded so a flood cannot starve the deadline check).
    uint8_t buf[2048];
    for (int i = 0; i < 256; ++i) {
        const RecvResult r = transport_->recv(buf, sizeof buf);
        if (r.status == TransportStatus::Ok) { (void)client_->on_datagram(buf, r.len, now_ms, unix_s); continue; }
        if (r.status == TransportStatus::TooLarge) continue;
        if (r.status == TransportStatus::Closed || r.status == TransportStatus::Error) {
            end_attempt_failed(r.status == TransportStatus::Closed ? "transport closed by the peer" : "transport I/O error", now_ms, unix_s, false);
            return;
        }
        break;
    }

    for (const auto& d : client_->poll(now_ms, unix_s)) {
        const TransportStatus st = transport_->send(d.data(), d.size());
        if (st == TransportStatus::Closed || st == TransportStatus::Error) {
            end_attempt_failed("transport send failed", now_ms, unix_s, false);
            return;
        }
        // WouldBlock/TooLarge: the control channel's own retransmission covers it.
    }
    transport_->flush();

    switch (client_->state()) {
        case ControlClient::State::Established:
            history_.push_back({*kind_, true, "established", now_ms - attempt_start_});
            policy_.on_success();
            state_ = State::Connected;
            return;
        case ControlClient::State::Failed:
            end_attempt_failed("control channel failed: " + client_->failure_reason(), now_ms, unix_s,
                               client_->failure_kind() == ControlClient::FailureKind::Rejected);
            return;
        default: break;
    }
    if (now_ms - attempt_start_ >= policy_.connect_timeout_ms())
        end_attempt_failed("timeout after " + std::to_string(now_ms - attempt_start_) + " ms", now_ms, unix_s, false);
}

}  // namespace pf
