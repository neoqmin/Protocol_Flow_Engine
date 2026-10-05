#pragma once
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <utility>
#include <vector>

namespace pf {

enum class TransportKind { Udp, Tcp, TcpViaProxy, Relay };

// Ordered transport fallback: UDP -> TCP -> proxy -> relay, driven by the
// caller reporting connect success/failure. Pure logic, no I/O or clocks:
// the caller owns the timer and uses connect_timeout_ms() as its deadline.
class FallbackPolicy {
public:
    explicit FallbackPolicy(std::vector<TransportKind> order, unsigned retries_per_transport = 1)
        : order_(std::move(order)), retries_(retries_per_transport ? retries_per_transport : 1) {}
    FallbackPolicy(std::initializer_list<TransportKind> order, unsigned retries_per_transport = 1)
        : FallbackPolicy(std::vector<TransportKind>(order), retries_per_transport) {}

    static FallbackPolicy default_policy() {
        return FallbackPolicy({TransportKind::Udp, TransportKind::Tcp,
                               TransportKind::TcpViaProxy, TransportKind::Relay});
    }
    // For networks where direct UDP/TCP is not allowed: proxy first, then relay.
    static FallbackPolicy proxy_or_relay() {
        return FallbackPolicy({TransportKind::TcpViaProxy, TransportKind::Relay});
    }

    bool exhausted() const { return idx_ >= order_.size(); }
    // Precondition: !exhausted().
    TransportKind current() const { return order_[idx_]; }
    const std::vector<TransportKind>& order() const { return order_; }

    // Records a failed attempt. Retries the same transport until
    // retries_per_transport is used up, then advances. Returns true if
    // another attempt (same or next transport) is available.
    bool on_failure() {
        if (exhausted()) return false;
        if (++failures_ >= retries_) { ++idx_; failures_ = 0; }
        return !exhausted();
    }
    void on_success() { failures_ = 0; }  // keep using the transport that worked
    void reset() { idx_ = 0; failures_ = 0; }

    uint32_t connect_timeout_ms() const { return timeout_ms_; }
    void set_connect_timeout_ms(uint32_t ms) { timeout_ms_ = ms; }

private:
    std::vector<TransportKind> order_;
    unsigned retries_;
    size_t idx_ = 0;
    unsigned failures_ = 0;
    uint32_t timeout_ms_ = 5000;
};

}  // namespace pf
