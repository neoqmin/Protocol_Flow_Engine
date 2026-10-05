#pragma once
#include <cstddef>
#include <initializer_list>
#include <vector>

namespace pf {

enum class TransportKind { Udp, Tcp, TcpViaProxy, Relay };

// Ordered transport fallback: UDP -> TCP -> proxy -> relay, driven by the
// caller reporting connect success/failure. Pure logic, no I/O.
class FallbackPolicy {
public:
    explicit FallbackPolicy(std::vector<TransportKind> order) : order_(std::move(order)) {}
    FallbackPolicy(std::initializer_list<TransportKind> order) : order_(order) {}

    static FallbackPolicy default_policy() {
        return FallbackPolicy({TransportKind::Udp, TransportKind::Tcp,
                               TransportKind::TcpViaProxy, TransportKind::Relay});
    }
    // For networks where only an outbound proxy is allowed.
    static FallbackPolicy proxy_only() {
        return FallbackPolicy({TransportKind::TcpViaProxy, TransportKind::Relay});
    }

    bool exhausted() const { return idx_ >= order_.size(); }
    // Precondition: !exhausted().
    TransportKind current() const { return order_[idx_]; }
    const std::vector<TransportKind>& order() const { return order_; }

    // Returns true if another transport is available.
    bool on_failure() {
        if (!exhausted()) ++idx_;
        return !exhausted();
    }
    void on_success() {}  // keep using the transport that worked
    void reset() { idx_ = 0; }

private:
    std::vector<TransportKind> order_;
    size_t idx_ = 0;
};

}  // namespace pf
