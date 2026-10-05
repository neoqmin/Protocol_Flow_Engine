#include "pf/transport_fallback.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(starts_with_first_transport) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp, TransportKind::Relay});
    PF_CHECK(p.current() == TransportKind::Udp);
}

PF_TEST(failure_advances_in_order) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp, TransportKind::Relay});
    PF_CHECK(p.on_failure());
    PF_CHECK(p.current() == TransportKind::Tcp);
    PF_CHECK(p.on_failure());
    PF_CHECK(p.current() == TransportKind::Relay);
}

PF_TEST(exhausted_after_last_failure) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp});
    PF_CHECK(p.on_failure());
    PF_CHECK(!p.on_failure());
    PF_CHECK(p.exhausted());
}

PF_TEST(success_keeps_current_and_reset_restarts) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp});
    p.on_failure();
    p.on_success();
    PF_CHECK(p.current() == TransportKind::Tcp);
    PF_CHECK(!p.exhausted());
    p.reset();
    PF_CHECK(p.current() == TransportKind::Udp);
}

PF_TEST(empty_policy_is_exhausted) {
    FallbackPolicy p({});
    PF_CHECK(p.exhausted());
}

PF_TEST(default_policy_prefers_udp_first_relay_last) {
    auto p = FallbackPolicy::default_policy();
    PF_CHECK(p.current() == TransportKind::Udp);
    PF_CHECK(p.order().back() == TransportKind::Relay);
}

PF_TEST(proxy_only_policy_skips_udp) {
    auto p = FallbackPolicy::proxy_only();
    for (auto k : p.order()) PF_CHECK(k != TransportKind::Udp);
}
