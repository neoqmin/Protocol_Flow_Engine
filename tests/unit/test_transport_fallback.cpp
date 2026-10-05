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

PF_TEST(proxy_or_relay_policy_skips_direct_transports) {
    auto p = FallbackPolicy::proxy_or_relay();
    for (auto k : p.order()) PF_CHECK(k != TransportKind::Udp && k != TransportKind::Tcp);
    PF_CHECK(p.current() == TransportKind::TcpViaProxy);
}

PF_TEST(retries_before_advancing) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp}, /*retries_per_transport=*/3);
    PF_CHECK(p.on_failure());   // 1st failure: retry same transport
    PF_CHECK(p.current() == TransportKind::Udp);
    PF_CHECK(p.on_failure());   // 2nd failure: retry
    PF_CHECK(p.current() == TransportKind::Udp);
    PF_CHECK(p.on_failure());   // 3rd failure: advance
    PF_CHECK(p.current() == TransportKind::Tcp);
}

PF_TEST(retry_counter_resets_on_advance) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp}, 2);
    p.on_failure(); p.on_failure();          // -> Tcp
    PF_CHECK(p.current() == TransportKind::Tcp);
    PF_CHECK(p.on_failure());                // retry on Tcp
    PF_CHECK(p.current() == TransportKind::Tcp);
    PF_CHECK(!p.on_failure());               // exhausted
}

PF_TEST(zero_retries_is_treated_as_one_attempt) {
    FallbackPolicy p({TransportKind::Udp, TransportKind::Tcp}, 0);
    PF_CHECK(p.on_failure());
    PF_CHECK(p.current() == TransportKind::Tcp);
}

PF_TEST(timeout_is_configurable_with_sane_default) {
    FallbackPolicy p({TransportKind::Udp});
    PF_CHECK(p.connect_timeout_ms() > 0);
    p.set_connect_timeout_ms(1234);
    PF_CHECK_EQ(p.connect_timeout_ms(), 1234u);
}

PF_TEST(on_failure_when_exhausted_is_idempotent) {
    FallbackPolicy p({TransportKind::Udp});
    PF_CHECK(!p.on_failure());
    PF_CHECK(!p.on_failure());
    PF_CHECK(p.exhausted());
}
