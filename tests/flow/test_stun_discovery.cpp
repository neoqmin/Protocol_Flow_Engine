// PM-2b N3: RFC 5780 NAT behaviour discovery over the simulator (pf/nat_sim.h): for every RFC 4787 mapping x filtering
// combination (and every port allocation), what the STUN client DISCOVERS must be what the simulated NAT IS.
#include <string>

#include "pf_test.h"
#include "stun_sim_lab.h"

using namespace pf;
using namespace pf::natsim;
using namespace pf::stun;
using pf_test::StunLab;
using pf_test::from_stun_ip;

namespace {
DiscoveryResult discover(StunLab& lab, uint64_t seed = 1, uint32_t probe_rto = 500, uint32_t probe_rm = 16) {
    DeterministicRandom rnd(seed);
    DiscoveryConfig cfg;
    cfg.server = lab.server_address();
    cfg.local = pf_test::to_stun(lab.client_local);
    cfg.probe_rto_ms = probe_rto;
    cfg.probe_rm = probe_rm;
    auto d = NatDiscovery::create(cfg, rnd);
    PF_REQUIRE(d != nullptr);
    lab.run(*d);
    return d->result();
}
const NatMapping kMaps[] = {NatMapping::EndpointIndependent, NatMapping::AddressDependent, NatMapping::AddressAndPortDependent};
const NatFiltering kFilts[] = {NatFiltering::EndpointIndependent, NatFiltering::AddressDependent, NatFiltering::AddressAndPortDependent};
}  // namespace

PF_TEST(discovery_finds_every_simulated_nat_behaviour) {
    size_t checked = 0;
    for (const auto m : kMaps)
        for (const auto f : kFilts)
            for (const auto ports : {PortAllocation::Preserve, PortAllocation::Sequential, PortAllocation::Random}) {
                NatConfig c;
                c.mapping = m;
                c.filtering = f;
                c.ports = ports;
                c.seed = 99;
                StunLab lab({c});
                const DiscoveryResult r = discover(lab);
                const std::string what = std::string(nat_mapping_name(m)) + "+" + nat_filtering_name(f);
                PF_CHECK(r.status == DiscoveryStatus::Done);
                PF_REQUIRE(r.mapping.has_value() && r.filtering.has_value());
                PF_CHECK(*r.mapping == m);
                PF_CHECK(*r.filtering == f);
                if (*r.mapping != m || *r.filtering != f)
                    std::fprintf(stderr, "%s discovered as %s+%s (%s)\n", what.c_str(), nat_mapping_name(*r.mapping),
                                 nat_filtering_name(*r.filtering), r.detail.c_str());
                PF_CHECK(r.behind_nat);
                PF_CHECK_EQ(from_stun_ip(r.mapped), ipv4(203, 0, 113, 1));
                PF_CHECK(r.other_address.has_value());
                ++checked;
            }
    PF_CHECK_EQ(checked, size_t{27});
}

PF_TEST(discovery_without_nat_and_through_carrier_grade_nat) {
    StunLab open({});                                                // client on the public internet
    const DiscoveryResult r = discover(open);
    PF_CHECK(r.status == DiscoveryStatus::Done);
    PF_CHECK(!r.behind_nat);
    PF_CHECK(r.mapping == NatMapping::EndpointIndependent);
    PF_CHECK(r.filtering == NatFiltering::EndpointIndependent);

    // a full-cone home NAT behind a symmetric CGN behaves, end to end, like the CGN
    StunLab cgn({NatConfig::symmetric(), NatConfig::full_cone()});
    const DiscoveryResult c = discover(cgn);
    PF_CHECK(c.status == DiscoveryStatus::Done);
    PF_CHECK(c.mapping == NatMapping::AddressAndPortDependent);
    PF_CHECK(c.filtering == NatFiltering::AddressAndPortDependent);
    // and the other way round (a strict home NAT behind a permissive CGN): the strict one decides
    StunLab rev({NatConfig::full_cone(), NatConfig::port_restricted_cone()});
    const DiscoveryResult v = discover(rev);
    PF_CHECK(v.mapping == NatMapping::EndpointIndependent);
    PF_CHECK(v.filtering == NatFiltering::AddressAndPortDependent);
}

PF_TEST(discovery_reports_what_it_cannot_find_out) {
    StunLab plain({NatConfig::symmetric()}, true, false);              // server without RFC 5780
    const DiscoveryResult r = discover(plain);
    PF_CHECK(r.status == DiscoveryStatus::NoRfc5780);
    PF_CHECK_EQ(from_stun_ip(r.mapped), ipv4(203, 0, 113, 1));         // the public endpoint is still known
    PF_CHECK(!r.mapping.has_value() && !r.filtering.has_value());

    StunLab dark({NatConfig::port_restricted_cone()}, false);         // no server at all (UDP blocked)
    const DiscoveryResult n = discover(dark);
    PF_CHECK(n.status == DiscoveryStatus::NoResponse);
    PF_CHECK_EQ(dark.net.now(), uint64_t{39500});                      // gave up on the RFC 8489 schedule
}

PF_TEST(discovery_probe_timing_is_configurable) {
    // APDF: both filtering probes time out. With RFC defaults that costs 2 x 39.5 s; short probes cost far less.
    StunLab slow({NatConfig::symmetric()});
    discover(slow);
    const uint64_t t_slow = slow.net.now();
    StunLab fast({NatConfig::symmetric()});
    const DiscoveryResult r = discover(fast, 1, 100, 4);
    PF_CHECK(r.status == DiscoveryStatus::Done && r.filtering == NatFiltering::AddressAndPortDependent);
    PF_CHECK(t_slow >= 2 * 39500);
    PF_CHECK(fast.net.now() < 2 * 7000);
}

PF_TEST(discovery_does_not_trust_a_server_that_ignores_change_request) {
    // The server claims RFC 5780 (OTHER-ADDRESS) but answers every probe from where it arrived. A full-cone NAT would let
    // the "changed" answer in, but it did not come from the other address and port, so it proves nothing: filtering
    // must stay unknown rather than be reported as EIF/ADF.
    StunLab lab({NatConfig::full_cone()});
    lab.honour_change = false;
    const DiscoveryResult r = discover(lab, 1, 100, 4);
    PF_CHECK(!r.filtering.has_value());
    PF_CHECK(!r.detail.empty());
    PF_CHECK(r.mapping == NatMapping::EndpointIndependent);          // mapping tests do not depend on CHANGE-REQUEST
}

