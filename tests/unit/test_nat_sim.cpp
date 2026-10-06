// PM-2b N2: one simulated NAT (pf/nat_sim.h) against the RFC 4787 definitions - all 3 x 3 mapping/filtering
// combinations, port allocation, timeouts and refresh, plus a random property test against an observation oracle.
#include <map>
#include <ostream>
#include <random>
#include <set>
#include <string>

#include "pf/nat_sim.h"
#include "pf_test.h"

using namespace pf::natsim;

namespace pf::natsim {
inline std::ostream& operator<<(std::ostream& os, const Endpoint& e) { return os << e.to_string(); }
}  // namespace pf::natsim

namespace {
const uint32_t kExt = ipv4(203, 0, 113, 1);
const Endpoint X{ipv4(10, 0, 0, 2), 5000};
const Endpoint X2{ipv4(10, 0, 0, 3), 5000};
const Endpoint Y1a{ipv4(198, 51, 100, 1), 3478};
const Endpoint Y1b{ipv4(198, 51, 100, 1), 3479};
const Endpoint Y2a{ipv4(198, 51, 100, 2), 3478};

NatConfig cfg(MappingBehavior m, FilteringBehavior f) {
    NatConfig c;
    c.mapping = m;
    c.filtering = f;
    return c;
}
const MappingBehavior kMappings[] = {MappingBehavior::EndpointIndependent, MappingBehavior::AddressDependent,
                                     MappingBehavior::AddressAndPortDependent};
const FilteringBehavior kFilterings[] = {FilteringBehavior::EndpointIndependent, FilteringBehavior::AddressDependent,
                                         FilteringBehavior::AddressAndPortDependent};
}  // namespace

PF_TEST(nat_mapping_behaviour_all_nine_combinations) {
    for (const auto m : kMappings)
        for (const auto f : kFilterings) {
            Nat nat(kExt, cfg(m, f));
            const auto e1 = nat.outbound(X, Y1a, 0), e2 = nat.outbound(X, Y1b, 0), e3 = nat.outbound(X, Y2a, 0);
            PF_REQUIRE(e1 && e2 && e3);
            PF_CHECK(e1->ip == kExt && e2->ip == kExt && e3->ip == kExt);
            switch (m) {
                case MappingBehavior::EndpointIndependent:     // one mapping for every destination
                    PF_CHECK(*e1 == *e2 && *e1 == *e3);
                    PF_CHECK_EQ(nat.mapping_count(), size_t{1});
                    break;
                case MappingBehavior::AddressDependent:        // same destination address -> same mapping
                    PF_CHECK(*e1 == *e2 && *e1 != *e3);
                    PF_CHECK_EQ(nat.mapping_count(), size_t{2});
                    break;
                case MappingBehavior::AddressAndPortDependent: // every destination endpoint has its own mapping
                    PF_CHECK(*e1 != *e2 && *e1 != *e3 && *e2 != *e3);
                    PF_CHECK_EQ(nat.mapping_count(), size_t{3});
                    break;
            }
            // the same flow again reuses its mapping
            PF_CHECK(*nat.outbound(X, Y1a, 1) == *e1);
        }
}

PF_TEST(nat_filtering_behaviour_all_nine_combinations) {
    for (const auto m : kMappings)
        for (const auto f : kFilterings) {
            Nat nat(kExt, cfg(m, f));
            const auto e = nat.outbound(X, Y1a, 0);                  // X has talked to Y1a only
            PF_REQUIRE(e.has_value());
            const std::string what = std::string(behavior_name(m)) + "+" + behavior_name(f);
            auto in = [&](const Endpoint& from) { return nat.inbound(from, e->port, 0).status; };
            PF_CHECK(in(Y1a) == Nat::InboundStatus::Deliver);        // the contacted endpoint always gets in
            const bool same_addr_ok = f != FilteringBehavior::AddressAndPortDependent;
            const bool other_addr_ok = f == FilteringBehavior::EndpointIndependent;
            PF_CHECK((in(Y1b) == Nat::InboundStatus::Deliver) == same_addr_ok);
            PF_CHECK((in(Y2a) == Nat::InboundStatus::Deliver) == other_addr_ok);
            if (in(Y2a) != Nat::InboundStatus::Deliver) PF_CHECK(in(Y2a) == Nat::InboundStatus::Filtered);
            PF_CHECK_EQ(nat.inbound(Y1a, e->port, 0).internal, X);
            const uint16_t unused = static_cast<uint16_t>(e->port == 60000 ? 60001 : 60000);
            PF_CHECK(nat.inbound(Y1a, unused, 0).status == Nat::InboundStatus::NoMapping);
            if (!(in(Y1a) == Nat::InboundStatus::Deliver)) std::fprintf(stderr, "%s\n", what.c_str());
        }
}

PF_TEST(nat_presets_are_the_classic_types) {
    PF_CHECK(NatConfig::full_cone().mapping == MappingBehavior::EndpointIndependent);
    PF_CHECK(NatConfig::full_cone().filtering == FilteringBehavior::EndpointIndependent);
    PF_CHECK(NatConfig::restricted_cone().filtering == FilteringBehavior::AddressDependent);
    PF_CHECK(NatConfig::port_restricted_cone().filtering == FilteringBehavior::AddressAndPortDependent);
    PF_CHECK(NatConfig::port_restricted_cone().mapping == MappingBehavior::EndpointIndependent);
    PF_CHECK(NatConfig::symmetric().mapping == MappingBehavior::AddressAndPortDependent);
    PF_CHECK(NatConfig::symmetric().filtering == FilteringBehavior::AddressAndPortDependent);
}

PF_TEST(nat_port_allocation_preserve_sequential_random) {
    NatConfig p = NatConfig::port_restricted_cone();
    Nat pres(kExt, p);
    PF_CHECK_EQ(pres.outbound(X, Y1a, 0)->port, uint16_t{5000});            // port preserved
    const auto other = pres.outbound(X2, Y1a, 0);                           // same internal port, other host
    PF_REQUIRE(other.has_value());
    PF_CHECK(other->port != 5000);                                          // collision: no port overloading
    NatConfig low = p;
    low.port_min = 20000;
    low.port_max = 30000;
    Nat out_of_range(kExt, low);
    const auto r = out_of_range.outbound(X, Y1a, 0);                        // 5000 is outside the range
    PF_CHECK(r->port >= 20000 && r->port <= 30000);

    NatConfig s = NatConfig::symmetric();
    s.ports = PortAllocation::Sequential;
    s.port_min = 40000;
    Nat seq(kExt, s);
    PF_CHECK_EQ(seq.outbound(X, Y1a, 0)->port, uint16_t{40000});
    PF_CHECK_EQ(seq.outbound(X, Y1b, 0)->port, uint16_t{40001});
    PF_CHECK_EQ(seq.outbound(X, Y2a, 0)->port, uint16_t{40002});

    NatConfig rnd = NatConfig::symmetric();
    rnd.ports = PortAllocation::Random;
    rnd.port_min = 10000;
    rnd.port_max = 60000;
    rnd.seed = 7;
    Nat r1(kExt, rnd), r2(kExt, rnd);
    rnd.seed = 8;
    Nat r3(kExt, rnd);
    std::set<uint16_t> seen;
    bool differs = false;
    for (uint16_t k = 0; k < 50; ++k) {
        const Endpoint d{ipv4(198, 51, 100, 9), static_cast<uint16_t>(1000 + k)};
        const auto a = r1.outbound(X, d, 0), b = r2.outbound(X, d, 0), c = r3.outbound(X, d, 0);
        PF_REQUIRE(a && b && c);
        PF_CHECK(a->port == b->port);                                        // deterministic per seed
        differs |= a->port != c->port;
        PF_CHECK(a->port >= 10000 && a->port <= 60000);
        PF_CHECK(seen.insert(a->port).second);                               // unique
    }
    PF_CHECK(differs);
}

PF_TEST(nat_port_exhaustion_and_reuse_after_expiry) {
    NatConfig c = NatConfig::symmetric();
    c.port_min = 50000;
    c.port_max = 50002;
    c.mapping_timeout_ms = 1000;
    Nat nat(kExt, c);
    for (uint16_t k = 0; k < 3; ++k) PF_CHECK(nat.outbound(X, {ipv4(198, 51, 100, 1), static_cast<uint16_t>(k + 1)}, 0).has_value());
    PF_CHECK(!nat.outbound(X, {ipv4(198, 51, 100, 1), 99}, 10).has_value());   // all three ports taken
    PF_CHECK(nat.outbound(X, {ipv4(198, 51, 100, 1), 99}, 1000).has_value());  // idle mappings expired, port reused
    PF_CHECK_EQ(nat.mapping_count(), size_t{1});
    NatConfig empty = c;
    empty.port_min = 2;
    empty.port_max = 1;
    Nat none(kExt, empty);
    PF_CHECK(!none.outbound(X, Y1a, 0).has_value());
}

PF_TEST(nat_timeout_and_refresh) {
    NatConfig c = NatConfig::port_restricted_cone();
    c.mapping_timeout_ms = 30000;
    Nat nat(kExt, c);
    const auto e = nat.outbound(X, Y1a, 0);
    PF_REQUIRE(e.has_value());
    PF_CHECK(nat.inbound(Y1a, e->port, 29999).status == Nat::InboundStatus::Deliver);
    PF_CHECK(nat.inbound(Y1a, e->port, 30000).status == Nat::InboundStatus::NoMapping);   // expired exactly at the timeout
    PF_CHECK_EQ(nat.mapping_count(), size_t{0});

    // outbound traffic refreshes, inbound does not (default)
    const auto f = nat.outbound(X, Y1a, 100000);
    nat.outbound(X, Y1a, 120000);
    PF_CHECK(nat.inbound(Y1a, f->port, 149999).status == Nat::InboundStatus::Deliver);
    PF_CHECK(nat.inbound(Y1a, f->port, 150000).status == Nat::InboundStatus::NoMapping);

    // inbound refresh when configured
    c.inbound_refresh = true;
    Nat in_ref(kExt, c);
    const auto g = in_ref.outbound(X, Y1a, 0);
    PF_CHECK(in_ref.inbound(Y1a, g->port, 20000).status == Nat::InboundStatus::Deliver);
    PF_CHECK(in_ref.inbound(Y1a, g->port, 49999).status == Nat::InboundStatus::Deliver);   // refreshed at 20000
    PF_CHECK(in_ref.inbound(Y1a, g->port, 79999 + 1).status == Nat::InboundStatus::NoMapping);
    // a filtered packet never refreshes
    const auto h = in_ref.outbound(X, Y1a, 200000);
    PF_CHECK(in_ref.inbound(Y2a, h->port, 220000).status == Nat::InboundStatus::Filtered);
    PF_CHECK(in_ref.inbound(Y1a, h->port, 230000).status == Nat::InboundStatus::NoMapping);

    // permissions die with the mapping: after expiry, a new mapping knows only its new destination
    NatConfig sym = NatConfig::port_restricted_cone();
    sym.mapping_timeout_ms = 10;
    sym.ports = PortAllocation::Sequential;
    Nat n2(kExt, sym);
    const auto a = n2.outbound(X, Y1a, 0);
    const auto b = n2.outbound(X, Y2a, 50);                                    // new mapping, maybe a new port
    PF_CHECK(a->port != b->port);
    PF_CHECK(n2.inbound(Y1a, b->port, 50).status == Nat::InboundStatus::Filtered);
    PF_CHECK(!n2.lookup(X, Y1a).has_value() || n2.lookup(X, Y1a)->port == b->port);
}

PF_TEST(nat_lookup_does_not_create_or_refresh) {
    NatConfig c = NatConfig::symmetric();
    c.mapping_timeout_ms = 100;
    Nat nat(kExt, c);
    PF_CHECK(!nat.lookup(X, Y1a).has_value());
    PF_CHECK_EQ(nat.mapping_count(), size_t{0});
    const auto e = nat.outbound(X, Y1a, 0);
    PF_CHECK(*nat.lookup(X, Y1a) == *e);
    PF_CHECK(!nat.lookup(X, Y1b).has_value());
    nat.expire(100);
    PF_CHECK(!nat.lookup(X, Y1a).has_value());
}

// Random sequences on random configurations, checked against an oracle that only uses what it OBSERVED (the external
// endpoints returned) and the RFC 4787 definitions: port uniqueness, mapping reuse rules, filter decisions, expiry.
PF_TEST(nat_random_sequences_match_the_rfc4787_oracle) {
    std::mt19937 rng(4787);
    const Endpoint internals[] = {X, X2, {ipv4(10, 0, 0, 4), 6000}};
    const Endpoint remotes[] = {Y1a, Y1b, Y2a, {ipv4(198, 51, 100, 2), 3479}, {ipv4(192, 0, 2, 7), 9}};
    size_t delivered = 0, filtered = 0, nomap = 0, expired_seen = 0;
    for (int round = 0; round < 300; ++round) {
        NatConfig c;
        c.mapping = kMappings[rng() % 3];
        c.filtering = kFilterings[rng() % 3];
        c.ports = static_cast<PortAllocation>(rng() % 3);
        c.mapping_timeout_ms = 50 + rng() % 200;
        c.inbound_refresh = rng() & 1;
        c.port_min = 30000;
        c.port_max = static_cast<uint16_t>(30000 + 40 + rng() % 40);
        c.seed = static_cast<uint32_t>(rng());
        Nat nat(kExt, c);
        // oracle state per observed external port
        struct Obs { Endpoint internal; std::vector<Endpoint> remotes; uint64_t last; std::set<std::pair<Endpoint, Endpoint>> flows; };
        std::map<uint16_t, Obs> live;
        uint64_t now = 0;
        auto expire_oracle = [&]() {
            for (auto it = live.begin(); it != live.end();) {
                if (now - it->second.last >= c.mapping_timeout_ms) { it = live.erase(it); ++expired_seen; }
                else ++it;
            }
        };
        auto same_mapping = [&](const Endpoint& d1, const Endpoint& d2) {
            switch (c.mapping) {
                case MappingBehavior::EndpointIndependent: return true;
                case MappingBehavior::AddressDependent: return d1.ip == d2.ip;
                case MappingBehavior::AddressAndPortDependent: return d1 == d2;
            }
            return false;
        };
        for (int step = 0; step < 120; ++step) {
            now += rng() % 40;
            expire_oracle();
            const Endpoint& in = internals[rng() % 3];
            const Endpoint& rem = remotes[rng() % 5];
            if (rng() % 3) {                                                     // outbound
                // which live mapping (if any) must be reused
                std::optional<uint16_t> expected;
                for (const auto& [port, o] : live)
                    if (o.internal == in)
                        for (const auto& [i2, d2] : o.flows)
                            if (i2 == in && same_mapping(d2, rem)) expected = port;
                const auto e = nat.outbound(in, rem, now);
                if (!e) {                                                         // only when every port is taken
                    PF_CHECK(!expected.has_value());
                    PF_CHECK_EQ(live.size(), size_t{c.port_max - c.port_min + 1u});
                    continue;
                }
                PF_CHECK(e->port >= c.port_min && e->port <= c.port_max);
                if (expected) PF_CHECK_EQ(e->port, *expected);
                else PF_CHECK(live.count(e->port) == 0);                          // a NEW mapping gets an unused port
                Obs& o = live[e->port];
                if (!expected) o = Obs{in, {}, now, {}};
                o.last = now;
                o.flows.insert({in, rem});
                if (std::find(o.remotes.begin(), o.remotes.end(), rem) == o.remotes.end()) o.remotes.push_back(rem);
            } else {                                                              // inbound to a known or random port
                uint16_t port = static_cast<uint16_t>(c.port_min + rng() % (c.port_max - c.port_min + 1u));
                if (!live.empty() && (rng() & 1)) {
                    auto it = live.begin();
                    std::advance(it, static_cast<long>(rng() % live.size()));
                    port = it->first;
                }
                const Nat::Inbound r = nat.inbound(rem, port, now);
                const auto o = live.find(port);
                if (o == live.end()) { PF_CHECK(r.status == Nat::InboundStatus::NoMapping); ++nomap; continue; }
                bool allowed = false;
                for (const auto& p : o->second.remotes)
                    allowed |= c.filtering == FilteringBehavior::EndpointIndependent ||
                               (c.filtering == FilteringBehavior::AddressDependent && p.ip == rem.ip) || p == rem;
                PF_CHECK((r.status == Nat::InboundStatus::Deliver) == allowed);
                if (allowed) {
                    PF_CHECK(r.internal == o->second.internal);
                    if (c.inbound_refresh) o->second.last = now;
                    ++delivered;
                } else {
                    PF_CHECK(r.status == Nat::InboundStatus::Filtered);
                    ++filtered;
                }
            }
            PF_CHECK_EQ(nat.mapping_count(), live.size());
        }
    }
    PF_CHECK(delivered > 500);
    PF_CHECK(filtered > 500);
    PF_CHECK(nomap > 200);
    PF_CHECK(expired_seen > 200);
}
