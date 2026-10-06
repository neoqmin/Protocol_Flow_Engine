// PM-2b N2: the simulated network (pf/nat_sim.h) - routing through NATs, hairpinning, carrier-grade (nested) NAT,
// latency, the Transport adapter - and REAL STUN (the N1 codec) through every RFC 4787 combination: what a STUN
// server observes, and which "other address/port" replies a client can receive (the RFC 5780 tests N3 will run).
#include <string>
#include <vector>

#include "pf/nat_sim.h"
#include "pf/stun.h"
#include "pf_test.h"

using namespace pf;
using namespace pf::natsim;

namespace {

const uint32_t kNatA = ipv4(203, 0, 113, 10);
const uint32_t kServer1 = ipv4(198, 51, 100, 1), kServer2 = ipv4(198, 51, 100, 2);

std::vector<uint8_t> bytes(const char* s) { return std::vector<uint8_t>(s, s + std::char_traits<char>::length(s)); }

Network::Drop send(Network& n, Network::HostId h, uint16_t port, const Endpoint& to, const char* msg) {
    const auto b = bytes(msg);
    return n.send(h, port, to, b.data(), b.size());
}
std::string text(const Network::Datagram& d) { return std::string(d.data.begin(), d.data.end()); }

stun::TransactionId tid(uint8_t k) {
    stun::TransactionId t{};
    for (size_t i = 0; i < t.size(); ++i) t[i] = static_cast<uint8_t>(k * 31 + i);
    return t;
}
stun::Address to_stun(const Endpoint& e) {
    stun::Address a;
    a.family = stun::Address::Family::V4;
    a.ip = {static_cast<uint8_t>(e.ip >> 24), static_cast<uint8_t>(e.ip >> 16), static_cast<uint8_t>(e.ip >> 8), static_cast<uint8_t>(e.ip)};
    a.port = e.port;
    return a;
}
Endpoint from_stun(const stun::Address& a) {
    return {ipv4(a.ip[0], a.ip[1], a.ip[2], a.ip[3]), a.port};
}

// Minimal STUN Binding responder for the test (the real server is N5): answers from (reply_host, reply_port), which
// may differ from where the request arrived - that is how RFC 5780 probes filtering ("CHANGE-REQUEST").
void serve_binding(Network& n, Network::HostId server, uint16_t port, Network::HostId reply_host, uint16_t reply_port) {
    while (auto d = n.receive(server, port)) {
        stun::Message req;
        PF_REQUIRE(stun::parse(d->data.data(), d->data.size(), req) == stun::ParseStatus::Ok);
        PF_REQUIRE(req.cls == stun::Class::Request && req.method == stun::kMethodBinding);
        stun::MessageBuilder resp(stun::kMethodBinding, stun::Class::Success, req.tid);
        resp.add_xor_address(stun::kAttrXorMappedAddress, to_stun(d->from)).add_fingerprint();
        PF_REQUIRE(resp.ok());
        n.send(reply_host, reply_port, d->from, resp.bytes().data(), resp.bytes().size());
    }
}

// Sends a Binding request from (client, cport) to `server_ep`; the response (if any reaches the client) gives the
// mapped address the server saw.
std::optional<Endpoint> binding(Network& n, Network::HostId client, uint16_t cport, const Endpoint& server_ep, Network::HostId server,
                                Network::HostId reply_host, uint16_t reply_port, uint8_t k) {
    stun::MessageBuilder req(stun::kMethodBinding, stun::Class::Request, tid(k));
    req.add_fingerprint();
    n.send(client, cport, server_ep, req.bytes().data(), req.bytes().size());
    serve_binding(n, server, server_ep.port, reply_host, reply_port);
    auto d = n.receive(client, cport);
    if (!d) return std::nullopt;
    stun::Message m;
    PF_REQUIRE(stun::parse(d->data.data(), d->data.size(), m) == stun::ParseStatus::Ok);
    PF_REQUIRE(m.tid == tid(k));
    stun::Address a;
    PF_REQUIRE(stun::decode_xor_address(*m.find(stun::kAttrXorMappedAddress), m.tid, a));
    return from_stun(a);
}

}  // namespace

PF_TEST(network_routes_through_nats_both_ways) {
    Network n;
    const auto natA = n.add_nat(kNatA, NatConfig::port_restricted_cone());
    const auto a = n.add_host(ipv4(10, 0, 0, 2), natA);
    const auto s = n.add_host(kServer1);
    PF_REQUIRE(n.bind(a, 5000) && n.bind(s, 3478));
    PF_CHECK(!n.bind(s, 3478));                                         // already bound
    PF_CHECK(send(n, a, 5000, {kServer1, 3478}, "hello") == Network::Drop::None);
    auto at_server = n.receive(s, 3478);
    PF_REQUIRE(at_server.has_value());
    PF_CHECK(at_server->from == (Endpoint{kNatA, 5000}));               // the server sees the NAT's mapping
    PF_CHECK_EQ(text(*at_server), std::string("hello"));
    PF_CHECK(send(n, s, 3478, at_server->from, "back") == Network::Drop::None);
    auto at_client = n.receive(a, 5000);
    PF_REQUIRE(at_client.has_value());
    PF_CHECK(at_client->from == (Endpoint{kServer1, 3478}));
    // unsolicited inbound: another server, an unmapped port, a private address from outside
    const auto s2 = n.add_host(kServer2);
    PF_CHECK(send(n, s2, 1, {kNatA, 5000}, "x") == Network::Drop::Filtered);
    PF_CHECK(send(n, s2, 1, {kNatA, 5001}, "x") == Network::Drop::NoMapping);
    PF_CHECK(send(n, s2, 1, {ipv4(10, 0, 0, 2), 5000}, "x") == Network::Drop::NoRoute);
    PF_CHECK(send(n, a, 5000, {kServer1, 9999}, "x") == Network::Drop::NotBound);
    PF_CHECK_EQ(n.dropped(Network::Drop::Filtered), uint64_t{1});
    PF_CHECK_EQ(n.dropped(Network::Drop::NoMapping), uint64_t{1});
    PF_CHECK_EQ(n.delivered(), uint64_t{2});
}

PF_TEST(network_same_realm_is_direct_and_hairpin_goes_through_the_nat) {
    Network n;
    NatConfig c = NatConfig::full_cone();
    const auto nat = n.add_nat(kNatA, c);
    const auto a = n.add_host(ipv4(10, 0, 0, 2), nat), b = n.add_host(ipv4(10, 0, 0, 3), nat);
    const auto s = n.add_host(kServer1);
    PF_REQUIRE(n.bind(a, 5000) && n.bind(b, 6000) && n.bind(s, 1));
    PF_CHECK(send(n, a, 5000, {ipv4(10, 0, 0, 3), 6000}, "lan") == Network::Drop::None);
    PF_CHECK(n.receive(b, 6000)->from == (Endpoint{ipv4(10, 0, 0, 2), 5000}));   // LAN: private source, no NAT state
    PF_CHECK_EQ(n.nat(nat).mapping_count(), size_t{0});
    // B gets a mapping by talking to the server; A reaches B through the NAT's external address (hairpin)
    send(n, b, 6000, {kServer1, 1}, "x");
    PF_CHECK(send(n, a, 5000, {kNatA, 6000}, "hairpin") == Network::Drop::None);
    auto d = n.receive(b, 6000);
    PF_REQUIRE(d.has_value());
    PF_CHECK(d->from == (Endpoint{kNatA, 5000}));                      // RFC 4787 6: the sender's EXTERNAL endpoint
    PF_CHECK_EQ(text(*d), std::string("hairpin"));
    // without hairpin support
    Network n2;
    c.hairpin = false;
    const auto nat2 = n2.add_nat(kNatA, c);
    const auto a2 = n2.add_host(ipv4(10, 0, 0, 2), nat2), b2 = n2.add_host(ipv4(10, 0, 0, 3), nat2);
    const auto s2 = n2.add_host(kServer1);
    PF_REQUIRE(n2.bind(b2, 6000) && n2.bind(s2, 1));
    send(n2, b2, 6000, {kServer1, 1}, "x");
    PF_CHECK(send(n2, a2, 5000, {kNatA, 6000}, "hairpin") == Network::Drop::HairpinDisabled);
}

PF_TEST(network_carrier_grade_nat_nests) {
    // home NAT (192.168.1.1 external, inside the CGN's 100.64/10 realm) behind a CGN with public 203.0.113.99
    Network n;
    const auto cgn = n.add_nat(ipv4(203, 0, 113, 99), NatConfig::symmetric());
    const auto home = n.add_nat(ipv4(100, 64, 0, 5), NatConfig::port_restricted_cone(), cgn);
    const auto pc = n.add_host(ipv4(192, 168, 1, 10), home);
    const auto s = n.add_host(kServer1);
    PF_REQUIRE(n.bind(pc, 4000) && n.bind(s, 3478));
    PF_CHECK(send(n, pc, 4000, {kServer1, 3478}, "via two NATs") == Network::Drop::None);
    auto d = n.receive(s, 3478);
    PF_REQUIRE(d.has_value());
    PF_CHECK_EQ(d->from.ip, ipv4(203, 0, 113, 99));                   // the server sees only the CGN
    PF_CHECK(send(n, s, 3478, d->from, "reply") == Network::Drop::None);
    PF_CHECK(n.receive(pc, 4000).has_value());
    PF_CHECK_EQ(n.nat(home).mapping_count(), size_t{1});
    PF_CHECK_EQ(n.nat(cgn).mapping_count(), size_t{1});
}

PF_TEST(network_latency_and_clock) {
    Network n;
    n.set_latency_ms(25);
    const auto a = n.add_host(kServer1), b = n.add_host(kServer2);
    PF_REQUIRE(n.bind(b, 7));
    n.set_now(1000);
    send(n, a, 1, {kServer2, 7}, "late");
    PF_CHECK(!n.receive(b, 7).has_value());
    PF_CHECK(n.next_delivery(b, 7) == std::optional<uint64_t>(1025));
    n.set_now(1024);
    PF_CHECK(!n.receive(b, 7).has_value());
    n.set_now(1025);
    PF_CHECK(n.receive(b, 7).has_value());
    n.set_now(10);                                                     // the clock never goes back
    PF_CHECK_EQ(n.now(), uint64_t{1025});
    // mappings expire on the network clock
    NatConfig c = NatConfig::port_restricted_cone();
    c.mapping_timeout_ms = 30000;
    Network m;
    const auto nat = m.add_nat(kNatA, c);
    const auto h = m.add_host(ipv4(10, 0, 0, 2), nat), srv = m.add_host(kServer1);
    PF_REQUIRE(m.bind(h, 5000) && m.bind(srv, 1));
    send(m, h, 5000, {kServer1, 1}, "x");
    m.set_now(29999);
    PF_CHECK(send(m, srv, 1, {kNatA, 5000}, "in time") == Network::Drop::None);
    m.set_now(30000);
    PF_CHECK(send(m, srv, 1, {kNatA, 5000}, "too late") == Network::Drop::NoMapping);
}

PF_TEST(network_transport_is_a_connected_udp_socket) {
    Network n;
    const auto nat = n.add_nat(kNatA, NatConfig::port_restricted_cone());
    const auto c = n.add_host(ipv4(10, 0, 0, 2), nat), s = n.add_host(kServer1), other = n.add_host(kServer2);
    NetworkTransport client(n, c, 5000, {kServer1, 1194});
    PF_REQUIRE(client.bound() && client.is_open());
    PF_REQUIRE(n.bind(s, 1194));
    const uint8_t ping[3] = {1, 2, 3};
    PF_CHECK(client.send(ping, 3) == TransportStatus::Ok);
    auto at_server = n.receive(s, 1194);
    PF_REQUIRE(at_server.has_value());
    NetworkTransport server(n, s, 1195, at_server->from);              // reply socket "connected" to the client's mapping
    // the client is connected to :1194, so a reply from :1195 is not "the peer"
    PF_CHECK(server.send(ping, 3) == TransportStatus::Ok);
    PF_CHECK(server.last_drop() == Network::Drop::Filtered);           // and port-restricted filtering drops it anyway
    n.send(s, 1194, at_server->from, ping, 3);
    uint8_t buf[16];
    RecvResult r = client.recv(buf, sizeof buf);
    PF_CHECK(r.status == TransportStatus::Ok && r.len == 3);
    PF_CHECK(client.recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
    // a packet from someone else that passes the NAT (the client contacted them) is still not delivered to recv()
    const uint8_t hi[2] = {9, 9};
    n.send(c, 5000, {kServer2, 1}, hi, 2);
    PF_REQUIRE(n.bind(other, 1));
    n.send(c, 5000, {kServer2, 1}, hi, 2);
    n.receive(other, 1);
    n.send(other, 1, at_server->from, hi, 2);
    PF_CHECK(client.recv(buf, sizeof buf).status == TransportStatus::WouldBlock);
    PF_CHECK_EQ(client.foreign_discarded(), uint64_t{1});
    // too large, closed
    std::vector<uint8_t> big(2000, 0);
    PF_CHECK(client.send(big.data(), big.size()) == TransportStatus::TooLarge);
    n.send(s, 1194, at_server->from, big.data(), 20);
    PF_CHECK(client.recv(buf, 4).status == TransportStatus::TooLarge);
    client.close();
    PF_CHECK(client.send(ping, 3) == TransportStatus::Closed);
    PF_CHECK(client.recv(buf, sizeof buf).status == TransportStatus::Closed);
    NetworkTransport again(n, c, 5000, {kServer1, 1194});              // the port was released
    PF_CHECK(again.bound());
    NetworkTransport clash(n, c, 5000, {kServer1, 1194});
    PF_CHECK(!clash.bound());
    PF_CHECK(!clash.is_open());
}

// STUN through all nine RFC 4787 combinations. A STUN server with two addresses and two ports (like RFC 5780) sees:
//   EIM  -> one mapped address for every server address/port        ADM -> one per server ADDRESS     APDM -> one each
// and a reply that comes from a different address/port reaches the client only if the filtering allows it.
PF_TEST(stun_binding_through_every_nat_combination) {
    const MappingBehavior maps[] = {MappingBehavior::EndpointIndependent, MappingBehavior::AddressDependent,
                                    MappingBehavior::AddressAndPortDependent};
    const FilteringBehavior filts[] = {FilteringBehavior::EndpointIndependent, FilteringBehavior::AddressDependent,
                                       FilteringBehavior::AddressAndPortDependent};
    for (const auto m : maps)
        for (const auto f : filts) {
            Network n;
            NatConfig c;
            c.mapping = m;
            c.filtering = f;
            c.ports = PortAllocation::Sequential;
            const auto nat = n.add_nat(kNatA, c);
            const auto cl = n.add_host(ipv4(10, 0, 0, 2), nat);
            const auto s1 = n.add_host(kServer1), s2 = n.add_host(kServer2);
            PF_REQUIRE(n.bind(cl, 5000) && n.bind(s1, 3478) && n.bind(s1, 3479) && n.bind(s2, 3478));
            const auto a = binding(n, cl, 5000, {kServer1, 3478}, s1, s1, 3478, 1);
            const auto b = binding(n, cl, 5000, {kServer1, 3479}, s1, s1, 3479, 2);
            const auto d = binding(n, cl, 5000, {kServer2, 3478}, s2, s2, 3478, 3);
            PF_REQUIRE(a && b && d);
            PF_CHECK_EQ(a->ip, kNatA);
            // the mapped address IS the NAT's mapping for that flow
            PF_CHECK(*a == *n.nat(nat).lookup({ipv4(10, 0, 0, 2), 5000}, {kServer1, 3478}));
            const bool same_port_ok = *a == *b, same_addr_ok = *a == *d;
            PF_CHECK(same_addr_ok == (m == MappingBehavior::EndpointIndependent));
            PF_CHECK(same_port_ok == (m != MappingBehavior::AddressAndPortDependent));

            // filtering probes (fresh mapping each, all from a never-contacted source): reply from another port of
            // the same server address, and from the other server address
            NatConfig cf = c;
            Network p;
            const auto pnat = p.add_nat(kNatA, cf);
            const auto pc = p.add_host(ipv4(10, 0, 0, 2), pnat);
            const auto ps1 = p.add_host(kServer1), ps2 = p.add_host(kServer2);
            PF_REQUIRE(p.bind(pc, 5000) && p.bind(ps1, 3478) && p.bind(ps1, 3479) && p.bind(ps2, 3478));
            const bool other_port = binding(p, pc, 5000, {kServer1, 3478}, ps1, ps1, 3479, 4).has_value();
            const bool other_addr = binding(p, pc, 5000, {kServer1, 3478}, ps1, ps2, 3478, 5).has_value();
            PF_CHECK(other_port == (f != FilteringBehavior::AddressAndPortDependent));
            PF_CHECK(other_addr == (f == FilteringBehavior::EndpointIndependent));
            PF_CHECK(binding(p, pc, 5000, {kServer1, 3478}, ps1, ps1, 3478, 6).has_value());   // same endpoint: always
        }
}
