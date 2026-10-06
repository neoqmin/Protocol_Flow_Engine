// Test lab: a STUN client behind simulated NATs (pf/nat_sim.h) and an RFC 5780 responder (pf/stun_responder.h) on two
// public addresses x two ports. Delivers datagrams and advances the network clock to the next deadline.
#pragma once
#include <array>
#include <optional>
#include <vector>

#include "pf/nat_sim.h"
#include "pf/stun_client.h"
#include "pf/stun_responder.h"
#include "pf_test.h"

namespace pf_test {

inline pf::stun::Address to_stun(const pf::natsim::Endpoint& e) {
    pf::stun::Address a;
    a.family = pf::stun::Address::Family::V4;
    a.ip = {static_cast<uint8_t>(e.ip >> 24), static_cast<uint8_t>(e.ip >> 16), static_cast<uint8_t>(e.ip >> 8), static_cast<uint8_t>(e.ip)};
    a.port = e.port;
    return a;
}
inline pf::natsim::Endpoint from_stun(const pf::stun::Address& a) {
    return {pf::natsim::ipv4(a.ip[0], a.ip[1], a.ip[2], a.ip[3]), a.port};
}
inline uint32_t from_stun_ip(const pf::stun::Address& a) { return from_stun(a).ip; }

struct StunLab {
    static constexpr uint32_t kIp1 = pf::natsim::ipv4(198, 51, 100, 1);
    static constexpr uint32_t kIp2 = pf::natsim::ipv4(198, 51, 100, 2);
    static constexpr uint16_t kP1 = 3478, kP2 = 3479;
    pf::natsim::Network net;
    pf::natsim::Network::HostId client = 0, s1 = 0, s2 = 0;
    uint16_t client_port = 5000;
    pf::natsim::Endpoint client_local{};
    bool servers = true, rfc5780 = true;
    bool honour_change = true;          // false: a broken server that ignores CHANGE-REQUEST (answers from where it got it)
    uint64_t server_requests = 0;

    // nats: outermost first (e.g. {cgn, home}); empty = client on the public internet
    explicit StunLab(const std::vector<pf::natsim::NatConfig>& nats, bool with_servers = true, bool with_rfc5780 = true)
        : servers(with_servers), rfc5780(with_rfc5780) {
        using namespace pf::natsim;
        Network::NatId realm = Network::kPublic;
        uint32_t ext = ipv4(203, 0, 113, 1);
        for (const auto& c : nats) {
            realm = net.add_nat(ext, c, realm);
            ext = ipv4(100, 64, 0, static_cast<uint8_t>(realm + 1));            // the next NAT's external address
        }
        client_local = {realm == Network::kPublic ? ipv4(192, 0, 2, 50) : ipv4(10, 0, 0, 2), client_port};
        client = net.add_host(client_local.ip, realm);
        PF_REQUIRE(net.bind(client, client_port));
        if (servers) {
            s1 = net.add_host(kIp1);
            s2 = net.add_host(kIp2);
            for (auto h : {s1, s2}) for (uint16_t p : {kP1, kP2}) PF_REQUIRE(net.bind(h, p));
        }
    }
    pf::stun::Address server_address() const { return to_stun({kIp1, kP1}); }

    void send_all(const std::vector<pf::stun::Outgoing>& out) {
        for (const auto& o : out) net.send(client, client_port, from_stun(o.to), o.bytes.data(), o.bytes.size());
    }
    void pump_servers() {
        if (!servers) return;
        pf::stun::ResponderAddresses addrs;
        addrs.primary = to_stun({kIp1, kP1});
        if (rfc5780) addrs.alternate = to_stun({kIp2, kP2});
        for (auto h : {s1, s2})
            for (uint16_t p : {kP1, kP2})
                while (auto d = net.receive(h, p)) {
                    ++server_requests;
                    const pf::natsim::Endpoint local{net.host_ip(h), p};
                    auto r = pf::stun::respond_to_binding(d->data.data(), d->data.size(), to_stun(d->from), to_stun(local), addrs, "pf-test");
                    if (!r) continue;
                    if (!honour_change) r->from = to_stun(local);
                    const pf::natsim::Endpoint from = from_stun(r->from);
                    net.send(from.ip == kIp1 ? s1 : s2, from.port, from_stun(r->to), r->bytes.data(), r->bytes.size());
                }
    }
    // Runs any client object with start/on_datagram/poll/next_deadline_ms/done until done (or the guard trips).
    template <typename C, typename OnDatagram>
    void run(C& c, OnDatagram deliver) {
        send_all(c.start(net.now()));
        for (int guard = 0; guard < 100000 && !c.done(); ++guard) {
            pump_servers();
            bool got = false;
            while (auto d = net.receive(client, client_port)) {
                got = true;
                send_all(deliver(*d));
            }
            if (c.done()) break;
            if (got) continue;
            const auto next = c.next_deadline_ms();
            PF_REQUIRE(next.has_value());
            net.set_now(*next);
            send_all(c.poll(net.now()));
        }
        PF_REQUIRE(c.done());
    }
    void run(pf::stun::NatDiscovery& d) {
        run(d, [&](const pf::natsim::Network::Datagram& dg) {
            std::vector<pf::stun::Outgoing> out;
            d.on_datagram(dg.data.data(), dg.data.size(), to_stun(dg.from), net.now(), out);
            return out;
        });
    }
    void run(pf::stun::BindingClient& b) {
        run(b, [&](const pf::natsim::Network::Datagram& dg) {
            b.on_datagram(dg.data.data(), dg.data.size(), to_stun(dg.from), net.now());
            return std::vector<pf::stun::Outgoing>{};
        });
    }
};

}  // namespace pf_test
