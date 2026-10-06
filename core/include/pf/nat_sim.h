#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pf/nat_behavior.h"
#include "pf/transport.h"

namespace pf::natsim {

// In-memory NAT simulator (PM-2b N2, D-046). Deterministic, sans-I/O, no sockets: tests, the hole-punching matrix (N6)
// and the NAT lab (N8) run real protocol code through it. Behaviour follows RFC 4787 (NAT UDP behavioural
// requirements) terms, not the old "cone" names (those are only presets):
//
//   mapping    which outbound flows share one external port      (RFC 4787 4.1)
//              EndpointIndependent | AddressDependent | AddressAndPortDependent
//   filtering  which inbound packets a mapping lets through       (RFC 4787 5)
//              EndpointIndependent | AddressDependent | AddressAndPortDependent
//   ports      how an external port is chosen                     (RFC 4787 4.2): Preserve | Sequential | Random
//   timeout    a mapping (and its filter permissions) expires after `mapping_timeout_ms` without an outbound packet,
//              or any packet when inbound_refresh is set           (RFC 4787 4.3)
//   hairpin    an internal host may reach another one through the NAT's own external address; the packet arrives
//              with the sender's EXTERNAL endpoint as source       (RFC 4787 6)
//
// IPv4 UDP only. No port overloading: an external port belongs to exactly one mapping (RFC 4787 4.2.1 rules
// port overloading out).

struct Endpoint {
    uint32_t ip = 0;          // host byte order: 10.0.0.1 = 0x0A000001
    uint16_t port = 0;
    bool operator==(const Endpoint& o) const { return ip == o.ip && port == o.port; }
    bool operator!=(const Endpoint& o) const { return !(*this == o); }
    bool operator<(const Endpoint& o) const { return ip != o.ip ? ip < o.ip : port < o.port; }
    std::string to_string() const;            // "10.0.0.1:5000"
};
constexpr uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t{a} << 24) | (uint32_t{b} << 16) | (uint32_t{c} << 8) | uint32_t{d};
}
std::string ip_to_string(uint32_t ip);

using MappingBehavior = NatMapping;               // pf/nat_behavior.h (shared with STUN discovery)
using FilteringBehavior = NatFiltering;
enum class PortAllocation : uint8_t { Preserve, Sequential, Random };
const char* behavior_name(MappingBehavior m);
const char* behavior_name(FilteringBehavior f);

struct NatConfig {
    MappingBehavior mapping = MappingBehavior::EndpointIndependent;
    FilteringBehavior filtering = FilteringBehavior::AddressAndPortDependent;
    PortAllocation ports = PortAllocation::Preserve;
    uint16_t port_min = 1024, port_max = 65535;   // external port range (inclusive)
    uint64_t mapping_timeout_ms = 120000;         // RFC 4787 4.3: >= 2 min for real NATs; anything goes here
    bool inbound_refresh = false;                 // RFC 4787 4.3: outbound always refreshes, inbound MAY
    bool hairpin = true;                          // RFC 4787 6 requires it; false models NATs that do not
    uint32_t seed = 1;                            // PortAllocation::Random

    // The classic names (RFC 3489), as presets of the RFC 4787 behaviours.
    static NatConfig full_cone();                 // EIM + EIF
    static NatConfig restricted_cone();           // EIM + ADF
    static NatConfig port_restricted_cone();      // EIM + APDF (what Linux netfilter masquerade usually behaves like)
    static NatConfig symmetric();                 // APDM + APDF
};

// One NAT device with one external address.
class Nat {
public:
    Nat(uint32_t external_ip, NatConfig cfg);

    // Outbound packet from internal `src` to external `dst` at `now`: the external source endpoint (creating or
    // refreshing the mapping and recording the filter permission), or nullopt when no external port is free.
    std::optional<Endpoint> outbound(const Endpoint& src, const Endpoint& dst, uint64_t now);

    enum class InboundStatus { Deliver, NoMapping, Filtered };
    struct Inbound {
        InboundStatus status = InboundStatus::NoMapping;
        Endpoint internal;                        // valid for Deliver
    };
    // Inbound packet from external `src` to our external `port` at `now`.
    Inbound inbound(const Endpoint& src, uint16_t port, uint64_t now);

    // Removes mappings idle for >= the timeout (also done lazily by outbound/inbound).
    void expire(uint64_t now);
    size_t mapping_count() const { return mappings_.size(); }
    // The external endpoint mapped for (internal src -> dst), if any. Does not create, refresh or expire: a mapping past
    // its timeout is removed by the next outbound/inbound/expire() call.
    std::optional<Endpoint> lookup(const Endpoint& src, const Endpoint& dst) const;

    uint32_t external_ip() const { return ip_; }
    const NatConfig& config() const { return cfg_; }

private:
    struct Key {                                  // what identifies a mapping, per the mapping behaviour
        Endpoint internal;
        Endpoint remote;                          // EIM: zero; ADM: ip only; APDM: ip and port
        bool operator<(const Key& o) const { return internal != o.internal ? internal < o.internal : remote < o.remote; }
    };
    struct Mapping {
        Key key;
        uint16_t port = 0;
        uint64_t last_used = 0;
        std::vector<Endpoint> permitted;          // remote endpoints contacted through this mapping
    };
    Key key_for(const Endpoint& src, const Endpoint& dst) const;
    std::optional<uint16_t> allocate(uint16_t wanted);
    bool permits(const Mapping& m, const Endpoint& remote) const;
    bool expired(const Mapping& m, uint64_t now) const { return now >= m.last_used && now - m.last_used >= cfg_.mapping_timeout_ms; }

    uint32_t ip_;
    NatConfig cfg_;
    std::map<Key, Mapping> mappings_;
    std::map<uint16_t, Key> by_port_;
    uint32_t next_port_;
    uint64_t rng_;
};

// A simulated internet of realms: the public realm, and the private realm behind each NAT. A NAT's external interface
// lives in a realm too (the public one, or another NAT's private realm: carrier-grade NAT, RFC 6888), so NATs nest.
// Routing from a realm: an address owned in the same realm is delivered directly; otherwise the packet leaves through
// the realm's NAT (outbound translation) into the parent realm and routing continues there. A packet that arrives at a
// NAT's external address goes inbound through it. Hairpinning falls out of this: a host sends to its own NAT's
// external address, leaves through the NAT, and comes straight back in.
//
// The path (and every NAT decision on it) is evaluated when the packet is sent; it is delivered `latency_ms` later.
class Network {
public:
    using HostId = size_t;
    using NatId = size_t;
    static constexpr NatId kPublic = static_cast<NatId>(-1);   // "the public realm" as a parent

    // A NAT whose private realm hosts can be added to, with its external address in realm `parent`.
    NatId add_nat(uint32_t external_ip, NatConfig cfg, NatId parent = kPublic);
    // A host with address `ip` in realm `realm` (kPublic or a NAT's private realm). Addresses are unique per realm.
    HostId add_host(uint32_t ip, NatId realm = kPublic);

    void set_latency_ms(uint64_t ms) { latency_ = ms; }
    // The simulation clock (monotonic). Delivery and NAT timeouts use it.
    void set_now(uint64_t ms) { if (ms > now_) now_ = ms; }
    uint64_t now() const { return now_; }

    bool bind(HostId h, uint16_t port);           // false if already bound
    void unbind(HostId h, uint16_t port);

    enum class Drop { None, NoRoute, PortsExhausted, NoMapping, Filtered, HairpinDisabled, NotBound, LoopDetected };
    struct Datagram {
        Endpoint from;                            // the source as the receiver sees it (after NATs)
        uint16_t to_port = 0;
        std::vector<uint8_t> data;
        uint64_t deliver_at = 0;
    };
    // Sends from host `h` port `src_port` (need not be bound) to `dst`. Returns why it was dropped, or None.
    Drop send(HostId h, uint16_t src_port, const Endpoint& dst, const uint8_t* data, size_t len);
    // Oldest datagram for (h, port) whose delivery time has come, if any.
    std::optional<Datagram> receive(HostId h, uint16_t port);
    // Earliest pending delivery time for (h, port).
    std::optional<uint64_t> next_delivery(HostId h, uint16_t port) const;

    Nat& nat(NatId n) { return *nats_[n].nat; }
    uint32_t host_ip(HostId h) const { return hosts_[h].ip; }
    uint64_t delivered() const { return delivered_; }
    uint64_t dropped(Drop why) const;

private:
    struct HostRec { uint32_t ip; NatId realm; };
    struct NatRec { std::unique_ptr<Nat> nat; NatId parent; };
    std::optional<HostId> host_at(NatId realm, uint32_t ip) const;
    std::optional<NatId> nat_at(NatId realm, uint32_t ip) const;
    Drop route(NatId realm, Endpoint src, const Endpoint& dst, std::vector<uint8_t>&& data, int depth, std::optional<NatId> came_out_of);

    std::vector<HostRec> hosts_;
    std::vector<NatRec> nats_;
    std::map<std::pair<HostId, uint16_t>, std::deque<Datagram>> inbox_;
    uint64_t now_ = 0, latency_ = 0, delivered_ = 0;
    std::map<Drop, uint64_t> dropped_;
};
const char* drop_name(Network::Drop d);

// A connected UDP Transport over the simulated network (like platform/linux UdpTransport): sends to `peer`, receives
// only from `peer` (others are discarded, counted), uses the network's clock. Lets unchanged protocol code (control
// client, STUN machines, TURN) run through simulated NATs.
class NetworkTransport : public Transport {
public:
    NetworkTransport(Network& net, Network::HostId host, uint16_t local_port, Endpoint peer, size_t max_packet = 1500);
    ~NetworkTransport() override;
    TransportKind kind() const override { return TransportKind::Udp; }
    TransportStatus send(const uint8_t* data, size_t len) override;
    RecvResult recv(uint8_t* buf, size_t cap) override;
    bool is_open() const override { return open_; }
    void close() override;
    size_t max_packet() const override { return max_packet_; }
    bool bound() const { return bound_; }
    Network::Drop last_drop() const { return last_drop_; }
    uint64_t foreign_discarded() const { return foreign_; }

private:
    Network& net_;
    Network::HostId host_;
    uint16_t port_;
    Endpoint peer_;
    size_t max_packet_;
    bool open_ = true, bound_ = false;
    Network::Drop last_drop_ = Network::Drop::None;
    uint64_t foreign_ = 0;
};

}  // namespace pf::natsim
