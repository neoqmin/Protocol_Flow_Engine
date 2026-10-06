#include "pf/nat_sim.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace pf::natsim {

std::string ip_to_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 0xFF) + "." + std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

std::string Endpoint::to_string() const { return ip_to_string(ip) + ":" + std::to_string(port); }

const char* behavior_name(MappingBehavior m) {
    switch (m) {
        case MappingBehavior::EndpointIndependent: return "EIM";
        case MappingBehavior::AddressDependent: return "ADM";
        case MappingBehavior::AddressAndPortDependent: return "APDM";
    }
    return "?";
}
const char* behavior_name(FilteringBehavior f) {
    switch (f) {
        case FilteringBehavior::EndpointIndependent: return "EIF";
        case FilteringBehavior::AddressDependent: return "ADF";
        case FilteringBehavior::AddressAndPortDependent: return "APDF";
    }
    return "?";
}

NatConfig NatConfig::full_cone() {
    NatConfig c;
    c.mapping = MappingBehavior::EndpointIndependent;
    c.filtering = FilteringBehavior::EndpointIndependent;
    return c;
}
NatConfig NatConfig::restricted_cone() {
    NatConfig c;
    c.mapping = MappingBehavior::EndpointIndependent;
    c.filtering = FilteringBehavior::AddressDependent;
    return c;
}
NatConfig NatConfig::port_restricted_cone() {
    NatConfig c;
    c.mapping = MappingBehavior::EndpointIndependent;
    c.filtering = FilteringBehavior::AddressAndPortDependent;
    return c;
}
NatConfig NatConfig::symmetric() {
    NatConfig c;
    c.mapping = MappingBehavior::AddressAndPortDependent;
    c.filtering = FilteringBehavior::AddressAndPortDependent;
    return c;
}

// ---- Nat ----------------------------------------------------------------------------------------------------------------

Nat::Nat(uint32_t external_ip, NatConfig cfg) : ip_(external_ip), cfg_(cfg), next_port_(cfg.port_min), rng_(cfg.seed ? cfg.seed : 1) {}

Nat::Key Nat::key_for(const Endpoint& src, const Endpoint& dst) const {
    switch (cfg_.mapping) {
        case MappingBehavior::EndpointIndependent: return {src, {}};
        case MappingBehavior::AddressDependent: return {src, {dst.ip, 0}};
        case MappingBehavior::AddressAndPortDependent: return {src, dst};
    }
    return {src, dst};
}

std::optional<uint16_t> Nat::allocate(uint16_t wanted) {
    if (cfg_.port_min > cfg_.port_max) return std::nullopt;
    const uint32_t lo = cfg_.port_min, hi = cfg_.port_max, span = hi - lo + 1;
    auto is_free = [&](uint32_t p) { return by_port_.find(static_cast<uint16_t>(p)) == by_port_.end(); };
    if (cfg_.ports == PortAllocation::Preserve && wanted >= lo && wanted <= hi && is_free(wanted)) return wanted;
    if (cfg_.ports == PortAllocation::Random) {
        for (int k = 0; k < 64; ++k) {
            rng_ ^= rng_ << 13;                       // xorshift64: deterministic per seed
            rng_ ^= rng_ >> 7;
            rng_ ^= rng_ << 17;
            const uint32_t p = lo + static_cast<uint32_t>(rng_ % span);
            if (is_free(p)) return static_cast<uint16_t>(p);
        }
    }
    for (uint32_t k = 0; k < span; ++k) {             // sequential (also the fallback of the other two)
        const uint32_t p = next_port_ < lo || next_port_ > hi ? lo : next_port_;
        next_port_ = p >= hi ? lo : p + 1;
        if (is_free(p)) return static_cast<uint16_t>(p);
    }
    return std::nullopt;
}

bool Nat::permits(const Mapping& m, const Endpoint& remote) const {
    switch (cfg_.filtering) {
        case FilteringBehavior::EndpointIndependent: return true;
        case FilteringBehavior::AddressDependent:
            return std::any_of(m.permitted.begin(), m.permitted.end(), [&](const Endpoint& e) { return e.ip == remote.ip; });
        case FilteringBehavior::AddressAndPortDependent:
            return std::find(m.permitted.begin(), m.permitted.end(), remote) != m.permitted.end();
    }
    return false;
}

void Nat::expire(uint64_t now) {
    for (auto it = mappings_.begin(); it != mappings_.end();) {
        if (expired(it->second, now)) {
            by_port_.erase(it->second.port);
            it = mappings_.erase(it);
        } else {
            ++it;
        }
    }
}

std::optional<Endpoint> Nat::outbound(const Endpoint& src, const Endpoint& dst, uint64_t now) {
    expire(now);
    const Key k = key_for(src, dst);
    auto it = mappings_.find(k);
    if (it == mappings_.end()) {
        const auto port = allocate(src.port);
        if (!port) return std::nullopt;
        Mapping m;
        m.key = k;
        m.port = *port;
        it = mappings_.emplace(k, m).first;
        by_port_.emplace(*port, k);
    }
    Mapping& m = it->second;
    m.last_used = now;
    if (std::find(m.permitted.begin(), m.permitted.end(), dst) == m.permitted.end()) m.permitted.push_back(dst);
    return Endpoint{ip_, m.port};
}

Nat::Inbound Nat::inbound(const Endpoint& src, uint16_t port, uint64_t now) {
    expire(now);
    Inbound r;
    const auto p = by_port_.find(port);
    if (p == by_port_.end()) return r;                // NoMapping
    Mapping& m = mappings_.at(p->second);
    if (!permits(m, src)) { r.status = InboundStatus::Filtered; return r; }
    if (cfg_.inbound_refresh) m.last_used = now;
    r.status = InboundStatus::Deliver;
    r.internal = m.key.internal;
    return r;
}

std::optional<Endpoint> Nat::lookup(const Endpoint& src, const Endpoint& dst) const {
    const auto it = mappings_.find(key_for(src, dst));
    if (it == mappings_.end()) return std::nullopt;
    return Endpoint{ip_, it->second.port};
}

// ---- Network ------------------------------------------------------------------------------------------------------------

const char* drop_name(Network::Drop d) {
    switch (d) {
        case Network::Drop::None: return "None";
        case Network::Drop::NoRoute: return "NoRoute";
        case Network::Drop::PortsExhausted: return "PortsExhausted";
        case Network::Drop::NoMapping: return "NoMapping";
        case Network::Drop::Filtered: return "Filtered";
        case Network::Drop::HairpinDisabled: return "HairpinDisabled";
        case Network::Drop::NotBound: return "NotBound";
        case Network::Drop::LoopDetected: return "LoopDetected";
    }
    return "?";
}

Network::NatId Network::add_nat(uint32_t external_ip, NatConfig cfg, NatId parent) {
    nats_.push_back({std::make_unique<Nat>(external_ip, cfg), parent});
    return nats_.size() - 1;
}

Network::HostId Network::add_host(uint32_t ip, NatId realm) {
    hosts_.push_back({ip, realm});
    return hosts_.size() - 1;
}

bool Network::bind(HostId h, uint16_t port) {
    if (h >= hosts_.size()) return false;
    return inbox_.emplace(std::make_pair(h, port), std::deque<Datagram>{}).second;
}

void Network::unbind(HostId h, uint16_t port) { inbox_.erase({h, port}); }

std::optional<Network::HostId> Network::host_at(NatId realm, uint32_t ip) const {
    for (size_t i = 0; i < hosts_.size(); ++i) if (hosts_[i].realm == realm && hosts_[i].ip == ip) return i;
    return std::nullopt;
}

std::optional<Network::NatId> Network::nat_at(NatId realm, uint32_t ip) const {
    for (size_t i = 0; i < nats_.size(); ++i) if (nats_[i].parent == realm && nats_[i].nat->external_ip() == ip) return i;
    return std::nullopt;
}

Network::Drop Network::route(NatId realm, Endpoint src, const Endpoint& dst, std::vector<uint8_t>&& data, int depth,
                             std::optional<NatId> came_out_of) {
    if (depth > 32) return Drop::LoopDetected;
    if (const auto h = host_at(realm, dst.ip)) {
        auto box = inbox_.find({*h, dst.port});
        if (box == inbox_.end()) return Drop::NotBound;
        box->second.push_back({src, dst.port, std::move(data), now_ + latency_});
        ++delivered_;
        return Drop::None;
    }
    if (const auto n = nat_at(realm, dst.ip)) {
        Nat& nat = *nats_[*n].nat;
        if (came_out_of == *n && !nat.config().hairpin) return Drop::HairpinDisabled;
        const Nat::Inbound in = nat.inbound(src, dst.port, now_);
        if (in.status == Nat::InboundStatus::NoMapping) return Drop::NoMapping;
        if (in.status == Nat::InboundStatus::Filtered) return Drop::Filtered;
        return route(*n, src, in.internal, std::move(data), depth + 1, std::nullopt);
    }
    if (realm == kPublic) return Drop::NoRoute;
    const auto ext = nats_[realm].nat->outbound(src, dst, now_);
    if (!ext) return Drop::PortsExhausted;
    return route(nats_[realm].parent, *ext, dst, std::move(data), depth + 1, realm);
}

Network::Drop Network::send(HostId h, uint16_t src_port, const Endpoint& dst, const uint8_t* data, size_t len) {
    if (h >= hosts_.size()) return Drop::NoRoute;
    std::vector<uint8_t> copy(data, data + len);
    const Drop d = route(hosts_[h].realm, {hosts_[h].ip, src_port}, dst, std::move(copy), 0, std::nullopt);
    if (d != Drop::None) ++dropped_[d];
    return d;
}

std::optional<Network::Datagram> Network::receive(HostId h, uint16_t port) {
    auto box = inbox_.find({h, port});
    if (box == inbox_.end() || box->second.empty() || box->second.front().deliver_at > now_) return std::nullopt;
    Datagram d = std::move(box->second.front());
    box->second.pop_front();
    return d;
}

std::optional<uint64_t> Network::next_delivery(HostId h, uint16_t port) const {
    auto box = inbox_.find({h, port});
    if (box == inbox_.end() || box->second.empty()) return std::nullopt;
    return box->second.front().deliver_at;
}

uint64_t Network::dropped(Drop why) const {
    const auto it = dropped_.find(why);
    return it == dropped_.end() ? 0 : it->second;
}

// ---- NetworkTransport ---------------------------------------------------------------------------------------------------

NetworkTransport::NetworkTransport(Network& net, Network::HostId host, uint16_t local_port, Endpoint peer, size_t max_packet)
    : net_(net), host_(host), port_(local_port), peer_(peer), max_packet_(max_packet) {
    bound_ = net_.bind(host_, port_);
    open_ = bound_;
}

NetworkTransport::~NetworkTransport() { close(); }

void NetworkTransport::close() {
    if (bound_) net_.unbind(host_, port_);
    bound_ = false;
    open_ = false;
}

TransportStatus NetworkTransport::send(const uint8_t* data, size_t len) {
    if (!open_) return TransportStatus::Closed;
    if (len > max_packet_) return TransportStatus::TooLarge;
    last_drop_ = net_.send(host_, port_, peer_, data, len);    // UDP: a loss on the path is silent to the sender
    return TransportStatus::Ok;
}

RecvResult NetworkTransport::recv(uint8_t* buf, size_t cap) {
    RecvResult r;
    if (!open_) { r.status = TransportStatus::Closed; return r; }
    while (auto d = net_.receive(host_, port_)) {
        if (d->from != peer_) { ++foreign_; continue; }        // a connected socket ignores everyone else
        if (d->data.size() > cap) { r.status = TransportStatus::TooLarge; return r; }
        if (!d->data.empty()) std::memcpy(buf, d->data.data(), d->data.size());
        r.status = TransportStatus::Ok;
        r.len = d->data.size();
        return r;
    }
    return r;                                                     // WouldBlock
}

}  // namespace pf::natsim
