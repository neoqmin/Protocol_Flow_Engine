// Many ControlClients <-> one ServerCore over an in-memory "UDP network" with addresses (PM-11 V2). Needs OpenSSL.
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "pf/server_core.h"
#include "server_rig.h"

namespace pf_test {

inline NetAddress addr(uint8_t host, uint16_t port, uint8_t net = 1) { return NetAddress::v4((uint32_t{198} << 24) | (uint32_t{51} << 16) | (uint32_t{net} << 8) | host, port); }

inline ServerCoreConfig core_cfg() {
    ServerCoreConfig c;
    c.session = control_server_cfg();
    c.prepare_push = [](uint32_t peer_id, ServerPush& p) {
        p.ifconfig_ip = 0x0A080002 + peer_id;                  // 10.8.0.2 + peer-id (V3 brings the real pool)
        p.ifconfig_netmask = 0xFFFFFF00;
        p.route_gateway = 0x0A080001;
        return peer_id < 250;
    };
    return c;
}

inline ControlClientConfig distinct_client(uint32_t seed) {
    ControlClientConfig c = client_cfg(nullptr);
    uint32_t ctr = seed * 7919u;
    c.random = [ctr](uint8_t* p, size_t n) mutable { for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>((++ctr * 2654435761u) >> 24); };
    return c;
}

struct CoreNet {
    struct Client {
        NetAddress address;
        std::unique_ptr<KeyStore> keys = std::make_unique<KeyStore>();
        std::unique_ptr<ControlClient> client;
        bool online = true;                                    // false: its packets are not sent/received
    };
    ServerCore& core;
    std::vector<Client> clients;
    uint64_t now = 1000;
    uint32_t unix_s = 1790000000;
    std::function<int(bool to_server, size_t index)> fate = [](bool, size_t) { return 1; };
    size_t idx = 0;
    std::vector<ServerCore::Received> received;                 // every routing decision, in order

    explicit CoreNet(ServerCore& c) : core(c) {}

    size_t add(ControlClientConfig cc, const NetAddress& a, bool start = true) {
        Client c;
        c.address = a;
        cc.keys = c.keys.get();
        std::string err;
        c.client = ControlClient::create(std::move(cc), err);
        PF_REQUIRE(c.client != nullptr);
        if (start) c.client->start(now, unix_s);
        clients.push_back(std::move(c));
        return clients.size() - 1;
    }
    void deliver(const std::vector<ServerCore::Outgoing>& out) {
        for (const auto& o : out)
            for (auto& c : clients)
                if (c.online && c.address == o.to && fate(false, idx++) > 0) c.client->on_datagram(o.bytes.data(), o.bytes.size(), now, unix_s);
    }
    void send_raw(const std::vector<uint8_t>& d, const NetAddress& from) {
        std::vector<ServerCore::Outgoing> out;
        received.push_back(core.on_datagram(d.data(), d.size(), from, now, unix_s, out));
        deliver(out);
    }
    void step() {
        for (auto& c : clients) {
            if (!c.online) continue;
            for (auto& d : c.client->poll(now, unix_s)) {
                const int copies = fate(true, idx++);
                for (int k = 0; k < copies; ++k) send_raw(d, c.address);
            }
        }
        deliver(core.poll(now, unix_s));
    }
    void run(uint64_t ms, uint64_t step_ms = 100) {
        const uint64_t end = now + ms;
        while (now < end) { step(); now += step_ms; }
    }
    template <typename Pred> bool run_until(Pred pred, uint64_t budget_ms, uint64_t step_ms = 100) {
        for (uint64_t t = 0; t < budget_ms; t += step_ms) {
            if (pred()) return true;
            run(step_ms, step_ms);
        }
        return pred();
    }
    bool all_established() const {
        for (const auto& c : clients) if (c.client->state() != ControlClient::State::Established) return false;
        return true;
    }
};

inline std::unique_ptr<ServerCore> make_core(ServerCoreConfig cfg, DeterministicRandom& r) {
    cfg.random = &r;
    std::string err;
    auto c = ServerCore::create(std::move(cfg), err);
    PF_REQUIRE(c != nullptr);
    return c;
}

}  // namespace pf_test
