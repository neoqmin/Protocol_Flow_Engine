// libFuzzer: arbitrary datagrams into the STUN client side (PM-2b N3): BindingClient, NatDiscovery and the Binding
// responder. Invariants: nothing faults; a client that finished stays finished with a consistent result; every reply
// the responder produces is itself a valid STUN message; time only moves forward.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "pf/stun_client.h"
#include "pf/stun_responder.h"

namespace {
pf::stun::Address addr(uint8_t last, uint16_t port) {
    pf::stun::Address a;
    a.ip = {198, 51, 100, last};
    a.port = port;
    return a;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace pf::stun;
    if (size < 2) return 0;
    pf::DeterministicRandom rnd(data[0]);
    BindingConfig cfg;
    cfg.server = addr(1, 3478);
    cfg.accept_any_source = data[1] & 1;
    auto c = BindingClient::create(cfg, rnd);
    DiscoveryConfig dc;
    dc.server = cfg.server;
    dc.probe_rto_ms = 50;
    auto d = NatDiscovery::create(dc, rnd);
    if (!c || !d) std::abort();
    uint64_t now = 0;
    c->start(now);
    d->start(now);
    // the rest: chunks of [len][source selector][bytes...]; a chunk with len 0 advances the clock instead
    size_t i = 2;
    const ResponderAddresses addrs{addr(1, 3478), addr(2, 3479)};
    while (i < size) {
        const size_t len = data[i++];
        if (len == 0 || i >= size) { now += 700; c->poll(now); d->poll(now); continue; }
        const uint8_t sel = data[i++];
        const size_t n = len < size - i ? len : size - i;
        const uint8_t* p = data + i;
        i += n;
        const Address from = addr(sel & 1 ? 2 : 1, sel & 2 ? 3479 : 3478);
        const bool was_done = c->done();
        const BindingResult before = c->result();
        c->on_datagram(p, n, from, now);
        if (was_done && (c->result().status != before.status || c->result().mapped != before.mapped)) std::abort();
        std::vector<Outgoing> out;
        d->on_datagram(p, n, from, now, out);
        if (auto r = respond_to_binding(p, n, from, addrs.primary, addrs)) {
            Message m;
            if (parse(r->bytes.data(), r->bytes.size(), m) != ParseStatus::Ok) std::abort();
            if (m.cls != Class::Success && m.cls != Class::Error) std::abort();
        }
    }
    if (c->result().status == BindingStatus::Succeeded && c->next_deadline_ms()) std::abort();
    return 0;
}
