// PM-2b N3: the STUN Binding transaction (BindingClient over the binding State Machine): RFC 8489 retransmission
// timing, response validation, error responses, injected randomness, trace, and the machine's golden file.
#include <fstream>
#include <set>
#include <sstream>
#include <string>

#include "pf/machine_json.h"
#include "pf/stun_client.h"
#include "pf_test.h"

using namespace pf;
using namespace pf::stun;

#ifndef GOLDEN_DIR
#define GOLDEN_DIR "tests/regression/golden"
#endif

namespace {

Address addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    Address x;
    x.family = Address::Family::V4;
    x.ip = {a, b, c, d};
    x.port = port;
    return x;
}
const Address kServer = addr(198, 51, 100, 1, 3478);
const Address kMapped = addr(203, 0, 113, 7, 40000);

BindingConfig to(const Address& server) {
    BindingConfig c;
    c.server = server;
    return c;
}

class FailingRandom final : public RandomSource {
public:
    bool fill(uint8_t*, size_t) override { return false; }
};

std::vector<uint8_t> success_for(const TransactionId& tid, const Address& mapped, uint16_t extra_required = 0) {
    MessageBuilder b(kMethodBinding, Class::Success, tid);
    b.add_xor_address(kAttrXorMappedAddress, mapped);
    if (extra_required) b.add(extra_required, nullptr, 0);
    b.add_fingerprint();
    PF_REQUIRE(b.ok());
    return b.bytes();
}

std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

PF_TEST(stun_binding_machine_is_valid_and_matches_its_golden_file) {
    const MachineDocument doc = binding_machine_document();
    const MachineValidation v = validate_machine(doc);
    for (const auto& i : v.issues) std::fprintf(stderr, "%s %s %s\n", i.code.c_str(), i.path.c_str(), i.message.c_str());
    PF_CHECK(v.ok());
    const std::string golden = slurp(std::string(GOLDEN_DIR) + "/machine_stun_binding.machine.json");
    PF_REQUIRE(!golden.empty());
    PF_CHECK_EQ(write_machine_json(doc), golden);
    PF_CHECK(load_machine_json(golden, {}).ok());
}

PF_TEST(stun_binding_retransmits_on_the_rfc_8489_schedule_then_fails) {
    DeterministicRandom rnd(1);
    auto c = BindingClient::create(to(kServer), rnd);
    PF_REQUIRE(c != nullptr);
    std::vector<uint64_t> sends;
    std::set<std::vector<uint8_t>> distinct;
    auto out = c->start(1000);
    for (const auto& o : out) { sends.push_back(1000); distinct.insert(o.bytes); PF_CHECK(o.to == kServer); }
    while (!c->done()) {
        const auto t = c->next_deadline_ms();
        PF_REQUIRE(t.has_value());
        PF_CHECK(c->poll(*t - 1).empty());                     // nothing fires early
        for (const auto& o : c->poll(*t)) { sends.push_back(*t); distinct.insert(o.bytes); }
    }
    // RFC 8489 6.2.1: RTO 500 ms, Rc = 7, Rm = 16 -> requests at 0, 500, 1500, 3500, 7500, 15500, 31500; fail at 39500
    const std::vector<uint64_t> want{1000, 1500, 2500, 4500, 8500, 16500, 32500};
    PF_CHECK(sends == want);
    PF_CHECK_EQ(distinct.size(), size_t{1});                    // every retransmission is the identical request
    PF_CHECK(c->result().status == BindingStatus::Failed);
    PF_CHECK(c->result().failure == BindingFailure::Timeout);
    PF_CHECK_EQ(c->result().requests_sent, 7);
    PF_CHECK(!c->next_deadline_ms().has_value());
    // the failure happened exactly Rm * RTO after the last request
    DeterministicRandom rnd2(1);
    auto d = BindingClient::create(to(kServer), rnd2);
    d->start(0);
    uint64_t t = 0;
    while (!d->done()) { t = *d->next_deadline_ms(); d->poll(t); }
    PF_CHECK_EQ(t, uint64_t{39500});
    // other RTO / Rm
    DeterministicRandom rnd3(1);
    BindingConfig fast = to(kServer);
    fast.rto_ms = 100;
    fast.rm = 4;
    auto e = BindingClient::create(fast, rnd3);
    e->start(0);
    while (!e->done()) { t = *e->next_deadline_ms(); e->poll(t); }
    PF_CHECK_EQ(t, uint64_t{100 + 200 + 400 + 800 + 1600 + 3200 + 400});
}

PF_TEST(stun_binding_accepts_the_matching_response) {
    DeterministicRandom rnd(2);
    auto c = BindingClient::create(to(kServer), rnd);
    PF_REQUIRE(c != nullptr);
    const auto first = c->start(0);
    PF_REQUIRE(first.size() == 1);
    Message req;
    PF_REQUIRE(parse(first[0].bytes.data(), first[0].bytes.size(), req) == ParseStatus::Ok);
    PF_CHECK(req.cls == Class::Request && req.method == kMethodBinding && req.fingerprint.has_value());
    PF_CHECK(req.tid == c->transaction_id());
    c->poll(500);
    c->poll(1500);                                               // two retransmissions, then the answer arrives
    const auto resp = success_for(c->transaction_id(), kMapped);
    PF_CHECK(c->on_datagram(resp.data(), resp.size(), kServer, 1600));
    PF_CHECK(c->done());
    PF_CHECK(c->result().status == BindingStatus::Succeeded);
    PF_CHECK(c->result().mapped == kMapped);
    PF_CHECK(c->result().responded_from == kServer);
    PF_CHECK_EQ(c->result().requests_sent, 3);
    PF_CHECK_EQ(c->result().rtt_ms, uint64_t{1600});
    PF_CHECK(!c->next_deadline_ms().has_value());
    PF_CHECK(c->on_datagram(resp.data(), resp.size(), kServer, 1700));   // a duplicate is ours but changes nothing
    PF_CHECK_EQ(c->discarded(), uint64_t{1});
    PF_CHECK(c->poll(100000).empty());
}

PF_TEST(stun_binding_ignores_or_discards_what_is_not_a_valid_answer) {
    DeterministicRandom rnd(3);
    auto c = BindingClient::create(to(kServer), rnd);
    PF_REQUIRE(c != nullptr);
    c->start(0);
    const TransactionId tid = c->transaction_id();
    TransactionId other = tid;
    other[0] ^= 1;
    const auto wrong_tid = success_for(other, kMapped);
    PF_CHECK(!c->on_datagram(wrong_tid.data(), wrong_tid.size(), kServer, 10));        // someone else's transaction
    const auto good = success_for(tid, kMapped);
    PF_CHECK(!c->on_datagram(good.data(), good.size(), addr(198, 51, 100, 66, 3478), 10));   // forged source
    const uint8_t junk[3] = {1, 2, 3};
    PF_CHECK(!c->on_datagram(junk, sizeof junk, kServer, 10));
    auto bad_fp = good;
    bad_fp.back() ^= 1;
    PF_CHECK(!c->on_datagram(bad_fp.data(), bad_fp.size(), kServer, 10));             // fails to parse: not ours
    const auto unknown = success_for(tid, kMapped, 0x7F00);                           // unknown comprehension-required
    PF_CHECK(c->on_datagram(unknown.data(), unknown.size(), kServer, 10));
    MessageBuilder noaddr(kMethodBinding, Class::Success, tid);
    noaddr.add_fingerprint();
    PF_CHECK(c->on_datagram(noaddr.bytes().data(), noaddr.bytes().size(), kServer, 10));
    MessageBuilder wrong_method(kMethodAllocate, Class::Success, tid);
    wrong_method.add_xor_address(kAttrXorMappedAddress, kMapped);
    PF_CHECK(c->on_datagram(wrong_method.bytes().data(), wrong_method.bytes().size(), kServer, 10));
    MessageBuilder req(kMethodBinding, Class::Request, tid);
    PF_CHECK(c->on_datagram(req.bytes().data(), req.bytes().size(), kServer, 10));
    PF_CHECK_EQ(c->discarded(), uint64_t{4});
    PF_CHECK(c->result().status == BindingStatus::Pending);                         // still waiting, still retrying
    PF_CHECK(!c->poll(500).empty());
    PF_CHECK(c->on_datagram(good.data(), good.size(), kServer, 600));
    PF_CHECK(c->result().status == BindingStatus::Succeeded);

    // MAPPED-ADDRESS fallback (a server that sends only the old attribute)
    DeterministicRandom rnd2(4);
    auto d = BindingClient::create(to(kServer), rnd2);
    d->start(0);
    MessageBuilder old(kMethodBinding, Class::Success, d->transaction_id());
    old.add_address(kAttrMappedAddress, kMapped);
    PF_CHECK(d->on_datagram(old.bytes().data(), old.bytes().size(), kServer, 5));
    PF_CHECK(d->result().mapped == kMapped);
}

PF_TEST(stun_binding_error_response_ends_the_transaction) {
    for (int code : {300, 400, 420, 500}) {
        DeterministicRandom rnd(static_cast<uint64_t>(code));
        auto c = BindingClient::create(to(kServer), rnd);
        c->start(0);
        MessageBuilder e(kMethodBinding, Class::Error, c->transaction_id());
        e.add_error_code(code, "nope").add_fingerprint();
        PF_CHECK(c->on_datagram(e.bytes().data(), e.bytes().size(), kServer, 20));
        PF_CHECK(c->result().status == BindingStatus::Failed);
        PF_CHECK(c->result().failure == BindingFailure::ErrorResponse);
        PF_CHECK_EQ(c->result().error_code, code);
        PF_CHECK(!c->next_deadline_ms().has_value());
    }
    // an error response without a usable ERROR-CODE is discarded, not believed
    DeterministicRandom rnd(9);
    auto c = BindingClient::create(to(kServer), rnd);
    c->start(0);
    MessageBuilder e(kMethodBinding, Class::Error, c->transaction_id());
    PF_CHECK(c->on_datagram(e.bytes().data(), e.bytes().size(), kServer, 20));
    PF_CHECK(c->result().status == BindingStatus::Pending);
}

PF_TEST(stun_binding_takes_its_transaction_id_from_the_random_source) {
    DeterministicRandom a(7), b(7), c(8);
    auto x = BindingClient::create(to(kServer), a), y = BindingClient::create(to(kServer), b), z = BindingClient::create(to(kServer), c);
    PF_CHECK(x->transaction_id() == y->transaction_id());
    PF_CHECK(x->transaction_id() != z->transaction_id());
    auto x2 = BindingClient::create(to(kServer), a);
    PF_CHECK(x2->transaction_id() != x->transaction_id());        // the source advances
    FailingRandom broken;
    std::string err;
    PF_CHECK(BindingClient::create(to(kServer), broken, &err) == nullptr);
    PF_CHECK(err.find("random") != std::string::npos);
    BindingConfig bad = to(kServer);
    bad.rto_ms = 0;
    PF_CHECK(BindingClient::create(bad, a, &err) == nullptr);
}

PF_TEST(stun_binding_request_carries_change_request_and_software) {
    DeterministicRandom rnd(5);
    BindingConfig cfg = to(kServer);
    cfg.change = kChangeIp | kChangePort;
    cfg.software = "pf_stun";
    auto c = BindingClient::create(cfg, rnd);
    const auto out = c->start(0);
    PF_REQUIRE(out.size() == 1);
    Message m;
    PF_REQUIRE(parse(out[0].bytes.data(), out[0].bytes.size(), m) == ParseStatus::Ok);
    const Attribute* cr = m.find(kAttrChangeRequest);
    PF_REQUIRE(cr != nullptr && cr->length == 4);
    PF_CHECK_EQ(int{cr->value[3]}, 0x06);
    PF_CHECK_EQ(std::string(attribute_text(*m.find(kAttrSoftware))), std::string("pf_stun"));
    PF_CHECK(m.unknown_required.empty());                          // CHANGE-REQUEST is understood
    // accept_any_source: an answer from another address counts (RFC 5780 probes)
    cfg.accept_any_source = true;
    auto d = BindingClient::create(cfg, rnd);
    d->start(0);
    const auto resp = success_for(d->transaction_id(), kMapped);
    PF_CHECK(d->on_datagram(resp.data(), resp.size(), addr(198, 51, 100, 2, 3479), 10));
    PF_CHECK(d->result().responded_from == addr(198, 51, 100, 2, 3479));
}

PF_TEST(stun_binding_is_traced_through_its_machine) {
    DeterministicRandom rnd(6);
    auto c = BindingClient::create(to(kServer), rnd);
    TraceRing ring(64);
    c->set_trace(&ring);
    c->start(0);
    c->poll(500);
    const auto resp = success_for(c->transaction_id(), kMapped);
    c->on_datagram(resp.data(), resp.size(), kServer, 700);
    const std::string j = write_trace_jsonl(ring);
    PF_CHECK(j.find("\"machine\":\"stun_binding\"") != std::string::npos);
    PF_CHECK(j.find("\"output\":\"send\"") != std::string::npos);
    PF_CHECK(j.find("\"event\":\"timer:rto\"") != std::string::npos);
    PF_CHECK(j.find("\"status\":\"Succeeded\"") != std::string::npos);
    PF_CHECK(j.find("\"t\":700") != std::string::npos);
}
