#include "pf/stun_client.h"

namespace pf::stun {

namespace {

const Machine& binding_machine() {
    static const Machine m = [] {
        MachineCompileResult c = compile_machine(binding_machine_document(), FlowLibrary{});
        return c.ok() ? std::move(c.machine) : Machine();        // a broken built-in document fails every create()
    }();
    return m;
}

bool same_ip(const Address& a, const Address& b) { return a.family == b.family && a.ip == b.ip; }

}  // namespace

MachineDocument binding_machine_document() {
    MachineBuilder b("stun_binding");
    b.doc().description = "STUN Binding transaction: RFC 8489 6.2.1 retransmissions (Rc = 7, doubling RTO, final wait Rm * RTO)";
    b.event("command:start").event("packet:response").event("packet:error").output("send")
        .counter("tries", kBindingMaxRequests)
        .timer_param("rto", "rtoMs").backoff("tries")
        .timer_param("final", "finalMs")
        .initial("idle").state("waiting").state("last").final_ok("done").final_failed("failed")
        .transition("idle", "command:start", "waiting").act({"emit:send", "inc:tries", "arm:rto"})
        .transition("waiting", "packet:response", "done").act({"cancel:rto"})
        .transition("waiting", "packet:error", "failed").act({"cancel:rto"})
        .transition("waiting", "timer:rto", "waiting").when("tries", "<", kBindingMaxRequests - 1).act({"emit:send", "inc:tries", "arm:rto"})
        .transition("waiting", "timer:rto", "last").when("tries", ">=", kBindingMaxRequests - 1).act({"emit:send", "inc:tries", "arm:final"})
        .transition("last", "packet:response", "done").act({"cancel:final"})
        .transition("last", "packet:error", "failed").act({"cancel:final"})
        .transition("last", "timer:final", "failed");
    return b.doc();
}

const char* binding_failure_name(BindingFailure f) {
    switch (f) {
        case BindingFailure::None: return "None";
        case BindingFailure::Timeout: return "Timeout";
        case BindingFailure::ErrorResponse: return "ErrorResponse";
        case BindingFailure::RandomFailure: return "RandomFailure";
    }
    return "?";
}

std::unique_ptr<BindingClient> BindingClient::create(const BindingConfig& cfg, RandomSource& random, std::string* error) {
    auto fail = [&](const std::string& e) -> std::unique_ptr<BindingClient> { if (error) *error = e; return nullptr; };
    const uint64_t final_ms = uint64_t{cfg.rto_ms} * cfg.rm;
    std::string why;
    auto runner = MachineRunner::create(binding_machine(), {{"rtoMs", cfg.rto_ms}, {"finalMs", static_cast<int64_t>(final_ms)}}, &why);
    if (!runner) return fail("binding machine: " + why);
    std::unique_ptr<BindingClient> c(new BindingClient(cfg, std::move(*runner)));
    if (!random.fill(c->tid_.data(), c->tid_.size())) {
        c->result_.failure = BindingFailure::RandomFailure;
        return fail("random source failed");
    }
    MessageBuilder req(kMethodBinding, Class::Request, c->tid_);
    if (cfg.change) req.add_u32(kAttrChangeRequest, cfg.change);
    if (!cfg.software.empty()) req.add_text(kAttrSoftware, cfg.software);
    req.add_fingerprint();
    if (!req.ok()) return fail("cannot build the request");
    c->request_ = req.bytes();
    return c;
}

void BindingClient::collect(const MachineStep& s, std::vector<Outgoing>& out) {
    for (size_t i = 0; i < s.emits.size(); ++i) {
        out.push_back({cfg_.server, request_});
        ++result_.requests_sent;
    }
}

void BindingClient::settle(uint64_t now_ms) {
    if (result_.status != BindingStatus::Pending) return;
    if (runner_.status() == MachineStatus::Succeeded) {
        result_.status = BindingStatus::Succeeded;
        result_.rtt_ms = now_ms - started_;
    } else if (runner_.status() == MachineStatus::Failed) {
        result_.status = BindingStatus::Failed;
        if (result_.failure == BindingFailure::None) result_.failure = BindingFailure::Timeout;
    }
}

std::vector<Outgoing> BindingClient::start(uint64_t now_ms) {
    std::vector<Outgoing> out;
    if (result_.status != BindingStatus::Idle) return out;
    started_ = now_ms;
    result_.status = BindingStatus::Pending;
    runner_.start(ctx_, now_ms);
    collect(runner_.on_event(*binding_machine().find_event("command:start"), ctx_, now_ms), out);
    return out;
}

std::vector<Outgoing> BindingClient::poll(uint64_t now_ms) {
    std::vector<Outgoing> out;
    while (auto s = runner_.poll_timer(ctx_, now_ms)) collect(*s, out);
    settle(now_ms);
    return out;
}

bool BindingClient::on_datagram(const uint8_t* data, size_t len, const Address& from, uint64_t now_ms) {
    Message m;
    if (parse(data, len, m) != ParseStatus::Ok || m.tid != tid_) return false;
    if (!cfg_.accept_any_source && from != cfg_.server) return false;   // not from where we sent it: not our answer
    if (result_.status != BindingStatus::Pending) { ++discarded_; return true; }    // late duplicate
    auto discard = [&] { ++discarded_; return true; };
    if (m.method != kMethodBinding || !m.unknown_required.empty()) return discard();
    if (m.cls == Class::Success) {
        Address mapped;
        const Attribute* x = m.find(kAttrXorMappedAddress);
        const Attribute* p = m.find(kAttrMappedAddress);
        if (!(x && decode_xor_address(*x, m.tid, mapped)) && !(p && decode_address(*p, mapped))) return discard();
        result_.mapped = mapped;
        result_.responded_from = from;
        Address a;
        if (const Attribute* o = m.find(kAttrOtherAddress); o && decode_address(*o, a)) result_.other_address = a;
        if (const Attribute* o = m.find(kAttrResponseOrigin); o && decode_address(*o, a)) result_.response_origin = a;
        runner_.on_event(*binding_machine().find_event("packet:response"), ctx_, now_ms);
    } else if (m.cls == Class::Error) {
        ErrorCode e;
        const Attribute* ec = m.find(kAttrErrorCode);
        if (!ec || !decode_error_code(*ec, e)) return discard();
        result_.error_code = e.code;
        result_.responded_from = from;
        result_.failure = BindingFailure::ErrorResponse;               // includes 3xx: ALTERNATE-SERVER is not supported
        runner_.on_event(*binding_machine().find_event("packet:error"), ctx_, now_ms);
    } else {
        return discard();
    }
    settle(now_ms);
    return true;
}

// ---- discovery ----------------------------------------------------------------------------------------------------------

const char* discovery_status_name(DiscoveryStatus s) {
    switch (s) {
        case DiscoveryStatus::Running: return "Running";
        case DiscoveryStatus::Done: return "Done";
        case DiscoveryStatus::NoResponse: return "NoResponse";
        case DiscoveryStatus::NoRfc5780: return "NoRfc5780";
        case DiscoveryStatus::Failed: return "Failed";
    }
    return "?";
}

std::unique_ptr<NatDiscovery> NatDiscovery::create(const DiscoveryConfig& cfg, RandomSource& random, std::string* error) {
    if (cfg.rto_ms == 0 || cfg.probe_rto_ms == 0) {
        if (error) *error = "rto must be positive";
        return nullptr;
    }
    return std::unique_ptr<NatDiscovery>(new NatDiscovery(cfg, random));
}

void NatDiscovery::finish(DiscoveryStatus s, std::string detail) {
    result_.status = s;
    if (!detail.empty()) result_.detail = std::move(detail);
    step_ = Step::Finished;
    current_.reset();
}

std::vector<Outgoing> NatDiscovery::begin(Step s, uint64_t now_ms) {
    step_ = s;
    BindingConfig c;
    c.server = cfg_.server;
    c.rto_ms = cfg_.rto_ms;
    c.rm = cfg_.rm;
    c.software = cfg_.software;
    const Address other = result_.other_address.value_or(cfg_.server);
    switch (s) {
        case Step::Basic: break;
        case Step::FilterIpPort:
        case Step::FilterPort:
            c.change = s == Step::FilterIpPort ? (kChangeIp | kChangePort) : kChangePort;
            c.accept_any_source = true;
            c.rto_ms = cfg_.probe_rto_ms;
            c.rm = cfg_.probe_rm;
            break;
        case Step::MapOtherIp:
            c.server = other;
            c.server.port = cfg_.server.port;
            break;
        case Step::MapOtherBoth: c.server = other; break;
        case Step::Finished: return {};
    }
    std::string why;
    current_ = BindingClient::create(c, random_, &why);
    if (!current_) { finish(DiscoveryStatus::Failed, why); return {}; }
    current_->set_trace(trace_);
    return current_->start(now_ms);
}

std::vector<Outgoing> NatDiscovery::start(uint64_t now_ms) {
    if (step_ != Step::Basic || current_) return {};
    return begin(Step::Basic, now_ms);
}

std::vector<Outgoing> NatDiscovery::advance(uint64_t now_ms) {
    const BindingResult r = current_->result();
    const bool ok = r.status == BindingStatus::Succeeded;
    switch (step_) {
        case Step::Basic:
            if (!ok) { finish(DiscoveryStatus::NoResponse, binding_failure_name(r.failure)); return {}; }
            result_.mapped = r.mapped;
            result_.behind_nat = !(cfg_.local && *cfg_.local == r.mapped);
            result_.other_address = r.other_address;
            if (!r.other_address) { finish(DiscoveryStatus::NoRfc5780, "server sent no OTHER-ADDRESS"); return {}; }
            return begin(Step::FilterIpPort, now_ms);
        case Step::FilterIpPort:
            if (ok) {
                if (!same_ip(r.responded_from, cfg_.server) && r.responded_from.port != cfg_.server.port)
                    result_.filtering = NatFiltering::EndpointIndependent;
                else
                    result_.detail = "server did not change address and port";   // filtering left unknown
                return begin(Step::MapOtherIp, now_ms);
            }
            if (r.failure == BindingFailure::Timeout) return begin(Step::FilterPort, now_ms);
            result_.detail = "filtering probe answered with an error";
            return begin(Step::MapOtherIp, now_ms);
        case Step::FilterPort:
            if (ok && same_ip(r.responded_from, cfg_.server) && r.responded_from.port != cfg_.server.port)
                result_.filtering = NatFiltering::AddressDependent;
            else if (!ok && r.failure == BindingFailure::Timeout)
                result_.filtering = NatFiltering::AddressAndPortDependent;
            else
                result_.detail = "unexpected answer to the port-change probe";
            return begin(Step::MapOtherIp, now_ms);
        case Step::MapOtherIp:
            if (!ok) { finish(DiscoveryStatus::Failed, "no answer from the alternate address"); return {}; }
            mapped_other_ip_ = r.mapped;
            if (r.mapped == result_.mapped) {
                result_.mapping = NatMapping::EndpointIndependent;
                finish(DiscoveryStatus::Done);
                return {};
            }
            return begin(Step::MapOtherBoth, now_ms);
        case Step::MapOtherBoth:
            if (!ok) { finish(DiscoveryStatus::Failed, "no answer from the alternate address and port"); return {}; }
            result_.mapping = r.mapped == mapped_other_ip_ ? NatMapping::AddressDependent : NatMapping::AddressAndPortDependent;
            finish(DiscoveryStatus::Done);
            return {};
        case Step::Finished: break;
    }
    return {};
}

bool NatDiscovery::on_datagram(const uint8_t* data, size_t len, const Address& from, uint64_t now_ms, std::vector<Outgoing>& out) {
    if (!current_) return false;
    const bool consumed = current_->on_datagram(data, len, from, now_ms);
    if (current_->done()) {
        auto more = advance(now_ms);
        out.insert(out.end(), more.begin(), more.end());
    }
    return consumed;
}

std::vector<Outgoing> NatDiscovery::poll(uint64_t now_ms) {
    if (!current_) return {};
    std::vector<Outgoing> out = current_->poll(now_ms);
    if (current_ && current_->done()) {
        auto more = advance(now_ms);
        out.insert(out.end(), more.begin(), more.end());
    }
    return out;
}

}  // namespace pf::stun
