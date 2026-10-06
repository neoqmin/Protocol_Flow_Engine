#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pf/machine.h"
#include "pf/nat_behavior.h"
#include "pf/random.h"
#include "pf/stun.h"
#include "pf/trace.h"

namespace pf::stun {

// STUN client (PM-2b N3, D-047). Sans-I/O like the rest of the core: the caller passes the clock, delivers datagrams
// and sends what comes out. No sockets here (platform/linux has them, the simulator replaces them in tests).

// One datagram to send.
struct Outgoing {
    Address to;
    std::vector<uint8_t> bytes;
};

// ---- the Binding transaction ------------------------------------------------------------------------------------------
// The retransmission rule of RFC 8489 6.2.1 is a State Machine (F-1): requests at 0, RTO, 3 RTO, 7 RTO ... (doubling,
// Rc = 7 requests), then wait Rm * RTO for the last one; with RTO = 500 ms: sends at 0, 0.5, 1.5, 3.5, 7.5, 15.5,
// 31.5 s and failure at 39.5 s. tests/regression/golden/machine_stun_binding.machine.json is this document.
//   params  rtoMs (initial RTO), finalMs (Rm * RTO)      events  command:start, packet:response, packet:error
//   output  send (transmit the request - always the SAME bytes, as RFC 8489 requires for retransmissions)
MachineDocument binding_machine_document();
inline constexpr int kBindingMaxRequests = 7;    // Rc (RFC 8489 default)

struct BindingConfig {
    Address server;
    uint32_t rto_ms = 500;            // RFC 8489: initial RTO SHOULD be > 500 ms (simulations may go lower)
    uint32_t rm = 16;                 // last wait = rm * rto_ms
    uint32_t change = 0;              // RFC 5780 CHANGE-REQUEST flags (kChangeIp | kChangePort)
    bool accept_any_source = false;   // take a response from another address than `server` (RFC 5780 tests)
    std::string software;             // SOFTWARE attribute, empty = none
};

enum class BindingStatus { Idle, Pending, Succeeded, Failed };
enum class BindingFailure { None, Timeout, ErrorResponse, RandomFailure };
const char* binding_failure_name(BindingFailure f);

struct BindingResult {
    BindingStatus status = BindingStatus::Idle;
    BindingFailure failure = BindingFailure::None;
    Address mapped;                           // XOR-MAPPED-ADDRESS (MAPPED-ADDRESS if a server only sends that)
    Address responded_from;                   // where the accepted response came from
    std::optional<Address> other_address;     // RFC 5780 OTHER-ADDRESS
    std::optional<Address> response_origin;   // RFC 5780 RESPONSE-ORIGIN
    int error_code = 0;                       // ErrorResponse
    int requests_sent = 0;
    uint64_t rtt_ms = 0;                      // first request to accepted response (includes retransmissions)
};

class BindingClient {
public:
    // The transaction id comes from `random` (a CSPRNG in production). nullptr + error if it fails.
    static std::unique_ptr<BindingClient> create(const BindingConfig& cfg, RandomSource& random, std::string* error = nullptr);

    std::vector<Outgoing> start(uint64_t now_ms);
    // true if the datagram was a response to THIS transaction (accepted or discarded as malformed); false if it is
    // someone else's (other transaction id, other source) and the caller may hand it elsewhere.
    bool on_datagram(const uint8_t* data, size_t len, const Address& from, uint64_t now_ms);
    std::vector<Outgoing> poll(uint64_t now_ms);
    std::optional<uint64_t> next_deadline_ms() const { return runner_.next_deadline_ms(); }

    const BindingResult& result() const { return result_; }
    bool done() const { return result_.status == BindingStatus::Succeeded || result_.status == BindingStatus::Failed; }
    const TransactionId& transaction_id() const { return tid_; }
    uint64_t discarded() const { return discarded_; }    // malformed / unusable responses to our transaction
    void set_trace(TraceSink* t) { runner_.set_trace(t); }

private:
    BindingClient(const BindingConfig& cfg, MachineRunner runner) : cfg_(cfg), runner_(std::move(runner)) {}
    void collect(const MachineStep& s, std::vector<Outgoing>& out);
    void settle(uint64_t now_ms);

    BindingConfig cfg_;
    MachineRunner runner_;
    TransactionId tid_{};
    std::vector<uint8_t> request_;
    BindingResult result_;
    uint64_t started_ = 0, discarded_ = 0;
    FlowContext ctx_;
};

// ---- NAT behaviour discovery (RFC 5780 section 4) -----------------------------------------------------------------------
// Needs a server with an alternate address (OTHER-ADDRESS). Order:
//   1  Binding to the server                              -> mapped address M1, OTHER-ADDRESS (or: no RFC 5780)
//   2  filtering: CHANGE-REQUEST ip+port; reply arrives   -> EIF; else CHANGE-REQUEST port; arrives -> ADF; else APDF
//   3  mapping: Binding to (other IP, primary port) == M1 -> EIM; else (other IP, other port) == that -> ADM; else APDM
// Filtering runs BEFORE the mapping tests so that the only remote the NAT has seen us contact is the primary address:
// contacting the other IP first would open address-dependent filters and make ADF look like EIF.
// The sequencing compares addresses between steps, which State Machine v1 (no variables) cannot express, so this is
// sans-I/O code driving one BindingClient (one Machine) per step.
struct DiscoveryConfig {
    Address server;
    std::optional<Address> local;     // our own address: mapped == local means no NAT
    uint32_t rto_ms = 500, rm = 16;   // for the Binding requests
    uint32_t probe_rto_ms = 500, probe_rm = 16;   // for the filtering probes, whose failure is the expected outcome
    std::string software;
};

enum class DiscoveryStatus { Running, Done, NoResponse, NoRfc5780, Failed };
const char* discovery_status_name(DiscoveryStatus s);

struct DiscoveryResult {
    DiscoveryStatus status = DiscoveryStatus::Running;
    Address mapped;
    bool behind_nat = true;                    // false when mapped == local (only known if local was given)
    std::optional<NatMapping> mapping;
    std::optional<NatFiltering> filtering;
    std::optional<Address> other_address;
    std::string detail;                        // why a step failed, for logs
};

class NatDiscovery {
public:
    static std::unique_ptr<NatDiscovery> create(const DiscoveryConfig& cfg, RandomSource& random, std::string* error = nullptr);

    std::vector<Outgoing> start(uint64_t now_ms);
    bool on_datagram(const uint8_t* data, size_t len, const Address& from, uint64_t now_ms, std::vector<Outgoing>& out);
    std::vector<Outgoing> poll(uint64_t now_ms);
    std::optional<uint64_t> next_deadline_ms() const { return current_ ? current_->next_deadline_ms() : std::nullopt; }
    bool done() const { return result_.status != DiscoveryStatus::Running; }
    const DiscoveryResult& result() const { return result_; }
    void set_trace(TraceSink* t) { trace_ = t; if (current_) current_->set_trace(t); }

private:
    enum class Step { Basic, FilterIpPort, FilterPort, MapOtherIp, MapOtherBoth, Finished };
    NatDiscovery(const DiscoveryConfig& cfg, RandomSource& random) : cfg_(cfg), random_(random) {}
    std::vector<Outgoing> begin(Step s, uint64_t now_ms);
    std::vector<Outgoing> advance(uint64_t now_ms);   // current transaction finished: decide and start the next
    void finish(DiscoveryStatus s, std::string detail = {});

    DiscoveryConfig cfg_;
    RandomSource& random_;
    TraceSink* trace_ = nullptr;
    Step step_ = Step::Basic;
    std::unique_ptr<BindingClient> current_;
    Address mapped_other_ip_;
    DiscoveryResult result_;
};

}  // namespace pf::stun
