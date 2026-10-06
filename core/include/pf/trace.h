#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pf/block.h"
#include "pf/error.h"

namespace pf {

// Packet / transition trace (F-3, D-042; plans/Protocol_Flow_Engine_Flow_Model_Extension_Plan.md section 7).
// One record format for the flow runner (every node executed, how each flow ended) and the state machine runner
// (events, transitions, emits, how the machine ended). Consumers: tests, `pf_client --trace`, the editor (PM-6), MCP
// resources (PM-7), the NAT lab (PM-2).
//
// PRIVACY BY CONSTRUCTION: a record has no field that can hold packet bytes, plaintext or key material - only names
// (flow/node/machine/state/event/output ids, which are identifiers, not data), result codes and a packet LENGTH.
// tests/flow/test_trace_openssl.cpp pins that a trace of real decryptions contains neither the key nor the plaintext.
enum class TraceKind : uint8_t {
    Node,          // one block executed:     scope=flow, name=node label, block, result=BlockResult, error, value=packet length
    FlowEnd,       // run_flow finished:      scope=flow, name=last node label, result=FlowOutcome, error, value=steps
    Event,         // event delivered:        scope=machine, name=event, state=current, result=TraceEvent
    Transition,    // transition taken:       scope=machine, name=event, state=from, to=target, value=transition index
    Emit,          // output emitted:         scope=machine, name=output, state=current
    MachineEnd,    // machine finished:       scope=machine, state=where, result=MachineStatus, error
};
const char* trace_kind_name(TraceKind k);

// What happened to an event (TraceKind::Event result). A selected event may still be dropped by its handler Flow:
// that shows up as the following FlowEnd(Dropped) with no Transition after it.
enum class TraceEvent : uint8_t { Selected, Ignored, Rejected };

// View handed to a sink; the string_views are only valid during record().
struct TraceRecord {
    TraceKind kind = TraceKind::Node;
    uint64_t t_ms = 0;
    std::string_view scope, name, state, to;
    BlockId block = 0;
    uint8_t result = 0;
    Error error = Error::None;
    uint32_t value = 0;
};

class TraceSink {
public:
    virtual ~TraceSink() = default;
    virtual void record(const TraceRecord& r) = 0;
    // The clock records are stamped with. Whoever drives time sets it (MachineRunner does on every call; TunnelSession
    // before it runs a Flow). run_flow itself has no clock and uses this value.
    uint64_t now_ms = 0;
};

// Fixed-capacity flight recorder: allocates once, never in record(); when full the oldest record is overwritten and
// counted. Names longer than kTraceNameMax are truncated (ids are at most 64 bytes, events at most 72).
inline constexpr size_t kTraceNameMax = 79;

struct TraceName {
    std::array<char, kTraceNameMax + 1> buf{};
    uint8_t len = 0;
    void set(std::string_view s);
    std::string_view view() const { return std::string_view(buf.data(), len); }
};

struct TraceEntry {
    uint64_t seq = 0;                 // 1, 2, 3 ... over the ring's lifetime (gaps at the start = overwritten)
    TraceKind kind = TraceKind::Node;
    uint64_t t_ms = 0;
    TraceName scope, name, state, to;
    BlockId block = 0;
    uint8_t result = 0;
    Error error = Error::None;
    uint32_t value = 0;
};

class TraceRing : public TraceSink {
public:
    explicit TraceRing(size_t capacity);
    void record(const TraceRecord& r) override;

    size_t size() const { return count_; }
    size_t capacity() const { return entries_.size(); }
    uint64_t total() const { return next_seq_ - 1; }            // records ever received
    uint64_t overwritten() const { return total() - count_; }
    const TraceEntry& at(size_t i) const;                         // 0 = oldest kept
    void clear();

private:
    std::vector<TraceEntry> entries_;
    size_t head_ = 0, count_ = 0;                                 // head_ = slot of the oldest entry
    uint64_t next_seq_ = 1;
};

// One JSON object (compact, no newline), field names per kind, e.g.
//   {"seq":3,"t":1000,"kind":"node","flow":"openvpn_rx","node":"decrypt","block":9,"result":"Drop","error":"AuthFailed","len":120}
std::string trace_entry_json(const TraceEntry& e);
// JSON Lines: a header line {"kind":"trace","records":N,"overwritten":M} then one line per entry, oldest first.
std::string write_trace_jsonl(const TraceRing& ring);

}  // namespace pf
