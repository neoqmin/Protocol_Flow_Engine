#include "pf/trace.h"

#include <algorithm>
#include <cstring>

#include "pf/flow.h"
#include "pf/json.h"
#include "pf/machine.h"

namespace pf {

namespace {

const char* block_result_name(uint8_t r) {
    switch (static_cast<BlockResult>(r)) {
        case BlockResult::Continue: return "Continue";
        case BlockResult::Yes: return "Yes";
        case BlockResult::No: return "No";
        case BlockResult::Drop: return "Drop";
        case BlockResult::Error: return "Error";
    }
    return "Unknown";
}
const char* flow_outcome_name(uint8_t o) {
    switch (static_cast<FlowOutcome>(o)) {
        case FlowOutcome::Completed: return "Completed";
        case FlowOutcome::Dropped: return "Dropped";
        case FlowOutcome::Errored: return "Errored";
    }
    return "Unknown";
}
const char* event_outcome_name(uint8_t o) {
    switch (static_cast<TraceEvent>(o)) {
        case TraceEvent::Selected: return "selected";
        case TraceEvent::Ignored: return "ignored";
        case TraceEvent::Rejected: return "rejected";
    }
    return "unknown";
}
const char* machine_status_name(uint8_t s) {
    switch (static_cast<MachineStatus>(s)) {
        case MachineStatus::Running: return "Running";
        case MachineStatus::Succeeded: return "Succeeded";
        case MachineStatus::Failed: return "Failed";
    }
    return "Unknown";
}

JsonValue str(std::string_view s) { return JsonValue::string(std::string(s)); }

}  // namespace

const char* trace_kind_name(TraceKind k) {
    switch (k) {
        case TraceKind::Node: return "node";
        case TraceKind::FlowEnd: return "flow_end";
        case TraceKind::Event: return "event";
        case TraceKind::Transition: return "transition";
        case TraceKind::Emit: return "emit";
        case TraceKind::MachineEnd: return "machine_end";
    }
    return "unknown";
}

void TraceName::set(std::string_view s) {
    size_t n = std::min(s.size(), kTraceNameMax);
    if (n < s.size())                           // never cut a UTF-8 sequence in half
        while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;
    len = static_cast<uint8_t>(n);
    if (len) std::memcpy(buf.data(), s.data(), len);
}

TraceRing::TraceRing(size_t capacity) : entries_(std::max<size_t>(capacity, 1)) {}

void TraceRing::record(const TraceRecord& r) {
    size_t slot;
    if (count_ < entries_.size()) {
        slot = (head_ + count_) % entries_.size();
        ++count_;
    } else {                                    // full: overwrite the oldest
        slot = head_;
        head_ = (head_ + 1) % entries_.size();
    }
    TraceEntry& e = entries_[slot];
    e.seq = next_seq_++;
    e.kind = r.kind;
    e.t_ms = r.t_ms;
    e.scope.set(r.scope);
    e.name.set(r.name);
    e.state.set(r.state);
    e.to.set(r.to);
    e.block = r.block;
    e.result = r.result;
    e.error = r.error;
    e.value = r.value;
}

const TraceEntry& TraceRing::at(size_t i) const { return entries_[(head_ + i) % entries_.size()]; }

void TraceRing::clear() {
    head_ = count_ = 0;
    next_seq_ = 1;
}

std::string trace_entry_json(const TraceEntry& e) {
    JsonValue o = JsonValue::object();
    o.set("seq", JsonValue::integer(static_cast<int64_t>(e.seq)));
    o.set("t", JsonValue::integer(static_cast<int64_t>(e.t_ms)));
    o.set("kind", JsonValue::string(trace_kind_name(e.kind)));
    switch (e.kind) {
        case TraceKind::Node:
            o.set("flow", str(e.scope.view()));
            o.set("node", str(e.name.view()));
            o.set("block", JsonValue::integer(e.block));
            o.set("result", JsonValue::string(block_result_name(e.result)));
            if (e.error != Error::None) o.set("error", JsonValue::string(error_name(e.error)));
            o.set("len", JsonValue::integer(e.value));
            break;
        case TraceKind::FlowEnd:
            o.set("flow", str(e.scope.view()));
            o.set("last", str(e.name.view()));
            o.set("outcome", JsonValue::string(flow_outcome_name(e.result)));
            if (e.error != Error::None) o.set("error", JsonValue::string(error_name(e.error)));
            o.set("steps", JsonValue::integer(e.value));
            break;
        case TraceKind::Event:
            o.set("machine", str(e.scope.view()));
            o.set("state", str(e.state.view()));
            o.set("event", str(e.name.view()));
            o.set("outcome", JsonValue::string(event_outcome_name(e.result)));
            if (e.error != Error::None) o.set("error", JsonValue::string(error_name(e.error)));
            break;
        case TraceKind::Transition:
            o.set("machine", str(e.scope.view()));
            o.set("from", str(e.state.view()));
            o.set("event", str(e.name.view()));
            o.set("to", str(e.to.view()));
            o.set("index", JsonValue::integer(e.value));
            break;
        case TraceKind::Emit:
            o.set("machine", str(e.scope.view()));
            o.set("state", str(e.state.view()));
            o.set("output", str(e.name.view()));
            break;
        case TraceKind::MachineEnd:
            o.set("machine", str(e.scope.view()));
            o.set("state", str(e.state.view()));
            o.set("status", JsonValue::string(machine_status_name(e.result)));
            if (e.error != Error::None) o.set("error", JsonValue::string(error_name(e.error)));
            break;
    }
    return write_json(o, false);
}

std::string write_trace_jsonl(const TraceRing& ring) {
    JsonValue h = JsonValue::object();
    h.set("kind", JsonValue::string("trace"));
    h.set("records", JsonValue::integer(static_cast<int64_t>(ring.size())));
    h.set("overwritten", JsonValue::integer(static_cast<int64_t>(ring.overwritten())));
    std::string out = write_json(h, false) + "\n";
    for (size_t i = 0; i < ring.size(); ++i) out += trace_entry_json(ring.at(i)) + "\n";
    return out;
}

}  // namespace pf
