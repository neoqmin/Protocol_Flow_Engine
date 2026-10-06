// libFuzzer: protocol-machine text -> parse -> validate -> compile -> RUN (F-1). Invariants checked on every input:
//   * nothing crashes the loader, validator, compiler or runner;
//   * canonical output is a fixed point: write(parse(write(doc))) == write(doc);
//   * a machine the validator accepted never runs away through auto transitions (StepLimit) and, when it has no
//     `unbounded` transition, stops by itself once only timers fire (bounded firings) - the UnboundedRetry guarantee.
// Bytes after the text drive the machine: each byte delivers a declared event or advances the clock.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "pf/machine_json.h"
#include "pf/trace.h"

namespace {
pf::BlockResult pass(pf::FlowContext&) { return pf::BlockResult::Continue; }
pf::BlockResult drop(pf::FlowContext& ctx) { ctx.error = pf::Error::PolicyDenied; return pf::BlockResult::Drop; }

const pf::FlowLibrary& library() {
    static const pf::FlowLibrary lib = [] {
        pf::BlockRegistry r;
        r.add({1, "pass", pf::BlockType::Action, pass});
        r.add({2, "drop", pf::BlockType::Action, drop});
        pf::FlowLibrary l;
        for (auto [name, id] : {std::pair<const char*, pf::BlockId>{"pass", 1}, {"drop", 2}}) {
            pf::FlowBuilder fb(name);
            fb.add("n", id);
            l.emplace(name, fb.build(r).flow);
        }
        return l;
    }();
    return lib;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const size_t split = 1 + (static_cast<size_t>(data[0]) * 64) % size;    // [1,split) = text, rest = drive bytes
    const size_t text_end = split < size ? split : size;
    const std::string_view text(reinterpret_cast<const char*>(data + 1), text_end > 1 ? text_end - 1 : 0);

    const pf::MachineJsonResult pr = pf::parse_machine_json(text);
    if (pr.ok()) {
        const std::string once = pf::write_machine_json(pr.doc);
        const pf::MachineJsonResult again = pf::parse_machine_json(once);
        if (!again.ok() || pf::write_machine_json(again.doc) != once) std::abort();
    }
    pf::LoadedMachine l = pf::load_machine_json(text, library());
    if (!l.ok()) return 0;

    std::vector<std::pair<std::string, int64_t>> params;
    for (const auto& t : l.doc.timers)
        if (!t.param.empty()) params.emplace_back(t.param, 1 + static_cast<int64_t>(t.param.size()) * 7);
    auto r = pf::MachineRunner::create(l.machine, params);
    if (!r) std::abort();                                   // every param was supplied with a legal value
    pf::FlowContext ctx;
    uint64_t now = 0;
    pf::TraceRing trace(64);                                // tracing must never change or break anything
    r->set_trace(&trace);
    r->start(ctx, now);
    if (r->error() == pf::Error::StepLimit) std::abort();
    const size_t nevents = l.doc.events.size();
    for (size_t i = text_end; i < size && r->status() == pf::MachineStatus::Running; ++i) {
        const uint8_t b = data[i];
        if ((b & 0x80) || nevents == 0) {
            now += b & 0x7f;
            while (const auto d = r->next_deadline_ms()) {
                if (*d > now) break;
                r->poll_timer(ctx, *d);
            }
        } else {
            r->on_event(*l.machine.find_event(l.doc.events[b % nevents]), ctx, now);
        }
        if (r->error() == pf::Error::StepLimit) std::abort();
    }
    bool unbounded = false;
    for (const auto& t : l.doc.transitions) unbounded |= !t.unbounded.empty();
    if (!unbounded) {
        long firings = 0;
        while (r->status() == pf::MachineStatus::Running) {
            const auto d = r->next_deadline_ms();
            if (!d) break;
            r->poll_timer(ctx, *d);
            if (++firings > 1000000) std::abort();         // validator accepted a machine that retries forever
        }
    }
    if (pf::write_trace_jsonl(trace).empty()) std::abort();
    return 0;
}
