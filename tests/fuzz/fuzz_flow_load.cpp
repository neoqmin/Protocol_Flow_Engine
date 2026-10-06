// libFuzzer: text -> parse -> validate -> compile -> RUN, with the real block registry. Nothing the fuzzer can write
// may crash the loader/validator, the validator and builder must agree, and a flow that loaded must also run on an
// arbitrary packet without crashing (blocks report Drop/Error for missing services, they never fault).
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "pf/blocks/data_plane_blocks.h"
#include "pf/blocks/openvpn_blocks.h"
#include "pf/flow_validator.h"
#include "pf/trace.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static pf::BlockRegistry reg = [] {
        pf::BlockRegistry r;
        pf::register_openvpn_blocks(r);
        pf::register_data_plane_blocks(r);
        return r;
    }();
    if (size < 1) return 0;
    const size_t split = 1 + data[0] % (size);                 // [0,split) = flow text, rest = packet bytes
    const size_t text_end = split < size ? split : size;
    pf::LoadedFlow l = pf::load_flow_json(std::string_view(reinterpret_cast<const char*>(data + 1), text_end > 1 ? text_end - 1 : 0), reg);
    for (const auto& i : l.issues) if (i.code == "Internal") std::abort();
    if (!l.ok() || l.flow.node_count() == 0) return 0;
    pf::PacketBuffer pkt = pf::PacketBuffer::from_bytes(data + text_end, size - text_end);
    pf::FlowContext ctx;
    ctx.packet = &pkt;
    pf::PacketBuffer copy = pf::PacketBuffer::from_bytes(data + text_end, size - text_end);
    pf::FlowContext traced;
    traced.packet = &copy;
    pf::TraceRing trace(32);
    const pf::FlowResult a = pf::run_flow(l.flow, ctx);
    const pf::FlowResult b = pf::run_flow(l.flow, traced, nullptr, pf::kDefaultMaxSteps, &trace);   // tracing changes nothing
    if (a.outcome != b.outcome || a.error != b.error || a.steps != b.steps || pkt.size() != copy.size()) std::abort();
    if (trace.size() == 0 || pf::write_trace_jsonl(trace).empty()) std::abort();
    return 0;
}
