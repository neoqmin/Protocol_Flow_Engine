// Flow runner overhead micro benchmark (F-3): an 8-node flow of trivial blocks, so the runner itself dominates.
// Prints ns per flow run with tracing OFF (trace == nullptr: must stay at the pre-trace baseline) and ON (ring sink).
// Not a pass/fail test. Run: build-rel/tests/pf_bench_flow_trace
#include <chrono>
#include <cstdio>

#include "pf/flow.h"
#ifndef PF_BENCH_NO_TRACE
#include "pf/trace.h"
#endif

using namespace pf;

namespace {
BlockResult act(FlowContext& ctx) { ctx.flags += 1; return BlockResult::Continue; }
BlockResult dec(FlowContext& ctx) { return (ctx.flags & 1) ? BlockResult::Yes : BlockResult::No; }

template <typename F>
double ns_per_run(F&& run) {
    const auto t0 = std::chrono::steady_clock::now();
    size_t n = 0;
    double secs = 0;
    do {
        for (int i = 0; i < 100000; ++i) { run(); ++n; }
        secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    } while (secs < 1.0);
    return secs * 1e9 / static_cast<double>(n);
}
}  // namespace

int main() {
    BlockRegistry reg;
    reg.add({1, "act", BlockType::Action, act});
    reg.add({2, "dec", BlockType::Decision, dec});
    FlowBuilder fb("bench");
    fb.add("a1", 1).add("a2", 1).add("d", 2).add("a3", 1).add("a4", 1).add("a5", 1).add("a6", 1).add("a7", 1);
    fb.on_yes("d", "a3").on_no("d", "a3");
    auto built = fb.build(reg);
    if (!built.ok()) { std::fprintf(stderr, "build failed\n"); return 1; }
    FlowContext ctx;
    volatile size_t sink = 0;
    for (int round = 0; round < 3; ++round) {
        const double off = ns_per_run([&] { sink = sink + run_flow(built.flow, ctx).steps; });
#ifndef PF_BENCH_NO_TRACE
        TraceRing ring(4096);
        const double on = ns_per_run([&] { sink = sink + run_flow(built.flow, ctx, nullptr, kDefaultMaxSteps, &ring).steps; });
        std::printf("trace off %6.1f ns/run   trace on (ring) %6.1f ns/run\n", off, on);
#else
        std::printf("trace off %6.1f ns/run\n", off);
#endif
    }
    return 0;
}
