#include <string>

#include "pf/trace.h"
#include "pf_test.h"

using namespace pf;

namespace {
TraceRecord node(const char* label, uint64_t t = 0) {
    TraceRecord r;
    r.kind = TraceKind::Node;
    r.t_ms = t;
    r.scope = "rx";
    r.name = label;
    r.block = 6;
    return r;
}
}  // namespace

PF_TEST(trace_ring_keeps_the_newest_and_counts_overwrites) {
    TraceRing ring(3);
    PF_CHECK_EQ(ring.capacity(), size_t{3});
    PF_CHECK_EQ(ring.size(), size_t{0});
    for (int i = 0; i < 5; ++i) ring.record(node(("n" + std::to_string(i)).c_str(), static_cast<uint64_t>(i)));
    PF_CHECK_EQ(ring.size(), size_t{3});
    PF_CHECK_EQ(ring.total(), uint64_t{5});
    PF_CHECK_EQ(ring.overwritten(), uint64_t{2});
    PF_CHECK_EQ(std::string(ring.at(0).name.view()), std::string("n2"));     // oldest kept
    PF_CHECK_EQ(std::string(ring.at(2).name.view()), std::string("n4"));
    PF_CHECK_EQ(ring.at(0).seq, uint64_t{3});
    PF_CHECK_EQ(ring.at(2).t_ms, uint64_t{4});
    ring.clear();
    PF_CHECK_EQ(ring.size(), size_t{0});
    PF_CHECK_EQ(ring.total(), uint64_t{0});
    ring.record(node("again"));
    PF_CHECK_EQ(ring.at(0).seq, uint64_t{1});
    TraceRing tiny(0);                                     // capacity is at least 1
    tiny.record(node("x"));
    PF_CHECK_EQ(tiny.size(), size_t{1});
}

PF_TEST(trace_names_are_copied_and_truncated_safely) {
    TraceRing ring(2);
    std::string label(200, 'a');
    ring.record(node(label.c_str()));
    label.assign(200, 'b');                                // the ring holds its own copy
    PF_CHECK_EQ(ring.at(0).name.view().size(), kTraceNameMax);
    PF_CHECK(ring.at(0).name.view().find('b') == std::string_view::npos);
    std::string utf8(kTraceNameMax - 1, 'x');
    utf8 += "\xc3\xa9\xc3\xa9";                            // a 2-byte sequence straddles the limit
    ring.record(node(utf8.c_str()));
    PF_CHECK_EQ(ring.at(1).name.view().size(), kTraceNameMax - 1);         // cut before the sequence, not inside it
}

PF_TEST(trace_entries_render_as_json_lines) {
    TraceRing ring(8);
    TraceRecord r = node("decrypt", 1000);
    r.block = 9;
    r.result = static_cast<uint8_t>(BlockResult::Drop);
    r.error = Error::AuthFailed;
    r.value = 120;
    ring.record(r);
    TraceRecord end;
    end.kind = TraceKind::FlowEnd;
    end.t_ms = 1000;
    end.scope = "rx";
    end.name = "decrypt";
    end.result = 1;                                        // FlowOutcome::Dropped
    end.error = Error::AuthFailed;
    end.value = 4;
    ring.record(end);
    TraceRecord ev;
    ev.kind = TraceKind::Event;
    ev.t_ms = 1001;
    ev.scope = "stun";
    ev.name = "timer:rto";
    ev.state = "waiting";
    ring.record(ev);
    TraceRecord tr;
    tr.kind = TraceKind::Transition;
    tr.scope = "stun";
    tr.name = "timer:rto";
    tr.state = "waiting";
    tr.to = "failed";
    tr.value = 3;
    ring.record(tr);
    TraceRecord em;
    em.kind = TraceKind::Emit;
    em.scope = "ka";
    em.name = "ping";
    em.state = "alive";
    ring.record(em);
    TraceRecord me;
    me.kind = TraceKind::MachineEnd;
    me.scope = "stun";
    me.state = "failed";
    me.result = 2;                                         // MachineStatus::Failed
    ring.record(me);

    PF_CHECK_EQ(trace_entry_json(ring.at(0)),
                std::string(R"({"seq":1,"t":1000,"kind":"node","flow":"rx","node":"decrypt","block":9,"result":"Drop","error":"AuthFailed","len":120})"));
    PF_CHECK_EQ(trace_entry_json(ring.at(1)),
                std::string(R"({"seq":2,"t":1000,"kind":"flow_end","flow":"rx","last":"decrypt","outcome":"Dropped","error":"AuthFailed","steps":4})"));
    PF_CHECK_EQ(trace_entry_json(ring.at(2)),
                std::string(R"({"seq":3,"t":1001,"kind":"event","machine":"stun","state":"waiting","event":"timer:rto","outcome":"selected"})"));
    PF_CHECK_EQ(trace_entry_json(ring.at(3)),
                std::string(R"({"seq":4,"t":0,"kind":"transition","machine":"stun","from":"waiting","event":"timer:rto","to":"failed","index":3})"));
    PF_CHECK_EQ(trace_entry_json(ring.at(4)), std::string(R"({"seq":5,"t":0,"kind":"emit","machine":"ka","state":"alive","output":"ping"})"));
    PF_CHECK_EQ(trace_entry_json(ring.at(5)), std::string(R"({"seq":6,"t":0,"kind":"machine_end","machine":"stun","state":"failed","status":"Failed"})"));

    const std::string jsonl = write_trace_jsonl(ring);
    PF_CHECK_EQ(jsonl.substr(0, jsonl.find('\n')), std::string(R"({"kind":"trace","records":6,"overwritten":0})"));
    size_t lines = 0;
    for (char c : jsonl) lines += c == '\n';
    PF_CHECK_EQ(lines, size_t{7});
}
