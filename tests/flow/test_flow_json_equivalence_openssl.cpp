// C3: the Flows stored as JSON (tests/regression/golden/flow_*.flow.json) must behave EXACTLY like the static Flows built
// in code - same graph, same results, same bytes - on real traffic captured from unmodified OpenVPN 2.6.19.
// Needs OpenSSL (real AES-256-GCM). GOLDEN_DIR is injected by CMake.
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "pf/blocks/data_plane_blocks.h"
#include "pf/blocks/openvpn_blocks.h"
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/flow.h"
#include "pf/flow_validator.h"
#include "pf/key_store.h"
#include "pf_test.h"

using namespace pf;

namespace {

std::string golden(const std::string& name) { return std::string(GOLDEN_DIR) + "/" + name; }
std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}
std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t\r");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
std::vector<std::vector<std::string>> table(const std::string& file) {
    std::vector<std::vector<std::string>> rows;
    std::ifstream f(golden(file));
    PF_REQUIRE(f.good());
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> cells;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, '|')) cells.push_back(trim(cell));
        rows.push_back(std::move(cells));
    }
    return rows;
}

BlockRegistry registry() {
    BlockRegistry r;
    PF_REQUIRE(register_openvpn_blocks(r));
    PF_REQUIRE(register_data_plane_blocks(r));
    return r;
}

// The static definitions (what the code built before Flow JSON existed).
Flow static_openvpn_rx(const BlockRegistry& r) {
    FlowBuilder b("openvpn_rx");
    b.add("parse", kBlockParseOvpnHeader).add("policy", kBlockRejectLegacyOpcode).add("is_data", kBlockIsDataV2)
     .add("strip", kBlockStripDataV2Header).add("control", kBlockMarkControlPacket);
    b.on_yes("is_data", "strip").on_no("is_data", "control");
    b.on_continue("strip", "");
    auto res = b.build(r);
    PF_REQUIRE(res.ok());
    return std::move(res.flow);
}
Flow static_data_rx(const BlockRegistry& r) {
    FlowBuilder b("data_rx");
    b.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
     .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
    auto res = b.build(r);
    PF_REQUIRE(res.ok());
    return std::move(res.flow);
}
Flow static_data_tx(const BlockRegistry& r) {
    FlowBuilder b("data_tx");
    b.add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
    auto res = b.build(r);
    PF_REQUIRE(res.ok());
    return std::move(res.flow);
}
Flow from_json(const BlockRegistry& r, const char* file) {
    LoadedFlow l = load_flow_json(slurp(golden(file)), r);
    if (!l.ok()) std::printf("%s: %s %s %s\n", file, l.issues[0].code.c_str(), l.issues[0].path.c_str(), l.issues[0].message.c_str());
    PF_REQUIRE(l.ok());
    return std::move(l.flow);
}

bool same_graph(const Flow& a, const Flow& b) {
    if (a.name() != b.name() || a.node_count() != b.node_count()) return false;
    for (size_t i = 0; i < a.node_count(); ++i) {
        const FlowNode &x = a.node(i), &y = b.node(i);
        if (x.label != y.label || x.block != y.block || x.type != y.type || x.execute != y.execute || x.on_continue != y.on_continue ||
            x.on_yes != y.on_yes || x.on_no != y.on_no)
            return false;
    }
    return true;
}

struct Outcome {
    FlowResult result;
    std::vector<uint8_t> bytes;
    uint32_t flags;
    bool header_valid;
    int opcode, key_id;
    uint32_t peer_id;
};
bool same(const Outcome& a, const Outcome& b) {
    return a.result.outcome == b.result.outcome && a.result.error == b.result.error && a.result.steps == b.result.steps &&
           a.result.last_node == b.result.last_node && a.bytes == b.bytes && a.flags == b.flags && a.header_valid == b.header_valid &&
           a.opcode == b.opcode && a.key_id == b.key_id && a.peer_id == b.peer_id;
}

Outcome run_header(const Flow& f, const std::vector<uint8_t>& wire) {
    PacketBuffer pkt = PacketBuffer::from_bytes(wire.data(), wire.size());
    FlowContext ctx;
    ctx.packet = &pkt;
    Outcome o{};
    o.result = run_flow(f, ctx);
    o.bytes.assign(pkt.data(), pkt.data() + pkt.size());
    o.flags = ctx.flags;
    o.header_valid = ctx.header_valid;
    o.opcode = static_cast<int>(ctx.header.opcode);
    o.key_id = ctx.header.key_id;
    o.peer_id = ctx.header.peer_id;
    return o;
}

// DATA_V2 receive on a private KeyStore (replay state is per store), key from a golden row.
struct RxRig {
    KeyStore keys;
    std::unique_ptr<AeadProvider> aead = make_openssl_aes256gcm();
    explicit RxRig(const std::vector<uint8_t>& key, const std::vector<uint8_t>& tail, uint8_t key_id) {
        DataKey k;
        std::copy(key.begin(), key.end(), k.key.begin());
        std::copy(tail.begin(), tail.end(), k.nonce_tail.begin());
        keys.bind_rx(key_id, keys.add(k));
    }
    Outcome run(const Flow& f, const std::vector<uint8_t>& wire) {
        PacketBuffer pkt = PacketBuffer::from_bytes(wire.data(), wire.size());
        FlowContext ctx;
        ctx.packet = &pkt;
        ctx.keys = &keys;
        ctx.aead = aead.get();
        Outcome o{};
        o.result = run_flow(f, ctx);
        o.bytes.assign(pkt.data(), pkt.data() + pkt.size());
        o.flags = ctx.flags;
        o.header_valid = ctx.header_valid;
        return o;
    }
};

}  // namespace

PF_TEST(json_flows_have_exactly_the_graph_of_the_static_flows) {
    const BlockRegistry r = registry();
    PF_CHECK(same_graph(from_json(r, "flow_openvpn_rx.flow.json"), static_openvpn_rx(r)));
    PF_CHECK(same_graph(from_json(r, "flow_data_v2_rx.flow.json"), static_data_rx(r)));
    PF_CHECK(same_graph(from_json(r, "flow_data_v2_tx.flow.json"), static_data_tx(r)));
}

PF_TEST(json_openvpn_rx_matches_the_static_flow_on_every_header_golden_vector) {
    const BlockRegistry r = registry();
    const Flow st = static_openvpn_rx(r), js = from_json(r, "flow_openvpn_rx.flow.json");
    size_t n = 0;
    for (const char* file : {"openvpn_header.golden"}) {
        std::ifstream probe(golden(file));
        if (!probe.good()) continue;
        for (const auto& row : table(file)) {
            if (row.empty() || row[0].empty()) continue;
            const auto wire = unhex(row[0]);
            const Outcome a = run_header(st, wire), b = run_header(js, wire);
            if (!same(a, b)) pf_test::record(__FILE__, __LINE__, std::string(file) + " packet " + row[0] + ": JSON flow and static flow disagree");
            ++n;
        }
    }
    PF_CHECK(n >= 10);
    // Every opcode byte and key_id (all 256 first bytes, 4-byte packets): the two flows are interchangeable.
    for (int b0 = 0; b0 < 256; ++b0) {
        const std::vector<uint8_t> wire = {static_cast<uint8_t>(b0), 0, 0, 1, 0xAA, 0xBB};
        if (!same(run_header(st, wire), run_header(js, wire))) pf_test::record(__FILE__, __LINE__, "first byte " + std::to_string(b0) + ": flows disagree");
    }
}

PF_TEST(json_data_rx_matches_the_static_flow_on_real_openvpn_data_packets) {
    const BlockRegistry r = registry();
    const Flow st = static_data_rx(r), js = from_json(r, "flow_data_v2_rx.flow.json");
    const auto rows = table("data_v2_gcm.golden");
    PF_REQUIRE(rows.size() >= 10);
    for (const auto& row : rows) {
        PF_REQUIRE(row.size() == 4);
        const auto key = unhex(row[0]), tail = unhex(row[1]), wire = unhex(row[2]), plain = unhex(row[3]);
        const uint8_t key_id = wire[0] & 7;
        RxRig a(key, tail, key_id), b(key, tail, key_id);
        Outcome oa = a.run(st, wire), ob = b.run(js, wire);
        PF_CHECK(oa.result.outcome == FlowOutcome::Completed);
        PF_CHECK(same(oa, ob));
        PF_CHECK(ob.bytes == plain);                                              // and it is OpenVPN's real plaintext
        // Replay of the same packet: both reject it for the same reason, with the same effect on the buffer.
        oa = a.run(st, wire);
        ob = b.run(js, wire);
        PF_CHECK(oa.result.outcome == FlowOutcome::Dropped && oa.result.error == Error::ReplayDetected);
        PF_CHECK(same(oa, ob));
        // Tampered tag / ciphertext: same drop, nothing released.
        for (const size_t at : {size_t(9), wire.size() - 1}) {
            auto bad = wire;
            bad[at] ^= 0x01;
            RxRig c(key, tail, key_id), d(key, tail, key_id);
            const Outcome oc = c.run(st, bad), od = d.run(js, bad);
            PF_CHECK(oc.result.outcome == FlowOutcome::Dropped && oc.result.error == Error::AuthFailed);
            PF_CHECK(same(oc, od));
        }
        // Wrong key id: unknown key in both.
        auto other = wire;
        other[0] = static_cast<uint8_t>((other[0] & 0xF8) | ((key_id + 3) & 7));
        RxRig e(key, tail, key_id), f(key, tail, key_id);
        const Outcome oe = e.run(st, other), of = f.run(js, other);
        PF_CHECK(oe.result.error == Error::UnknownKey);
        PF_CHECK(same(oe, of));
    }
}

PF_TEST(json_data_tx_reproduces_openvpns_exact_wire_bytes) {
    const BlockRegistry r = registry();
    const Flow st = static_data_tx(r), js = from_json(r, "flow_data_v2_tx.flow.json");
    const auto aead = make_openssl_aes256gcm();
    for (const auto& row : table("data_v2_gcm.golden")) {
        const auto key = unhex(row[0]), tail = unhex(row[1]), wire = unhex(row[2]), plain = unhex(row[3]);
        const uint8_t key_id = wire[0] & 7;
        const uint32_t peer = (uint32_t(wire[1]) << 16) | (uint32_t(wire[2]) << 8) | wire[3];
        const uint32_t pid = (uint32_t(wire[4]) << 24) | (uint32_t(wire[5]) << 16) | (uint32_t(wire[6]) << 8) | wire[7];
        std::vector<std::vector<uint8_t>> out;
        for (const Flow* f : {&st, &js}) {
            KeyStore keys;
            DataKey k;
            std::copy(key.begin(), key.end(), k.key.begin());
            std::copy(tail.begin(), tail.end(), k.nonce_tail.begin());
            k.tx_next = pid;                                                       // continue OpenVPN's packet-id sequence
            keys.bind_tx(key_id, keys.add(k));
            PacketBuffer pkt = PacketBuffer::from_bytes(plain.data(), plain.size());
            FlowContext ctx;
            ctx.packet = &pkt;
            ctx.keys = &keys;
            ctx.aead = aead.get();
            ctx.header = OvpnHeader{OvpnOpcode::DataV2, key_id, peer};
            ctx.header_valid = true;
            PF_REQUIRE(run_flow(*f, ctx).outcome == FlowOutcome::Completed);
            out.emplace_back(pkt.data(), pkt.data() + pkt.size());
        }
        PF_CHECK(out[0] == out[1]);
        PF_CHECK(out[1] == wire);                                                  // byte-identical to the real OpenVPN packet
    }
}

PF_TEST(a_flow_loaded_from_text_is_independent_of_how_it_was_written) {
    // Same Flow, different spelling (member order, extra whitespace, explicit defaults, x- extensions): same behavior.
    const BlockRegistry r = registry();
    const std::string noisy = R"({ "nodes":[ {"id":"parse","block":"parse_ovpn_header","x-pos":[1,2]},{"id":"policy","block":"reject_legacy_opcode"},
        {"id":"is_data","block":"is_data_v2"},{"id":"strip","block":"strip_data_v2_header"},{"id":"control","block":"mark_control_packet"} ],
        "edges":[ {"to":"control","from":"is_data","port":"no"}, {"from":"is_data","to":"strip","port":"yes"}, {"from":"strip","port":"continue","to":null} ],
        "version":1, "flow":{"runtime":["user"],"name":"openvpn_rx"}, "format":"protocol-flow", "x-editor":"test" })";
    LoadedFlow l = load_flow_json(noisy, r);
    PF_REQUIRE(l.ok());
    PF_CHECK(same_graph(l.flow, static_openvpn_rx(r)));
}
