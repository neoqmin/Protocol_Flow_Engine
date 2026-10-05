// Parses the captured control-channel plaintexts (from tls_crypt.golden) with the control-packet parser
// and replays them through the reliability layer. The golden file's wire/plaintext columns are used as
// data, so no crypto is needed here.
#include <fstream>
#include <sstream>
#include "pf/control_packet.h"
#include "pf/reliable.h"
#include "pf_test.h"

using namespace pf;

namespace {
struct CtlVec { bool c2s; std::vector<uint8_t> wire, plain; int line; };

std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t\r");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
std::vector<CtlVec> load() {
    std::vector<CtlVec> out;
    std::ifstream f(std::string(GOLDEN_DIR) + "/tls_crypt.golden");
    PF_REQUIRE(f.good());
    std::string line; int n = 0;
    while (std::getline(f, line)) {
        ++n;
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c; std::stringstream ss(line); std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(trim(cell));
        PF_REQUIRE(c.size() == 4);
        out.push_back({c[0] == "c2s", unhex(c[2]), unhex(c[3]), n});
    }
    return out;
}
}  // namespace

PF_TEST(golden_control_plaintexts_parse_and_rebuild_byte_for_byte) {
    auto vecs = load();
    PF_CHECK(vecs.size() >= 10);
    for (auto& v : vecs) {
        ControlPacket p;
        auto st = parse_control(v.wire[0], v.wire.data() + 1, v.plain.data(), v.plain.size(), p);
        if (st != ControlParseStatus::Ok) { pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": parse failed"); continue; }
        std::vector<uint8_t> again;
        if (!build_control_plaintext(p, again) || again != v.plain)
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": rebuilt plaintext differs");
    }
}

PF_TEST(golden_server_messages_arrive_in_order_and_form_tls_records) {
    // Feed the captured server->client messages into the receiver exactly as received.
    auto vecs = load();
    ReliableReceiver rx;
    std::vector<ReliableReceiver::Delivered> delivered;
    size_t msgs = 0;
    for (auto& v : vecs) {
        if (v.c2s) continue;
        ControlPacket p;
        PF_REQUIRE(parse_control(v.wire[0], v.wire.data() + 1, v.plain.data(), v.plain.size(), p) == ControlParseStatus::Ok);
        if (!p.has_message) continue;
        ++msgs;
        auto r = rx.on_message(p.message_id, p.payload, delivered);
        if (r != ReliableReceiver::Result::Delivered)
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": message not delivered in order");
    }
    PF_CHECK(msgs >= 4);
    PF_CHECK_EQ(delivered.size(), msgs);
    PF_REQUIRE(delivered.size() >= 2);
    PF_CHECK_EQ(delivered[0].payload.size(), size_t(0));          // HARD_RESET_SERVER has no payload
    PF_REQUIRE(!delivered[1].payload.empty());
    PF_CHECK_EQ(delivered[1].payload[0], 0x16);                   // first TLS record: handshake (ServerHello)
    PF_CHECK_EQ(delivered[1].payload[1], 0x03);
}

PF_TEST(golden_client_acks_cover_every_server_message) {
    auto vecs = load();
    std::vector<uint32_t> server_ids, acked_by_client;
    for (auto& v : vecs) {
        ControlPacket p;
        PF_REQUIRE(parse_control(v.wire[0], v.wire.data() + 1, v.plain.data(), v.plain.size(), p) == ControlParseStatus::Ok);
        if (!v.c2s && p.has_message) server_ids.push_back(p.message_id);
        if (v.c2s) acked_by_client.insert(acked_by_client.end(), p.acks.begin(), p.acks.end());
    }
    for (uint32_t id : server_ids) {
        bool found = false;
        for (uint32_t a : acked_by_client) if (a == id) found = true;
        if (!found) pf_test::record(__FILE__, __LINE__, "server message " + std::to_string(id) + " never acknowledged by the client");
    }
}
