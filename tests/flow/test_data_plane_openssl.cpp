// Full data-plane flows with REAL AES-256-GCM against OpenVPN 2.6.19 golden packets. Requires OpenSSL.
#include <fstream>
#include <sstream>
#include <map>
#include "pf/blocks/data_plane_blocks.h"
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/flow.h"
#include "pf/key_store.h"
#include "pf_test.h"

using namespace pf;

static std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t\r");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

PF_TEST(real_openvpn_packets_flow_through_rx_blocks_in_capture_order) {
    BlockRegistry reg; PF_REQUIRE(register_data_plane_blocks(reg));
    FlowBuilder b("dp_rx");
    b.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
     .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
    auto built = b.build(reg); PF_REQUIRE(built.ok());

    auto aead = make_openssl_aes256gcm();
    std::ifstream f(std::string(GOLDEN_DIR) + "/data_v2_gcm.golden");
    PF_REQUIRE(f.good());

    // One KeyStore per (key, tail) = per direction+generation. Vectors come in capture order,
    // so packet-ids increase within each store and the replay window must accept every one once.
    std::map<std::string, std::unique_ptr<KeyStore>> stores;
    int ok = 0, n = 0;
    std::string line;
    while (std::getline(f, line)) {
        ++n;
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c; std::stringstream ss(line); std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(trim(cell));
        PF_REQUIRE(c.size() == 4);
        auto key = unhex(c[0]), tail = unhex(c[1]), wire = unhex(c[2]), plain = unhex(c[3]);

        auto& store = stores[c[0] + c[1]];
        const uint8_t key_id = wire[0] & 7;
        if (!store) {
            store = std::make_unique<KeyStore>();
            DataKey dk;
            std::copy(key.begin(), key.end(), dk.key.begin());
            std::copy(tail.begin(), tail.end(), dk.nonce_tail.begin());
            PF_REQUIRE(store->bind_rx(key_id, store->add(dk)));
        }
        PacketBuffer pkt = PacketBuffer::from_bytes(wire.data(), wire.size());
        FlowContext ctx; ctx.packet = &pkt; ctx.keys = store.get(); ctx.aead = aead.get();
        FlowResult r = run_flow(built.flow, ctx);
        if (r.outcome != FlowOutcome::Completed) {
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(n) + ": flow ended " + error_name(r.error));
            continue;
        }
        if (std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size()) != plain)
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(n) + ": plaintext mismatch");
        else ++ok;

        // The same packet again must now be rejected as a replay.
        PacketBuffer again = PacketBuffer::from_bytes(wire.data(), wire.size());
        FlowContext c2; c2.packet = &again; c2.keys = store.get(); c2.aead = aead.get();
        FlowResult r2 = run_flow(built.flow, c2);
        if (r2.outcome != FlowOutcome::Dropped || r2.error != Error::ReplayDetected)
            pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(n) + ": replay not detected");
    }
    PF_CHECK(ok >= 10);
}
