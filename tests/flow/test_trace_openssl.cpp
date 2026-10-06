// F-3 privacy rule, pinned on REAL traffic: trace the data-plane Flows while they decrypt (and re-encrypt) every DATA_V2
// golden vector captured from unmodified OpenVPN 2.6.19, then search the JSON Lines output for the key, the nonce tail
// and the plaintext - raw and hex. None may appear. (Records have no byte fields by construction; this keeps it so.)
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/data_path.h"
#include "pf/trace.h"
#include "pf_test.h"

using namespace pf;

#ifndef GOLDEN_DIR
#define GOLDEN_DIR "tests/regression/golden"
#endif

namespace {

struct Vec { std::vector<uint8_t> key, tail, wire, plain; };

std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}
std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t\r");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
std::vector<Vec> load() {
    std::vector<Vec> out;
    std::ifstream f(std::string(GOLDEN_DIR) + "/data_v2_gcm.golden");
    PF_REQUIRE(f.good());
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(trim(cell));
        PF_REQUIRE(c.size() == 4);
        out.push_back({unhex(c[0]), unhex(c[1]), unhex(c[2]), unhex(c[3])});
    }
    return out;
}
std::string hex(const uint8_t* p, size_t n, bool upper) {
    static const char* lo = "0123456789abcdef";
    static const char* up = "0123456789ABCDEF";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += (upper ? up : lo)[p[i] >> 4]; s += (upper ? up : lo)[p[i] & 15]; }
    return s;
}
// Any 8-byte window of `secret` (raw or hex) found in `text`.
bool leaks(const std::string& text, const std::vector<uint8_t>& secret) {
    const size_t w = 8;
    if (secret.size() < w) return text.find(hex(secret.data(), secret.size(), false)) != std::string::npos && secret.size() >= 4;
    for (size_t i = 0; i + w <= secret.size(); ++i) {
        if (text.find(std::string(reinterpret_cast<const char*>(secret.data() + i), w)) != std::string::npos) return true;
        if (text.find(hex(secret.data() + i, w, false)) != std::string::npos) return true;
        if (text.find(hex(secret.data() + i, w, true)) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

PF_TEST(trace_of_real_decryption_contains_no_key_or_plaintext) {
    const auto vecs = load();
    PF_REQUIRE(vecs.size() >= 10);
    auto aead = make_openssl_aes256gcm();
    TraceRing ring(100000);
    size_t opened = 0;
    for (const auto& v : vecs) {
        KeyStore keys;
        DataKey k;
        std::copy(v.key.begin(), v.key.end(), k.key.begin());
        std::copy(v.tail.begin(), v.tail.end(), k.nonce_tail.begin());
        const uint8_t key_id = v.wire[0] & 7;
        const KeyRef ref = keys.add(k);
        PF_REQUIRE(keys.bind_rx(key_id, ref));
        PF_REQUIRE(keys.bind_tx(key_id, ref));
        DataPath dp;
        PF_REQUIRE(dp.init(&keys, aead.get()));
        dp.set_trace(&ring);

        PacketBuffer pkt = PacketBuffer::from_bytes(v.wire.data(), v.wire.size());
        const DataPath::Opened o = dp.open(pkt);
        PF_CHECK_EQ(o.error, Error::None);
        if (o.error == Error::None && std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size()) == v.plain) ++opened;

        PacketBuffer replay = PacketBuffer::from_bytes(v.wire.data(), v.wire.size());
        PF_CHECK_EQ(dp.open(replay).error, Error::ReplayDetected);        // a drop is traced too

        PacketBuffer tx = DataPath::make_tx_buffer(2048);
        std::copy(v.plain.begin(), v.plain.end(), tx.put(v.plain.size()));
        PF_CHECK_EQ(dp.seal(tx, key_id, 0), Error::None);
    }
    PF_CHECK_EQ(opened, vecs.size());
    PF_CHECK(ring.overwritten() == 0);
    const std::string out = write_trace_jsonl(ring);
    PF_CHECK(out.find("\"node\":\"decrypt\"") != std::string::npos);      // the trace is really there
    PF_CHECK(out.find("ReplayDetected") != std::string::npos);
    for (size_t i = 0; i < vecs.size(); ++i) {
        PF_CHECK(!leaks(out, vecs[i].key));
        PF_CHECK(!leaks(out, vecs[i].tail));
        PF_CHECK(!leaks(out, vecs[i].plain));
    }
    // and the leak check itself works
    PF_CHECK(leaks(out + hex(vecs[0].key.data(), 8, false), vecs[0].key));
}
