// Replays DATA_V2 golden vectors captured from unmodified OpenVPN 2.6.19.
// Requires OpenSSL. GOLDEN_DIR is injected by CMake.
#include <fstream>
#include <sstream>
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/data_v2.h"
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

struct Vec { std::vector<uint8_t> key, tail, wire, plain; int line; };

static std::vector<Vec> load() {
    std::vector<Vec> out;
    std::ifstream f(std::string(GOLDEN_DIR) + "/data_v2_gcm.golden");
    PF_REQUIRE(f.good());
    std::string line; int n = 0;
    while (std::getline(f, line)) {
        ++n;
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c; std::stringstream ss(line); std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(trim(cell));
        PF_REQUIRE(c.size() == 4);
        out.push_back({unhex(c[0]), unhex(c[1]), unhex(c[2]), unhex(c[3]), n});
    }
    return out;
}

PF_TEST(golden_data_v2_decrypts_with_documented_nonce_and_aad) {
    auto vecs = load();
    PF_CHECK(vecs.size() >= 10);
    auto aead = make_openssl_aes256gcm();
    for (auto& v : vecs) {
        DataV2Packet d{};
        PF_REQUIRE(parse_data_v2(v.wire.data(), v.wire.size(), d) == ParseStatus::Ok);
        uint8_t nonce[12];
        for (int i = 0; i < 4; ++i) nonce[i] = v.wire[4 + i];            // packet_id as on the wire
        for (int i = 0; i < 8; ++i) nonce[4 + i] = v.tail[i];
        std::vector<uint8_t> buf(v.wire.begin() + kDataV2Overhead, v.wire.end());
        bool ok = aead->decrypt(v.key.data(), nonce, v.wire.data(), kDataV2AadLen, buf.data(), buf.size(), d.tag.data());
        if (!ok) pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": authentication failed");
        else if (buf != v.plain) pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": plaintext mismatch");
    }
}

PF_TEST(golden_data_v2_encrypt_reproduces_wire_bytes) {
    // GCM is deterministic for a fixed (key, nonce, aad): re-encrypting the plaintext must give OpenVPN's exact bytes.
    auto vecs = load();
    auto aead = make_openssl_aes256gcm();
    for (auto& v : vecs) {
        uint8_t nonce[12];
        for (int i = 0; i < 4; ++i) nonce[i] = v.wire[4 + i];
        for (int i = 0; i < 8; ++i) nonce[4 + i] = v.tail[i];
        std::vector<uint8_t> buf = v.plain; uint8_t tag[16];
        PF_REQUIRE(aead->encrypt(v.key.data(), nonce, v.wire.data(), kDataV2AadLen, buf.data(), buf.size(), tag));
        std::vector<uint8_t> rebuilt(v.wire.begin(), v.wire.begin() + kDataV2AadLen);
        rebuilt.insert(rebuilt.end(), tag, tag + 16);
        rebuilt.insert(rebuilt.end(), buf.begin(), buf.end());
        if (rebuilt != v.wire) pf_test::record(__FILE__, __LINE__, "golden line " + std::to_string(v.line) + ": re-encrypted bytes differ");
    }
}

PF_TEST(golden_data_v2_wrong_aad_fails_authentication) {
    auto vecs = load();
    PF_REQUIRE(!vecs.empty());
    auto aead = make_openssl_aes256gcm();
    auto& v = vecs[0];
    DataV2Packet d{};
    PF_REQUIRE(parse_data_v2(v.wire.data(), v.wire.size(), d) == ParseStatus::Ok);
    uint8_t nonce[12];
    for (int i = 0; i < 4; ++i) nonce[i] = v.wire[4 + i];
    for (int i = 0; i < 8; ++i) nonce[4 + i] = v.tail[i];
    std::vector<uint8_t> buf(v.wire.begin() + kDataV2Overhead, v.wire.end());
    // packet_id only (4B) as AAD: the layout we rejected during profile verification
    PF_CHECK(!aead->decrypt(v.key.data(), nonce, v.wire.data() + 4, 4, buf.data(), buf.size(), d.tag.data()));
}
