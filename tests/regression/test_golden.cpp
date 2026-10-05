#include <cctype>
// Replays golden vectors. GOLDEN_DIR is injected by CMake.
#include <fstream>
#include <sstream>
#include "pf/openvpn_header.h"
#include "pf_test.h"

using namespace pf;

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> out; std::string cur; std::istringstream is(s);
    while (std::getline(is, cur, d)) {
        size_t a = cur.find_first_not_of(" \t"), b = cur.find_last_not_of(" \t\r");
        out.push_back(a == std::string::npos ? "" : cur.substr(a, b - a + 1));
    }
    return out;
}

static bool parse_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2 != 0) return false;
    for (size_t i = 0; i < s.size(); i += 2) {
        for (size_t j = i; j < i + 2; ++j)
            if (!std::isxdigit(static_cast<unsigned char>(s[j]))) return false;
        out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    }
    return true;
}

PF_TEST(golden_openvpn_header) {
    std::ifstream f(std::string(GOLDEN_DIR) + "/openvpn_header.golden");
    PF_REQUIRE(f.good());
    std::string line; int lineno = 0, n = 0;
    while (std::getline(f, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#') continue;
        const std::string where = "golden line " + std::to_string(lineno) + ": ";
        auto c = split(line, '|');
        if (c.size() != 5) { pf_test::record(__FILE__, __LINE__, where + "expected 5 columns"); continue; }

        std::vector<uint8_t> pkt;
        if (!parse_hex(c[0], pkt)) { pf_test::record(__FILE__, __LINE__, where + "bad hex '" + c[0] + "'"); continue; }

        OvpnHeader h{};
        auto st = parse_ovpn_header(pkt.data(), pkt.size(), h);
        const char* name = st == ParseStatus::Ok ? "Ok" : st == ParseStatus::Truncated ? "Truncated" : "InvalidOpcode";
        if (c[1] != name) {
            pf_test::record(__FILE__, __LINE__, where + "status expected " + c[1] + " got " + name);
            continue;
        }
        if (st == ParseStatus::Ok) {
            if (int(h.opcode) != std::stoi(c[2]) || int(h.key_id) != std::stoi(c[3]) ||
                h.peer_id != uint32_t(std::stoul(c[4])))
                pf_test::record(__FILE__, __LINE__, where + "field mismatch");
        } else if (c[2] != "0" || c[3] != "0" || c[4] != "0") {
            pf_test::record(__FILE__, __LINE__, where + "non-Ok rows must use 0 for opcode/key_id/peer_id");
        }
        ++n;
    }
    PF_CHECK(n > 0);
}
