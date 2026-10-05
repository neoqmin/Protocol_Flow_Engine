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

PF_TEST(golden_openvpn_header) {
    std::ifstream f(std::string(GOLDEN_DIR) + "/openvpn_header.golden");
    PF_CHECK(f.good());
    std::string line; int n = 0;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto c = split(line, '|');
        PF_CHECK_EQ(c.size(), size_t(5));
        std::vector<uint8_t> pkt;
        for (size_t i = 0; i + 1 < c[0].size(); i += 2)
            pkt.push_back(static_cast<uint8_t>(std::stoi(c[0].substr(i, 2), nullptr, 16)));
        OvpnHeader h{};
        auto st = parse_ovpn_header(pkt.data(), pkt.size(), h);
        const char* name = st == ParseStatus::Ok ? "Ok" : st == ParseStatus::Truncated ? "Truncated" : "InvalidOpcode";
        PF_CHECK(c[1] == name);
        if (st == ParseStatus::Ok) {
            PF_CHECK_EQ(int(h.opcode), std::stoi(c[2]));
            PF_CHECK_EQ(int(h.key_id), std::stoi(c[3]));
            PF_CHECK_EQ(h.peer_id, uint32_t(std::stoul(c[4])));
        }
        ++n;
    }
    PF_CHECK(n > 0);
}
